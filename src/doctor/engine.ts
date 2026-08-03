// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { lstat, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { CredentialStore } from "../auth/credentials.js";
import { localTokenStatus } from "../auth/token-lifecycle.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import { probeAtomicWrite } from "../config/atomic-write.js";
import type {
  AclTarget,
  AclTargetKind,
  VerifiedFileSecurity,
} from "../config/file-security.js";
import { secureDirectory } from "../config/file-security.js";
import type { PlatformPaths } from "../config/paths.js";
import type {
  ProfileStore,
  SelectionEnvironment,
  SiteProfile,
} from "../config/profiles.js";
import type { ArtifactStore } from "../output/artifacts.js";

export type DoctorStatus = "pass" | "warn" | "fail";

export interface DoctorCheck {
  readonly id: string;
  readonly status: DoctorStatus;
  readonly summary: string;
  readonly evidence: Readonly<Record<string, unknown>>;
  readonly fixed?: boolean;
}

export interface DoctorReport {
  readonly version: 1;
  readonly offline: boolean;
  readonly fix: boolean;
  readonly status: DoctorStatus;
  readonly checks: readonly DoctorCheck[];
}

export interface DoctorCheckDefinition {
  readonly id: string;
  run(): Promise<Omit<DoctorCheck, "id">>;
}

export interface OfflineDoctorDependencies {
  readonly paths: PlatformPaths;
  readonly security: VerifiedFileSecurity;
  readonly profiles: ProfileStore;
  readonly credentials: CredentialStore;
  readonly abilityCache: AbilityMetadataCache;
  readonly artifacts: ArtifactStore;
  readonly environment: SelectionEnvironment;
  readonly nodeVersion?: string;
  readonly platform?: NodeJS.Platform;
  readonly now?: () => number;
}

interface PermissionCandidate {
  readonly path: string;
  readonly kind: AclTargetKind;
  readonly label: string;
}

interface PermissionTarget extends PermissionCandidate {
  readonly safe: boolean;
  readonly fixable: boolean;
}

// A candidate that survived `lstat`. `verify` marks the ones whose node type
// already matches, which are exactly the ones worth an ACL question; the rest
// are unsafe no matter what the ACL says.
interface InspectedTarget {
  readonly target: PermissionTarget;
  readonly verify: boolean;
}

// Deliberately sequential. Several checks reach the same profile lock key —
// `oauth.token` and `profile.valid` both lock on the profile name, and
// `storage.atomic --fix` locks the cache and artifact keys — and
// `ProfileLockManager.acquire` rejects a key its own manager already holds.
// Overlapping the definitions would therefore fail intermittently; the cost
// they used to dominate is batched inside the individual checks instead.
export async function runDoctorChecks(
  definitions: readonly DoctorCheckDefinition[],
  options: { readonly offline: boolean; readonly fix: boolean },
): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];
  for (const definition of definitions) {
    try {
      checks.push({ id: definition.id, ...(await definition.run()) });
    } catch {
      checks.push({
        id: definition.id,
        status: "fail",
        summary: "The check could not be completed.",
        evidence: { error: "check_threw" },
      });
    }
  }
  return {
    version: 1,
    offline: options.offline,
    fix: options.fix,
    status: overallStatus(checks),
    checks,
  };
}

export function offlineDoctorDefinitions(
  dependencies: OfflineDoctorDependencies,
  options: { readonly fix: boolean; readonly site?: string },
): readonly DoctorCheckDefinition[] {
  const selectedProfile = () =>
    dependencies.profiles.trySelect(options.site, dependencies.environment);
  return [
    {
      id: "runtime.node",
      run: () =>
        Promise.resolve(
          runtimeCheck(
            dependencies.nodeVersion ?? process.versions.node,
            dependencies.platform ?? process.platform,
          ),
        ),
    },
    {
      id: "storage.permissions",
      run: () => permissionCheck(dependencies, options.fix),
    },
    {
      id: "storage.atomic",
      run: () => storageCheck(dependencies, options.fix),
    },
    {
      id: "credential.backend",
      run: () => Promise.resolve(credentialCheck(dependencies.credentials)),
    },
    {
      id: "profile.valid",
      run: () =>
        profileCheck(
          dependencies.profiles,
          selectedProfile,
          options.site ?? dependencies.environment.NOVAMIRA_SITE,
        ),
    },
    {
      id: "oauth.token",
      run: () => tokenCheck(dependencies, selectedProfile),
    },
  ];
}

export async function runOfflineDoctor(
  dependencies: OfflineDoctorDependencies,
  options: { readonly fix: boolean; readonly site?: string },
): Promise<DoctorReport> {
  return runDoctorChecks(offlineDoctorDefinitions(dependencies, options), {
    offline: true,
    fix: options.fix,
  });
}

function runtimeCheck(
  nodeVersion: string,
  platform: NodeJS.Platform,
): Omit<DoctorCheck, "id"> {
  const major = Number(nodeVersion.split(".")[0]);
  const evidence = { nodeVersion, platform, minimumMajor: 22 };
  if (!Number.isSafeInteger(major) || major < 22)
    return {
      status: "fail",
      summary: "Node.js 22 or newer is required.",
      evidence,
    };
  if (
    major % 2 !== 0 ||
    !(["linux", "darwin", "win32"] as readonly string[]).includes(platform)
  )
    return {
      status: "warn",
      summary:
        "The runtime is supported but is not a primary tested LTS platform.",
      evidence,
    };
  return {
    status: "pass",
    summary: "The Node.js runtime is supported.",
    evidence,
  };
}

async function permissionCheck(
  dependencies: OfflineDoctorDependencies,
  fix: boolean,
): Promise<Omit<DoctorCheck, "id">> {
  let targets = await permissionTargets(
    dependencies.paths,
    dependencies.security,
  );
  let fixed = false;
  if (fix) {
    const repairable = targets.filter(
      (candidate) => !candidate.safe && candidate.fixable,
    );
    if (repairable.length > 0) {
      // One hardening pass for every repairable target, then one verification
      // pass, instead of a helper process per target.
      //
      // A rejection is not reported here. `secureMany` fails the whole batch
      // when any target cannot be proved owner-only afterwards, and a lock or
      // cache file another `novamira` process removes mid-repair counts as
      // exactly that - the same race the enumeration below already tolerates.
      // Re-enumerating is what decides: a target that vanished is omitted and
      // one that is genuinely still unsafe is reported as a failure, so a real
      // problem is never swallowed.
      await dependencies.security
        .secureMany(repairable.map(aclTarget))
        .catch(() => undefined);
      fixed = true;
      targets = await permissionTargets(
        dependencies.paths,
        dependencies.security,
      );
    }
  }
  const unsafe = targets.filter((target) => !target.safe);
  const evidence = {
    inspected: targets.length,
    unsafe: unsafe.map((target) => target.label).sort(),
  };
  if (unsafe.length > 0)
    return {
      status: "fail",
      summary:
        "Private local storage has unsafe ownership, permissions, or file types.",
      evidence,
      ...(fixed ? { fixed: true } : {}),
    };
  if (targets.length === 0)
    return {
      status: "warn",
      summary: "Private local storage has not been initialized.",
      evidence,
    };
  return {
    status: "pass",
    summary: fixed
      ? "Private local storage permissions were repaired."
      : "Private local storage permissions are safe.",
    evidence,
    ...(fixed ? { fixed: true } : {}),
  };
}

async function storageCheck(
  dependencies: OfflineDoctorDependencies,
  fix: boolean,
): Promise<Omit<DoctorCheck, "id">> {
  try {
    const state = await lstat(dependencies.paths.stateDir);
    if (!state.isDirectory())
      return {
        status: "fail",
        summary: "The state location is not a directory.",
        evidence: { atomicRename: false },
      };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    if (!fix)
      return {
        status: "warn",
        summary: "The state location has not been initialized.",
        evidence: { atomicRename: null },
      };
    await secureDirectory(dependencies.paths.stateDir, dependencies.security);
  }

  try {
    await probeAtomicWrite(dependencies.paths.stateDir);
  } catch {
    return {
      status: "fail",
      summary:
        "The state location does not support the required atomic write pattern.",
      evidence: { atomicRename: false },
    };
  }
  const cleanup = fix
    ? {
        abilityCache: await dependencies.abilityCache.cleanupExpired(),
        artifacts: await dependencies.artifacts.cleanup(),
      }
    : undefined;
  return {
    status: "pass",
    summary: fix
      ? "Atomic storage works and bounded cache maintenance completed."
      : "Atomic storage is available.",
    evidence: {
      atomicRename: true,
      ...(cleanup === undefined ? {} : { cleanup }),
    },
    ...(fix ? { fixed: true } : {}),
  };
}

function credentialCheck(
  credentials: CredentialStore,
): Omit<DoctorCheck, "id"> {
  const diagnostic = credentials.diagnostic();
  const evidence = {
    backend: diagnostic.backend,
    osBackedEncryption: diagnostic.osBackedEncryption,
  };
  return diagnostic.osBackedEncryption
    ? {
        status: "pass",
        summary: "Credentials use an OS-backed credential service.",
        evidence,
      }
    : {
        status: "warn",
        summary: "Credentials use the owner-only file fallback.",
        evidence,
      };
}

async function profileCheck(
  profiles: ProfileStore,
  selected: () => Promise<SiteProfile | undefined>,
  requested: string | undefined,
): Promise<Omit<DoctorCheck, "id">> {
  const all = await profiles.list();
  const profile = await selected();
  const evidence = {
    profiles: all.map(({ name }) => name),
    selected: profile?.name ?? null,
  };
  if (all.length === 0)
    return {
      status: "warn",
      summary: "No site profiles are configured.",
      evidence,
    };
  if (requested !== undefined && requested !== "" && profile === undefined)
    return {
      status: "fail",
      summary: "The requested site profile does not exist.",
      evidence,
    };
  if (profile === undefined)
    return {
      status: "warn",
      summary: "A site profile must be selected for profile-specific checks.",
      evidence,
    };
  return {
    status: "pass",
    summary: "The selected profile is valid and normalized.",
    evidence,
  };
}

async function tokenCheck(
  dependencies: OfflineDoctorDependencies,
  selected: () => Promise<SiteProfile | undefined>,
): Promise<Omit<DoctorCheck, "id">> {
  const profile = await selected();
  if (profile === undefined)
    return {
      status: "warn",
      summary: "No profile is selected for local token inspection.",
      evidence: { credentialState: "not_checked" },
    };
  let credential;
  try {
    credential = await dependencies.credentials.read({
      profileName: profile.name,
      origin: profile.origin,
    });
  } catch {
    return {
      status: "fail",
      summary: "Stored credentials are corrupt or cannot be read safely.",
      evidence: { credentialState: "invalid" },
    };
  }
  const local = localTokenStatus(
    credential,
    dependencies.now?.() ?? Date.now(),
  );
  const evidence = {
    credentialState: local.credentialState,
    expiresAt: local.expiresAt ?? null,
    publicClientConfigured: profile.clientId !== undefined,
  };
  if (local.credentialState === "absent")
    return {
      status: "warn",
      summary:
        "No local OAuth credentials are stored for the selected profile.",
      evidence,
    };
  if (local.credentialState === "expired" || profile.clientId === undefined)
    return {
      status: "fail",
      summary: "The local OAuth token state is not coherent or usable.",
      evidence,
    };
  if (local.credentialState === "near_expiry")
    return {
      status: "warn",
      summary: "The access token is inside the refresh safety window.",
      evidence,
    };
  return {
    status: "pass",
    summary: "The local OAuth token state is coherent.",
    evidence,
  };
}

function aclTarget(candidate: PermissionCandidate): AclTarget {
  return { path: candidate.path, kind: candidate.kind };
}

// The candidate order is contractual: the evidence list and the fix ordering
// both depend on it. Directories in their listed order, then the config file,
// then each globbed group sorted by name.
async function permissionCandidates(
  paths: PlatformPaths,
): Promise<readonly PermissionCandidate[]> {
  const directories = [
    [dirname(paths.configFile), "config.directory"],
    [paths.stateDir, "state.directory"],
    [join(paths.stateDir, "locks"), "locks.directory"],
    [paths.credentialsDir, "credentials.directory"],
    [join(paths.credentialsDir, "v1"), "credentials.v1.directory"],
    [paths.cacheDir, "cache.directory"],
    [join(paths.cacheDir, "abilities", "v1"), "cache.abilities.directory"],
    [join(paths.cacheDir, "artifacts", "v1"), "cache.artifacts.directory"],
  ] as const;
  const groups = await Promise.all(
    (
      [
        [join(paths.stateDir, "locks"), /^[a-f0-9]{64}\.lock$/, "locks.file"],
        [
          join(paths.credentialsDir, "v1"),
          /^[a-f0-9]{64}\.json$/,
          "credentials.file",
        ],
        [
          join(paths.cacheDir, "abilities", "v1"),
          /^[a-f0-9]{64}\.json$/,
          "cache.ability.file",
        ],
        [
          join(paths.cacheDir, "artifacts", "v1"),
          /^\d{13}-[a-f0-9-]{36}\.json$/,
          "cache.artifact.file",
        ],
      ] as const
    ).map(async ([directory, pattern, label]) => {
      let names: string[];
      try {
        names = await readdir(directory);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT")
          return [] as readonly PermissionCandidate[];
        throw error;
      }
      return names
        .filter((candidate) => pattern.test(candidate))
        .sort()
        .map((name) => ({
          path: join(directory, name),
          kind: "file" as const,
          label,
        }));
    }),
  );
  return [
    ...directories.map(([path, label]) => ({
      path,
      kind: "directory" as const,
      label,
    })),
    { path: paths.configFile, kind: "file" as const, label: "config.file" },
    ...groups.flat(),
  ];
}

// Every `lstat` runs first and concurrently, because they are cheap; the ACL
// verdicts then arrive from a single batched check, so inspecting thirteen
// targets costs one helper process on Windows rather than thirteen.
async function permissionTargets(
  paths: PlatformPaths,
  security: VerifiedFileSecurity,
): Promise<PermissionTarget[]> {
  const inspected = (
    await Promise.all((await permissionCandidates(paths)).map(inspectCandidate))
  ).filter((entry): entry is InspectedTarget => entry !== undefined);
  const pending = inspected.filter((entry) => entry.verify);
  if (pending.length === 0) return inspected.map((entry) => entry.target);
  let verdicts: readonly boolean[];
  // A checker that fails outright used to leave every target it touched
  // unsafe and unfixable, and still does; only a working checker can prove a
  // target safe.
  let checkerFailed = false;
  try {
    verdicts = await security.verifyMany(
      pending.map((entry) => aclTarget(entry.target)),
    );
  } catch {
    verdicts = [];
    checkerFailed = true;
  }
  let index = 0;
  const judged = inspected.map((entry) => {
    if (!entry.verify) return entry.target;
    const safe = verdicts[index] ?? false;
    index += 1;
    return {
      ...entry.target,
      safe,
      fixable: checkerFailed ? false : entry.target.fixable,
    };
  });
  return dropVanished(judged);
}

// A target can disappear between the `lstat` pass and the batched verdict -
// another `novamira` process releasing a lock file, or evicting a cache
// record, is enough - and the checker answers `false` for a path it cannot
// read. Reporting that as unsafe would fail `storage.permissions` for a
// correctly hardened installation, so a target that no longer exists is
// omitted, exactly as it would have been had the `lstat` come a moment later.
async function dropVanished(
  targets: readonly PermissionTarget[],
): Promise<PermissionTarget[]> {
  const present = await Promise.all(
    targets.map(async (target) => {
      if (target.safe) return true;
      try {
        await lstat(target.path);
        return true;
      } catch (error) {
        return (error as NodeJS.ErrnoException).code !== "ENOENT";
      }
    }),
  );
  return targets.filter((_, index) => present[index]);
}

async function inspectCandidate(
  candidate: PermissionCandidate,
): Promise<InspectedTarget | undefined> {
  try {
    const info = await lstat(candidate.path);
    const typeMatches =
      candidate.kind === "directory" ? info.isDirectory() : info.isFile();
    return {
      // `safe` is provisional: only a batched ACL verdict can raise it, and a
      // target whose node type is already wrong never gets one.
      target: {
        ...candidate,
        safe: false,
        fixable: typeMatches && !info.isSymbolicLink(),
      },
      verify: typeMatches,
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    return {
      target: { ...candidate, safe: false, fixable: false },
      verify: false,
    };
  }
}

function overallStatus(checks: readonly DoctorCheck[]): DoctorStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.some((check) => check.status === "warn")) return "warn";
  return "pass";
}
