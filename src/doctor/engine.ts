// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { lstat, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { CredentialStore } from "../auth/credentials.js";
import { localTokenStatus } from "../auth/token-lifecycle.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import { probeAtomicWrite } from "../config/atomic-write.js";
import type { VerifiedFileSecurity } from "../config/file-security.js";
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

interface PermissionTarget {
  readonly path: string;
  readonly kind: "directory" | "file";
  readonly label: string;
  readonly safe: boolean;
  readonly fixable: boolean;
}

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
    selectProfile(
      dependencies.profiles,
      options.site,
      dependencies.environment,
    );
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
    for (const target of targets.filter(
      (candidate) => !candidate.safe && candidate.fixable,
    )) {
      if (target.kind === "directory")
        await dependencies.security.secureDirectory(target.path);
      else await dependencies.security.secureFile(target.path);
      fixed = true;
    }
    if (fixed)
      targets = await permissionTargets(
        dependencies.paths,
        dependencies.security,
      );
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
    access: local.access,
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
  if (
    local.credentialState === "expired" ||
    local.access === "unknown" ||
    profile.clientId === undefined
  )
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

async function selectProfile(
  profiles: ProfileStore,
  explicitSite: string | undefined,
  environment: SelectionEnvironment,
): Promise<SiteProfile | undefined> {
  const all = await profiles.list();
  const requested = explicitSite ?? environment.NOVAMIRA_SITE;
  if (requested !== undefined && requested !== "")
    return all.find((profile) => profile.name === requested);
  return all.length === 1 ? all[0] : undefined;
}

async function permissionTargets(
  paths: PlatformPaths,
  security: VerifiedFileSecurity,
): Promise<PermissionTarget[]> {
  const targets: PermissionTarget[] = [];
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
  for (const [path, label] of directories) {
    const target = await inspectPermissionTarget(
      path,
      "directory",
      label,
      security,
    );
    if (target !== undefined) targets.push(target);
  }
  const config = await inspectPermissionTarget(
    paths.configFile,
    "file",
    "config.file",
    security,
  );
  if (config !== undefined) targets.push(config);
  for (const [directory, pattern, label] of [
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
  ] as const) {
    let names: string[];
    try {
      names = await readdir(directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    for (const name of names
      .filter((candidate) => pattern.test(candidate))
      .sort()) {
      const target = await inspectPermissionTarget(
        join(directory, name),
        "file",
        label,
        security,
      );
      if (target !== undefined) targets.push(target);
    }
  }
  return targets;
}

async function inspectPermissionTarget(
  path: string,
  kind: "directory" | "file",
  label: string,
  security: VerifiedFileSecurity,
): Promise<PermissionTarget | undefined> {
  try {
    const info = await lstat(path);
    const typeMatches =
      kind === "directory" ? info.isDirectory() : info.isFile();
    const safe =
      typeMatches &&
      (kind === "directory"
        ? await security.verifyDirectory(path)
        : await security.verifyFile(path));
    return {
      path,
      kind,
      label,
      safe,
      fixable: typeMatches && !info.isSymbolicLink(),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    return { path, kind, label, safe: false, fixable: false };
  }
}

function overallStatus(checks: readonly DoctorCheck[]): DoctorStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.some((check) => check.status === "warn")) return "warn";
  return "pass";
}
