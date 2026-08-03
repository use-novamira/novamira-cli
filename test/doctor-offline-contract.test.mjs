// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AbilityMetadataCache } from "../dist/cache/ability-cache.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import { ProfileStore } from "../dist/config/profiles.js";
import {
  offlineDoctorDefinitions,
  runDoctorChecks,
} from "../dist/doctor/engine.js";
import { main } from "../dist/main.js";
import { ArtifactStore } from "../dist/output/artifacts.js";

function capture() {
  let stdout = "";
  let stderr = "";
  return {
    streams: {
      stdout: { write: (value) => (stdout += value) },
      stderr: { write: (value) => (stderr += value) },
    },
    read: () => ({ stdout, stderr }),
  };
}

function fakeDependencies(root, overrides = {}) {
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const security = new UnixFileSecurity();
  return {
    paths,
    security,
    profiles: { list: async () => [], trySelect: async () => undefined },
    credentials: {
      diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
      read: async () => undefined,
    },
    abilityCache: {
      cleanupExpired: async () => ({ removed: 0, remainingBytes: 0 }),
    },
    artifacts: {
      cleanup: async () => ({ removed: 0, remainingBytes: 0 }),
    },
    environment: {},
    now: () => Date.parse("2026-07-21T12:00:00.000Z"),
    ...overrides,
  };
}

async function runCheck(dependencies, id, options = {}) {
  const definition = offlineDoctorDefinitions(dependencies, {
    fix: false,
    ...options,
  }).find((candidate) => candidate.id === id);
  assert.ok(definition);
  return definition.run();
}

async function statusOf(dependencies, id, options = {}) {
  return (await runCheck(dependencies, id, options)).status;
}

// Records how the doctor asks about ACLs. `single` must stay zero: one helper
// process per target is exactly the Windows regression this guards against.
function countingSecurity(inner = new UnixFileSecurity()) {
  const calls = { single: 0, verifyMany: [], secureMany: [] };
  return {
    calls,
    security: {
      verifyDirectory: async (path) => {
        calls.single += 1;
        return inner.verifyDirectory(path);
      },
      verifyFile: async (path) => {
        calls.single += 1;
        return inner.verifyFile(path);
      },
      secureDirectory: async (path) => {
        calls.single += 1;
        return inner.secureDirectory(path);
      },
      secureFile: async (path) => {
        calls.single += 1;
        return inner.secureFile(path);
      },
      verifyMany: async (targets) => {
        calls.verifyMany.push(targets.map(({ path }) => path));
        return inner.verifyMany(targets);
      },
      secureMany: async (targets) => {
        calls.secureMany.push(targets.map(({ path }) => path));
        return inner.secureMany(targets);
      },
    },
  };
}

const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);

// One tree holding every classification the permission check distinguishes:
// safe, unsafe-but-fixable, symlinked, wrong node type, and missing.
async function mixedPermissionTree(root) {
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const locks = join(paths.stateDir, "locks");
  const credentialsV1 = join(paths.credentialsDir, "v1");
  const credentialsReal = join(paths.credentialsDir, "v1-real");
  const abilities = join(paths.cacheDir, "abilities", "v1");

  await mkdir(locks, { recursive: true, mode: 0o700 });
  await mkdir(credentialsReal, { recursive: true, mode: 0o700 });
  await mkdir(abilities, { recursive: true, mode: 0o700 });
  // A symlinked directory still lists its contents but can never be hardened
  // in place, so it must be unsafe and unfixable.
  await symlink(credentialsReal, credentialsV1);
  // cache/artifacts/v1 is deliberately absent: a missing target is omitted
  // entirely rather than reported unsafe.
  await chmod(abilities, 0o755);
  await writeFile(paths.configFile, "{}", { mode: 0o600 });
  // A directory carrying a lock-file name is the wrong node type.
  await mkdir(join(locks, `${HEX_A}.lock`), { mode: 0o700 });
  await writeFile(join(locks, `${HEX_B}.lock`), "{}", { mode: 0o600 });
  await writeFile(join(credentialsReal, `${HEX_A}.json`), "{}", {
    mode: 0o644,
  });
  await writeFile(join(abilities, `${HEX_A}.json`), "{}", { mode: 0o600 });

  return {
    paths,
    // Every well-typed target, in the contractual inspection order.
    verifiable: [
      root,
      paths.stateDir,
      locks,
      paths.credentialsDir,
      paths.cacheDir,
      abilities,
      paths.configFile,
      join(locks, `${HEX_B}.lock`),
      join(credentialsV1, `${HEX_A}.json`),
      join(abilities, `${HEX_A}.json`),
    ],
    repairable: [abilities, join(credentialsV1, `${HEX_A}.json`)],
    abilities,
    credentialFile: join(credentialsV1, `${HEX_A}.json`),
  };
}

test("offline check IDs are stable and local pass, warn, and fail states remain distinct", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-checks-"));
  const missingRoot = join(root, "missing");
  try {
    const dependencies = fakeDependencies(missingRoot);
    assert.deepEqual(
      offlineDoctorDefinitions(dependencies, { fix: false }).map(
        ({ id }) => id,
      ),
      [
        "runtime.node",
        "storage.permissions",
        "storage.atomic",
        "credential.backend",
        "profile.valid",
        "oauth.token",
      ],
    );

    assert.equal(
      await statusOf(
        { ...dependencies, nodeVersion: "24.0.0" },
        "runtime.node",
      ),
      "pass",
    );
    assert.equal(
      await statusOf(
        { ...dependencies, nodeVersion: "23.0.0" },
        "runtime.node",
      ),
      "warn",
    );
    assert.equal(
      await statusOf(
        { ...dependencies, nodeVersion: "20.0.0" },
        "runtime.node",
      ),
      "fail",
    );

    assert.equal(await statusOf(dependencies, "storage.permissions"), "warn");
    await mkdir(missingRoot, { mode: 0o700 });
    assert.equal(await statusOf(dependencies, "storage.permissions"), "pass");
    await chmod(missingRoot, 0o755);
    assert.equal(await statusOf(dependencies, "storage.permissions"), "fail");
    await chmod(missingRoot, 0o700);

    assert.equal(await statusOf(dependencies, "storage.atomic"), "warn");
    await mkdir(dependencies.paths.stateDir, { mode: 0o700 });
    assert.equal(await statusOf(dependencies, "storage.atomic"), "pass");
    await rm(dependencies.paths.stateDir, { recursive: true });
    await writeFile(dependencies.paths.stateDir, "not a directory");
    assert.equal(await statusOf(dependencies, "storage.atomic"), "fail");
    await rm(dependencies.paths.stateDir);

    assert.equal(await statusOf(dependencies, "credential.backend"), "warn");
    assert.equal(
      await statusOf(
        fakeDependencies(missingRoot, {
          credentials: {
            diagnostic: () => ({
              backend: "linux-secret-service",
              osBackedEncryption: true,
            }),
            read: async () => undefined,
          },
        }),
        "credential.backend",
      ),
      "pass",
    );
    const brokenCredentialDefinition = offlineDoctorDefinitions(
      fakeDependencies(missingRoot, {
        credentials: {
          diagnostic: () => {
            throw new Error("backend unavailable");
          },
          read: async () => undefined,
        },
      }),
      { fix: false },
    ).find(({ id }) => id === "credential.backend");
    assert.ok(brokenCredentialDefinition);
    assert.equal(
      (
        await runDoctorChecks([brokenCredentialDefinition], {
          offline: true,
          fix: false,
        })
      ).checks[0].status,
      "fail",
    );

    const profile = {
      name: "production",
      siteUrl: "https://example.test",
      origin: "https://example.test",
      clientId: "public-client",
    };
    const profileDependencies = fakeDependencies(missingRoot, {
      profiles: {
        list: async () => [profile],
        trySelect: async (site) => (site === "missing" ? undefined : profile),
      },
    });
    assert.equal(await statusOf(dependencies, "profile.valid"), "warn");
    assert.equal(await statusOf(profileDependencies, "profile.valid"), "pass");
    assert.equal(
      await statusOf(profileDependencies, "profile.valid", { site: "missing" }),
      "fail",
    );
    assert.equal(await statusOf(dependencies, "oauth.token"), "warn");
    assert.equal(
      await statusOf(
        fakeDependencies(missingRoot, {
          profiles: {
            list: async () => [profile],
            trySelect: async () => profile,
          },
          credentials: {
            diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
            read: async () => ({
              version: 1,
              accessToken: "secret",
              refreshToken: "secret",
              scope: "mcp",
              expiresAt: "2026-07-21T13:00:00.000Z",
            }),
          },
        }),
        "oauth.token",
      ),
      "pass",
    );
    assert.equal(
      await statusOf(
        fakeDependencies(missingRoot, {
          profiles: {
            list: async () => [profile],
            trySelect: async () => profile,
          },
          credentials: {
            diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
            read: async () => ({
              version: 1,
              accessToken: "secret",
              refreshToken: "secret",
              scope: "mcp",
              expiresAt: "2026-07-21T11:00:00.000Z",
            }),
          },
        }),
        "oauth.token",
      ),
      "fail",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the engine isolates thrown checks and preserves one deterministic report", async () => {
  const report = await runDoctorChecks(
    [
      {
        id: "first",
        run: async () => ({ status: "pass", summary: "ok", evidence: {} }),
      },
      {
        id: "broken",
        run: async () => {
          throw new Error("secret detail");
        },
      },
      {
        id: "last",
        run: async () => ({ status: "warn", summary: "later", evidence: {} }),
      },
    ],
    { offline: true, fix: false },
  );
  assert.equal(report.status, "fail");
  assert.deepEqual(
    report.checks.map(({ id }) => id),
    ["first", "broken", "last"],
  );
  assert.deepEqual(report.checks[1].evidence, { error: "check_threw" });
  assert.doesNotMatch(JSON.stringify(report), /secret detail/);
});

test("offline fixes are idempotent, bounded, owner-only, and never use network or credentials", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-fix-"));
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const security = new UnixFileSecurity();
  const locks = new ProfileLockManager(paths.stateDir, security);
  const profiles = new ProfileStore(paths.configFile, locks, security);
  const profile = await profiles.upsert({
    name: "production",
    siteUrl: "https://example.test",
    clientId: "public-client",
  });
  const credentialDirectory = join(paths.credentialsDir, "v1");
  await mkdir(credentialDirectory, { recursive: true, mode: 0o700 });
  const credentialSentinel = join(credentialDirectory, "do-not-touch.txt");
  await writeFile(credentialSentinel, "credential sentinel", { mode: 0o600 });
  const cache = new AbilityMetadataCache(paths.cacheDir, locks, security, {
    now: () => 1,
  });
  await cache.put(
    {
      origin: profile.origin,
      profileName: profile.name,
      abilityName: "novamira/read-file",
    },
    1,
    { name: "novamira/read-file" },
  );
  const artifacts = new ArtifactStore(paths.cacheDir, locks, security, {
    now: () => 1,
  });
  const artifact = await artifacts.budget(
    { output: "x".repeat(100) },
    { maxOutputBytes: 1 },
  );
  await chmod(root, 0o755);

  const originalFetch = globalThis.fetch;
  const originalConnect = net.Socket.prototype.connect;
  let networkAttempts = 0;
  globalThis.fetch = async () => {
    networkAttempts += 1;
    throw new Error("offline fetch attempted");
  };
  net.Socket.prototype.connect = function (...args) {
    networkAttempts += 1;
    return originalConnect.apply(this, args);
  };
  try {
    for (let index = 0; index < 2; index += 1) {
      const output = capture();
      assert.equal(
        await main(
          ["--json", "--site", "production", "doctor", "--offline", "--fix"],
          output.streams,
          {
            NOVAMIRA_HOME: root,
            NOVAMIRA_CREDENTIAL_BACKEND: "file",
          },
        ),
        0,
      );
      const envelope = JSON.parse(output.read().stdout);
      assert.equal(envelope.ok, true);
      assert.equal(envelope.data.offline, true);
      assert.equal(envelope.data.checks.length, 6);
      assert.equal(output.read().stderr.includes("secret"), false);
    }
    assert.equal(networkAttempts, 0);
    assert.equal((await stat(root)).mode & 0o777, 0o700);
    assert.equal((await stat(paths.configFile)).mode & 0o777, 0o600);
    assert.equal(
      await readFile(credentialSentinel, "utf8"),
      "credential sentinel",
    );
    assert.equal(
      await profiles.get("production").then((value) => value.name),
      "production",
    );
    await assert.rejects(stat(artifact.artifact), { code: "ENOENT" });
  } finally {
    globalThis.fetch = originalFetch;
    net.Socket.prototype.connect = originalConnect;
    await rm(root, { recursive: true, force: true });
  }
});

test("permission targets keep their order and classification behind a single batched ACL check", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-batch-"));
  try {
    const tree = await mixedPermissionTree(root);
    const { calls, security } = countingSecurity();
    const result = await runCheck(
      fakeDependencies(root, { security }),
      "storage.permissions",
    );

    // One helper process for every target, not one per target.
    assert.equal(calls.verifyMany.length, 1);
    assert.equal(calls.single, 0);
    assert.equal(calls.secureMany.length, 0);
    assert.deepEqual(calls.verifyMany[0], tree.verifiable);

    assert.equal(result.status, "fail");
    assert.equal(result.fixed, undefined);
    // Twelve inspected targets: the missing artifacts directory and its empty
    // file group are omitted rather than reported.
    assert.equal(result.evidence.inspected, 12);
    assert.deepEqual(result.evidence.unsafe, [
      "cache.abilities.directory",
      "credentials.file",
      "credentials.v1.directory",
      "locks.file",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("permission repair hardens every fixable target in one pass and re-verifies in one more", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-batch-fix-"));
  try {
    const tree = await mixedPermissionTree(root);
    const { calls, security } = countingSecurity();
    const result = await runCheck(
      fakeDependencies(root, { security }),
      "storage.permissions",
      { fix: true },
    );

    // Verify, repair, verify again: three helper processes regardless of how
    // many targets are involved.
    assert.equal(calls.secureMany.length, 1);
    assert.deepEqual(calls.secureMany[0], tree.repairable);
    assert.equal(calls.verifyMany.length, 2);
    assert.equal(calls.single, 0);

    assert.equal((await stat(tree.abilities)).mode & 0o777, 0o700);
    assert.equal((await stat(tree.credentialFile)).mode & 0o777, 0o600);

    assert.equal(result.fixed, true);
    assert.equal(result.status, "fail");
    // The symlinked directory and the wrongly typed lock survive the repair
    // because neither is fixable.
    assert.deepEqual(result.evidence.unsafe, [
      "credentials.v1.directory",
      "locks.file",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ACL inspection cost stays bounded as the number of cached files grows", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-bounded-"));
  try {
    const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
    const artifacts = join(paths.cacheDir, "artifacts", "v1");
    await mkdir(join(paths.stateDir, "locks"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(join(paths.credentialsDir, "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(join(paths.cacheDir, "abilities", "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(artifacts, { recursive: true, mode: 0o700 });
    await writeFile(paths.configFile, "{}", { mode: 0o600 });
    for (let index = 0; index < 30; index += 1)
      await writeFile(
        join(
          artifacts,
          `${String(1700000000000 + index)}-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.json`,
        ),
        "{}",
        { mode: 0o600 },
      );

    const { calls, security } = countingSecurity();
    const result = await runCheck(
      fakeDependencies(root, { security }),
      "storage.permissions",
    );

    assert.equal(result.status, "pass");
    // Eight directories, the config file, and thirty artifacts.
    assert.equal(result.evidence.inspected, 39);
    assert.equal(calls.single, 0);
    assert.equal(calls.verifyMany.length, 1);
    assert.equal(calls.verifyMany[0].length, result.evidence.inspected);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a failing ACL checker leaves every inspected target unsafe and unrepairable", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-acl-broken-"));
  try {
    const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
    await mkdir(paths.stateDir, { recursive: true, mode: 0o700 });
    await writeFile(paths.configFile, "{}", { mode: 0o600 });
    const { calls, security } = countingSecurity();
    const result = await runCheck(
      fakeDependencies(root, {
        security: {
          ...security,
          verifyMany: async (targets) => {
            calls.verifyMany.push(targets.map(({ path }) => path));
            throw new Error("powershell.exe exited with status 1");
          },
        },
      }),
      "storage.permissions",
      { fix: true },
    );

    assert.equal(calls.verifyMany.length, 1);
    assert.equal(calls.single, 0);
    // Nothing is fixable while the checker cannot prove a postcondition, so
    // no repair is attempted and the check reports rather than throws.
    assert.equal(calls.secureMany.length, 0);
    assert.equal(result.status, "fail");
    assert.equal(result.fixed, undefined);
    assert.deepEqual(result.evidence.unsafe, [
      "config.directory",
      "config.file",
      "state.directory",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a target that disappears during --fix does not fail the whole repair", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-fix-vanish-"));
  try {
    const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
    const locks = join(paths.stateDir, "locks");
    await mkdir(locks, { recursive: true, mode: 0o700 });
    await mkdir(join(paths.credentialsDir, "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(join(paths.cacheDir, "abilities", "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(join(paths.cacheDir, "artifacts", "v1"), {
      recursive: true,
      mode: 0o700,
    });

    // Two repairable targets: a world-readable config file and a lock file
    // that another process removes while the repair is in flight.
    await writeFile(paths.configFile, "{}", { mode: 0o644 });
    const lock = join(locks, `${HEX_A}.lock`);
    await writeFile(lock, "{}", { mode: 0o644 });

    // `secureMany` fails the whole batch when a target cannot be proved
    // owner-only afterwards, and a vanished path cannot be. Reporting that as
    // `check_threw` would turn an ordinary race into a broken doctor run.
    const inner = new UnixFileSecurity();
    const racing = {
      ...inner,
      verifyDirectory: (path) => inner.verifyDirectory(path),
      verifyFile: (path) => inner.verifyFile(path),
      secureDirectory: (path) => inner.secureDirectory(path),
      secureFile: (path) => inner.secureFile(path),
      verifyMany: (targets) => inner.verifyMany(targets),
      secureMany: async (targets) => {
        await rm(lock, { force: true });
        return inner.secureMany(targets);
      },
    };
    const result = await runCheck(
      fakeDependencies(root, { security: racing }),
      "storage.permissions",
      { fix: true },
    );

    // The config file was still repaired, and the run reports a repair rather
    // than a thrown check.
    assert.equal(result.status, "pass");
    assert.equal(result.fixed, true);
    assert.deepEqual(result.evidence.unsafe, []);
    assert.notEqual(result.evidence.error, "check_threw");
    assert.equal(
      await new UnixFileSecurity().verifyFile(paths.configFile),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a target that disappears during the batched check is omitted, not condemned", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-doctor-vanish-"));
  try {
    const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
    const locks = join(paths.stateDir, "locks");
    await mkdir(locks, { recursive: true, mode: 0o700 });
    await mkdir(join(paths.credentialsDir, "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(join(paths.cacheDir, "abilities", "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await mkdir(join(paths.cacheDir, "artifacts", "v1"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(paths.configFile, "{}", { mode: 0o600 });
    const lock = join(locks, `${HEX_A}.lock`);
    await writeFile(lock, "{}", { mode: 0o600 });

    // Any second `novamira` process creates and releases a lock file within
    // milliseconds. Batching widened the gap between the `lstat` pass and the
    // ACL verdict to a whole PowerShell round trip, and a path the checker
    // cannot read answers `false`; reporting that as unsafe would fail a
    // correctly hardened installation.
    const inner = new UnixFileSecurity();
    const racing = {
      ...inner,
      verifyDirectory: (path) => inner.verifyDirectory(path),
      verifyFile: (path) => inner.verifyFile(path),
      secureDirectory: (path) => inner.secureDirectory(path),
      secureFile: (path) => inner.secureFile(path),
      secureMany: (targets) => inner.secureMany(targets),
      verifyMany: async (targets) => {
        await rm(lock, { force: true });
        return inner.verifyMany(targets);
      },
    };
    const result = await runCheck(
      fakeDependencies(root, { security: racing }),
      "storage.permissions",
    );

    assert.equal(result.status, "pass");
    assert.deepEqual(result.evidence.unsafe, []);
    // Eight directories and the config file; the lock is gone, so it is no
    // longer a target at all.
    assert.equal(result.evidence.inspected, 9);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
