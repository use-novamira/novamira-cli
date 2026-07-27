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
    profiles: { list: async () => [] },
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

async function statusOf(dependencies, id, options = {}) {
  const definition = offlineDoctorDefinitions(dependencies, {
    fix: false,
    ...options,
  }).find((candidate) => candidate.id === id);
  assert.ok(definition);
  return (await definition.run()).status;
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
      profiles: { list: async () => [profile] },
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
          profiles: { list: async () => [profile] },
          credentials: {
            diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
            read: async () => ({
              version: 1,
              accessToken: "secret",
              refreshToken: "secret",
              scope: "abilities:read",
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
          profiles: { list: async () => [profile] },
          credentials: {
            diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
            read: async () => ({
              version: 1,
              accessToken: "secret",
              refreshToken: "secret",
              scope: "abilities:read",
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
