// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  AbilityMetadataCache,
  abilityCacheKey,
} from "../dist/cache/ability-cache.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import {
  ArtifactStore,
  HTTP_RESPONSE_CEILING_BYTES,
  assertHttpResponseSize,
} from "../dist/output/artifacts.js";
import { redact } from "../dist/output/redact.js";
import { isCredentialClassifiedResult } from "../dist/security/classify.js";

async function state() {
  const root = await mkdtemp(join(tmpdir(), "novamira-cache-"));
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const security = new UnixFileSecurity();
  const locks = new ProfileLockManager(paths.stateDir, security);
  return { root, paths, security, locks };
}

const key = {
  origin: "https://example.test",
  profileName: "production",
  abilityName: "novamira/read-file",
};

test("credential classification is shared while redaction remains conservative", () => {
  for (const name of [
    "authorization",
    "access_token",
    "clientSecret",
    "password",
    "codeVerifier",
    "credential",
  ]) {
    assert.equal(
      isCredentialClassifiedResult({ nested: [{ [name]: "value" }] }),
      true,
    );
  }
  assert.equal(
    isCredentialClassifiedResult({ code: "ordinary-result-code" }),
    false,
  );
  assert.deepEqual(redact({ code: "oauth-callback-code" }), {
    code: "[REDACTED]",
  });
});

test("Ability metadata cache crosses processes and enforces freshness, separation, invalidation, corruption, and deterministic budget", async () => {
  const current = await state();
  let now = Date.parse("2026-07-20T12:00:00.000Z");
  try {
    const options = { ttlMs: 100, budgetBytes: 10_000, now: () => now };
    const first = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      current.security,
      options,
    );
    await first.put(key, 1, {
      name: key.abilityName,
      schema: { type: "object" },
    });
    const second = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      current.security,
      options,
    );
    const child = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import {AbilityMetadataCache} from './dist/cache/ability-cache.js';import {UnixFileSecurity} from './dist/config/file-security.js';import {ProfileLockManager} from './dist/config/lock.js';const cache=new AbilityMetadataCache(process.argv[1],new ProfileLockManager(process.argv[2],new UnixFileSecurity()),new UnixFileSecurity(),{ttlMs:Number.MAX_SAFE_INTEGER});process.stdout.write(JSON.stringify(await cache.get(JSON.parse(process.argv[3]),1)));`,
        current.paths.cacheDir,
        current.paths.stateDir,
        JSON.stringify(key),
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), {
      name: key.abilityName,
      schema: { type: "object" },
    });
    assert.deepEqual(await second.get(key, 1), {
      name: key.abilityName,
      schema: { type: "object" },
    });
    const rejectedKey = { ...key, abilityName: "vendor/unsafe" };
    await assert.rejects(
      first.put(rejectedKey, 1, { access_token: "must-not-be-cached" }),
      /Credential-classified/,
    );
    const path = join(
      current.paths.cacheDir,
      "abilities",
      "v1",
      `${abilityCacheKey(key)}.json`,
    );
    assert.equal((await stat(path)).mode & 0o777, 0o600);

    const otherProfile = { ...key, profileName: "staging" };
    const otherAbility = { ...key, abilityName: "novamira/run-wp-cli" };
    await first.put(otherProfile, 1, { marker: "other-profile" });
    await first.put(otherAbility, 1, { marker: "other-ability" });
    await first.invalidateProfile(key.origin, key.profileName);
    assert.equal(await second.get(key, 1), undefined);
    assert.equal(await second.get(otherAbility, 1), undefined);
    assert.deepEqual(await second.get(otherProfile, 1), {
      marker: "other-profile",
    });

    await first.put(key, 1, { marker: "old-contract" });
    await first.put(otherAbility, 1, { marker: "old-contract-sibling" });
    await first.put(key, 2, { marker: "expires" });
    assert.equal(await second.get(otherAbility, 2), undefined);
    assert.deepEqual(await second.get(key, 2), { marker: "expires" });
    now += 100;
    assert.equal(await second.get(key, 2), undefined);

    await mkdir(join(current.paths.cacheDir, "abilities", "v1"), {
      recursive: true,
    });
    await writeFile(path, "{secret corrupt cache", { mode: 0o600 });
    assert.equal(await second.get(key, 2), undefined);
    await assert.rejects(stat(path), { code: "ENOENT" });

    now += 1;
    const candidates = [
      { ...key, abilityName: "vendor/alpha" },
      { ...key, abilityName: "vendor/beta" },
    ];
    const measured = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      current.security,
      { ttlMs: 10_000, budgetBytes: 420, now: () => now },
    );
    for (const candidate of candidates)
      await measured.put(candidate, 2, { padding: "x".repeat(180) });
    const ordered = candidates.toSorted((left, right) =>
      abilityCacheKey(left).localeCompare(abilityCacheKey(right)),
    );
    assert.equal(await measured.get(ordered[0], 2), undefined);
    assert.equal((await measured.get(ordered[1], 2)).padding.length, 180);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("large output uses valid owner-only bounded artifacts and refuses credential persistence", async () => {
  const current = await state();
  let now = Date.parse("2026-07-20T12:00:00.000Z");
  try {
    const store = new ArtifactStore(
      current.paths.cacheDir,
      current.locks,
      current.security,
      {
        now: () => now,
        previewBudgetBytes: 96,
        retentionMs: 100,
        totalBudgetBytes: 500,
      },
    );
    const complete = { output: "🙂".repeat(100), nested: [1, 2, 3] };
    const first = await store.budget(complete, { maxOutputBytes: 20 });
    assert.equal(first.truncated, true);
    assert.equal(typeof first.artifact, "string");
    assert.ok(Buffer.byteLength(JSON.stringify(first.data)) <= 96);
    assert.doesNotThrow(() => JSON.parse(JSON.stringify(first.data)));
    assert.deepEqual(
      JSON.parse(await readFile(first.artifact, "utf8")),
      complete,
    );
    assert.equal((await stat(first.artifact)).mode & 0o777, 0o600);
    assert.equal(
      (await stat(join(current.paths.cacheDir, "artifacts", "v1"))).mode &
        0o777,
      0o700,
    );

    const sensitive = await store.budget(
      { access_token: "must-never-reach-disk", padding: "x".repeat(100) },
      { maxOutputBytes: 20, credentialClassified: true },
    );
    assert.equal(sensitive.artifact, undefined);
    assert.doesNotMatch(JSON.stringify(sensitive.data), /must-never/);
    const artifactDirectory = join(current.paths.cacheDir, "artifacts", "v1");
    assert.equal((await readdir(artifactDirectory)).length, 1);

    now += 1;
    const second = await store.budget(
      { output: "y".repeat(200) },
      { maxOutputBytes: 20 },
    );
    assert.equal((await readdir(artifactDirectory)).length, 1);
    await assert.rejects(stat(first.artifact), { code: "ENOENT" });
    assert.equal(typeof second.artifact, "string");

    now += 100;
    assert.deepEqual(await store.cleanup(), { removed: 1, remainingBytes: 0 });
    assert.equal((await readdir(artifactDirectory)).length, 0);
    assert.throws(
      () => assertHttpResponseSize(HTTP_RESPONSE_CEILING_BYTES + 1),
      {
        code: "network_error",
      },
    );
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});
