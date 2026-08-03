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
  HTTP_RESPONSE_CEILING_BYTES,
  assertHttpResponseSize,
} from "../dist/limits.js";
import { ArtifactStore } from "../dist/output/artifacts.js";
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

test("batched Ability cache writes stay atomic, classified-safe, and share one invalidation, expiry, and budget pass", async () => {
  const current = await state();
  let now = Date.parse("2026-07-20T12:00:00.000Z");
  const directory = join(current.paths.cacheDir, "abilities", "v1");
  const named = (abilityName) => ({ ...key, abilityName });
  try {
    const cache = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      current.security,
      { ttlMs: 100, budgetBytes: 10_000, now: () => now },
    );
    const entries = Array.from({ length: 5 }, (_, index) => ({
      key: named(`vendor/batched-${index}`),
      metadata: { name: `vendor/batched-${index}`, schema: { type: "object" } },
    }));
    await cache.putMany(entries, 1);
    for (const entry of entries)
      assert.deepEqual(await cache.get(entry.key, 1), entry.metadata);
    assert.equal((await readdir(directory)).length, entries.length);
    for (const name of await readdir(directory))
      assert.equal((await stat(join(directory, name))).mode & 0o777, 0o600);

    // A single credential-classified record rejects the whole batch, and no
    // part of that batch reaches disk.
    await assert.rejects(
      cache.putMany(
        [
          { key: named("vendor/clean"), metadata: { marker: "clean" } },
          {
            key: named("vendor/unsafe"),
            metadata: { access_token: "must-not-be-cached" },
          },
        ],
        1,
      ),
      /Credential-classified/,
    );
    assert.equal(await cache.get(named("vendor/clean"), 1), undefined);
    assert.equal((await readdir(directory)).length, entries.length);

    // A record whose file cannot be verified is removed; its siblings survive.
    const rejected = named("vendor/rejected");
    const rejectedName = `${abilityCacheKey(rejected)}.json`;
    const partial = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      {
        secureDirectory: (path) => current.security.secureDirectory(path),
        secureFile: (path) => current.security.secureFile(path),
        secureMany: (targets) => current.security.secureMany(targets),
        verifyDirectory: (path) => current.security.verifyDirectory(path),
        verifyFile: (path) => current.security.verifyFile(path),
        async verifyMany(targets) {
          const verdicts = await current.security.verifyMany(targets);
          return verdicts.map((safe, index) =>
            targets[index].path.endsWith(rejectedName) ? false : safe,
          );
        },
      },
      { ttlMs: 100, budgetBytes: 10_000, now: () => now },
    );
    await assert.rejects(
      partial.putMany(
        [
          { key: named("vendor/accepted"), metadata: { marker: "accepted" } },
          { key: rejected, metadata: { marker: "rejected" } },
        ],
        1,
      ),
      /permissions could not be verified/,
    );
    await assert.rejects(stat(join(directory, rejectedName)), {
      code: "ENOENT",
    });
    assert.deepEqual(await cache.get(named("vendor/accepted"), 1), {
      marker: "accepted",
    });

    // One contract-version invalidation covers the whole batch.
    await cache.putMany([{ key: named("vendor/next"), metadata: {} }], 2);
    assert.deepEqual(await readdir(directory), [
      `${abilityCacheKey(named("vendor/next"))}.json`,
    ]);
    assert.deepEqual(await cache.get(named("vendor/next"), 2), {});

    // The single cleanup pass at the end of a batch still expires by TTL.
    now += 100;
    await cache.putMany([{ key: named("vendor/fresh"), metadata: {} }], 2);
    assert.deepEqual(await readdir(directory), [
      `${abilityCacheKey(named("vendor/fresh"))}.json`,
    ]);

    // Oldest-first eviction still enforces the byte budget across a batch.
    await cache.invalidateProfile(key.origin, key.profileName);
    const padded = ["vendor/alpha", "vendor/beta"].map((abilityName) => ({
      key: named(abilityName),
      metadata: { padding: "x".repeat(180) },
    }));
    const measured = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      current.security,
      { ttlMs: 10_000, budgetBytes: 420, now: () => now },
    );
    await measured.putMany(padded, 2);
    const ordered = padded
      .map(({ key: entry }) => entry)
      .toSorted((left, right) =>
        abilityCacheKey(left).localeCompare(abilityCacheKey(right)),
      );
    assert.equal(await measured.get(ordered[0], 2), undefined);
    assert.equal((await measured.get(ordered[1], 2)).padding.length, 180);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

async function directoryBytes(directory) {
  let total = 0;
  for (const name of await readdir(directory))
    total += (await stat(join(directory, name))).size;
  return total;
}

// Everything the cache does to its own files goes through this interface, so a
// wrapper is how a test observes the directory at the moments the cache itself
// decides to look at it.
function observing(security, hooks = {}) {
  return {
    secureDirectory: (path) => security.secureDirectory(path),
    secureFile: (path) => security.secureFile(path),
    verifyDirectory: (path) => security.verifyDirectory(path),
    verifyFile: (path) => security.verifyFile(path),
    async secureMany(targets) {
      await hooks.secureMany?.(targets);
      return security.secureMany(targets);
    },
    async verifyMany(targets) {
      await hooks.verifyMany?.(targets);
      return security.verifyMany(targets);
    },
  };
}

test("a batched Ability cache write is bounded by the budget and reclaims its own abandoned temporaries", async () => {
  const current = await state();
  const directory = join(current.paths.cacheDir, "abilities", "v1");
  const budgetBytes = 10_000;
  // Temporary staleness is measured against `mtime`, which the filesystem
  // stamps from the real clock, so this test's clock has to start there too.
  let now = Date.now();
  try {
    // A discovery is server-controlled: the HTTP contract allows a thousand
    // pages of up to 25 MiB each. Writing the whole batch before evicting
    // anything would let a site drive that much into the cache directory, so
    // the batch is written in slices and swept after each one.
    const peaks = [];
    const batches = [];
    const bounded = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      observing(current.security, {
        secureMany: (targets) => {
          batches.push(targets.length);
        },
        verifyMany: async () => {
          peaks.push(await directoryBytes(directory));
        },
      }),
      { ttlMs: 10_000, budgetBytes, now: () => now },
    );
    const large = Array.from({ length: 20 }, (_, index) => ({
      key: { ...key, abilityName: `vendor/large-${index}` },
      metadata: { padding: "x".repeat(2000) },
    }));
    await bounded.putMany(large, 1);
    const unsliced = large.length * 2000;
    assert.ok(
      Math.max(...peaks) < unsliced / 2,
      `peak ${String(Math.max(...peaks))} must stay far below ${String(unsliced)}`,
    );
    assert.ok(Math.max(...peaks) <= budgetBytes + budgetBytes / 4 + 2500);
    assert.ok((await directoryBytes(directory)) <= budgetBytes);

    // An ordinary discovery still costs one hardening pass for its files, so
    // the slicing cannot reintroduce a helper process per record.
    batches.length = 0;
    await bounded.invalidateProfile(key.origin, key.profileName);
    await bounded.putMany(
      Array.from({ length: 12 }, (_, index) => ({
        key: { ...key, abilityName: `vendor/small-${index}` },
        metadata: { index },
      })),
      1,
    );
    assert.deepEqual(batches, [12]);

    // A process killed between writing a batch's temporaries and renaming them
    // leaves one temporary per record behind. They match no record pattern, so
    // nothing else in the CLI ever looks at them again.
    const orphans = Array.from(
      { length: 4 },
      (_, index) =>
        `.${"a".repeat(64)}.json.${String(1000 + index)}.00000000-0000-4000-8000-00000000000${String(index)}.tmp`,
    );
    for (const orphan of orphans)
      await writeFile(join(directory, orphan), "{}", { mode: 0o600 });
    // Still fresh: a write that is merely slow must not have its temporaries
    // pulled out from under it.
    assert.equal((await bounded.cleanupExpired()).removed, 0);
    for (const orphan of orphans)
      assert.equal((await stat(join(directory, orphan))).size, 2);
    now += 6 * 60 * 1000;
    const swept = await bounded.cleanupExpired();
    assert.equal(swept.removed, orphans.length + 12);
    assert.deepEqual(await readdir(directory), []);

    // A single record bigger than the whole budget is not written at all. The
    // sweep that follows the write would evict it again anyway, and the server
    // chooses its size: one `describe` of a response many times the budget
    // would otherwise drive a full cache that far past its bound first.
    batches.length = 0;
    const huge = {
      key: { ...key, abilityName: "vendor/huge" },
      metadata: { padding: "x".repeat(budgetBytes * 2) },
    };
    await bounded.putMany([huge], 1);
    assert.equal(await bounded.get(huge.key, 1), undefined);
    assert.deepEqual(batches, []);
    assert.deepEqual(await readdir(directory), []);

    // The same record travelling with ordinary ones is the only one dropped.
    const mixed = [
      huge,
      { key: { ...key, abilityName: "vendor/ok" }, metadata: { ok: true } },
    ];
    await bounded.putMany(mixed, 1);
    assert.equal(await bounded.get(huge.key, 1), undefined);
    assert.deepEqual(await bounded.get(mixed[1].key, 1), { ok: true });
    assert.ok((await directoryBytes(directory)) <= budgetBytes);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("a batched Ability cache write that cannot finish keeps what it already replaced", async () => {
  const current = await state();
  const directory = join(current.paths.cacheDir, "abilities", "v1");
  const now = Date.parse("2026-07-20T12:00:00.000Z");
  try {
    const cache = new AbilityMetadataCache(
      current.paths.cacheDir,
      current.locks,
      current.security,
      { ttlMs: 10_000, budgetBytes: 1_000_000, now: () => now },
    );
    const entries = ["vendor/a", "vendor/b", "vendor/c"].map((abilityName) => ({
      key: { ...key, abilityName },
      metadata: { marker: abilityName },
    }));
    // A directory where a record belongs makes exactly one rename fail, which
    // is what an antivirus or indexer holding a handle does on Windows.
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const blocked = join(directory, `${abilityCacheKey(entries[2].key)}.json`);
    await mkdir(blocked);

    // The first two records already held valid metadata from an earlier
    // discovery, so the failing batch is refreshing them, not creating them.
    await cache.putMany(entries.slice(0, 2), 1);

    await assert.rejects(cache.putMany(entries, 1));

    // Records the batch committed before it failed survive. Unlinking them to
    // make the batch all-or-nothing would delete metadata that was valid
    // before it started - a discovery that fails on the last of 108 Abilities
    // would empty the cache it had just refreshed.
    for (const entry of entries.slice(0, 2))
      assert.deepEqual(await cache.get(entry.key, 1), entry.metadata);

    // Each committed record is complete and owner-only, and the entry that
    // never landed left no temporary behind.
    for (const entry of entries.slice(0, 2))
      assert.equal(
        await current.security.verifyFile(
          join(directory, `${abilityCacheKey(entry.key)}.json`),
        ),
        true,
      );
    assert.deepEqual(
      (await readdir(directory)).filter((name) => name.endsWith(".tmp")),
      [],
    );
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
