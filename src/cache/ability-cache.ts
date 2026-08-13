// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from "node:crypto";
import { readFile, readdir, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { atomicWriteFiles } from "../config/atomic-write.js";
import type {
  AclTarget,
  VerifiedFileSecurity,
} from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";
import type {
  ProfileCleanupHook,
  ProfileRenameHook,
  SiteProfile,
} from "../config/profiles.js";
import { isCredentialClassifiedResult } from "../security/classify.js";

export const ABILITY_CACHE_TTL_MS = 5 * 60 * 1000;
export const ABILITY_CACHE_BUDGET_BYTES = 10 * 1024 * 1024;
const CACHE_FORMAT_VERSION = 1;
// A batch is written in slices no larger than this fraction of the budget and
// swept after each one, so the directory peaks at a little over the budget
// instead of at whatever the site chose to return.
const BATCH_SLICE_DIVISOR = 4;
// An abandoned temporary is reclaimed once it is older than this. The write
// that created it holds the cache lock, whose own stale window is 60 s, so
// nothing still in progress can be this old.
const TEMPORARY_STALE_MS = 5 * 60 * 1000;
// `atomicWriteFiles` names its temporaries `.<destination>.<pid>.<uuid>.tmp`.
const TEMPORARY_PATTERN = /^\.[a-f0-9]{64}\.json\.\d+\.[0-9a-f-]{36}\.tmp$/;

export interface AbilityCacheKey {
  readonly origin: string;
  readonly profileName: string;
  readonly abilityName: string;
}

interface CacheDocument {
  readonly version: 1;
  readonly contractVersion: number;
  readonly key: AbilityCacheKey;
  readonly cachedAt: string;
  readonly metadata: unknown;
}

interface CacheFile {
  readonly path: string;
  readonly bytes: number;
  readonly cachedAt: number;
}

export interface AbilityCacheEntry {
  readonly key: AbilityCacheKey;
  readonly metadata: unknown;
}

interface PendingRecord {
  readonly key: AbilityCacheKey;
  readonly path: string;
  readonly content: string;
}

export interface AbilityCacheCleanupResult {
  readonly removed: number;
  readonly remainingBytes: number;
}

export interface AbilityMetadataCacheOptions {
  readonly ttlMs?: number;
  readonly budgetBytes?: number;
  readonly now?: () => number;
}

function canonicalKey(key: AbilityCacheKey): AbilityCacheKey {
  const url = new URL(key.origin);
  if (url.username !== "" || url.password !== "" || url.origin !== key.origin)
    throw new Error("Ability cache origin must be normalized.");
  if (key.profileName === "" || key.abilityName === "")
    throw new Error("Ability cache key fields must not be empty.");
  return key;
}

export function abilityCacheKey(key: AbilityCacheKey): string {
  const canonical = canonicalKey(key);
  return createHash("sha256")
    .update(canonical.origin)
    .update("\0")
    .update(canonical.profileName)
    .update("\0")
    .update(canonical.abilityName)
    .digest("hex");
}

function isKey(value: unknown): value is AbilityCacheKey {
  if (value === null || typeof value !== "object") return false;
  const key = value as Partial<AbilityCacheKey>;
  return (
    Object.keys(key).every((name) =>
      ["origin", "profileName", "abilityName"].includes(name),
    ) &&
    typeof key.origin === "string" &&
    typeof key.profileName === "string" &&
    typeof key.abilityName === "string"
  );
}

function parseDocument(raw: string): CacheDocument {
  const value = JSON.parse(raw) as unknown;
  if (value === null || typeof value !== "object")
    throw new Error("invalid Ability cache record");
  const candidate = value as Partial<CacheDocument>;
  if (
    candidate.version !== CACHE_FORMAT_VERSION ||
    typeof candidate.contractVersion !== "number" ||
    !Number.isSafeInteger(candidate.contractVersion) ||
    !isKey(candidate.key) ||
    typeof candidate.cachedAt !== "string" ||
    !Number.isFinite(Date.parse(candidate.cachedAt)) ||
    !Object.hasOwn(candidate, "metadata") ||
    !Object.keys(candidate).every((name) =>
      ["version", "contractVersion", "key", "cachedAt", "metadata"].includes(
        name,
      ),
    )
  ) {
    throw new Error("invalid Ability cache record");
  }
  return candidate as CacheDocument;
}

function fileTargets(paths: readonly string[]): readonly AclTarget[] {
  return paths.map((path) => ({ path, kind: "file" as const }));
}

function sameKey(left: AbilityCacheKey, right: AbilityCacheKey): boolean {
  return (
    left.origin === right.origin &&
    left.profileName === right.profileName &&
    left.abilityName === right.abilityName
  );
}

export class AbilityMetadataCache
  implements ProfileCleanupHook, ProfileRenameHook
{
  private readonly directory: string;
  private readonly ttlMs: number;
  private readonly budgetBytes: number;
  private readonly now: () => number;

  constructor(
    cacheRoot: string,
    private readonly locks: ProfileLockManager,
    private readonly security: VerifiedFileSecurity,
    options: AbilityMetadataCacheOptions = {},
  ) {
    this.directory = join(cacheRoot, "abilities", "v1");
    this.ttlMs = options.ttlMs ?? ABILITY_CACHE_TTL_MS;
    this.budgetBytes = options.budgetBytes ?? ABILITY_CACHE_BUDGET_BYTES;
    this.now = options.now ?? Date.now;
  }

  async get<T = unknown>(
    input: AbilityCacheKey,
    contractVersion: number,
  ): Promise<T | undefined> {
    const key = canonicalKey(input);
    return this.locks.withLock("__ability_cache__", async () => {
      const path = this.pathFor(key);
      let document: CacheDocument;
      try {
        document = parseDocument(await readFile(path, "utf8"));
        if (!(await this.security.verifyFile(path)))
          throw new Error("unsafe Ability cache permissions");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT")
          await unlink(path).catch(() => undefined);
        return undefined;
      }
      if (!sameKey(document.key, key)) {
        await unlink(path).catch(() => undefined);
        return undefined;
      }
      if (document.contractVersion !== contractVersion) {
        await this.invalidateProfileUnlocked(key.origin, key.profileName);
        return undefined;
      }
      if (this.now() - Date.parse(document.cachedAt) >= this.ttlMs) {
        await unlink(path).catch(() => undefined);
        return undefined;
      }
      return document.metadata as T;
    });
  }

  async put(
    input: AbilityCacheKey,
    contractVersion: number,
    metadata: unknown,
  ): Promise<void> {
    await this.putMany([{ key: input, metadata }], contractVersion);
  }

  // Caches a whole discovery in one pass. Doing this record by record used to
  // take the cache lock, rescan the directory for a contract change and
  // re-verify every existing file once per Ability, which is quadratic in the
  // number of Abilities and, on Windows, quadratic in powershell.exe launches.
  // One lock and one invalidation keep the cost of a discovery independent of
  // its size.
  //
  // The records are written in slices rather than all at once, and each slice
  // is swept before the next is written. A discovery is server-controlled -
  // a thousand pages of up to 25 MiB each are within the HTTP contract - so
  // writing the whole batch first would let a site drive hundreds of MiB into
  // the cache directory before a single byte was evicted. A slice holds a
  // quarter of the budget, so an ordinary discovery is still one write, one
  // verification and one cleanup.
  async putMany(
    entries: readonly AbilityCacheEntry[],
    contractVersion: number,
  ): Promise<void> {
    // The whole batch is validated and serialized before the first byte is
    // written, so a credential-classified record rejects the call without
    // leaving any part of the batch on disk.
    const cachedAt = new Date(this.now()).toISOString();
    const pending: PendingRecord[] = entries.map((entry) => {
      const key = canonicalKey(entry.key);
      if (isCredentialClassifiedResult(entry.metadata))
        throw new Error(
          "Credential-classified data cannot enter the Ability cache.",
        );
      const document: CacheDocument = {
        version: CACHE_FORMAT_VERSION,
        contractVersion,
        key,
        cachedAt,
        metadata: entry.metadata,
      };
      return {
        key,
        path: this.pathFor(key),
        content: `${JSON.stringify(document)}\n`,
      };
    });
    // A record bigger than the whole budget can never be retained: the sweep
    // that follows its write evicts it again immediately. Writing it first is
    // pure overshoot, and the server controls how big it is - the HTTP
    // contract allows a response many times the budget, so one `describe`
    // could drive a full cache to several times its bound before a byte is
    // evicted. Such a record is not written at all; the next read misses and
    // re-fetches it, which is behaviour a cache is allowed to have. Everything
    // smaller is written, so the directory peaks one slice - or one oversized
    // record - above the budget before the sweep brings it back down.
    const writable = pending.filter(
      (record) => Buffer.byteLength(record.content, "utf8") <= this.budgetBytes,
    );
    if (writable.length === 0) return;
    await this.locks.withLock("__ability_cache__", async () => {
      // The invalidation only depends on the origin and profile of a key, so
      // one pass per distinct profile is exactly what the per-record loop did.
      const scopes = new Map<string, AbilityCacheKey>();
      for (const record of pending)
        scopes.set(
          `${record.key.origin}\u0000${record.key.profileName}`,
          record.key,
        );
      for (const scope of scopes.values())
        await this.invalidateChangedContractUnlocked(scope, contractVersion);
      for (const slice of this.slices(writable)) {
        await atomicWriteFiles(
          slice.map(({ path, content }) => ({ path, content })),
          this.security,
        );
        await this.verifyWrittenUnlocked(slice.map((record) => record.path));
        await this.cleanupUnlocked();
      }
    });
  }

  // Slices are bounded by bytes, not by count, because the budget is in bytes
  // and one record is already allowed to be large. A record larger than a
  // whole slice still gets a slice of its own rather than no slice at all;
  // `putMany` has already dropped the ones too large to be retained.
  private slices(records: readonly PendingRecord[]): PendingRecord[][] {
    const limit = Math.max(
      1,
      Math.floor(this.budgetBytes / BATCH_SLICE_DIVISOR),
    );
    const slices: PendingRecord[][] = [];
    let current: PendingRecord[] = [];
    let bytes = 0;
    for (const record of records) {
      const size = Buffer.byteLength(record.content, "utf8");
      if (current.length > 0 && bytes + size > limit) {
        slices.push(current);
        current = [];
        bytes = 0;
      }
      current.push(record);
      bytes += size;
    }
    if (current.length > 0) slices.push(current);
    return slices;
  }

  async invalidateProfile(origin: string, profileName: string): Promise<void> {
    await this.locks.withLock("__ability_cache__", async () => {
      await this.invalidateProfileUnlocked(origin, profileName);
    });
  }

  async cleanup(_profile?: SiteProfile): Promise<void> {
    if (_profile !== undefined) {
      await this.invalidateProfile(_profile.origin, _profile.name);
      return;
    }
    await this.locks.withLock("__ability_cache__", async () => {
      await this.cleanupUnlocked();
    });
  }

  // Cache keys embed the profile name, so entries written under the old name
  // are stale after a rename. Invalidation is cheaper and safer than moving
  // files; the next discovery or describe refetches them. The target name is
  // irrelevant because the old profile's entries are the stale ones.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async rename(from: SiteProfile, _toName: string): Promise<void> {
    await this.invalidateProfile(from.origin, from.name);
  }

  async cleanupExpired(): Promise<AbilityCacheCleanupResult> {
    return this.locks.withLock("__ability_cache__", async () =>
      this.cleanupUnlocked(),
    );
  }

  private pathFor(key: AbilityCacheKey): string {
    return join(this.directory, `${abilityCacheKey(key)}.json`);
  }

  private async entries(): Promise<string[]> {
    try {
      return (await readdir(this.directory)).sort();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  private async names(): Promise<string[]> {
    return (await this.entries()).filter((name) =>
      /^[a-f0-9]{64}\.json$/.test(name),
    );
  }

  // A process killed between writing a batch's temporaries and renaming them -
  // an interrupted or timed-out discovery - leaves one temporary per record
  // behind. They match no cache-record pattern, so neither `names` nor
  // doctor's permission candidates ever see them again: without this sweep
  // they accumulate for good while the cache reports itself as empty.
  private async removeStaleTemporariesUnlocked(): Promise<number> {
    let removed = 0;
    for (const name of await this.entries()) {
      if (!TEMPORARY_PATTERN.test(name)) continue;
      const path = join(this.directory, name);
      try {
        const info = await stat(path);
        if (this.now() - info.mtimeMs < TEMPORARY_STALE_MS) continue;
      } catch {
        continue;
      }
      await unlink(path).catch(() => undefined);
      removed += 1;
    }
    return removed;
  }

  private async invalidateProfileUnlocked(
    origin: string,
    profileName: string,
  ): Promise<void> {
    for (const name of await this.names()) {
      const path = join(this.directory, name);
      try {
        const document = parseDocument(await readFile(path, "utf8"));
        if (
          document.key.origin === origin &&
          document.key.profileName === profileName
        )
          await unlink(path);
      } catch {
        await unlink(path).catch(() => undefined);
      }
    }
  }

  private async invalidateChangedContractUnlocked(
    key: AbilityCacheKey,
    contractVersion: number,
  ): Promise<void> {
    for (const name of await this.names()) {
      const path = join(this.directory, name);
      try {
        const document = parseDocument(await readFile(path, "utf8"));
        if (
          document.key.origin === key.origin &&
          document.key.profileName === key.profileName &&
          document.contractVersion !== contractVersion
        ) {
          await this.invalidateProfileUnlocked(key.origin, key.profileName);
          return;
        }
      } catch {
        await unlink(path).catch(() => undefined);
      }
    }
  }

  // Rejects unless every freshly written record verifies as owner-only; a
  // record that does not is removed, as is the whole batch when the checker
  // itself fails, because nothing about those records is then verifiable.
  private async verifyWrittenUnlocked(paths: readonly string[]): Promise<void> {
    let verdicts: readonly boolean[];
    try {
      verdicts = await this.security.verifyMany(fileTargets(paths));
    } catch (error) {
      for (const path of paths) await unlink(path).catch(() => undefined);
      throw error;
    }
    const unsafe = paths.filter((_, index) => verdicts[index] !== true);
    if (unsafe.length === 0) return;
    for (const path of unsafe) await unlink(path).catch(() => undefined);
    throw new Error("Ability cache permissions could not be verified.");
  }

  // One verdict per cached file from one helper process. A failure of the
  // checker itself falls back to the single-path API so that each file keeps
  // its own verdict: a batch that cannot answer must not condemn every record
  // in the cache at once.
  private async verifyEachUnlocked(
    paths: readonly string[],
  ): Promise<readonly boolean[]> {
    if (paths.length === 0) return [];
    try {
      const verdicts = await this.security.verifyMany(fileTargets(paths));
      if (verdicts.length !== paths.length)
        throw new Error("incomplete Ability cache permission verdicts");
      return verdicts;
    } catch {
      const verdicts: boolean[] = [];
      for (const path of paths)
        verdicts.push(await this.security.verifyFile(path).catch(() => false));
      return verdicts;
    }
  }

  private async cleanupUnlocked(): Promise<AbilityCacheCleanupResult> {
    const files: CacheFile[] = [];
    let removed = await this.removeStaleTemporariesUnlocked();
    const paths = (await this.names()).map((name) =>
      join(this.directory, name),
    );
    const verdicts = await this.verifyEachUnlocked(paths);
    for (const [index, path] of paths.entries()) {
      try {
        const document = parseDocument(await readFile(path, "utf8"));
        const info = await stat(path);
        if (verdicts[index] !== true)
          throw new Error("unsafe Ability cache permissions");
        if (this.now() - Date.parse(document.cachedAt) >= this.ttlMs) {
          await unlink(path).catch(() => undefined);
          removed += 1;
          continue;
        }
        files.push({
          path,
          bytes: info.size,
          cachedAt: Date.parse(document.cachedAt),
        });
      } catch {
        await unlink(path).catch(() => undefined);
        removed += 1;
      }
    }
    files.sort(
      (left, right) =>
        left.cachedAt - right.cachedAt || left.path.localeCompare(right.path),
    );
    let total = files.reduce((sum, file) => sum + file.bytes, 0);
    for (const file of files) {
      if (total <= this.budgetBytes) break;
      await unlink(file.path).catch(() => undefined);
      total -= file.bytes;
      removed += 1;
    }
    return { removed, remainingBytes: Math.max(0, total) };
  }
}
