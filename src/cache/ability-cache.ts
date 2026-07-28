// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from "node:crypto";
import { readFile, readdir, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { atomicWriteFile } from "../config/atomic-write.js";
import type { VerifiedFileSecurity } from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";
import type { ProfileCleanupHook, SiteProfile } from "../config/profiles.js";
import { isCredentialClassifiedResult } from "../security/classify.js";

export const ABILITY_CACHE_TTL_MS = 5 * 60 * 1000;
export const ABILITY_CACHE_BUDGET_BYTES = 10 * 1024 * 1024;
const CACHE_FORMAT_VERSION = 1;

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

function sameKey(left: AbilityCacheKey, right: AbilityCacheKey): boolean {
  return (
    left.origin === right.origin &&
    left.profileName === right.profileName &&
    left.abilityName === right.abilityName
  );
}

export class AbilityMetadataCache implements ProfileCleanupHook {
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
    const key = canonicalKey(input);
    if (isCredentialClassifiedResult(metadata))
      throw new Error(
        "Credential-classified data cannot enter the Ability cache.",
      );
    const document: CacheDocument = {
      version: CACHE_FORMAT_VERSION,
      contractVersion,
      key,
      cachedAt: new Date(this.now()).toISOString(),
      metadata,
    };
    const content = `${JSON.stringify(document)}\n`;
    await this.locks.withLock("__ability_cache__", async () => {
      await this.invalidateChangedContractUnlocked(key, contractVersion);
      await atomicWriteFile(this.pathFor(key), content, this.security);
      if (!(await this.security.verifyFile(this.pathFor(key)))) {
        await unlink(this.pathFor(key)).catch(() => undefined);
        throw new Error("Ability cache permissions could not be verified.");
      }
      await this.cleanupUnlocked();
    });
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

  async cleanupExpired(): Promise<AbilityCacheCleanupResult> {
    return this.locks.withLock("__ability_cache__", async () =>
      this.cleanupUnlocked(),
    );
  }

  private pathFor(key: AbilityCacheKey): string {
    return join(this.directory, `${abilityCacheKey(key)}.json`);
  }

  private async names(): Promise<string[]> {
    try {
      return (await readdir(this.directory))
        .filter((name) => /^[a-f0-9]{64}\.json$/.test(name))
        .sort();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
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

  private async cleanupUnlocked(): Promise<AbilityCacheCleanupResult> {
    const files: CacheFile[] = [];
    let removed = 0;
    for (const name of await this.names()) {
      const path = join(this.directory, name);
      try {
        const document = parseDocument(await readFile(path, "utf8"));
        const info = await stat(path);
        if (!(await this.security.verifyFile(path)))
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
