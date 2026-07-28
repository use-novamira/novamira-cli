// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { atomicWriteFile } from "../config/atomic-write.js";
import type { VerifiedFileSecurity } from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";
import { compareSemver, isSemver } from "../semver.js";
import {
  DEFAULT_REGISTRY,
  fetchLatestVersion,
  type RegistryOptions,
} from "./registry.js";

export const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const UPDATE_CHECK_TIMEOUT_MS = 3_000;
const UPDATE_CHECK_LOCK = "__update_check__";
const RECORD_VERSION = 1;

export interface UpdateCheckEnvironment {
  readonly NOVAMIRA_UPDATE_CHECK?: string;
  readonly NOVAMIRA_REGISTRY?: string;
}

export interface UpdateStatus {
  readonly current: string;
  readonly latest: string;
  readonly updateAvailable: boolean;
  readonly checkedAt: string;
}

interface UpdateRecord {
  readonly version: 1;
  /** The registry the record came from; a different one is never reused. */
  readonly registry: string;
  /** The last known published version, or null when the last check failed. */
  readonly latest: string | null;
  readonly checkedAt: string;
}

export interface UpdateCheckerOptions extends RegistryOptions {
  readonly currentVersion: string;
  readonly intervalMs?: number;
  readonly now?: () => number;
}

/**
 * Reports whether a newer release is published. The background notice reads a
 * cached record and contacts the registry at most once per interval; every
 * failure is silent so an update check never changes a command's outcome.
 */
export class UpdateChecker {
  private readonly path: string;
  private readonly currentVersion: string;
  private readonly intervalMs: number;
  private readonly now: () => number;
  private readonly registryOptions: RegistryOptions;
  private readonly registry: string;

  constructor(
    stateDir: string,
    private readonly locks: ProfileLockManager,
    private readonly security: VerifiedFileSecurity,
    options: UpdateCheckerOptions,
  ) {
    this.path = join(stateDir, "update-check.json");
    this.currentVersion = options.currentVersion;
    this.intervalMs = options.intervalMs ?? UPDATE_CHECK_INTERVAL_MS;
    this.now = options.now ?? Date.now;
    this.registry = normalizeRegistry(options.registry ?? DEFAULT_REGISTRY);
    this.registryOptions = {
      timeoutMs: options.timeoutMs ?? UPDATE_CHECK_TIMEOUT_MS,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      ...(options.registry === undefined ? {} : { registry: options.registry }),
      ...(options.allowInsecureHttp === undefined
        ? {}
        : { allowInsecureHttp: options.allowInsecureHttp }),
    };
  }

  /** Contact the registry and record the result. Failures propagate. */
  async check(): Promise<UpdateStatus> {
    const latest = await fetchLatestVersion(this.registryOptions);
    const checkedAt = new Date(this.now()).toISOString();
    await this.locks.withLock(UPDATE_CHECK_LOCK, () =>
      this.write({
        version: RECORD_VERSION,
        registry: this.registry,
        latest,
        checkedAt,
      }),
    );
    return this.status(latest, checkedAt);
  }

  /**
   * Return a status without forcing a request when the cached record is still
   * fresh. Returns undefined only when the registry could not be consulted.
   */
  async refresh(): Promise<UpdateStatus | undefined> {
    const cached = await this.read();
    if (this.isFresh(cached)) return this.fromRecord(cached);
    // Hold the lock across the request as well as the write so two commands
    // starting at once still make at most one request per interval.
    return this.locks.withLock(UPDATE_CHECK_LOCK, async () => {
      const current = await this.read();
      if (this.isFresh(current)) return this.fromRecord(current);
      const checkedAt = new Date(this.now()).toISOString();
      let latest: string | null = null;
      try {
        latest = await fetchLatestVersion(this.registryOptions);
      } catch {
        // Record the attempt so an unreachable registry is not retried on
        // every invocation, then stay silent.
      }
      await this.write({
        version: RECORD_VERSION,
        registry: this.registry,
        latest,
        checkedAt,
      }).catch(() => undefined);
      return latest === null ? undefined : this.status(latest, checkedAt);
    });
  }

  /** The message shown when a newer release exists, otherwise undefined. */
  async notice(): Promise<string | undefined> {
    let status: UpdateStatus | undefined;
    try {
      status = await this.refresh();
    } catch {
      return undefined;
    }
    if (status?.updateAvailable !== true) return undefined;
    return updateNotice(status);
  }

  private isFresh(record: UpdateRecord | undefined): record is UpdateRecord {
    return (
      record?.registry === this.registry &&
      this.now() - Date.parse(record.checkedAt) < this.intervalMs
    );
  }

  private fromRecord(record: UpdateRecord): UpdateStatus | undefined {
    return record.latest === null
      ? undefined
      : this.status(record.latest, record.checkedAt);
  }

  private status(latest: string, checkedAt: string): UpdateStatus {
    return {
      current: this.currentVersion,
      latest,
      updateAvailable: isNewer(latest, this.currentVersion),
      checkedAt,
    };
  }

  private async read(): Promise<UpdateRecord | undefined> {
    try {
      const raw = await readFile(this.path, "utf8");
      if (!(await this.security.verifyFile(this.path)))
        throw new Error("unsafe update-check permissions");
      const value = JSON.parse(raw) as unknown;
      if (value === null || typeof value !== "object")
        throw new Error("invalid update-check record");
      const record = value as Partial<UpdateRecord>;
      if (
        record.version !== RECORD_VERSION ||
        typeof record.registry !== "string" ||
        typeof record.checkedAt !== "string" ||
        !Number.isFinite(Date.parse(record.checkedAt)) ||
        !(record.latest === null || isSemver(record.latest))
      )
        throw new Error("invalid update-check record");
      return record as UpdateRecord;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT")
        await unlink(this.path).catch(() => undefined);
      return undefined;
    }
  }

  /** Callers hold the update-check lock. */
  private async write(record: UpdateRecord): Promise<void> {
    await atomicWriteFile(
      this.path,
      `${JSON.stringify(record)}\n`,
      this.security,
    );
  }
}

/** Registry identity for the cached record; only the origin and path matter. */
function normalizeRegistry(registry: string): string {
  try {
    const url = new URL(registry);
    return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
  } catch {
    return registry;
  }
}

export function isNewer(candidate: string, current: string): boolean {
  try {
    return compareSemver(candidate, current) > 0;
  } catch {
    return false;
  }
}

export function updateNotice(status: UpdateStatus): string {
  return `A new novamira release is available: ${status.current} -> ${status.latest}. Run "novamira update" to install it.`;
}

/** The automatic notice is opt-out through NOVAMIRA_UPDATE_CHECK=0. */
export function updateCheckEnabled(
  environment: UpdateCheckEnvironment,
): boolean {
  const value = environment.NOVAMIRA_UPDATE_CHECK;
  return value !== "0" && value !== "false";
}
