// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from "node:crypto";
import { readdir, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { atomicWriteFile } from "../config/atomic-write.js";
import type { VerifiedFileSecurity } from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";
import { CliError } from "../errors.js";
import { assertHttpResponseSize } from "../limits.js";

export const DEFAULT_OUTPUT_BUDGET_BYTES = 1024 * 1024;
export const MAX_OUTPUT_BUDGET_BYTES = 10 * 1024 * 1024;
export const ARTIFACT_PREVIEW_BUDGET_BYTES = 64 * 1024;
export const ARTIFACT_RETENTION_MS = 24 * 60 * 60 * 1000;
export const ARTIFACT_TOTAL_BUDGET_BYTES = 100 * 1024 * 1024;

export interface BudgetedResult {
  readonly data: unknown;
  readonly truncated: boolean;
  readonly bytes: number;
  readonly artifact?: string;
}

export interface OutputBudgetOptions {
  readonly maxOutputBytes?: number;
  readonly credentialClassified?: boolean;
}

interface ArtifactFile {
  readonly path: string;
  readonly bytes: number;
  readonly createdAt: number;
}

export interface ArtifactStoreOptions {
  readonly retentionMs?: number;
  readonly totalBudgetBytes?: number;
  readonly previewBudgetBytes?: number;
  readonly now?: () => number;
}

function serialize(value: unknown): string {
  let serialized: unknown;
  try {
    serialized = JSON.stringify(value);
  } catch (cause) {
    throw new CliError("internal_error", "Result could not be serialized.", {
      cause,
    });
  }
  if (typeof serialized !== "string")
    throw new CliError("internal_error", "Result could not be serialized.");
  return serialized;
}

function bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function validJsonPreview(serialized: string, budget: number): unknown {
  const type = serialized.startsWith("[")
    ? "array"
    : serialized.startsWith("{")
      ? "object"
      : "value";
  const source = Buffer.from(serialized, "utf8");
  let low = 0;
  let high = Math.min(source.length, budget);
  let best: { readonly type: string; readonly jsonPreview: string } = {
    type,
    jsonPreview: "",
  };
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const prefix = source.subarray(0, middle).toString("utf8");
    const candidate = { type, jsonPreview: prefix };
    if (bytes(JSON.stringify(candidate)) <= budget) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

export class ArtifactStore {
  private readonly directory: string;
  private readonly retentionMs: number;
  private readonly totalBudgetBytes: number;
  private readonly previewBudgetBytes: number;
  private readonly now: () => number;

  constructor(
    cacheRoot: string,
    private readonly locks: ProfileLockManager,
    private readonly security: VerifiedFileSecurity,
    options: ArtifactStoreOptions = {},
  ) {
    this.directory = join(cacheRoot, "artifacts", "v1");
    this.retentionMs = options.retentionMs ?? ARTIFACT_RETENTION_MS;
    this.totalBudgetBytes =
      options.totalBudgetBytes ?? ARTIFACT_TOTAL_BUDGET_BYTES;
    this.previewBudgetBytes =
      options.previewBudgetBytes ?? ARTIFACT_PREVIEW_BUDGET_BYTES;
    this.now = options.now ?? Date.now;
  }

  async budget(
    value: unknown,
    options: OutputBudgetOptions = {},
  ): Promise<BudgetedResult> {
    const maxOutput = options.maxOutputBytes ?? DEFAULT_OUTPUT_BUDGET_BYTES;
    if (
      !Number.isSafeInteger(maxOutput) ||
      maxOutput < 1 ||
      maxOutput > MAX_OUTPUT_BUDGET_BYTES
    ) {
      throw new CliError(
        "usage_error",
        "--max-output must be between 1 byte and 10 MiB.",
      );
    }
    const serialized = serialize(value);
    const byteLength = bytes(serialized);
    assertHttpResponseSize(byteLength);
    if (byteLength <= maxOutput)
      return { data: value, truncated: false, bytes: byteLength };

    if (options.credentialClassified === true) {
      return {
        data: "[REDACTED CREDENTIAL RESPONSE]",
        truncated: true,
        bytes: byteLength,
      };
    }

    const artifact = await this.persist(serialized);
    return {
      data: validJsonPreview(serialized, this.previewBudgetBytes),
      truncated: true,
      bytes: byteLength,
      artifact,
    };
  }

  async cleanup(): Promise<{ removed: number; remainingBytes: number }> {
    return this.locks.withLock("__output_artifacts__", async () =>
      this.cleanupUnlocked(),
    );
  }

  private async persist(serialized: string): Promise<string> {
    return this.locks.withLock("__output_artifacts__", async () => {
      const path = join(
        this.directory,
        `${String(this.now()).padStart(13, "0")}-${randomUUID()}.json`,
      );
      await atomicWriteFile(path, serialized, this.security);
      if (!(await this.security.verifyFile(path))) {
        await unlink(path).catch(() => undefined);
        throw new CliError(
          "internal_error",
          "Artifact permissions could not be verified.",
        );
      }
      await this.cleanupUnlocked();
      return path;
    });
  }

  private async files(): Promise<ArtifactFile[]> {
    let names: string[];
    try {
      names = await readdir(this.directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    const files: ArtifactFile[] = [];
    for (const name of names.sort()) {
      const match = /^(\d{13})-[a-f0-9-]{36}\.json$/.exec(name);
      if (match === null) continue;
      const createdAt = Number(match[1]);
      const path = join(this.directory, name);
      try {
        const info = await stat(path);
        if (!info.isFile() || !(await this.security.verifyFile(path)))
          throw new Error("unsafe artifact");
        files.push({ path, bytes: info.size, createdAt });
      } catch {
        await unlink(path).catch(() => undefined);
      }
    }
    return files;
  }

  private async cleanupUnlocked(): Promise<{
    removed: number;
    remainingBytes: number;
  }> {
    const files = (await this.files()).sort(
      (left, right) =>
        left.createdAt - right.createdAt || left.path.localeCompare(right.path),
    );
    let removed = 0;
    let total = files.reduce((sum, file) => sum + file.bytes, 0);
    const survivors: ArtifactFile[] = [];
    for (const file of files) {
      if (this.now() - file.createdAt >= this.retentionMs) {
        await unlink(file.path).catch(() => undefined);
        total -= file.bytes;
        removed += 1;
      } else {
        survivors.push(file);
      }
    }
    for (const file of survivors) {
      if (total <= this.totalBudgetBytes) break;
      await unlink(file.path).catch(() => undefined);
      total -= file.bytes;
      removed += 1;
    }
    return { removed, remainingBytes: Math.max(0, total) };
  }
}
