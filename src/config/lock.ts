// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { open, readFile, stat, unlink } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CliError } from "../errors.js";
import type { FileSecurity } from "./file-security.js";
import { secureDirectory } from "./file-security.js";

export interface LockOptions {
  readonly timeoutMs?: number;
  readonly staleMs?: number;
  readonly pollMs?: number;
}

export class ProfileLockManager {
  private readonly heldKeys = new Set<string>();

  constructor(
    private readonly stateDir: string,
    private readonly security: FileSecurity,
  ) {}

  async withLock<T>(
    profileName: string,
    operation: () => Promise<T>,
    options: LockOptions = {},
  ): Promise<T> {
    const release = await this.acquire(profileName, options);
    try {
      return await operation();
    } finally {
      await release();
    }
  }

  async acquire(
    profileName: string,
    options: LockOptions = {},
  ): Promise<() => Promise<void>> {
    if (this.heldKeys.has(profileName)) {
      throw new CliError(
        "internal_error",
        `Profile lock ${profileName} is already held by this lock manager.`,
      );
    }
    const timeoutMs = options.timeoutMs ?? 10_000;
    const staleMs = options.staleMs ?? 60_000;
    const pollMs = options.pollMs ?? 25;
    const lockDir = join(this.stateDir, "locks");
    await secureDirectory(lockDir, this.security);
    const digest = createHash("sha256").update(profileName).digest("hex");
    const lockPath = join(lockDir, `${digest}.lock`);
    const started = Date.now();

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- acquisition retries until success or timeout
    while (true) {
      let handle: Awaited<ReturnType<typeof open>> | undefined;
      try {
        handle = await open(lockPath, "wx", 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      if (handle !== undefined) {
        try {
          try {
            await handle.writeFile(
              JSON.stringify({
                pid: process.pid,
                host: hostname(),
                createdAt: Date.now(),
              }),
            );
            await handle.sync();
          } finally {
            await handle.close();
          }
          await this.security.secureFile(lockPath);
        } catch (error) {
          await unlink(lockPath).catch(() => undefined);
          throw error;
        }
        this.heldKeys.add(profileName);
        let released = false;
        return async () => {
          if (released) return;
          released = true;
          try {
            await unlink(lockPath).catch((error: unknown) => {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT")
                throw error;
            });
          } finally {
            this.heldKeys.delete(profileName);
          }
        };
      }

      if (await this.isRecoverable(lockPath, staleMs)) {
        await unlink(lockPath).catch(() => undefined);
        continue;
      }
      if (Date.now() - started >= timeoutMs) {
        throw new CliError(
          "internal_error",
          `Timed out waiting for profile lock ${profileName}.`,
          {
            retryable: true,
          },
        );
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  }

  private async isRecoverable(
    lockPath: string,
    staleMs: number,
  ): Promise<boolean> {
    try {
      const info = await stat(lockPath);
      const expired = Date.now() - info.mtimeMs >= staleMs;
      const raw = JSON.parse(await readFile(lockPath, "utf8")) as {
        pid?: unknown;
        host?: unknown;
      };
      if (raw.host !== hostname() || typeof raw.pid !== "number")
        return expired;
      try {
        process.kill(raw.pid, 0);
        return false;
      } catch (error) {
        return (error as NodeJS.ErrnoException).code === "ESRCH";
      }
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT";
    }
  }
}
