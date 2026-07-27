// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from "node:crypto";
import { readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { CliError } from "../errors.js";
import { atomicWriteFile } from "../config/atomic-write.js";
import type { VerifiedFileSecurity } from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";

export const CREDENTIAL_VERSION = 1;
export const CREDENTIAL_SERVICE = "ai.novamira.cli";

export interface CredentialRecord {
  readonly version: 1;
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly scope: string;
  readonly expiresAt: string;
}

export interface CredentialTarget {
  readonly profileName: string;
  readonly origin: string;
}

export interface CredentialDiagnostic {
  readonly backend:
    | "macos-keychain"
    | "linux-secret-service"
    | "windows-credential-manager"
    | "file";
  readonly osBackedEncryption: boolean;
  readonly warning?: string;
}

export interface CredentialStore {
  read(target: CredentialTarget): Promise<CredentialRecord | undefined>;
  readUnderLock(
    target: CredentialTarget,
  ): Promise<CredentialRecord | undefined>;
  replace(target: CredentialTarget, record: CredentialRecord): Promise<void>;
  replaceUnderLock(
    target: CredentialTarget,
    record: CredentialRecord,
  ): Promise<void>;
  delete(target: CredentialTarget): Promise<void>;
  /** Operate while the caller already holds this profile's lock. */
  deleteUnderLock(target: CredentialTarget): Promise<void>;
  diagnostic(): CredentialDiagnostic;
}

export interface CredentialBackend {
  read(account: string): Promise<string | undefined>;
  replace(account: string, serialized: string): Promise<void>;
  delete(account: string): Promise<void>;
  diagnostic(): CredentialDiagnostic;
}

export function credentialAccount(target: CredentialTarget): string {
  return createHash("sha256")
    .update(target.origin)
    .update("\0")
    .update(target.profileName)
    .digest("hex");
}

export function validateCredentialRecord(value: unknown): CredentialRecord {
  if (value === null || typeof value !== "object") throw corruptCredentials();
  const record = value as Partial<CredentialRecord>;
  const keys = Object.keys(record).sort();
  if (
    JSON.stringify(keys) !==
    JSON.stringify([
      "accessToken",
      "expiresAt",
      "refreshToken",
      "scope",
      "version",
    ])
  ) {
    throw corruptCredentials();
  }
  if (
    record.version !== CREDENTIAL_VERSION ||
    typeof record.accessToken !== "string" ||
    record.accessToken === "" ||
    typeof record.refreshToken !== "string" ||
    record.refreshToken === "" ||
    typeof record.scope !== "string" ||
    record.scope === "" ||
    typeof record.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(record.expiresAt))
  ) {
    throw corruptCredentials();
  }
  return record as CredentialRecord;
}

function corruptCredentials(cause?: unknown): CliError {
  return new CliError(
    "auth_required",
    "Stored credentials are corrupt; authorize this site again.",
    {
      ...(cause === undefined ? {} : { cause }),
    },
  );
}

export class LockedCredentialStore implements CredentialStore {
  private warned = false;

  constructor(
    private readonly locks: ProfileLockManager,
    private readonly backend: CredentialBackend,
    private readonly onWarning?: (message: string) => void,
  ) {}

  async read(target: CredentialTarget): Promise<CredentialRecord | undefined> {
    this.warnIfNeeded();
    return this.locks.withLock(target.profileName, async () =>
      this.readUnderLock(target),
    );
  }

  async readUnderLock(
    target: CredentialTarget,
  ): Promise<CredentialRecord | undefined> {
    this.warnIfNeeded();
    const serialized = await this.backend.read(credentialAccount(target));
    if (serialized === undefined) return undefined;
    try {
      return validateCredentialRecord(JSON.parse(serialized) as unknown);
    } catch (cause) {
      if (cause instanceof CliError) throw cause;
      throw corruptCredentials(cause);
    }
  }

  async replace(
    target: CredentialTarget,
    record: CredentialRecord,
  ): Promise<void> {
    this.warnIfNeeded();
    await this.locks.withLock(target.profileName, async () =>
      this.replaceUnderLock(target, record),
    );
  }

  async replaceUnderLock(
    target: CredentialTarget,
    record: CredentialRecord,
  ): Promise<void> {
    this.warnIfNeeded();
    const validated = validateCredentialRecord(record);
    await this.backend.replace(
      credentialAccount(target),
      JSON.stringify(validated),
    );
  }

  async delete(target: CredentialTarget): Promise<void> {
    this.warnIfNeeded();
    await this.locks.withLock(target.profileName, async () =>
      this.deleteUnderLock(target),
    );
  }

  async deleteUnderLock(target: CredentialTarget): Promise<void> {
    this.warnIfNeeded();
    await this.backend.delete(credentialAccount(target));
  }

  diagnostic(): CredentialDiagnostic {
    return this.backend.diagnostic();
  }

  private warnIfNeeded(): void {
    if (this.warned) return;
    const warning = this.backend.diagnostic().warning;
    if (warning !== undefined) this.onWarning?.(warning);
    this.warned = true;
  }
}

export class FileCredentialBackend implements CredentialBackend {
  constructor(
    private readonly credentialsDir: string,
    private readonly security: VerifiedFileSecurity,
  ) {}

  async read(account: string): Promise<string | undefined> {
    const directory = join(this.credentialsDir, "v1");
    const path = join(directory, `${account}.json`);
    try {
      if (
        !(await this.security.verifyDirectory(directory)) ||
        !(await this.security.verifyFile(path))
      ) {
        throw new CliError(
          "auth_required",
          "Credential fallback permissions are unsafe; authorize again.",
        );
      }
      return await readFile(path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }

  async replace(account: string, serialized: string): Promise<void> {
    const path = join(this.credentialsDir, "v1", `${account}.json`);
    await atomicWriteFile(path, `${serialized}\n`, this.security);
    const directorySafe = await this.security.verifyDirectory(
      join(this.credentialsDir, "v1"),
    );
    const fileSafe = await this.security.verifyFile(path);
    if (!directorySafe || !fileSafe) {
      await unlink(path).catch(() => undefined);
      throw new CliError(
        "auth_required",
        "Credential fallback permissions could not be verified.",
      );
    }
  }

  async delete(account: string): Promise<void> {
    await unlink(join(this.credentialsDir, "v1", `${account}.json`)).catch(
      (error: unknown) => {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      },
    );
  }

  diagnostic(): CredentialDiagnostic {
    return {
      backend: "file",
      osBackedEncryption: false,
      warning:
        "Credentials use an owner-only file fallback and are not encrypted by an OS credential service.",
    };
  }
}
