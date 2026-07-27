// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { VerifiedFileSecurity } from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";
import type { CommandExecutor } from "./command-executor.js";
import {
  FileCredentialBackend,
  LockedCredentialStore,
  type CredentialStore,
} from "./credentials.js";
import { osCredentialBackend } from "./keychain-backends.js";

export interface CredentialStoreOptions {
  readonly platform?: NodeJS.Platform;
  readonly preference?: "auto" | "file";
  readonly executor?: CommandExecutor;
  readonly onWarning?: (message: string) => void;
}

export async function createCredentialStore(
  credentialsDir: string,
  locks: ProfileLockManager,
  security: VerifiedFileSecurity,
  options: CredentialStoreOptions = {},
): Promise<CredentialStore> {
  if (options.preference !== "file") {
    const platform = options.platform ?? process.platform;
    const backend =
      options.executor === undefined
        ? osCredentialBackend(platform)
        : osCredentialBackend(platform, options.executor);
    if (await backend.probe())
      return new LockedCredentialStore(locks, backend, options.onWarning);
  }
  return new LockedCredentialStore(
    locks,
    new FileCredentialBackend(credentialsDir, security),
    options.onWarning,
  );
}
