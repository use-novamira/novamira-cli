// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, basename, join } from "node:path";
import { randomUUID } from "node:crypto";
import type { FileSecurity } from "./file-security.js";
import { secureDirectory } from "./file-security.js";

export async function atomicWriteFile(
  destination: string,
  content: string,
  security: FileSecurity,
): Promise<void> {
  const directory = dirname(destination);
  await secureDirectory(directory, security);
  const temporary = join(
    directory,
    `.${basename(destination)}.${String(process.pid)}.${randomUUID()}.tmp`,
  );
  let created = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    created = true;
    try {
      await handle.writeFile(content, { encoding: "utf8" });
      await handle.sync();
    } finally {
      await handle.close();
    }
    await security.secureFile(temporary);
    await rename(temporary, destination);
    created = false;

    // Durably persist the directory entry where the platform supports directory fsync.
    try {
      const directoryHandle = await open(directory, "r");
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    } catch {
      // Windows and some filesystems do not permit opening directories; atomic rename still holds.
    }
  } finally {
    if (created) await unlink(temporary).catch(() => undefined);
  }
}

export async function probeAtomicWrite(directory: string): Promise<void> {
  const marker = randomUUID();
  const temporary = join(directory, `.doctor-${marker}.tmp`);
  const destination = join(directory, `.doctor-${marker}.probe`);
  let temporaryExists = false;
  let destinationExists = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    temporaryExists = true;
    try {
      await handle.writeFile(marker, { encoding: "utf8" });
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, destination);
    temporaryExists = false;
    destinationExists = true;
    if ((await readFile(destination, "utf8")) !== marker)
      throw new Error("Atomic storage probe did not preserve its content.");
  } finally {
    if (temporaryExists) await unlink(temporary).catch(() => undefined);
    if (destinationExists) await unlink(destination).catch(() => undefined);
  }
}
