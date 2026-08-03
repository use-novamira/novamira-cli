// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, basename, join } from "node:path";
import { randomUUID } from "node:crypto";
import type { FileSecurity, VerifiedFileSecurity } from "./file-security.js";
import { secureDirectory } from "./file-security.js";

export interface AtomicWriteEntry {
  readonly path: string;
  readonly content: string;
}

function temporaryPath(destination: string): string {
  return join(
    dirname(destination),
    `.${basename(destination)}.${String(process.pid)}.${randomUUID()}.tmp`,
  );
}

async function syncDirectory(directory: string): Promise<void> {
  // Durably persist the directory entry where the platform supports directory fsync.
  try {
    const handle = await open(directory, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // Windows and some filesystems do not permit opening directories; atomic rename still holds.
  }
}

export async function atomicWriteFile(
  destination: string,
  content: string,
  security: FileSecurity,
): Promise<void> {
  const directory = dirname(destination);
  await secureDirectory(directory, security);
  const temporary = temporaryPath(destination);
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
    await syncDirectory(directory);
  } finally {
    if (created) await unlink(temporary).catch(() => undefined);
  }
}

// Writes several files with the same guarantees as `atomicWriteFile` - every
// file reaches its destination by renaming an already-hardened temporary - but
// hardens the whole batch with one call. On Windows each `secureDirectory` and
// `secureFile` is a powershell.exe launch, so writing 108 Ability cache records
// one at a time costs more than two hundred processes; this costs two.
//
// Nothing is renamed until every temporary is written and hardened, so a
// failure before the rename loop leaves nothing behind at all. Once the loop
// starts, each rename is individually atomic and lands a file that is already
// owner-only, and a rename that fails part-way through leaves the destinations
// it already replaced in place.
//
// Leaving them is deliberate. An earlier revision unlinked them so that a
// rejected batch would commit nothing, but a destination that existed before
// the batch has valid previous content, and unlinking destroys it: a discovery
// that fails on record 90 would delete the 89 good records it had just
// refreshed. Nothing this function writes has a cross-file invariant - the
// Ability cache keys every record independently - so a committed prefix is
// consistent, whereas a deleted one is data loss. This also matches what the
// per-record loop this batch replaced did on the same failure.
export async function atomicWriteFiles(
  entries: readonly AtomicWriteEntry[],
  security: VerifiedFileSecurity,
): Promise<void> {
  if (entries.length === 0) return;
  const directories = [...new Set(entries.map((entry) => dirname(entry.path)))];
  for (const directory of directories)
    await secureDirectory(directory, security);
  const pending = entries.map((entry) => ({
    destination: entry.path,
    content: entry.content,
    temporary: temporaryPath(entry.path),
  }));
  const created = new Set<string>();
  try {
    for (const entry of pending) {
      const handle = await open(entry.temporary, "wx", 0o600);
      created.add(entry.temporary);
      try {
        await handle.writeFile(entry.content, { encoding: "utf8" });
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    await security.secureMany(
      pending.map((entry) => ({
        path: entry.temporary,
        kind: "file" as const,
      })),
    );
    for (const entry of pending) {
      await rename(entry.temporary, entry.destination);
      created.delete(entry.temporary);
    }
    for (const directory of directories) await syncDirectory(directory);
  } finally {
    // Only temporaries that never reached a destination are removed. A
    // destination is never unlinked here - see the note above the function.
    for (const temporary of created)
      await unlink(temporary).catch(() => undefined);
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
