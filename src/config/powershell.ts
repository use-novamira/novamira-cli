// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Every powershell.exe invocation starts with these. `-ExecutionPolicy Bypass`
// applies to this process only and is required for the inbox cmdlets to work at
// all: module autoloading runs the module's own manifest, so under the client
// default of `Restricted` even `Get-Acl` fails with "the module could not be
// loaded". The script is always our own inline text, never a file on disk.
export const POWERSHELL_PREFIX = [
  "-NoProfile",
  "-NonInteractive",
  "-ExecutionPolicy",
  "Bypass",
  "-Command",
] as const;

// `$args` is only populated when powershell.exe is invoked with `-File`. Under
// `-Command` any trailing values are appended to the command text and executed
// as commands, so every input must be inlined as a quoted literal instead.
export function powerShellLiteral(value: string): string {
  if (/["\r\n]/.test(value))
    throw new Error("value contains characters that cannot be quoted safely");
  return `'${value.replaceAll("'", "''")}'`;
}
