// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

// `$args` is only populated when powershell.exe is invoked with `-File`. Under
// `-Command` any trailing values are appended to the command text and executed
// as commands, so every input must be inlined as a quoted literal instead.
export function powerShellLiteral(value: string): string {
  if (/["\r\n]/.test(value))
    throw new Error("value contains characters that cannot be quoted safely");
  return `'${value.replaceAll("'", "''")}'`;
}
