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

// PowerShell 7 exports a `PSModulePath` that points at its own module tree. A
// `powershell.exe` (5.1) child that inherits it resolves the inbox modules to
// the PowerShell 7 builds and cannot load them, so `Get-Acl`, `Add-Type`, and
// `Start-Process` all fail with "the module could not be loaded". Dropping the
// variable makes Windows PowerShell rebuild its own default path. This matters
// whenever the CLI is launched from a PowerShell 7 session, not only in CI.
export function powerShellEnvironment(
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const environment = { ...base };
  delete environment.PSModulePath;
  return environment;
}

// `$args` is only populated when powershell.exe is invoked with `-File`. Under
// `-Command` any trailing values are appended to the command text and executed
// as commands, so every input must be inlined as a quoted literal instead.
export function powerShellLiteral(value: string): string {
  if (/["\r\n]/.test(value))
    throw new Error("value contains characters that cannot be quoted safely");
  return `'${value.replaceAll("'", "''")}'`;
}
