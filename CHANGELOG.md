# Changelog

## 1.0.3

### Changed

- The core guide now keeps agents proactive: setup, discovery, and description
  run without narration, and the user is involved only for mutation approval,
  browser sign-in, a genuine ambiguity, or a failure they must act on.

### Fixed

- Ability failures now show the actionable error message returned by WordPress
  instead of replacing it with a generic REST or schema-validation message.
- File-editing refusals such as identical strings, missing matches, and multiple
  matches now report a non-retryable validation error instead of an internal
  error.
- `discover` no longer stalls on sites with many Abilities; the whole discovery
  is cached in one batch.
- Windows: `doctor` inspects and repairs permissions in one helper process
  instead of one per target.
- Windows: hardening no longer fails when `Set-Acl` reports a missing
  `SeSecurityPrivilege` but the permissions are already correct.
- Windows: interrupted commands no longer leave `powershell.exe` running.
- Windows: paths that are not plain ASCII, such as `C:\Users\José`, are hardened
  and verified correctly.
- The Ability cache stays within its size budget during a large discovery and
  reclaims abandoned temporary files.
- `doctor` no longer fails when another `novamira` process removes a lock file
  mid-check.
- A discovery that fails part way keeps the records it already refreshed.

## 1.0.2

### Changed

- Login now always grants full access, without access modes.
- The minimum compatible Novamira server version is now 1.11.1.

## 1.0.1

### Fixed

- Windows: `auth login` failed with an internal error after a successful
  browser sign-in and stored no profile. ([#1])
- Windows: `doctor` always reported `storage.permissions` as failing, and
  `doctor --fix` could not repair it.
- Windows: credential storage and browser launch failed when the CLI was run
  from a PowerShell 7 session.
- `NOVAMIRA_ALLOW_INSECURE_HTTP` is now honored on every request path.
- Reentrant profile locks fail immediately instead of stalling for the
  ten-second lock timeout.

## 1.0.0

First stable release.

[#1]: https://github.com/use-novamira/novamira-cli/issues/1
