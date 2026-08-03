# Changelog

## Unreleased

### Fixed

- Ability failures now show the actionable error message returned by WordPress
  instead of replacing it with a generic REST or schema-validation message.
- File-editing refusals such as identical strings, missing matches, and multiple
  matches now report a non-retryable validation error instead of an internal
  error.

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
