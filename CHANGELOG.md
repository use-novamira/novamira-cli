# Changelog

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
