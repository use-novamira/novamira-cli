# Novamira CLI v1 Contract

Status: frozen contract

This document is normative for CLI major version 1. It fixes the values consumed by the plugin and CLI implementations.

## Package and release identity

| Item | v1 decision |
| --- | --- |
| npm package | `@novamira/cli` in the Ovation S.r.l.-controlled `@novamira` organization |
| executable | `novamira` |
| public repository | <https://github.com/use-novamira/novamira-cli> |
| package manager | Bun 1.2+ |
| lockfile | `bun.lock` |
| runtime | Node.js 22+; CI and package acceptance run Node 22 and Node 24 |
| modules | ESM only |
| build output | compiled JavaScript in `dist/`, with a Node shebang |
| lint / format | ESLint / Prettier |
| license | AGPL-3.0-or-later |
| release owner | Ovation S.r.l. through reviewed `use-novamira` GitHub workflows and npm trusted publishing with provenance |

The package has no lifecycle setup, downloaded runtime, required native executable or addon, MCP SDK, JSON-RPC client, or MCP session code. npm registry 404 responses reserve no ownership; release automation must verify authenticated access to `@novamira` before publishing, but the package identity does not fall back to an unscoped name.

## Compatibility

CLI 1.x supports exactly REST contract 1. The minimum server is WordPress 6.9 and Novamira 1.11.1.

| CLI major | WordPress | Novamira | REST contract | Required features | Result |
| --- | --- | --- | --- | --- | --- |
| 1 | `<6.9` | any | any | any | `server_unsupported` |
| 1 | `>=6.9` | `<1.11.1` or missing | any | any | `server_unsupported` |
| 1 | `>=6.9` | `>=1.11.1` | missing or not `1` | any | `server_unsupported` |
| 1 | `>=6.9` | `>=1.11.1` | `1` | any required feature missing or not `true` | `server_unsupported` |
| 1 | `>=6.9` | `>=1.11.1` | `1` | all `true` | supported |
| other | any | any | any | any | unsupported until that CLI major publishes its matrix |

The required feature keys are fixed:

```text
abilities_bearer_auth
agent_context
rest_skills
generalized_execution_shim
```

Protected-resource metadata exposes the compatibility object as `novamira`. Authenticated `novamira/agent-context` exposes the identical object as `server`. `plugin_version`, `rest_api_version`, `wordpress_version`, `minimum_wordpress_version`, and the complete `features` object must agree. Version comparisons use SemVer for Novamira and dotted numeric core versions for WordPress; prerelease plugin versions do not satisfy the corresponding final minimum.

## OAuth and REST exposure

The v1 token audience remains the existing normalized `rest_url('mcp/novamira-oauth')` resource identifier. The CLI never sends a runtime request to that endpoint; the value is only an OAuth audience/resource identifier.

`mcp` is the single OAuth scope. It authorizes the MCP protected resource and the
complete REST-visible Ability surface, including compatible third-party
abilities with `meta.show_in_rest: true`. Every authorization request and token
refresh converges to this scope. Servers may accept the former
`abilities:read`, `abilities`, `read`, and `write` scope names as upgrade
aliases, but they are not advertised or requested by the CLI and do not
represent permission modes.

Consent must say: **“Full access permits execution of REST-visible abilities
registered by Novamira and compatible third-party plugins, including abilities
that can execute code, change content or settings, modify files, and create
temporary administrator access.”** Authorization does not bypass the user's
Novamira management capability, target Ability permission callback, or
`show_in_rest` requirement.

## Command grammar

The v1 command names are fixed:

```text
novamira auth login <url> [--name <name>] [--no-open] [--device]
novamira auth status
novamira auth logout
novamira sites list
novamira sites remove <name>
novamira sites rename <name> <new-name>
novamira discover
novamira describe <ability>
novamira run <ability> [--input <json|@file|->] [--fresh]
novamira skill get <slug>
novamira upload <local> <remote>
novamira guide list
novamira guide get <name> [--full]
novamira doctor [--offline] [--fix]
novamira update [--check]
```

`auth login` always requests the full `mcp` scope.

`auth login --device` runs the RFC 8628 device authorization grant instead of
the loopback authorization-code grant, for shells whose browser cannot reach a
listener on the CLI host. It is available only when authorization-server
metadata advertises both a same-origin `device_authorization_endpoint` and the
`urn:ietf:params:oauth:grant-type:device_code` grant; otherwise login fails with
`server_unsupported` before any client registration or device-code request. The
device client is registered separately from the loopback client, with no
`redirect_uris` and the device-code and `refresh_token` grants, and a stored
client the server rejects as `invalid_client` or `unauthorized_client` is
re-registered once. The profile records which grant its `clientId` was
registered for, and a stored client is reused only for that grant; a profile
written before this was recorded holds a loopback client. The CLI validates that `verification_uri` is a same-origin
endpoint, requires `expires_in` within 30 minutes and any `interval` within 60
seconds, defaults a missing `interval` to 5 seconds, adds 5 seconds on
`slow_down`, keeps polling on `authorization_pending`, and stops on any other
error. Polling ends at the earlier of the device code's expiry and `--timeout`;
that deadline also bounds each token request and is rechecked against the
response, so a grant that arrives after it is discarded rather than stored.
`verification_uri_complete` is never used, so approval always passes through the
page that renders the consent text, which accepts the code only from its own
manual-entry form. `--device` opens no listener, launches no
browser, and is unaffected by `--no-open`. The resulting grant, scope, storage,
and refresh behavior are identical to the browser flow. When the browser flow
runs in a session that advertises itself as remote (`SSH_CONNECTION` or
`SSH_TTY`) and the site supports device authorization, the CLI prints one stderr
hint naming `--device`.

Global options are `--site <name>`, `--json`, `--timeout <ms>`, `--yes`, `--max-output <bytes>`, `--no-color`, `--quiet`, `--verbose`, and `--version`. `NO_COLOR` has the same color-disabling effect as `--no-color`. Command-specific aliases and an implicit mutable default-site command are not part of v1.

`update` reads the `latest` dist-tag of `@novamira/cli` from the npm registry (or `NOVAMIRA_REGISTRY`) over HTTPS and, unless `--check` is given, installs that version with the package manager that owns the installation (`npm install --global --ignore-scripts --registry <registry>`, or `bun add --global --registry <registry>` for a Bun global installation), always from the registry the version was read from. Installer output goes to stderr only; an explicitly given `--timeout` bounds the installer process as well as the registry request. After any other successful command, the same anonymous dist-tag request runs at most once per 24 hours and prints one stderr warning when a newer version is published; the record lives in `state/update-check.json` as `{ "version": 1, "registry": string, "latest": string|null, "checkedAt": string }` under the shared lock (held across the request so concurrent commands make one request), atomic replacement, and verified private permissions. A record written for a different registry is never reused. The notice never changes stdout, an exit code, or a command's outcome, and every check failure is silent. It is suppressed by `--quiet`, by `doctor --offline`, and by `NOVAMIRA_UPDATE_CHECK=0`. The request sends no profile, site, credential, or telemetry data.

Target selection order is `--site`, `NOVAMIRA_SITE`, the sole configured profile, then `site_required`. No command picks one profile from multiple profiles.

`sites rename <name> <new-name>` renames a profile without changing its origin,
site base, OAuth client, or grant. The new name must be a valid profile name,
differ from the current name, and not already be in use; otherwise the command
fails with `site_not_found` or `usage_error` and nothing changes. Stored OAuth
credentials move to the record keyed by the new name, the old profile's Ability
cache entries are invalidated, and the profile document is atomically replaced
under both profile locks. No cleanup hook runs, so a rename never deletes
credentials or caches.

## Output and errors

stdout contains only requested output. stderr contains redacted diagnostics, warnings, progress, browser URLs, and prompts. JSON mode emits exactly one JSON object, never prompts, and emits no ANSI or spinner output.

Success envelope:

```json
{"ok":true,"data":{},"meta":{"site":"example-site","origin":"https://example.com","requestId":"local-request-id"}}
```

Failure envelope:

```json
{"ok":false,"error":{"code":"ability_not_found","message":"Ability novamira/example was not found.","retryable":false,"remoteCode":"novamira_ability_not_found"}}
```

Warnings in JSON mode are records in `meta.warnings` with `{ "code": string, "message": string }`. Optional safe details may be added under `details`. Result data, including a remote `success` property or a scalar/null result, is unchanged under `data`.

`run` accepts omitted input as `null`, inline JSON, `@file` JSON, or `-` for
stdin. Local schema warnings use a bounded diagnostic subset; they never block
a request or replace authoritative WordPress validation. A destructive run prompts only on an interactive non-JSON terminal
and otherwise requires `--yes`. Only an Ability explicitly annotated
idempotent is eligible for the existing confirmed-401 refresh replay; ambiguous
network failures are never retried.

`skill get` validates a nonempty, trim-stable 255-byte slug without slash or
control characters, then uses the ordinary `novamira/skill-get` Ability
description/execution path. Its site-controlled result, including
`{"found":false}`, remains raw output and uses the normal output/artifact
budget.

`upload` creates a temporary grant via `novamira/create-upload-link`. It accepts
only the exact same-origin upload
route, `PUT`, `X-Novamira-Upload-Token`, a future expiry of at most one hour,
and a positive safe-integer byte limit. The opened regular file is streamed
once with its exact length and only the temporary header credential; the OAuth
Bearer is never sent to that route. Success data contains only `destination`
and `bytesTransferred`, and no temporary grant value is logged or persisted.

Stable code and exit mapping:

| Exit | Codes |
| --- | --- |
| 0 | success only |
| 2 | `usage_error`, `site_required`, `site_not_found` |
| 3 | `auth_required`, `auth_denied`, `auth_expired`, `insufficient_scope` |
| 4 | `server_unsupported`, `network_error`, `rest_error`, `ability_not_found`, `ability_hidden` |
| 5 | `schema_validation_failed`, `remote_execution_failed` |
| 6 | `confirmation_required` |
| 1 | `internal_error` |

Exit 0 always has `ok: true`; nonzero exits always have `ok: false`. A request ID is a fresh lowercase UUID v4 generated locally per invocation and is safe to print. Secret values and keys are redacted before envelope or diagnostic formatting.

`doctor --offline` returns a version-1 report with the stable local check IDs
`runtime.node`, `storage.permissions`, `storage.atomic`,
`credential.backend`, `profile.valid`, and `oauth.token` in that order. Checks
have `pass`, `warn`, or `fail`, a stable summary, and output-safe evidence. A
thrown check is isolated as a failed record and does not suppress later checks.
A completed report uses exit 0 and `ok: true` even when the report's overall
status is `warn` or `fail`; only failure to produce the report uses the normal
typed nonzero contract. Offline mode performs no network operation and never
changes credentials, profiles, or login state. `--fix` is limited to reported
private-path permission repair, state-directory initialization for the
temporary atomic-write probe, and bounded Ability-cache/artifact cleanup.

Online `doctor` keeps the complete stable check order from `runtime.node`
through `site.permission` and uses the normal metadata, token lifecycle, and
Ability clients. Remote evidence distinguishes unsupported, unreachable,
unauthorized, insufficient-scope, and missing-surface outcomes without
including response bodies or credentials. Public compatibility must agree
exactly with authenticated agent context. `doctor --fix` may offer OAuth login
only in an interactive terminal after explicit confirmation. It never removes
a profile or revokes remote access.

## Limits

| Limit | Value |
| --- | --- |
| default operation timeout | 30 seconds |
| default browser authorization timeout | 5 minutes |
| compatibility metadata cache | 5 minutes |
| OAuth refresh safety window | 60 seconds |
| Ability metadata cache TTL / budget | 5 minutes / 10 MiB |
| default output budget | 1 MiB of UTF-8 JSON |
| maximum accepted `--max-output` | 10 MiB |
| persisted preview budget | 64 KiB of valid UTF-8 JSON data |
| hard buffered HTTP response ceiling | 25 MiB |
| artifact retention / total budget | 24 hours / 100 MiB |
| pagination page size / page bound | 100 / 1,000 pages |

Budgets count bytes, not JavaScript string length. JSON is never byte-sliced. Artifact cleanup is oldest-first by creation time, then lexical path as a deterministic tie-break. Credential-classified results have no artifact. Composite upload streams independently of the buffered response ceiling and must also obey server-advertised size and expiry limits.

## Cache and artifact layout

Ability records use versioned private files under `cache/abilities/v1`. A filename is the SHA-256 digest of normalized origin, a NUL separator, profile name, a NUL separator, and complete Ability name. The record repeats and validates that key, the REST contract version, cache timestamp, and metadata. Reads fail closed and remove corrupt, expired, mismatched, or unverifiably protected entries. A changed REST contract invalidates all Ability entries for that origin/profile; login, logout, and profile removal call the same explicit invalidation operation. Discovery caches its records as one batch: a single lock acquisition, one contract-change invalidation, and then an atomic write, a permission verification, and an expiry/budget pass per slice of the batch, so the cost of caching does not grow with the number of Abilities. A slice holds at most a quarter of the byte budget, and a record larger than the whole budget - which the following sweep would evict again in any case - is not written at all, so a server-controlled response can never drive the directory more than one slice past the budget before anything is evicted. A batch that contains credential-classified metadata is rejected before anything is written; a record whose permissions cannot be verified after the write is removed; and a temporary left behind by an interrupted write is reclaimed by the next expiry pass. An atomic write that cannot rename its whole slice keeps the records it has already renamed: each rename is individually atomic and lands an already-hardened file, records are keyed independently, and removing them would destroy the valid metadata a failed refresh had just replaced.

Eligible oversized JSON results are persisted exactly under `cache/artifacts/v1`; the returned data is a separately serialized, valid JSON preview with `truncated`, original UTF-8 byte count, and artifact path metadata. Artifact filenames begin with a millisecond creation timestamp so cleanup is deterministic across processes. Credential-classified oversized responses return only a fixed redacted preview and are never written. Cache and artifact writes use the shared cross-process locks, atomic replacement, and verified Unix owner modes or the verified Windows ACL policy below. Cleanup methods are reusable by `doctor --fix`.

## Profiles and credential layout

Profile format version 1 stores only profile name, normalized origin/site base, public OAuth client ID, and compatibility/cache metadata. Tokens never appear in config JSON. `NOVAMIRA_HOME` is an isolation root containing `config.json`, `state/`, `cache/`, and `credentials/` directly.

The credential-store interface reads, atomically replaces, and deletes one versioned record per profile:

```json
{
  "version": 1,
  "accessToken": "secret",
  "refreshToken": "secret",
  "scope": "mcp",
  "expiresAt": "2026-07-20T15:00:00.000Z"
}
```

Refresh re-reads this record under the per-profile lock and atomically replaces
all four token, scope, and expiry fields. A refresh may migrate a legacy
`abilities` or `abilities:read` credential to `mcp`; unrelated scope
substitutions are rejected. `invalid_grant`, a lost response, or an invalid
response removes the stale local credential so a possibly consumed rotating
refresh token cannot be replayed. Authenticated
callers may replay once after a confirmed 401 only when they explicitly classify
the request as known not accepted; ambiguous requests are never replayed.

OS-backed storage uses service `ai.novamira.cli` and an account equal to the stable SHA-256 hex digest of normalized origin, a NUL separator, and profile name. The selected implementation is an internal command adapter rather than an npm keychain dependency:

1. macOS `security` generic-password records.
2. Linux `secret-tool` Secret Service records.
3. Windows Credential Manager records through PowerShell `Add-Type` P/Invoke of inbox Advapi32 `CredReadW`, `CredWriteW`, and `CredDeleteW`. Credential blobs use compact UTF-8 so realistic access and refresh token pairs fit under Windows' 2,560-byte blob limit; reads retain compatibility with the UTF-16 records written by CLI 1.0.x.
4. Explicit file fallback under the platform credential directory, selected with `NOVAMIRA_CREDENTIAL_BACKEND=file` (or automatically only when the platform credential command is unavailable).

The spike rejected `keytar`, `@github/keytar`, `@napi-rs/keyring`, and `cross-keychain` as runtime dependencies because their native/optional-native payloads conflict with package acceptance. Platform tools receive arguments through `spawn`/`execFile`, never shell interpolation, and secrets are passed on stdin where supported.

Fallback files are `credentials/v1/<account>.json`, written under the profile lock by owner-only temporary file, fsync, atomic rename, and directory fsync where supported. Unix directories/files are verified as `0700`/`0600` with the current UID. Windows uses the current SID, not a username or Unix mode bit:

1. Resolve `[System.Security.Principal.WindowsIdentity]::GetCurrent().User`.
2. Judge the descriptor before writing anything. Verification reads it with `Get-Acl -LiteralPath` and applies the acceptance policy in step 10.
3. A descriptor that already verifies is not repaired at all: no owner is written, no access rule is written, and the descriptor is left byte-identical. A second apply, and `doctor --fix` over already-safe storage, therefore produce no churn.
4. To repair, obtain the object with `Get-Item -LiteralPath -Force` and read it with the `GetAccessControl` overload that names `AccessControlSections::Owner -bor AccessControlSections::Access`. `Set-Acl` decides for itself which sections to persist and reaches for the SACL, which needs `SeSecurityPrivilege` and fails for an ordinary account even when the DACL it would have written was correct; naming the sections keeps the read and the write to exactly the owner and the DACL, and never the group or the SACL.
5. Before mutating anything, capture from the descriptor that arrived, in one pass over its explicit and inherited rules: whether its DACL was already protected, whether it holds any `Deny` at all, and which of the permitted administrative SIDs hold an explicit `Allow`. The protection state must be read here, because `SetAccessRuleProtection` below would otherwise make every descriptor look protected and the safeguard inert.
6. Call `SetAccessRuleProtection($true, $false)` to remove inherited access, and purge every remaining explicit rule.
7. Set the owner to the current SID and add the mandatory allow rule for that SID with full control. It is written unconditionally, whatever the previous descriptor said.
8. Re-add an optional rule for `S-1-5-18` (SYSTEM) or `S-1-5-32-544` (`BUILTIN\Administrators`) only when all three preconditions from step 5 hold: the incoming DACL was already protected, it contained no `Deny` anywhere - explicit or inherited - and that exact SID held an explicit `Allow`. Accepted rules are re-added in canonical form rather than edited in place, so an insufficient, denied, duplicated, or wrongly flagged administrative rule needs no separate repair path.
9. Otherwise converge to owner-only. Optional administrative preservation is conservative and bounded; an unprotected or denied incoming descriptor preserves nothing optional at all.
10. Accept only a protected DACL whose owner is the current SID, which carries the mandatory current-user rule, and on which every present rule is explicit, `Allow`, full control, unique for its SID, flagged `ContainerInherit,ObjectInherit` for a directory or `None` for a file, and carries `PropagationFlags.None`. The only SIDs permitted are the current user's and the two administrative SIDs above.
11. Reject every `Deny`, every inherited rule, every unexpected SID, every duplicate rule for one SID, insufficient rights, invalid inheritance or propagation flags, a missing current-user rule, an owner that is not the current SID, and any descriptor that cannot be read. Reject unverifiable ACLs and remove an unsafe temporary file.
12. Apply with `SetAccessControl` on the object from step 4.
13. Re-read with `Get-Acl` and evaluate step 10 again. The postcondition is the authority: an apply failure is recorded, not raised, so a privilege error over an ACL that is already correct is not a failure while a genuinely unsafe result still is.

Counting rules is not the policy. Requiring exactly one rule rejected a DACL that granted SYSTEM and Administrators before it ever considered who those principals were, and left `Deny`, inheritance, propagation flags, and duplicates unreachable behind that count. Judging every rule is stricter on those four properties and wider in exactly one respect. Every identity comparison is SID to SID, so a localized account name cannot change a verdict. Owner-only remains a valid accepted shape: a freshly created directory inherits rather than carries explicit rules, so it still hardens to owner-only exactly as before. The protection precondition in step 5 is what makes a tree safe, because `doctor --fix` repairs parent before child: repairing a parent strips a `Deny` that a still-unprotected child had inherited, and without that precondition the child's own administrative rules would then be restored as full control, widening access across the pair even though each single-target decision was correct. Unix behavior is unchanged.

Every `powershell.exe` invocation passes the same prefix, `-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command`, so the call sites cannot drift apart. The policy override is process-scoped hardening rather than a fix for any observed failure: the command is always inline text this CLI generates, never a script file on disk, so a machine or user policy governing script execution should not be able to change how it runs.

Two shapes share that core, and both are locale-independent. `powershell.exe` populates `$args` only under `-File`; under `-Command` trailing values are appended to the command text and executed, so no input is ever passed as a trailing argument.

The single-path shape inlines the path as a single-quoted literal with embedded quotes doubled, and rejects any path containing a double quote or newline. It never propagates its result through an exception: it exits `0` when the ACL is safe, `3` when the ACL is unsafe, and `1` on any other failure, so an unsafe ACL is reported as an unsafe path rather than an internal error.

The batch shape hardens or verifies many paths in one helper process, because a directory of cache records would otherwise cost one process per record. It names no path at all: the targets arrive on stdin as one `<kind><path>` line per target, since a Windows command line cannot hold a hundred storage paths, and a path containing a carriage return or line feed is rejected. stdin is decoded as UTF-8 explicitly rather than through `[Console]::In`, whose encoding is the console code page and would mangle any non-ASCII path. The batch always exits `0` and answers with one `safe`/`unsafe` line per input line, in input order; a target that throws is reported `unsafe` instead of ending the batch, and only a failure of the helper itself is an error. A batch apply rejects unless every target ends within this policy, and the Unix implementation makes the same guarantee by re-verifying every target after `chmod`.

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$permitted = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
$wantInherit = if ($Directory) {
  [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
} else {
  [Security.AccessControl.InheritanceFlags]::None
}

function Test-Descriptor {
  $actual = Get-Acl -LiteralPath $Path
  $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  $owner = $actual.GetOwner([Security.Principal.SecurityIdentifier])
  $seen = @()
  $rulesOk = $true
  foreach ($rule in $rules) {
    $identity = $rule.IdentityReference.Value
    if ($rule.IsInherited) { $rulesOk = $false }
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { $rulesOk = $false }
    if ($permitted -notcontains $identity) { $rulesOk = $false }
    if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
        [Security.AccessControl.FileSystemRights]::FullControl) { $rulesOk = $false }
    if ($rule.InheritanceFlags -ne $wantInherit) { $rulesOk = $false }
    if ($rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { $rulesOk = $false }
    if ($seen -contains $identity) { $rulesOk = $false }
    $seen += $identity
  }
  $actual.AreAccessRulesProtected -and $null -ne $owner -and $owner.Value -eq $sid.Value -and
    $rules.Count -ge 1 -and $rules.Count -le $permitted.Count -and $rulesOk -and
    ($seen -contains $sid.Value)
}

# Judged before anything is written: a descriptor that already verifies is left
# exactly as it is.
if (Test-Descriptor) { exit 0 }

try {
  $item = Get-Item -LiteralPath $Path -Force
  $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
              [Security.AccessControl.AccessControlSections]::Access
  $acl = $item.GetAccessControl($sections)
  $current = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  if ($null -eq $current -or $current.Value -ne $sid.Value) { $acl.SetOwner($sid) }

  # One pass over the descriptor that arrived, before anything is purged. The
  # protection state must be read here: SetAccessRuleProtection below would
  # otherwise make every descriptor look protected.
  $wasProtected = $acl.AreAccessRulesProtected
  $allowed = @()
  $anyDeny = $false
  foreach ($existing in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
    if ($existing.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
      $anyDeny = $true
      continue
    }
    $identity = $existing.IdentityReference.Value
    if ($existing.IsInherited) { continue }
    if (@('S-1-5-18', 'S-1-5-32-544') -notcontains $identity) { continue }
    if ($allowed -notcontains $identity) { $allowed += $identity }
  }
  $keep = @(if ($wasProtected -and -not $anyDeny) { $allowed } else { @() })

  $acl.SetAccessRuleProtection($true, $false)
  foreach ($existing in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
    $acl.PurgeAccessRules($existing.IdentityReference)
  }
  # The owner's rule is mandatory and is written first.
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $wantInherit,
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow))
  foreach ($identity in $keep) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
      [Security.Principal.SecurityIdentifier]::new($identity),
      [Security.AccessControl.FileSystemRights]::FullControl,
      $wantInherit,
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow))
  }
  $item.SetAccessControl($acl)
} catch {
  # Recorded, not raised: the postcondition below is the authority.
}

if (-not (Test-Descriptor)) { exit 3 }
```

Ownership is compared SID to SID. `Get-Acl`'s `.Owner` property is the translated `NTAccount` form (`COMPUTER\user`), which never equals an SID string, so comparing against it rejects every correctly hardened path.

The sample above is the single-path shape, adapted in two ways for readability: the generated command inlines the evaluation body twice rather than defining a function, and it also writes an `unsafe path=...` diagnostic to stderr after a failed verdict. The batch shape runs the identical body per stdin line and writes a verdict instead of exiting. `$Directory` selects the inheritance flags every rule in the descriptor must carry: directory targets use `ContainerInherit,ObjectInherit`, file targets use `None`, and no target uses propagation flags. The `cross-keychain@1.1.0` spike demonstrated the same no-shell platform command shape and an inbox Windows Credential Manager P/Invoke backend, but its optional `@napi-rs/keyring` dependency made it unsuitable as a runtime dependency. This uses inbox PowerShell/.NET ACL APIs and is independent of localized `icacls` output. File fallback is not OS-backed encryption, so every backend diagnostic and first use warns without printing the path's contents.

## Fixtures

`fixtures/v1` contains protected-resource metadata, agent context, a WordPress REST error, and raw scalar/object success values. `../novamira/tests/fixtures/rest-v1` is the server copy. Both directories must be valid JSON and byte-identical. They use reserved `example.test` data and contain no credentials.
