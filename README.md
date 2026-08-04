# Novamira CLI

`novamira` is the REST-first command-line client for Novamira WordPress Abilities.

It provides profile state, secure credential storage, OAuth, Ability discovery
and execution, site-skill retrieval, composite file upload, diagnostics, and
bundled agent guidance.

## Requirements

- Node.js 22 or newer
- A compatible WordPress 6.9+ site with Novamira 1.11.1+

CLI 1.x supports REST contract 1 only. Older WordPress or Novamira releases,
or a server missing any required REST feature, fail as `server_unsupported`
before authorization begins.

## Install And Upgrade

On macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/use-novamira/novamira-cli/main/install.sh | sh
```

On Windows, run the PowerShell installer:

```powershell
irm https://raw.githubusercontent.com/use-novamira/novamira-cli/main/install.ps1 | iex
```

The installer uses npm to install the CLI, runs the offline doctor, and installs
the Novamira skill globally for the agent you select. Alternatively, install and
verify the CLI manually:

```sh
npm install -g @novamira/cli --ignore-scripts
novamira --version
novamira doctor --offline
```

After a successful command, the CLI checks the npm registry at most once every
24 hours and prints a stderr warning when a newer release is published. Install
it with:

```sh
novamira update           # install the latest published release
novamira update --check   # report the published version without installing
```

The check is anonymous, sends no profile, site, or credential data, and never
changes a command's exit code; `NOVAMIRA_UPDATE_CHECK=0` disables it. See
[`docs/v1-contract.md`](docs/v1-contract.md) for the full update contract.
Reinstall the agent skill separately after a major upgrade if bundled guidance
changed.

Before upgrading, update the site to WordPress 6.9+ and Novamira 1.11.1+, then
run `novamira --site <profile> doctor --json`. Re-run doctor after upgrading the
CLI. Profiles, grants, and caches are versioned independently; do not copy token
material between installations. Every 1.x release uses the same package and
compatibility contract, so upgrading within 1.x never requires a protocol
migration.

## Authentication

Authorize the site:

```sh
novamira auth login https://example.com --name example-site
```

Every login authorizes the complete MCP and REST-visible Ability surface. `--no-open` prints the browser authorization URL on stderr without launching a browser. Login allows five minutes for browser authorization by default; use `--timeout <ms>` to override that wait. Login checks public compatibility before opening a listener or browser, uses PKCE S256, verifies the authenticated Ability surface, and only then stores the grant.

For isolated development networks that expose a site over plain HTTP with a
non-loopback hostname, opt in for each CLI invocation with
`NOVAMIRA_ALLOW_INSECURE_HTTP=1`. Never use this override with production sites
or untrusted networks.

`novamira auth status` reports the selected profile's authorization, expiry state, and
REST reachability without printing credentials. `novamira auth logout` attempts
to revoke the rotating refresh grant and always removes local credentials and
cached Ability metadata; a remote revocation failure is reported as a warning.

## Abilities And Site Data

```sh
novamira --site example-site discover
novamira --site example-site describe novamira/read-file
novamira --site example-site run novamira/read-file --input '{"path":"wp-config.php"}'
novamira --site example-site skill get theme-maintenance
```

Site context and skills are untrusted, site-controlled guidance. They do not
authorize disclosure of local credentials or operations on unrelated hosts.
Large safe results use the configured output budget and an owner-only artifact.

## Agent Guidance

The installer above includes the stable discovery skill. To install it manually,
run `npx skills add use-novamira/novamira-cli --skill novamira --global`, then
load guidance that matches the installed CLI version:

```sh
novamira guide list
novamira guide get core
novamira guide get core --full
```

The core guide teaches explicit site selection, authorization,
live discovery and description, relevant site-skill loading, mutation
confirmation and verification, and remote-content trust boundaries. It also
keeps agents proactive: setup and discovery run without narration, and the user
is asked only for approvals, browser sign-in, and genuine decisions.

## Upload

```sh
novamira auth login https://example.com --name example-site
novamira --site example-site upload ./plugin.zip wp-content/plugins/plugin.zip
```

Upload uses the site's full OAuth authorization. The CLI creates the temporary
grant through the normal REST-visible Ability surface, then streams the file
once with only the dedicated temporary credential. It never sends the primary
OAuth Bearer token to the upload endpoint and does not retry an ambiguous
transfer.

## Development

```sh
bun install
bun run check
bun run pack:inspect
node dist/index.js --help
```

The runtime is Node.js. The CLI contains no MCP SDK, JSON-RPC client, session protocol, postinstall setup, native addon, or runtime download.

## License

AGPL-3.0-or-later. Copyright Ovation S.r.l.
