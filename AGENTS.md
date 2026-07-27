# AGENTS.md

## Repository overview

Novamira CLI (`@novamira/cli`, executable `novamira`) is a REST-only client for
agents working with Novamira-enabled WordPress sites. It manages site profiles
and OAuth credentials, discovers and runs WordPress Abilities, retrieves site
skills, uploads files, and provides diagnostics and bundled agent guidance.

The runtime is Node.js 22+ ESM, written in strict TypeScript and built with Bun.
Start with `README.md` for user-facing behavior and `docs/v1-contract.md` for the
normative compatibility, command, output, and security contract.

## Orientation

- `src/main.ts` wires commands to services; `src/cli/` defines the command line.
- `src/auth/`, `src/config/`, and `src/cache/` manage OAuth, credentials,
  profiles, locks, and local state.
- `src/rest/` is the HTTP boundary; `src/abilities/`, `src/skills/`, and
  `src/upload/` implement remote operations.
- `src/output/`, `src/doctor/`, and `src/guides/` handle rendering, diagnostics,
  artifacts, and bundled guidance.
- `test/*.test.mjs` contains contract tests against compiled `dist/` modules.
- `guide-data/` and `skills/` contain shipped agent guidance; `scripts/` and
  `.github/workflows/` cover packaging and releases.

## Making changes

- Edit `src/`, tests, and documentation; `dist/` is generated and ignored.
- Keep `.js` extensions in relative TypeScript imports and retain SPDX headers.
- Add or update a focused contract test for behavior changes.
- Run `bun install` when needed and `bun run check` before handoff. Run
  `bun run pack:inspect` for packaging, installer, or release changes.
- Preserve the REST-only design and security contracts in
  `docs/security-acceptance.md`. Never expose credentials; keep JSON stdout
  machine-parseable and diagnostics redacted.

## Test site

When invoking the workspace CLI against a local HTTP test site, set
`NOVAMIRA_ALLOW_INSECURE_HTTP=1` for every invocation. Never use this override
for production or untrusted sites.
