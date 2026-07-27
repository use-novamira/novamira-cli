# v1 security acceptance

The checks below close the cross-repository and security-sensitive v1
acceptance gate. Package installation and operating-system CI remain a separate
release gate.

| Contract | Automated evidence |
| --- | --- |
| REST-only runtime; no MCP request, SDK, JSON-RPC client, or session | `test/security-acceptance.test.mjs`; plugin `tests/integration/RestOnlyContractTest.php`; `test/guidance-contract.test.mjs` |
| Minimal direct dependencies, publish roots, and no lifecycle/native/runtime-download payload | `test/security-acceptance.test.mjs`; `bun run pack:inspect`; `scripts/package-acceptance.mjs` |
| Root/subdirectory routing and direct/reverse-proxy authorization forwarding | plugin `tests/integration/RestOnlyContractTest.php`; `test/http-compatibility-contract.test.mjs` |
| Unsupported WordPress, plugin, REST contract, or required features fail before authorization side effects | `test/http-compatibility-contract.test.mjs`; `test/oauth-login-contract.test.mjs` |
| PKCE login, default full access, explicit readonly access, refresh rotation, revoke, and re-login | `test/security-acceptance.test.mjs`; `test/oauth-login-contract.test.mjs`; `test/token-lifecycle-contract.test.mjs` |
| Readonly annotations, extension Ability grants, destructive confirmation, and capability removal after issuance | `test/security-acceptance.test.mjs`; plugin `tests/integration/RestOnlyContractTest.php`; `test/run-safety-contract.test.mjs` |
| Complete atomic discovery, live description, site context, and site skills | `test/security-acceptance.test.mjs`; `test/discovery-contract.test.mjs`; `test/site-skill-upload-contract.test.mjs` |
| No arbitrary profile selection and no cross-profile/origin credential access | `test/state-contract.test.mjs`; `test/credentials-contract.test.mjs` |
| Tokens excluded from argv, output diagnostics, profile metadata, and unintended endpoints | `test/security-acceptance.test.mjs`; `test/process-contract.test.mjs`; `test/credentials-contract.test.mjs`; `test/site-skill-upload-contract.test.mjs` |
| Concurrent refresh rotation and confirmed-401 replay only for known-unaccepted requests | `test/token-lifecycle-contract.test.mjs` |
| Ambiguous mutations and uploads are not retried | `test/run-safety-contract.test.mjs`; `test/site-skill-upload-contract.test.mjs` |
| Redirect/origin boundaries and bounded HTTP responses | `test/http-compatibility-contract.test.mjs`; `test/site-skill-upload-contract.test.mjs` |
| Bounded caches/output and owner-only credential/artifact storage | `test/cache-artifacts-contract.test.mjs`; `test/credentials-contract.test.mjs`; `test/state-contract.test.mjs` |
| Parseable JSON/exit agreement and complete doctor diagnostics | `test/process-contract.test.mjs`; `test/doctor-offline-contract.test.mjs`; `test/doctor-online-contract.test.mjs` |
| Anonymous HTTPS-only update check (plain HTTP only for a loopback registry with `NOVAMIRA_ALLOW_INSECURE_HTTP=1`) that sends no site, profile, or credential data, bounds the response, never changes a command outcome, and installs on request from the registry it queried | `test/update-contract.test.mjs` |
| Agent guidance teaches only the direct REST workflow | `test/guidance-contract.test.mjs` |
| Node 22/24 and Linux/macOS/Windows package installation | `.github/workflows/package.yml`; `scripts/package-acceptance.mjs` |
| Local, global, and npx installation with scripts disabled; help, version, offline doctor, and installed guides | `scripts/package-acceptance.mjs` |
| Restricted prerelease, exact registry integrity, provenance, ownership, and review controls | `.github/workflows/prerelease.yml` |
| Online doctor and representative REST workflow from release-equivalent compiled code | `test/doctor-online-contract.test.mjs`; `test/security-acceptance.test.mjs`; `.github/workflows/prerelease.yml` |

The plugin acceptance client and CLI acceptance edge intentionally expose no
protocol-session or JSON-RPC API. Production handler tests beneath the plugin
harness use real signed tokens and OAuth grant lifecycles; the CLI acceptance
test uses the production profile, credential, metadata, login, token lifecycle,
Ability, cache, and site-skill components.
