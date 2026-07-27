# Troubleshooting

Run `novamira --site <profile> doctor --json` first. Its stable findings distinguish local storage, OAuth, compatibility, scope, REST surface, and site-permission failures.

- For missing or expired authorization, rerun `auth login` for the same normalized site and profile. Add `--access read` when readonly access is requested.
- For insufficient scope, do not work around the server or choose another Ability merely to evade policy. Obtain explicit approval before replacing a readonly grant; login requests full access by default.
- For a missing or hidden Ability, rerun discovery and use only advertised REST-visible Abilities. Extensions and site permissions can change during a task.
- For schema errors, rerun `describe` and conform to the live input schema. Local diagnostics are advisory; the server remains authoritative.
- For compatibility or missing-surface findings, stop and report the doctor evidence. Do not guess routes or fall back to another protocol.
- For an ambiguous mutation failure, inspect state with a readonly Ability. Never automatically replay the mutation.
- Use `auth logout` when access is no longer needed; local credentials are removed even if remote revocation is unavailable.
