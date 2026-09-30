# Troubleshooting

Run `novamira --site <profile> doctor --json` first. Its stable findings distinguish local storage, OAuth, compatibility, scope, REST surface, and site-permission failures.

- For missing or expired authorization, rerun `auth login` yourself for the same normalized site and profile, and ask the user only to approve the site in the browser. Every login requests full access.
- Login waits for the browser approval, up to five minutes by default. Run it so you can read stderr while it waits, and give the user the printed authorization URL. If the launched browser is not the one where they are signed in to WordPress, or shows a not-found page, they open that URL in the right browser; the waiting login completes on its own. Use `--no-open` to print the URL without launching any browser.
- When the shell is remote and the user's browser cannot reach this host, rerun login with `--device` and give the user the printed URL and code to approve. If the site reports `server_unsupported` for `--device`, it is too old for that grant; use the browser flow.
- For insufficient scope, do not work around the server or choose another Ability merely to evade policy. Rerun login once to replace a legacy credential, then report the server or user-permission failure if it persists.
- For a missing or hidden Ability, rerun discovery and use only advertised REST-visible Abilities. Extensions and site permissions can change during a task.
- For schema errors, rerun `describe` and conform to the live input schema. Local diagnostics are advisory; the server remains authoritative.
- For compatibility or missing-surface findings, stop and report the doctor evidence. Do not guess routes or fall back to another protocol.
- For an ambiguous mutation failure, inspect state with a readonly Ability. Never automatically replay the mutation.
- Use `auth logout` when access is no longer needed; local credentials are removed even if remote revocation is unavailable.
