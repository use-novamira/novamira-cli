# Callable entry point

Since 1.3.0, distributors may import `main` and `VERSION` from
`@novamira/cli/entry`. The normal `novamira` executable remains supported.

```js
import { main } from "@novamira/cli/entry";

process.exitCode = await main(process.argv.slice(2), undefined, undefined, {
  managed: {
    updateHint: "Update the containing application instead.",
    commandPrefix: "novamira-hq site-cli",
  },
});
```

Run this entry in a dedicated child process. `main(argv, streams?, environment?,
distribution?)` accepts command arguments without the executable name and returns
the public CLI exit code as `Promise<number>`. Defaults use process stdout,
stderr, and environment; interactive commands use process stdin. Arguments,
human output, JSON envelopes, and exit codes follow `v1-contract.md`.

The optional `managed` setting suppresses automatic update checks before any
registry request or update-state write. Both `update` and `update --check` fail
with the supplied hint before registry access or package-manager execution.
The containing application owns updates to its pinned package. Standalone
invocations retain their existing update behavior.

Since 1.3.1, `managed.commandPrefix` renders executable examples in bundled
`guide get` output, including `--full` references and JSON content, using the
distributor's command. It accepts space-separated executable/subcommand tokens
(letters, digits, dots, underscores and hyphens), not shell expressions or paths
with spaces. Managed guidance replaces standalone update instructions with
`updateHint`. Site-provided skills, Ability identifiers, profile storage and
ordinary command output are never rewritten. An omitted prefix remains
`novamira`; standalone guide behavior is unchanged.

Packaging must retain `dist/` and `guide-data/` at their original relative paths,
as well as package dependencies and applicable licenses. Deno embedders must
include the complete module graph and package data in compiled artifacts.
Runtime diagnostics identify Deno separately from its Node compatibility version.

Embedding does not change profile paths, environment selection, credential
services, or token storage. Standalone and embedded versions using the v1
storage contract share state and locks; distributors should test coexistence
with their pinned version. A future incompatible storage format requires an
explicit migration and compatibility policy.
