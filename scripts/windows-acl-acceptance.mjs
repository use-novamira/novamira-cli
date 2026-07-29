#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Exercises the real Windows ACL path in src/config/file-security.ts against
// powershell.exe. The contract tests stub the command runner, so nothing else
// proves that the generated script binds its inputs and reads the actual ACLs.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";

if (process.platform !== "win32") {
  process.stdout.write(
    `windows acl acceptance: skipped on ${process.platform}\n`,
  );
  process.exit(0);
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const { WindowsFileSecurity, secureDirectory } = await import(
  new URL("../dist/config/file-security.js", import.meta.url).href
);
const { powerShellEnvironment } = await import(
  new URL("../dist/config/powershell.js", import.meta.url).href
);

// The storage root carries a space and a single quote: the two characters that
// break an unquoted or naively quoted script literal.
const home = await mkdtemp(join(tmpdir(), "novamira acl o'"));
const state = join(home, "state");
const locks = join(state, "locks");
const file = join(state, "credentials.json");

// The production runner discards output, which leaves a failing script with no
// explanation. This one reports what powershell.exe actually said.
const reportingRunner = {
  run: async (command, args) => {
    // Must match the production runner's environment, or this script would
    // pass or fail for reasons the CLI itself never sees.
    const result = spawnSync(command, args, {
      encoding: "utf8",
      windowsHide: true,
      env: powerShellEnvironment(),
    });
    if (result.error) throw result.error;
    // An unsafe verdict (3) is a normal result, but it still explains itself on
    // stderr, and that explanation is the whole point when a hardened path is
    // rejected.
    if (result.status !== 0 || result.stderr !== "")
      process.stderr.write(
        `${command} exited with ${String(result.status)}\n` +
          `script: ${args[5]}\n` +
          `inherited PSModulePath: ${process.env.PSModulePath ?? "(unset)"}\n` +
          `stdout: ${result.stdout}\nstderr: ${result.stderr}\n`,
      );
    return result.status;
  },
};

try {
  const security = new WindowsFileSecurity(reportingRunner);

  // An inherited ACL must read as unsafe. While the script relied on $args it
  // errored for every path, so a false here also proves Get-Acl was reached.
  const inherited = join(home, "inherited");
  await mkdir(inherited, { recursive: true });
  assert.equal(
    await security.verifyDirectory(inherited),
    false,
    "an inherited directory ACL must not verify as safe",
  );

  // doctor inspects the config directory (the storage root under
  // NOVAMIRA_HOME), the state directory, and the lock directory.
  for (const directory of [home, state, locks]) {
    await secureDirectory(directory, security);
    assert.equal(
      await security.verifyDirectory(directory),
      true,
      `a hardened directory must verify as safe: ${directory}`,
    );
  }

  await writeFile(file, "{}");
  await security.secureFile(file);
  assert.equal(
    await security.verifyFile(file),
    true,
    "a hardened file must verify as safe",
  );

  // doctor reads the same code through its own storage.permissions check.
  const doctor = spawnSync(
    process.execPath,
    [join(root, "dist", "index.js"), "doctor", "--offline", "--json"],
    {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        NOVAMIRA_HOME: home,
        NOVAMIRA_CREDENTIAL_BACKEND: "file",
        NOVAMIRA_UPDATE_CHECK: "0",
      },
    },
  );
  assert.ok(doctor.stdout, `doctor produced no report: ${doctor.stderr}`);
  const report = JSON.parse(doctor.stdout);
  const permissions = report.data.checks.find(
    (check) => check.id === "storage.permissions",
  );
  assert.ok(permissions, "doctor must report storage.permissions");
  assert.equal(
    permissions.status,
    "pass",
    `storage.permissions must pass on hardened storage: ${JSON.stringify(permissions)}`,
  );

  process.stdout.write("windows acl acceptance: ok\n");
} finally {
  await rm(home, { recursive: true, force: true });
}
