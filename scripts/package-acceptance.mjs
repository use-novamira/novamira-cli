#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const temporary = await mkdtemp(join(tmpdir(), "novamira-package-"));
const packageArgument = process.argv.find((value) =>
  value.startsWith("--package="),
);
const packageSpec = packageArgument?.slice("--package=".length);
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const cleanEnvironment = {
  ...process.env,
  NOVAMIRA_CREDENTIAL_BACKEND: "file",
  NOVAMIRA_UPDATE_CHECK: "0",
  npm_config_audit: "false",
  npm_config_fund: "false",
  npm_config_ignore_scripts: "true",
  npm_config_min_release_age: "0",
};

try {
  const packArguments = ["pack"];
  if (packageSpec !== undefined) packArguments.push(packageSpec);
  packArguments.push(
    "--json",
    "--ignore-scripts",
    "--pack-destination",
    temporary,
  );
  const packed = run(npm, packArguments, root);
  const [manifest] = JSON.parse(packed.stdout);
  assert.equal(manifest.name, "@novamira/cli");
  assert.equal(manifest.version, "1.0.0");
  assert.equal(
    manifest.integrity,
    process.env.NOVAMIRA_EXPECTED_INTEGRITY ?? manifest.integrity,
  );
  assert.equal(manifest.bundled.length, 0);

  const packageJson = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  assert.equal(packageJson.license, "AGPL-3.0-or-later");
  assert.equal(packageJson.author, "Ovation S.r.l.");
  assert.equal(packageJson.engines.node, ">=22");
  assert.deepEqual(packageJson.bin, { novamira: "dist/index.js" });
  assert.deepEqual(packageJson.dependencies, { commander: "^14.0.0" });
  assert.equal(packageJson.publishConfig.access, "public");
  assert.equal(packageJson.publishConfig.provenance, true);
  for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"])
    assert.equal(packageJson.scripts[lifecycle], undefined);

  const allowedRoots = new Set([
    "LICENSE",
    "README.md",
    "dist",
    "guide-data",
    "package.json",
    "skills",
  ]);
  for (const file of manifest.files)
    assert.ok(
      allowedRoots.has(file.path.split("/")[0]),
      `unexpected package file: ${file.path}`,
    );
  for (const required of [
    "LICENSE",
    "README.md",
    "dist/index.js",
    "guide-data/core/SKILL.md",
    "skills/novamira/SKILL.md",
  ])
    assert.ok(
      manifest.files.some(({ path }) => path === required),
      `missing ${required}`,
    );
  // Windows has no execute bit to record, so a tarball packed there never
  // carries one. Released tarballs are packed on Linux, where this holds.
  if (process.platform !== "win32") {
    const executable = manifest.files.find(
      ({ path }) => path === "dist/index.js",
    );
    assert.ok(
      (executable.mode & 0o111) !== 0,
      "dist/index.js is not executable",
    );
  }
  assert.ok(
    (await readFile(join(root, "dist/index.js"), "utf8")).startsWith(
      "#!/usr/bin/env node\n",
    ),
  );

  const tarball = join(temporary, basename(manifest.filename));
  const localRoot = join(temporary, "local");
  await writeFile(join(temporary, "package.json"), '{"private":true}\n');
  run(
    npm,
    ["install", "--ignore-scripts", "--prefix", localRoot, tarball],
    temporary,
  );
  const localBin = join(
    localRoot,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "novamira.cmd" : "novamira",
  );
  verifyInstalledCommands(localBin, join(temporary, "local-home"));
  run(
    process.execPath,
    [
      "--test",
      "test/security-acceptance.test.mjs",
      "test/doctor-online-contract.test.mjs",
    ],
    root,
    {
      NOVAMIRA_ACCEPTANCE_DIST: join(
        localRoot,
        "node_modules",
        "@novamira",
        "cli",
        "dist",
      ),
    },
  );

  const globalRoot = join(temporary, "global");
  run(
    npm,
    [
      "install",
      "--global",
      "--ignore-scripts",
      "--prefix",
      globalRoot,
      tarball,
    ],
    temporary,
  );
  const globalBin =
    process.platform === "win32"
      ? join(globalRoot, "novamira.cmd")
      : join(globalRoot, "bin", "novamira");
  assert.match(run(globalBin, ["--help"], temporary).stdout, /Usage: novamira/);

  const npxResult = run(
    npm,
    [
      "exec",
      "--yes",
      "--ignore-scripts",
      `--package=${tarball}`,
      "--",
      "novamira",
      "--version",
    ],
    temporary,
  );
  assert.equal(npxResult.stdout.trim(), manifest.version);

  process.stdout.write(
    `${JSON.stringify({ ok: true, package: manifest.name, version: manifest.version, integrity: manifest.integrity, files: manifest.entryCount })}\n`,
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}

function verifyInstalledCommands(command, home) {
  assert.match(run(command, ["--help"], temporary).stdout, /Usage: novamira/);
  assert.equal(run(command, ["--version"], temporary).stdout.trim(), "1.0.0");
  const guide = JSON.parse(
    run(command, ["--json", "guide", "get", "core", "--full"], temporary)
      .stdout,
  );
  assert.equal(guide.ok, true);
  assert.match(guide.data.content, /Novamira Core Workflow/);
  const doctor = JSON.parse(
    run(command, ["--json", "doctor", "--offline"], temporary, {
      NOVAMIRA_HOME: home,
    }).stdout,
  );
  assert.equal(doctor.ok, true);
  assert.equal(doctor.data.version, 1);
}

// Node refuses to spawn a .cmd shim without a shell, so Windows needs one. With
// a shell it passes the arguments verbatim, which makes quoting ours to do.
function quote(argument) {
  return /[\s"&()<>^|]/.test(argument)
    ? `"${argument.replaceAll('"', '""')}"`
    : argument;
}

function run(command, args, cwd, environment = {}) {
  const shell = process.platform === "win32";
  const result = spawnSync(
    shell ? quote(command) : command,
    shell ? args.map(quote) : args,
    {
      cwd,
      encoding: "utf8",
      shell,
      env: { ...cleanEnvironment, ...environment },
    },
  );
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(" ")} failed\nerror: ${result.error?.message ?? "none"}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`,
  );
  return result;
}
