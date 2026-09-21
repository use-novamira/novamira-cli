// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";
import process from "node:process";
import { VERSION } from "../dist/main.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = await mkdtemp(join(tmpdir(), "novamira-embedded-"));
try {
  const binary = join(
    temporary,
    process.platform === "win32" ? "cli.exe" : "cli",
  );
  const compiled = spawnSync(
    "deno",
    [
      "compile",
      "--no-check",
      "--node-modules-dir=manual",
      "--allow-env",
      "--allow-read",
      "--allow-write",
      "--allow-sys",
      "--include",
      "guide-data",
      "--output",
      binary,
      "scripts/embedded-entry.mjs",
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(compiled.status, 0, compiled.stderr);
  const run = (args, expected = 0) => {
    const result = spawnSync(binary, args, {
      cwd: temporary,
      encoding: "utf8",
      timeout: 30_000,
      env: {
        ...process.env,
        PATH: "",
        DENO_DIR: join(temporary, "empty-cache"),
        NOVAMIRA_HOME: join(temporary, "home"),
        NOVAMIRA_CREDENTIAL_BACKEND: "file",
      },
    });
    assert.equal(result.status, expected, result.stderr || result.stdout);
    return result.stdout;
  };
  assert.equal(run(["--version"]).trim(), VERSION);
  const guides = JSON.parse(run(["guide", "list", "--json"])).data.guides;
  assert.ok(guides.length > 0);
  for (const guide of guides) {
    assert.ok(
      JSON.parse(run(["guide", "get", guide.name, "--full", "--json"])).data
        .content.length > 0,
    );
  }
  const report = JSON.parse(run(["doctor", "--offline", "--json"])).data;
  assert.ok(report.checks.some((check) => check.id === "runtime.deno"));
  assert.match(run(["update", "--json"], 2), /containing application/);
  process.stdout.write(
    "Compiled entry, guides, diagnostics, and managed update policy passed offline.\n",
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
