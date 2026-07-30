// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { GuideStore } from "../dist/guides/store.js";

const root = new URL("../", import.meta.url);

test("bundled guidance is complete, consistent, and safely opinionated", async () => {
  const store = new GuideStore();
  assert.deepEqual(await store.list(), [{ name: "core" }]);
  const short = await store.get("core");
  const full = await store.get("core", true);

  assert.deepEqual(full.references, [
    "commands.md",
    "safety.md",
    "troubleshooting.md",
  ]);
  assert.ok(full.content.startsWith(short.content));
  for (const required of [
    "sites list",
    "--site <profile>",
    "doctor --json",
    "discover --json",
    "skill get <slug>",
    "describe <ability>",
    "run <ability>",
    "auth login",
    "--input @request.json",
    "--input -",
    "readonly Ability",
    "untrusted",
  ])
    assert.match(
      full.content,
      new RegExp(escapeRegex(required), "i"),
      required,
    );

  const allGuidance = `${await readFile(new URL("../skills/novamira/SKILL.md", import.meta.url), "utf8")}\n${full.content}`;
  const actionableGuidance = allGuidance
    .split("\n")
    .filter((line) => !/\b(?:do not|never|must not|cannot)\b/i.test(line))
    .join("\n");
  assert.doesNotMatch(
    actionableGuidance,
    /(?:use|connect|fallback).{0,30}\b(?:MCP|JSON-RPC)\b/i,
  );
  assert.doesNotMatch(
    actionableGuidance,
    /(?:automatically|without approval).{0,40}escalat/i,
  );
  assert.doesNotMatch(
    actionableGuidance,
    /\b(?:automatically|always)\s+(?:retry|replay)\b/i,
  );
  assert.doesNotMatch(
    actionableGuidance,
    /\b(?:retry|replay)\s+(?:on|after)\s+(?:an?\s+)?(?:timeout|ambiguous)/i,
  );
});

test("guide commands work from source and installed package layouts", async (context) => {
  const temporary = await mkdtemp(join(tmpdir(), "novamira-guides-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const packed = spawnSync(
    "bun",
    ["pm", "pack", "--destination", temporary, "--ignore-scripts", "--quiet"],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(packed.status, 0, packed.stderr);
  const tarball = (await readdir(temporary)).find((name) =>
    name.endsWith(".tgz"),
  );
  assert.ok(tarball, "pack produced a tarball");
  const extracted = spawnSync(
    "tar",
    ["-xzf", join(temporary, tarball), "-C", temporary],
    {
      encoding: "utf8",
    },
  );
  assert.equal(extracted.status, 0, extracted.stderr);
  const packageRoot = join(temporary, "package");

  const layouts = [
    join(temporary, "local", "node_modules", "@novamira", "cli"),
    join(temporary, "global", "lib", "node_modules", "@novamira", "cli"),
    join(temporary, "_npx", "fixture", "node_modules", "@novamira", "cli"),
  ];
  for (const layout of layouts) {
    await mkdir(layout, { recursive: true });
    await cp(packageRoot, layout, { recursive: true });
    await cp(
      new URL("../node_modules/commander", import.meta.url),
      join(layout, "..", "..", "commander"),
      { recursive: true },
    );
    const bin = join(layout, "dist", "index.js");
    const result = spawnSync(
      process.execPath,
      [bin, "--json", "guide", "get", "core", "--full"],
      {
        cwd: temporary,
        encoding: "utf8",
        env: { ...process.env, NOVAMIRA_UPDATE_CHECK: "0" },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).data.name, "core");
    assert.match(JSON.parse(result.stdout).data.content, /Bundled reference/);
  }

  const globalBin = join(temporary, "global", "bin", "novamira");
  await mkdir(join(temporary, "global", "bin"), { recursive: true });
  await symlink(layouts[1] + "/dist/index.js", globalBin);
  assert.equal(
    spawnSync(globalBin, ["guide", "list"], {
      encoding: "utf8",
      env: { ...process.env, NOVAMIRA_UPDATE_CHECK: "0" },
    }).status,
    0,
  );

  const local = spawnSync(
    process.execPath,
    [
      new URL("../dist/index.js", import.meta.url).pathname,
      "guide",
      "get",
      "core",
    ],
    {
      cwd: temporary,
      encoding: "utf8",
      env: { ...process.env, NOVAMIRA_UPDATE_CHECK: "0" },
    },
  );
  assert.equal(local.status, 0, local.stderr);
  assert.match(local.stdout, /Novamira Core Workflow/);
});

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
