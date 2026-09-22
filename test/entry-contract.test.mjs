// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { main, VERSION } from "@novamira/cli/entry";

test("public managed entry preserves output and blocks updates before side effects", async () => {
  const home = await mkdtemp(join(tmpdir(), "novamira-entry-"));
  try {
    const environment = {
      NOVAMIRA_HOME: home,
      NOVAMIRA_REGISTRY: "http://127.0.0.1:1",
    };
    const distribution = {
      managed: {
        updateHint: "Update the containing application instead.",
        commandPrefix: "novamira-hq site-cli",
      },
    };
    const run = async (argv) => {
      let stdout = "";
      let stderr = "";
      const code = await main(
        argv,
        {
          stdout: {
            write: (text) => {
              stdout += text;
            },
          },
          stderr: {
            write: (text) => {
              stderr += text;
            },
          },
        },
        environment,
        distribution,
      );
      return { code, stdout, stderr };
    };
    assert.equal((await run(["--version"])).stdout.trim(), VERSION);
    const guides = await run(["guide", "list", "--json"]);
    assert.equal(guides.code, 0);
    assert.ok(JSON.parse(guides.stdout).data.guides.length > 0);
    assert.equal(guides.stderr, "");
    for (const flags of [[], ["--full"], ["--full", "--json"]]) {
      const result = await run(["guide", "get", "core", ...flags]);
      assert.equal(result.code, 0);
      const content = flags.includes("--json")
        ? JSON.parse(result.stdout).data.content
        : result.stdout;
      assert.match(content, /novamira-hq site-cli sites list/);
      assert.match(content, /novamira-hq site-cli auth login/);
      assert.doesNotMatch(content, /(?<=`|^|\| )novamira(?= |`)/m);
      if (flags.includes("--full")) {
        assert.match(content, /describe novamira\/read-file/);
        assert.match(content, /\| novamira-hq site-cli --site/);
        assert.match(content, /Update the containing application instead\./);
        assert.doesNotMatch(
          content,
          /package manager|novamira-hq site-cli update/,
        );
      }
    }
    for (const argv of [
      ["update", "--json"],
      ["update", "--check", "--json"],
    ]) {
      const result = await run(argv);
      assert.notEqual(result.code, 0);
      assert.equal(
        JSON.parse(result.stdout).error.message,
        distribution.managed.updateHint,
      );
    }
    assert.deepEqual(await readdir(home), []);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
