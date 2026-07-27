// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import { main, VERSION } from "../dist/main.js";
import { redact } from "../dist/output/redact.js";

const home = await mkdtemp(join(tmpdir(), "novamira-process-"));
const environment = { NOVAMIRA_HOME: home };

after(async () => rm(home, { recursive: true, force: true }));

function capture() {
  let stdout = "";
  let stderr = "";
  return {
    streams: {
      stdout: { write: (value) => (stdout += value) },
      stderr: { write: (value) => (stderr += value) },
    },
    read: () => ({ stdout, stderr }),
  };
}

test("JSON success and failure are single values with matching exits", async () => {
  const success = capture();
  assert.equal(
    await main(["--json", "--version"], success.streams, environment),
    0,
  );
  assert.deepEqual(JSON.parse(success.read().stdout), {
    ok: true,
    data: { version: VERSION },
    meta: { requestId: JSON.parse(success.read().stdout).meta.requestId },
  });
  assert.equal(success.read().stderr, "");

  const failure = capture();
  assert.equal(
    await main(["--json", "unknown"], failure.streams, environment),
    2,
  );
  assert.equal(JSON.parse(failure.read().stdout).ok, false);
  assert.equal(JSON.parse(failure.read().stdout).error.code, "usage_error");
  assert.equal(failure.read().stderr, "");
});

test("implemented composite commands proceed to deterministic site selection", async () => {
  for (const command of [
    ["skill", "get", "theme-maintenance"],
    ["upload", "local.txt", "wp-content/local.txt"],
  ]) {
    const output = capture();
    assert.equal(
      await main(["--json", ...command], output.streams, environment),
      2,
    );
    assert.equal(JSON.parse(output.read().stdout).error.code, "site_required");
    assert.equal(output.read().stderr, "");
  }
});

test("diagnostics redact secret keys and values and never use ANSI in JSON mode", async () => {
  assert.deepEqual(
    redact({ accessToken: "secret-value", note: "value=secret-value" }, [
      "secret-value",
    ]),
    {
      accessToken: "[REDACTED]",
      note: "value=[REDACTED]",
    },
  );

  const output = capture();
  assert.equal(
    await main(
      ["--json", "--verbose", "skill", "get", "theme-maintenance"],
      output.streams,
      {
        ...environment,
        NO_COLOR: "1",
      },
    ),
    2,
  );
  assert.doesNotMatch(output.read().stdout + output.read().stderr, /\u001b\[/);
  assert.equal(JSON.parse(output.read().stdout).ok, false);
});
