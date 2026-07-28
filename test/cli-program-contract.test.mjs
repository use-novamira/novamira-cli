// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";
import { createProgram } from "../dist/cli/program.js";

function recordingHandlers(calls) {
  return new Proxy(
    {},
    {
      get:
        (_target, name) =>
        (...args) =>
          calls.push({ name, args }),
    },
  );
}

function silenceErrors(command) {
  command.configureOutput({
    writeErr: () => undefined,
    outputError: () => undefined,
  });
  for (const child of command.commands) silenceErrors(child);
}

test("the command tree routes named arguments and command-specific options", async () => {
  const cases = [
    { argv: ["--version"], name: "version", args: ["test"] },
    {
      argv: ["auth", "login", "https://example.test", "--access", "read"],
      name: "authLogin",
      args: ["https://example.test"],
      options: { access: "read", open: true, timeout: 300_000 },
    },
    { argv: ["auth", "status"], name: "authStatus", args: [] },
    { argv: ["auth", "logout"], name: "authLogout", args: [] },
    { argv: ["sites", "list"], name: "sitesList", args: [] },
    {
      argv: ["sites", "remove", "production"],
      name: "sitesRemove",
      args: ["production"],
    },
    { argv: ["discover"], name: "discover", args: [] },
    {
      argv: ["describe", "novamira/example"],
      name: "describe",
      args: ["novamira/example"],
    },
    {
      argv: ["run", "novamira/example", "--input", "{}", "--fresh"],
      name: "run",
      args: ["novamira/example"],
      options: { input: "{}", fresh: true },
    },
    {
      argv: ["skill", "get", "editorial"],
      name: "skillGet",
      args: ["editorial"],
    },
    {
      argv: ["upload", "local.txt", "remote.txt"],
      name: "upload",
      args: ["local.txt", "remote.txt"],
    },
    { argv: ["guide", "list"], name: "guideList", args: [] },
    {
      argv: ["guide", "get", "quickstart", "--full"],
      name: "guideGet",
      args: ["quickstart"],
      options: { full: true },
    },
    {
      argv: ["update", "--check"],
      name: "update",
      args: [],
      options: { check: true },
    },
    {
      argv: ["doctor", "--offline", "--fix"],
      name: "doctor",
      args: [],
      options: { offline: true, fix: true },
    },
  ];

  for (const entry of cases) {
    const calls = [];
    await createProgram("test", recordingHandlers(calls)).parseAsync(
      entry.argv,
      { from: "user" },
    );
    assert.equal(calls.length, 1, entry.name);
    assert.equal(calls[0].name, entry.name);
    const options = calls[0].args.at(-1);
    assert.deepEqual(calls[0].args.slice(0, -1), entry.args);
    for (const [name, value] of Object.entries(entry.options ?? {}))
      assert.equal(options[name], value, `${entry.name}.${name}`);
  }
});

test("Commander rejects missing required arguments before invoking a handler", async () => {
  const cases = [
    ["auth", "login"],
    ["sites", "remove"],
    ["describe"],
    ["run"],
    ["skill", "get"],
    ["upload", "local.txt"],
    ["guide", "get"],
  ];

  for (const argv of cases) {
    const calls = [];
    const program = createProgram("test", recordingHandlers(calls));
    silenceErrors(program);
    await assert.rejects(program.parseAsync(argv, { from: "user" }));
    assert.deepEqual(calls, [], argv.join(" "));
  }
});
