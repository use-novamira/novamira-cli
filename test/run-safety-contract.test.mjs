// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AbilityClient } from "../dist/abilities/client.js";
import { parseRunInput } from "../dist/abilities/input.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { CliError } from "../dist/errors.js";
import { ArtifactStore } from "../dist/output/artifacts.js";

const profile = {
  name: "production",
  siteUrl: "https://example.test/wordpress",
  origin: "https://example.test",
};
const compatibility = { rest_api_version: 1 };

function ability(extra = {}) {
  return {
    name: "vendor/group/action",
    input_schema: {
      type: "object",
      required: ["count"],
      properties: { count: { type: "integer", minimum: 1 } },
      additionalProperties: false,
    },
    output_schema: { type: "string" },
    meta: {
      show_in_rest: true,
      annotations: { destructive: false, idempotent: false },
    },
    ...extra,
  };
}

function harness({ cached, description = ability(), result = "ok" } = {}) {
  const requests = [];
  const writes = [];
  const cache = {
    async get(key, contractVersion) {
      requests.push({ kind: "cache", key, contractVersion });
      return cached;
    },
    async put(key, contractVersion, value) {
      writes.push({ key, contractVersion, value });
    },
  };
  const tokens = {
    async authenticatedJson(request, policy) {
      requests.push({
        kind: request.method === "POST" ? "run" : "describe",
        request,
        policy,
      });
      if (request.method !== "POST") return description;
      if (result instanceof Error) throw result;
      return result;
    },
  };
  return {
    client: new AbilityClient(
      profile,
      { protectedResource: async () => ({ novamira: compatibility }) },
      tokens,
      cache,
      5_000,
    ),
    requests,
    writes,
  };
}

test("run input accepts omitted, inline, file, and stdin JSON and rejects malformed input locally", async () => {
  assert.equal(await parseRunInput(undefined), null);
  assert.deepEqual(await parseRunInput('{"count":2}'), { count: 2 });
  assert.deepEqual(
    await parseRunInput("@request.json", {
      file: async (path) => {
        assert.equal(path, "request.json");
        return Buffer.from("[1,true]");
      },
    }),
    [1, true],
  );
  assert.equal(
    await parseRunInput("-", { stdin: async () => Buffer.from('"stdin"') }),
    "stdin",
  );
  for (const source of ["", "{", "@"])
    await assert.rejects(
      parseRunInput(source),
      (error) => error instanceof CliError && error.code === "usage_error",
    );
});

test("run resolves cached or live REST-visible metadata and applies confirmation and replay policy", async () => {
  const cached = harness({ cached: ability() });
  assert.deepEqual(
    await cached.client.run("vendor/group/action", { count: 1 }),
    {
      data: "ok",
      warnings: [],
    },
  );
  assert.equal(
    cached.requests.some(({ kind }) => kind === "describe"),
    false,
  );
  const post = cached.requests.find(({ kind }) => kind === "run");
  assert.equal(post.request.body, '{"input":{"count":1}}');
  assert.match(post.request.url, /\/vendor\/group\/action\/run$/);
  assert.equal(post.policy.unauthorizedReplay, "never");

  const fresh = harness({ cached: ability() });
  await fresh.client.run("vendor/group/action", { count: 1 }, { fresh: true });
  assert.equal(
    fresh.requests.some(({ kind }) => kind === "cache"),
    false,
  );
  assert.equal(
    fresh.requests.some(({ kind }) => kind === "describe"),
    true,
  );
  assert.equal(fresh.writes.length, 1);

  const hidden = harness({
    cached: ability({ meta: { show_in_rest: false, annotations: {} } }),
  });
  await assert.rejects(
    hidden.client.run("vendor/group/action", null),
    (error) => error instanceof CliError && error.code === "ability_hidden",
  );
  assert.equal(
    hidden.requests.some(({ kind }) => kind === "run"),
    false,
  );

  const destructiveRecord = ability({
    meta: {
      show_in_rest: true,
      annotations: { destructive: true, idempotent: true },
    },
  });
  const denied = harness({ cached: destructiveRecord });
  await assert.rejects(
    denied.client.run("vendor/group/action", { count: 1 }),
    (error) =>
      error instanceof CliError && error.code === "confirmation_required",
  );
  assert.equal(
    denied.requests.some(({ kind }) => kind === "run"),
    false,
  );

  for (const options of [{ confirmed: true }, { confirm: async () => true }]) {
    const approved = harness({ cached: destructiveRecord });
    await approved.client.run("vendor/group/action", { count: 1 }, options);
    assert.equal(
      approved.requests.find(({ kind }) => kind === "run").policy
        .unauthorizedReplay,
      "known-not-accepted",
    );
  }
});

test("schema findings stay advisory, server errors stay authoritative, and raw results remain budgetable", async () => {
  const mismatch = harness({ cached: ability(), result: { unexpected: true } });
  const result = await mismatch.client.run("vendor/group/action", {
    count: "wrong",
  });
  assert.deepEqual(
    result.warnings.map(({ code }) => code),
    ["local_input_schema_mismatch", "local_output_schema_mismatch"],
  );
  assert.equal(
    mismatch.requests.filter(({ kind }) => kind === "run").length,
    1,
  );

  const rejection = new CliError(
    "schema_validation_failed",
    "The server rejected the Ability input schema.",
  );
  const rejected = harness({ cached: ability(), result: rejection });
  await assert.rejects(
    rejected.client.run("vendor/group/action", { count: "wrong" }),
    (error) => error === rejection,
  );

  for (const raw of [null, true, 3, "text", [1], { ok: true }]) {
    const current = harness({
      cached: ability({ output_schema: {} }),
      result: raw,
    });
    assert.deepEqual(
      (await current.client.run("vendor/group/action", { count: 1 })).data,
      raw,
    );
  }

  const network = new CliError("network_error", "ambiguous", {
    retryable: true,
  });
  const ambiguous = harness({ cached: ability(), result: network });
  await assert.rejects(
    ambiguous.client.run("vendor/group/action", { count: 1 }),
    (error) => error === network,
  );
  assert.equal(
    ambiguous.requests.filter(({ kind }) => kind === "run").length,
    1,
  );

  const root = await mkdtemp(join(tmpdir(), "novamira-run-"));
  try {
    const security = new UnixFileSecurity();
    const artifacts = new ArtifactStore(
      join(root, "cache"),
      new ProfileLockManager(join(root, "state"), security),
      security,
      { previewBudgetBytes: 128 },
    );
    const budgeted = await artifacts.budget("x".repeat(2_000), {
      maxOutputBytes: 100,
    });
    assert.equal(budgeted.truncated, true);
    assert.equal(
      JSON.parse(await readFile(budgeted.artifact, "utf8")).length,
      2_000,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
