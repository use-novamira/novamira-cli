// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";
import { AbilityClient, ABILITY_PAGE_SIZE } from "../dist/abilities/client.js";
import { CliError } from "../dist/errors.js";
import { writeHumanAbilityDescription } from "../dist/output/render.js";

const profile = {
  name: "production",
  siteUrl: "https://example.test/wordpress",
  origin: "https://example.test",
};

const compatibility = {
  plugin_version: "1.11.0",
  rest_api_version: 1,
  wordpress_version: "6.9.2",
  minimum_wordpress_version: "6.9",
  features: {
    abilities_bearer_auth: true,
    abilities_read_scope: true,
    agent_context: true,
    rest_skills: true,
    generalized_execution_shim: true,
  },
};

const context = {
  server: compatibility,
  instructions: "Use the site policy.",
  skills: [
    {
      slug: "theme-maintenance",
      description: "Theme guidance",
      source: "user-cpt",
      extension: "preserved",
    },
  ],
  environment: { wordpress_version: "6.9.2", locale: "en_US" },
};

function record(name, extra = {}) {
  return {
    name,
    label: `Label for ${name}`,
    description: `Description for ${name}`,
    category: "filesystem",
    input_schema: { type: "object" },
    output_schema: { type: "string" },
    instructions: "Long Ability instructions",
    meta: {
      show_in_rest: true,
      annotations: {
        readonly: true,
        destructive: false,
        idempotent: true,
      },
    },
    ...extra,
  };
}

function harness({ pages, contextResult = context, description } = {}) {
  const requests = [];
  const writes = [];
  const tokens = {
    async authenticatedJsonResponse(request) {
      const url = new URL(request.url);
      requests.push({ kind: "page", url: url.toString() });
      const page = Number(url.searchParams.get("page"));
      const response = pages?.[page - 1];
      if (response === undefined) throw new Error(`Unexpected page ${page}`);
      return {
        data: response.data,
        status: 200,
        headers: new Headers(response.headers),
        url: url.toString(),
      };
    },
    async authenticatedJson(request) {
      const url = new URL(request.url);
      requests.push({
        kind: request.method === "POST" ? "context" : "item",
        url: url.toString(),
      });
      if (request.method === "POST") {
        if (contextResult instanceof Error) throw contextResult;
        return contextResult;
      }
      return description;
    },
  };
  const metadata = {
    protectedResource: async () => ({ novamira: compatibility }),
  };
  const cache = {
    async put(key, contractVersion, value) {
      writes.push({ key, contractVersion, value });
    },
  };
  return {
    client: new AbilityClient(profile, metadata, tokens, cache, 5_000),
    requests,
    writes,
  };
}

test("discovery is complete and atomic while projecting compact records", async () => {
  const first = record("novamira/read-file");
  const second = record("vendor/group/action");
  const state = harness({
    pages: [
      { data: [first], headers: { "x-wp-totalpages": "2" } },
      { data: [second], headers: { "x-wp-totalpages": "2" } },
    ],
  });

  const result = await state.client.discover();
  assert.deepEqual(result.context, context);
  assert.deepEqual(result.abilities, [
    {
      name: first.name,
      label: first.label,
      description: first.description,
      category: first.category,
      annotations: {
        readonly: true,
        destructive: false,
        idempotent: true,
      },
    },
    {
      name: second.name,
      label: second.label,
      description: second.description,
      category: second.category,
      annotations: {
        readonly: true,
        destructive: false,
        idempotent: true,
      },
    },
  ]);
  assert.equal(Object.hasOwn(result.abilities[0], "input_schema"), false);
  assert.deepEqual(
    state.writes.map(({ value }) => value),
    [first, second],
  );
  assert.deepEqual(
    state.writes.map(({ key }) => key.abilityName),
    [first.name, second.name],
  );
  assert.equal(state.requests.at(-1).kind, "context");

  for (const contextFailure of [
    new CliError("ability_not_found", "missing"),
    { ...context, server: { ...compatibility, plugin_version: "1.11.1" } },
  ]) {
    const failed = harness({
      pages: [{ data: [first], headers: { "x-wp-totalpages": "1" } }],
      contextResult: contextFailure,
    });
    await assert.rejects(
      failed.client.discover(),
      (error) =>
        error instanceof CliError && error.code === "server_unsupported",
    );
    assert.deepEqual(failed.writes, []);
  }
});

test("pagination accepts empty and Link catalogs and rejects unsafe changes", async () => {
  const empty = harness({
    pages: [{ data: [], headers: { "x-wp-totalpages": "0" } }],
  });
  assert.deepEqual((await empty.client.discover()).abilities, []);

  const next = new URL(
    "https://example.test/wordpress/wp-json/wp-abilities/v1/abilities",
  );
  next.searchParams.set("per_page", String(ABILITY_PAGE_SIZE));
  next.searchParams.set("page", "2");
  const linked = harness({
    pages: [
      {
        data: [record("novamira/one")],
        headers: { link: `<${next}>; rel="next"` },
      },
      {
        data: [record("novamira/two")],
        headers: { link: `<${next}>; rel="prev"` },
      },
    ],
  });
  assert.deepEqual(
    (await linked.client.discover()).abilities.map(({ name }) => name),
    ["novamira/one", "novamira/two"],
  );

  const invalidCases = [
    [
      { data: [record("novamira/one")], headers: { "x-wp-totalpages": "2" } },
      { data: [record("novamira/two")], headers: { "x-wp-totalpages": "3" } },
    ],
    [{ data: [], headers: { "x-wp-totalpages": "invalid" } }],
    [{ data: [], headers: { "x-wp-totalpages": "1001" } }],
    [{ data: {}, headers: { "x-wp-totalpages": "1" } }],
    [{ data: [], headers: {} }],
  ];
  for (const pages of invalidCases) {
    await assert.rejects(
      harness({ pages }).client.discover(),
      (error) =>
        error instanceof CliError && error.code === "server_unsupported",
    );
  }
});

test("describe uses segment-safe live retrieval, caches unchanged data, and surfaces safety", async () => {
  const abilityName = "vendor/group/action name";
  const description = record(abilityName);
  const state = harness({ description });
  assert.deepEqual(await state.client.describe(abilityName), description);
  assert.match(
    state.requests[0].url,
    /\/abilities\/vendor\/group\/action%20name$/,
  );
  assert.deepEqual(state.writes[0], {
    key: {
      origin: profile.origin,
      profileName: profile.name,
      abilityName,
    },
    contractVersion: 1,
    value: description,
  });

  let output = "";
  writeHumanAbilityDescription(
    { stdout: { write: (value) => (output += value) }, stderr: { write() {} } },
    description,
  );
  assert.match(output, /readonly: true/);
  assert.match(output, /destructive: false/);
  assert.match(output, /idempotent: true/);
  assert.match(output, /instructions: Long Ability instructions/);
});
