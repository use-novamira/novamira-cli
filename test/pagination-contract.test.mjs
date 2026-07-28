// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";
import {
  ABILITY_PAGE_SIZE,
  WordPressPaginator,
} from "../dist/abilities/paginator.js";
import { CliError } from "../dist/errors.js";

const endpoint = new URL(
  "https://example.test/wordpress/wp-json/wp-abilities/v1/abilities",
);

function record(name) {
  return { name };
}

function nextUrl(page, origin = endpoint.origin) {
  const url = new URL(endpoint);
  url.host = new URL(origin).host;
  url.searchParams.set("per_page", String(ABILITY_PAGE_SIZE));
  url.searchParams.set("page", String(page));
  return url.toString();
}

function paginator(pages) {
  const requests = [];
  return {
    requests,
    value: new WordPressPaginator({
      endpoint,
      expectedOrigin: endpoint.origin,
      fetchPage: async (url) => {
        requests.push(url.toString());
        const page = Number(url.searchParams.get("page"));
        const response = pages[page - 1];
        if (response === undefined) throw new Error(`Unexpected page ${page}`);
        return {
          data: response.data,
          headers: new Headers(response.headers),
        };
      },
      parseRecord: (value) => value,
    }),
  };
}

async function rejectsUnsupported(pages) {
  await assert.rejects(
    paginator(pages).value.collect(),
    (error) => error instanceof CliError && error.code === "server_unsupported",
  );
}

test("WordPressPaginator collects pages and owns request pagination", async () => {
  const state = paginator([
    { data: [record("novamira/one")], headers: { "x-wp-totalpages": "2" } },
    { data: [record("novamira/two")], headers: { "x-wp-totalpages": "2" } },
  ]);

  assert.deepEqual(await state.value.collect(), [
    record("novamira/one"),
    record("novamira/two"),
  ]);
  assert.deepEqual(
    state.requests.map((value) => {
      const url = new URL(value);
      return [url.searchParams.get("page"), url.searchParams.get("per_page")];
    }),
    [
      ["1", String(ABILITY_PAGE_SIZE)],
      ["2", String(ABILITY_PAGE_SIZE)],
    ],
  );
});

test("WordPressPaginator rejects catalog changes and pagination mode changes", async () => {
  await rejectsUnsupported([
    { data: [record("novamira/same")], headers: { "x-wp-totalpages": "2" } },
    { data: [record("novamira/same")], headers: { "x-wp-totalpages": "2" } },
  ]);
  await rejectsUnsupported([
    {
      data: [record("novamira/one")],
      headers: { link: `<${nextUrl(2)}>; rel="next"` },
    },
    { data: [], headers: { "x-wp-totalpages": "2" } },
  ]);
});

test("WordPressPaginator rejects unsafe, looping, and ambiguous next links", async () => {
  for (const link of [
    nextUrl(1),
    nextUrl(2, "https://attacker.test"),
    `${nextUrl(2)}#fragment`,
    `${nextUrl(2)}>; rel="next", <${nextUrl(3)}`,
  ]) {
    await rejectsUnsupported([
      {
        data: [record("novamira/one")],
        headers: { link: `<${link}>; rel="next"` },
      },
    ]);
  }
});
