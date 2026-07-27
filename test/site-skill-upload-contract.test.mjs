// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { CliError } from "../dist/errors.js";
import { diagnoseSchema } from "../dist/abilities/schema.js";
import { ArtifactStore } from "../dist/output/artifacts.js";
import { HttpClient } from "../dist/rest/http-client.js";
import { SITE_SKILL_ABILITY, getSiteSkill } from "../dist/skills/client.js";
import {
  CompositeUploader,
  UPLOAD_GRANT_ABILITY,
} from "../dist/upload/client.js";

const profile = {
  name: "production",
  siteUrl: "https://example.test/wordpress",
  origin: "https://example.test",
};
const now = Date.parse("2026-07-21T12:00:00.000Z");
const token = "temporary-secret.signature";
const uploadUrl = "https://example.test/wordpress/wp-json/novamira/v1/upload";

test("site skills use the ordinary Ability path and retain missing, permission, and large-output behavior", async () => {
  const calls = [];
  const abilities = {
    async run(name, input, options) {
      calls.push({ name, input, options });
      if (input.slug === "denied")
        throw new CliError("insufficient_scope", "denied");
      if (input.slug === "missing")
        return { data: { found: false }, warnings: [] };
      return {
        data: { found: true, slug: input.slug, content: "x".repeat(2_000) },
        warnings: [],
      };
    },
  };

  const found = await getSiteSkill(abilities, "theme-maintenance");
  assert.equal(calls[0].name, SITE_SKILL_ABILITY);
  assert.deepEqual(calls[0].input, { slug: "theme-maintenance" });
  assert.equal(calls[0].options, undefined);
  assert.deepEqual((await getSiteSkill(abilities, "missing")).data, {
    found: false,
  });
  await assert.rejects(getSiteSkill(abilities, "denied"), {
    code: "insufficient_scope",
  });
  const beforeInvalid = calls.length;
  for (const slug of ["", " padded", "group/skill", "bad\u0000slug"])
    await assert.rejects(getSiteSkill(abilities, slug), {
      code: "usage_error",
    });
  assert.equal(calls.length, beforeInvalid);
  const boundedFinding = diagnoseSchema(
    { ["remote".repeat(1_000)]: true },
    { type: "object", additionalProperties: false },
  )[0];
  assert.ok(boundedFinding.path.length <= 512);
  assert.deepEqual(
    diagnoseSchema(null, { type: Array.from({ length: 33 }, () => "string") }),
    [],
  );

  const root = await mkdtemp(join(tmpdir(), "novamira-skill-"));
  try {
    const security = new UnixFileSecurity();
    const artifacts = new ArtifactStore(
      join(root, "cache"),
      new ProfileLockManager(join(root, "state"), security),
      security,
      { previewBudgetBytes: 128 },
    );
    const budgeted = await artifacts.budget(found.data, {
      maxOutputBytes: 100,
    });
    assert.equal(budgeted.truncated, true);
    assert.equal(
      JSON.parse(await readFile(budgeted.artifact, "utf8")).content.length,
      2_000,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("composite upload requires full scope and streams only the temporary credential", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-upload-"));
  const local = join(root, "plugin.zip");
  const content = Buffer.from("streamed-binary-content");
  await writeFile(local, content);
  const requests = [];
  const diagnostics = [];
  const abilityCalls = [];
  let scopeChecks = 0;
  const abilities = {
    async run(name, input, options) {
      abilityCalls.push({ name, input, options });
      return {
        data: grant({ max_bytes: content.length }),
        warnings: [
          {
            code: "local_output_schema_mismatch",
            message: token,
            details: { findings: [{ path: uploadUrl }] },
          },
        ],
      };
    },
  };
  const http = new HttpClient({
    onDiagnostic: (value) => diagnostics.push(value),
    fetch: async (url, init = {}) => {
      const headers = new Headers(init.headers);
      const body = Buffer.from(await new Response(init.body).arrayBuffer());
      requests.push({ url: String(url), method: init.method, headers, body });
      return Response.json({ bytes_written: body.length });
    },
  });
  const uploader = new CompositeUploader(
    profile,
    {
      async requireScope(scope) {
        scopeChecks += 1;
        assert.equal(scope, "abilities");
      },
    },
    abilities,
    http,
    1_000,
    () => now,
  );

  try {
    const result = await uploader.upload(
      local,
      "wp-content/plugins/plugin.zip",
    );
    assert.deepEqual(result, {
      data: {
        destination: "wp-content/plugins/plugin.zip",
        bytesTransferred: content.length,
      },
      warnings: [],
    });
    assert.equal(scopeChecks, 1);
    assert.deepEqual(abilityCalls, [
      {
        name: UPLOAD_GRANT_ABILITY,
        input: { path: "wp-content/plugins/plugin.zip" },
        options: { fresh: true },
      },
    ]);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, uploadUrl);
    assert.equal(requests[0].method, "PUT");
    assert.deepEqual(requests[0].body, content);
    assert.equal(requests[0].headers.get("x-novamira-upload-token"), token);
    assert.equal(requests[0].headers.get("authorization"), null);
    assert.equal(requests[0].headers.get("cookie"), null);
    assert.equal(
      requests[0].headers.get("content-length"),
      String(content.length),
    );
    assert.doesNotMatch(
      JSON.stringify({ result, diagnostics }),
      new RegExp(token),
    );
    assert.equal(
      JSON.stringify({ result, diagnostics }).includes(uploadUrl),
      false,
    );
    assert.deepEqual(diagnostics, []);
    assert.doesNotMatch(
      JSON.stringify(diagnostics),
      /upload_url|authorization/i,
    );

    let grantCreated = false;
    const denied = new CompositeUploader(
      profile,
      {
        async requireScope() {
          throw new CliError("insufficient_scope", "full scope required");
        },
      },
      {
        async run() {
          grantCreated = true;
          return { data: grant(), warnings: [] };
        },
      },
      http,
      1_000,
      () => now,
    );
    await assert.rejects(denied.upload(local, "remote.zip"), {
      code: "insufficient_scope",
    });
    assert.equal(grantCreated, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("upload rejects unsafe limits and grants and never retries an ambiguous stream", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-upload-policy-"));
  const local = join(root, "payload.bin");
  await writeFile(local, "12345");
  const scope = { requireScope: async () => undefined };
  let fetches = 0;
  const failingHttp = new HttpClient({
    fetch: async () => {
      fetches += 1;
      throw new Error(`network failed ${token} ${uploadUrl}`);
    },
  });

  const withGrant = (data, http = failingHttp) =>
    new CompositeUploader(
      profile,
      scope,
      { run: async () => ({ data, warnings: [] }) },
      http,
      1_000,
      () => now,
    );

  try {
    await assert.rejects(
      withGrant(grant({ max_bytes: 4 })).upload(local, "remote.bin"),
      { code: "usage_error" },
    );
    assert.equal(fetches, 0);
    await assert.rejects(
      withGrant(grant({ expires_at: Math.floor(now / 1_000) })).upload(
        local,
        "remote.bin",
      ),
      { code: "server_unsupported" },
    );
    await assert.rejects(
      withGrant(grant({ expires_at: Math.floor(now / 1_000) + 3_601 })).upload(
        local,
        "remote.bin",
      ),
      { code: "server_unsupported" },
    );
    await assert.rejects(
      withGrant(grant({ token_header: "Authorization" })).upload(
        local,
        "remote.bin",
      ),
      { code: "server_unsupported" },
    );
    await assert.rejects(
      withGrant(grant({ upload_url: "https://attacker.test/upload" })).upload(
        local,
        "remote.bin",
      ),
      { code: "server_unsupported" },
    );
    await assert.rejects(
      withGrant(
        grant({ upload_url: "https://example.test/wordpress/wp-json/steal" }),
      ).upload(local, "remote.bin"),
      { code: "server_unsupported" },
    );
    await assert.rejects(withGrant(grant()).upload(root, "remote.bin"), {
      code: "usage_error",
    });
    let ambiguous;
    try {
      await withGrant(grant()).upload(local, "remote.bin");
      assert.fail("ambiguous upload unexpectedly succeeded");
    } catch (error) {
      ambiguous = error;
    }
    assert.equal(ambiguous.code, "network_error");
    assert.doesNotMatch(ambiguous.message, /temporary-secret|example\.test/);
    assert.equal(fetches, 1);

    let secretError;
    try {
      await withGrant(
        grant(),
        new HttpClient({
          fetch: async () =>
            Response.json(
              { code: token, message: uploadUrl, data: { status: 400 } },
              { status: 400 },
            ),
        }),
      ).upload(local, "remote.bin");
      assert.fail("secret-bearing REST error unexpectedly succeeded");
    } catch (error) {
      secretError = error;
    }
    assert.equal(secretError.remoteCode, "[REDACTED]");
    assert.doesNotMatch(JSON.stringify(secretError), /temporary-secret/);

    let redirects = 0;
    const redirected = withGrant(
      grant(),
      new HttpClient({
        fetch: async () => {
          redirects += 1;
          return new Response(null, {
            status: 307,
            headers: { location: uploadUrl },
          });
        },
      }),
    );
    await assert.rejects(redirected.upload(local, "remote.bin"), {
      code: "network_error",
    });
    assert.equal(redirects, 1);

    const partial = withGrant(
      grant(),
      new HttpClient({
        fetch: async () => Response.json({ bytes_written: 4 }),
      }),
    );
    await assert.rejects(partial.upload(local, "remote.bin"), {
      code: "network_error",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function grant(overrides = {}) {
  return {
    upload_url: uploadUrl,
    upload_token: token,
    token_header: "X-Novamira-Upload-Token",
    method: "PUT",
    expires_at: Math.floor(now / 1_000) + 900,
    max_bytes: 1_000,
    ...overrides,
  };
}
