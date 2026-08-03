// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  MetadataClient,
  REQUIRED_FEATURES,
  assertCompatible,
  validateAuthorizationServerMetadata,
  validateProtectedResourceMetadata,
} from "../dist/auth/metadata.js";
import { HttpClient } from "../dist/rest/http-client.js";
import { parseWordPressResponse } from "../dist/rest/wordpress-response.js";
import {
  abilityItemUrl,
  restUrl,
  restUrlFromResource,
  wellKnownUrl,
} from "../dist/rest/urls.js";

const protectedFixture = JSON.parse(
  await readFile("fixtures/v1/protected-resource-metadata.json", "utf8"),
);
const restErrorFixture = await readFile(
  "fixtures/v1/wordpress-rest-error.json",
  "utf8",
);

function authorizationMetadata(site = "https://example.test") {
  return {
    issuer: site,
    authorization_endpoint: `${site}/wp-admin/admin.php?page=novamira-oauth-authorize`,
    token_endpoint: `${site}/wp-json/novamira/v1/oauth/token`,
    registration_endpoint: `${site}/wp-json/novamira/v1/oauth/register`,
    revocation_endpoint: `${site}/wp-json/novamira/v1/oauth/revoke`,
    introspection_endpoint: `${site}/wp-json/novamira/v1/oauth/introspect`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["mcp"],
  };
}

function wordpressError(status, body) {
  let captured;
  try {
    parseWordPressResponse(status, JSON.stringify(body));
  } catch (error) {
    captured = error;
  }
  assert.notEqual(captured, undefined, "Expected a WordPress REST error");
  return captured;
}

test("HTTP client bounds redirects, time, response bytes, diagnostics, and heterogeneous REST values", async () => {
  let calls = 0;
  const redirected = new HttpClient({
    fetch: async (url) => {
      calls += 1;
      return calls === 1
        ? new Response(null, {
            status: 302,
            headers: { location: "/metadata-final" },
          })
        : new Response(JSON.stringify({ url: String(url) }));
    },
  });
  assert.deepEqual(
    await redirected.json({
      url: "https://example.test/start",
      redirectPolicy: "discovery",
    }),
    { url: "https://example.test/metadata-final" },
  );
  assert.equal(calls, 2);

  const attack = new HttpClient({
    fetch: async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://attacker.test/steal" },
      }),
  });
  await assert.rejects(
    attack.json({
      url: "https://example.test/discovery",
      redirectPolicy: "discovery",
    }),
    { code: "network_error" },
  );
  await assert.rejects(
    attack.json({
      url: "https://example.test/token",
      redirectPolicy: "oauth",
      method: "POST",
    }),
    { code: "network_error" },
  );

  const timed = new HttpClient({
    timeoutMs: 5,
    fetch: async (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("aborted", "AbortError"));
        });
      }),
  });
  await assert.rejects(
    timed.json({ url: "https://example.test/slow", redirectPolicy: "oauth" }),
    (error) => error.code === "network_error" && error.retryable === true,
  );

  const aborted = new HttpClient({
    fetch: async () => {
      throw new DOMException("aborted", "AbortError");
    },
  });
  await assert.rejects(
    aborted.json({
      url: "https://example.test/aborted",
      redirectPolicy: "authenticated",
    }),
    { code: "network_error" },
  );

  const oversized = new HttpClient({
    responseCeilingBytes: 20,
    fetch: async () => new Response(`"${"x".repeat(30)}"`),
  });
  await assert.rejects(
    oversized.json({
      url: "https://example.test/large",
      redirectPolicy: "authenticated",
    }),
    { code: "network_error" },
  );

  const invalid = new HttpClient({
    fetch: async () => new Response("not-json"),
  });
  await assert.rejects(
    invalid.json({
      url: "https://example.test/invalid",
      redirectPolicy: "authenticated",
    }),
    { code: "rest_error" },
  );

  const scalar = new HttpClient({
    fetch: async () => new Response('"raw scalar"'),
  });
  assert.equal(
    await scalar.json({
      url: "https://example.test/scalar",
      redirectPolicy: "authenticated",
    }),
    "raw scalar",
  );
  const wordpressError = new HttpClient({
    fetch: async () =>
      new Response(restErrorFixture, {
        status: 404,
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    wordpressError.json({
      url: "https://example.test/error",
      redirectPolicy: "authenticated",
    }),
    (error) =>
      error.code === "ability_not_found" &&
      error.remoteCode === "novamira_ability_not_found",
  );

  const diagnostics = [];
  let authorization;
  const authenticated = new HttpClient({
    onDiagnostic: (value) => diagnostics.push(value),
    fetch: async (_url, init) => {
      authorization = init?.headers.authorization;
      return new Response("true");
    },
  });
  assert.equal(
    await authenticated.authenticatedJson(
      {
        url: "https://example.test/api?code=must-not-log",
        expectedOrigin: "https://example.test",
      },
      { getAccessToken: async () => "bearer-must-not-log" },
    ),
    true,
  );
  assert.equal(authorization, "Bearer bearer-must-not-log");
  assert.doesNotMatch(
    JSON.stringify(diagnostics),
    /must-not-log|authorization/i,
  );
  await assert.rejects(
    authenticated.authenticatedJson(
      {
        url: "https://attacker.test/api",
        expectedOrigin: "https://example.test",
      },
      { getAccessToken: async () => "must-not-be-requested" },
    ),
    { code: "server_unsupported" },
  );

  const oauth = new HttpClient({
    fetch: async () =>
      new Response(
        JSON.stringify({
          error: "invalid_client",
          error_description: "secret diagnostic must not be surfaced",
        }),
        { status: 400 },
      ),
  });
  await assert.rejects(
    oauth.json({
      url: "https://example.test/token",
      method: "POST",
      redirectPolicy: "oauth",
      responseKind: "oauth",
    }),
    (error) =>
      error.code === "auth_denied" && error.remoteCode === "invalid_client",
  );
});

test("WordPress errors preserve safe actionable messages and classify semantic validation", async () => {
  const noChange = wordpressError(500, {
    code: "no_change",
    message: "old_string and new_string are identical. No edit needed.",
    data: null,
  });
  assert.equal(noChange.code, "schema_validation_failed");
  assert.equal(noChange.remoteCode, "no_change");
  assert.equal(
    noChange.message,
    "old_string and new_string are identical. No edit needed.",
  );
  assert.equal(noChange.retryable, false);
  assert.deepEqual(noChange.details, { status: 500 });

  const refusal = wordpressError(422, {
    code: "builder_element_refused",
    message:
      "Element hero cannot be updated because its source is locked; unlock it and retry.",
    data: { status: 422 },
  });
  assert.equal(refusal.code, "rest_error");
  assert.equal(refusal.remoteCode, "builder_element_refused");
  assert.equal(
    refusal.message,
    "Element hero cannot be updated because its source is locked; unlock it and retry.",
  );

  const invalidInput = wordpressError(400, {
    code: "ability_invalid_input",
    message:
      'Ability input is invalid. Reason: input["title"] is not of type string.',
    data: { status: 400 },
  });
  assert.equal(invalidInput.code, "schema_validation_failed");
  assert.equal(
    invalidInput.message,
    'Ability input is invalid. Reason: input["title"] is not of type string.',
  );

  const sanitized = wordpressError(400, {
    code: "invalid_input",
    message: `First line\n\u001b[31mSecond line ${"x".repeat(3_000)}`,
    data: { status: 400 },
  });
  assert.doesNotMatch(sanitized.message, /[\n\u001b]/u);
  assert.match(sanitized.message, /^First line \[31mSecond line /u);
  assert.equal([...sanitized.message].length, 2_048);
  assert.match(sanitized.message, /…$/u);

  const redacted = new HttpClient({
    fetch: async () =>
      new Response(
        JSON.stringify({
          code: "ability_invalid_input",
          message: "The submitted value bearer-must-not-log is invalid.",
          data: { status: 400 },
        }),
        { status: 400 },
      ),
  });
  await assert.rejects(
    redacted.authenticatedJson(
      {
        url: "https://example.test/run",
        expectedOrigin: "https://example.test",
      },
      { getAccessToken: async () => "bearer-must-not-log" },
    ),
    (error) =>
      error.code === "schema_validation_failed" &&
      error.message === "The submitted value [REDACTED] is invalid.",
  );
});

test("metadata validation rejects origin attacks and compatibility matrix failures while caching for five minutes", async () => {
  assert.deepEqual(
    validateProtectedResourceMetadata(protectedFixture, "https://example.test")
      .novamira,
    protectedFixture.novamira,
  );
  assert.equal(
    validateProtectedResourceMetadata(
      {
        ...protectedFixture,
        resource:
          "https://example.test/index.php?rest_route=/mcp/novamira-oauth",
      },
      "https://example.test",
    ).resource,
    "https://example.test/index.php?rest_route=/mcp/novamira-oauth",
  );
  assert.equal(
    validateAuthorizationServerMetadata(
      authorizationMetadata(),
      "https://example.test",
    ).token_endpoint,
    "https://example.test/wp-json/novamira/v1/oauth/token",
  );
  assert.throws(
    () =>
      validateAuthorizationServerMetadata(
        {
          ...authorizationMetadata(),
          token_endpoint: "https://attacker.test/token",
        },
        "https://example.test",
      ),
    { code: "server_unsupported" },
  );
  assert.throws(
    () =>
      validateProtectedResourceMetadata(
        {
          ...protectedFixture,
          authorization_servers: ["https://example.test/other"],
        },
        "https://example.test",
      ),
    { code: "server_unsupported" },
  );
  assert.throws(
    () =>
      validateProtectedResourceMetadata(
        {
          ...protectedFixture,
          resource: "https://example.test/wp-json/wrong-resource",
        },
        "https://example.test",
      ),
    {
      code: "server_unsupported",
      details: {
        expectedResources: [
          "https://example.test/wp-json/mcp/novamira-oauth",
          "https://example.test/index.php?rest_route=%2Fmcp%2Fnovamira-oauth",
        ],
        advertisedResource: "https://example.test/wp-json/wrong-resource",
      },
    },
  );

  const supported = protectedFixture.novamira;
  const failures = [
    { ...supported, wordpress_version: "6.8.9" },
    { ...supported, plugin_version: "1.9.9" },
    { ...supported, plugin_version: "1.10.1" },
    { ...supported, plugin_version: "1.10.2" },
    { ...supported, plugin_version: "1.11.0" },
    { ...supported, plugin_version: "1.11.1-beta.1" },
    { ...supported, rest_api_version: 2 },
    { ...supported, rest_api_version: undefined },
    ...REQUIRED_FEATURES.flatMap((feature) => [
      { ...supported, features: { ...supported.features, [feature]: false } },
      {
        ...supported,
        features: Object.fromEntries(
          Object.entries(supported.features).filter(
            ([name]) => name !== feature,
          ),
        ),
      },
    ]),
  ];
  for (const candidate of failures)
    assert.throws(() => assertCompatible(candidate), {
      code: "server_unsupported",
    });
  assert.equal(assertCompatible(supported).rest_api_version, 1);
  assert.equal(
    assertCompatible({ ...supported, plugin_version: "1.12.0" }).plugin_version,
    "1.12.0",
  );
  assert.throws(
    () => assertCompatible({ ...supported, plugin_version: undefined }),
    { code: "server_unsupported" },
  );

  let now = 1_000;
  let requests = 0;
  const metadata = new MetadataClient(
    new HttpClient({
      fetch: async (url) => {
        requests += 1;
        if (String(url).endsWith("oauth-protected-resource"))
          return new Response(JSON.stringify(protectedFixture));
        return new Response(JSON.stringify(authorizationMetadata()));
      },
    }),
    () => now,
  );
  const first = await metadata.protectedResource("https://example.test");
  assert.equal(
    (await metadata.protectedResource("https://example.test")).novamira,
    first.novamira,
  );
  assert.equal(requests, 1);
  now += 5 * 60 * 1000;
  await metadata.protectedResource("https://example.test");
  assert.equal(requests, 2);
  await metadata.authorizationServer("https://example.test", first);
  assert.equal(requests, 3);
});

test("unvalidated metadata probing leaves compatibility checks to the doctor", async () => {
  const incompatibleFixture = {
    ...protectedFixture,
    novamira: { ...protectedFixture.novamira, plugin_version: "1.10.0" },
  };
  const metadata = new MetadataClient(
    new HttpClient({
      fetch: async () => new Response(JSON.stringify(incompatibleFixture)),
    }),
  );

  const probed = await metadata.probeProtectedResourceUnvalidated(
    "https://example.test",
  );
  assert.equal(probed.novamira.plugin_version, "1.10.0");
  await assert.rejects(metadata.protectedResource("https://example.test"), {
    code: "server_unsupported",
  });
});

test("root and subdirectory URLs preserve the WordPress base and encode Ability segments separately", () => {
  assert.equal(
    wellKnownUrl("https://example.test", "oauth-protected-resource"),
    "https://example.test/.well-known/oauth-protected-resource",
  );
  assert.equal(
    wellKnownUrl(
      "https://example.test/wordpress/",
      "oauth-authorization-server",
    ),
    "https://example.test/wordpress/.well-known/oauth-authorization-server",
  );
  assert.equal(
    restUrl("https://example.test/wordpress", [
      "novamira",
      "v1",
      "oauth",
      "token",
    ]),
    "https://example.test/wordpress/wp-json/novamira/v1/oauth/token",
  );
  assert.equal(
    abilityItemUrl(
      "https://example.test/wordpress",
      "vendor/group/action name",
    ),
    "https://example.test/wordpress/wp-json/wp-abilities/v1/abilities/vendor/group/action%20name",
  );
  assert.equal(
    restUrlFromResource(
      "https://example.test/wordpress",
      "https://example.test/wordpress/index.php?rest_route=/mcp/novamira-oauth",
      ["wp-abilities", "v1", "abilities"],
    ),
    "https://example.test/wordpress/index.php?rest_route=%2Fwp-abilities%2Fv1%2Fabilities",
  );
});
