// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { resolve, sep } from "node:path";
import process from "node:process";
import test from "node:test";
import { pathToFileURL } from "node:url";

const distRoot =
  process.env.NOVAMIRA_ACCEPTANCE_DIST === undefined
    ? new URL("../dist/", import.meta.url)
    : pathToFileURL(`${resolve(process.env.NOVAMIRA_ACCEPTANCE_DIST)}${sep}`);
const { CliError } = await import(new URL("errors.js", distRoot));
const { onlineDoctorDefinitions } = await import(
  new URL("doctor/online.js", distRoot)
);

const profile = {
  name: "production",
  siteUrl: "https://example.test/wordpress",
  origin: "https://example.test",
  clientId: "public-client",
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

const resource = {
  resource: `${profile.siteUrl}/wp-json/mcp/novamira-oauth`,
  authorization_servers: [profile.siteUrl],
  bearer_methods_supported: ["header"],
  scopes_supported: ["abilities:read", "abilities"],
  novamira: compatibility,
};

const authorization = {
  issuer: profile.siteUrl,
  authorization_endpoint: `${profile.siteUrl}/authorize`,
  token_endpoint: `${profile.siteUrl}/token`,
  registration_endpoint: `${profile.siteUrl}/register`,
  revocation_endpoint: `${profile.siteUrl}/revoke`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: ["abilities:read", "abilities"],
};

const abilityNames = [
  "novamira/agent-context",
  "novamira/skill-get",
  "novamira/skill-write",
  "novamira/skill-edit",
  "novamira/skill-delete",
];

function dependencies(overrides = {}) {
  const lifecycle = overrides.lifecycle ?? {
    status: async () => ({
      site: profile.name,
      siteUrl: profile.siteUrl,
      access: "read",
      credentialState: "fresh",
      expiresAt: "2026-07-21T13:00:00.000Z",
      restReachable: true,
    }),
  };
  const abilities = overrides.abilities ?? {
    listAbilities: async () => abilityNames.map((name) => ({ name })),
    describe: async () => ({ name: "novamira/agent-context" }),
    agentContext: async () => ({
      server: compatibility,
      instructions: "Use the site policy.",
      skills: [{ slug: "maintenance" }],
      environment: { locale: "en_US" },
    }),
  };
  return {
    paths: {
      configFile: "/missing/config.json",
      stateDir: "/missing/state",
      cacheDir: "/missing/cache",
      credentialsDir: "/missing/credentials",
    },
    security: {},
    profiles: {
      list: async () => [profile],
      select: async () => profile,
    },
    credentials: {
      diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
      read: async () => ({
        version: 1,
        accessToken: "redacted-test-token",
        refreshToken: "redacted-test-refresh",
        scope: "abilities:read",
        expiresAt: "2026-07-21T13:00:00.000Z",
      }),
    },
    abilityCache: {
      cleanupExpired: async () => ({ removed: 0, remainingBytes: 0 }),
    },
    artifacts: { cleanup: async () => ({ removed: 0, remainingBytes: 0 }) },
    environment: {},
    now: () => Date.parse("2026-07-21T12:00:00.000Z"),
    metadata: {
      inspectProtectedResource: async () => resource,
      authorizationServer: async () => authorization,
    },
    createTokenLifecycle: () => lifecycle,
    createAbilityClient: () => abilities,
    ...overrides.dependencies,
  };
}

async function checkOf(input, id, options = { fix: false }) {
  const definition = onlineDoctorDefinitions(input, options).find(
    (candidate) => candidate.id === id,
  );
  assert.ok(definition);
  return definition.run();
}

test("online doctor keeps stable IDs and passes each complete remote surface", async () => {
  const definitions = onlineDoctorDefinitions(dependencies(), { fix: false });
  assert.deepEqual(
    definitions.map(({ id }) => id),
    [
      "runtime.node",
      "storage.permissions",
      "storage.atomic",
      "credential.backend",
      "profile.valid",
      "oauth.resource_metadata",
      "oauth.server_metadata",
      "server.wordpress_version",
      "server.plugin_version",
      "server.rest_api_contract",
      "server.features",
      "oauth.scope",
      "oauth.token",
      "rest.abilities_list",
      "rest.ability_info",
      "rest.shim",
      "rest.context",
      "rest.skills",
      "site.permission",
    ],
  );
  for (const definition of definitions.slice(5)) {
    const result = await definition.run();
    assert.equal(result.status, "pass", definition.id);
    if (definition.id === "server.plugin_version")
      assert.equal(result.evidence.requiredVersion, "1.11.0");
    assert.doesNotMatch(
      JSON.stringify(result),
      /redacted-test-(token|refresh)/,
    );
  }
});

test("online failures preserve unreachable, unauthorized, scope, missing, stale, and partial distinctions", async () => {
  const unreachable = dependencies({
    dependencies: {
      metadata: {
        inspectProtectedResource: async () => {
          throw new CliError("network_error", "private network detail");
        },
      },
    },
  });
  assert.equal(
    (await checkOf(unreachable, "oauth.resource_metadata")).evidence.category,
    "unreachable",
  );

  const unauthorized = dependencies({
    lifecycle: {
      status: async () => ({
        site: profile.name,
        siteUrl: profile.siteUrl,
        access: "read",
        credentialState: "fresh",
        restReachable: false,
        restError: "auth_required",
      }),
    },
  });
  const unauthorizedToken = await checkOf(unauthorized, "oauth.token");
  assert.equal(unauthorizedToken.evidence.restError, "auth_required");
  assert.equal(unauthorizedToken.evidence.category, "unauthorized");

  const insufficient = dependencies({
    abilities: {
      listAbilities: async () => {
        throw new CliError("insufficient_scope", "remote private detail");
      },
    },
  });
  assert.equal(
    (await checkOf(insufficient, "site.permission")).evidence.category,
    "site_permission_denied",
  );
  assert.equal(
    (await checkOf(insufficient, "rest.abilities_list")).evidence.category,
    "insufficient_scope",
  );

  const missing = dependencies({
    abilities: {
      listAbilities: async () =>
        abilityNames.slice(0, -1).map((name) => ({ name })),
      describe: async () => {
        throw new CliError("ability_not_found", "missing");
      },
      agentContext: async () => {
        throw new CliError("ability_not_found", "missing");
      },
    },
  });
  assert.equal(
    (await checkOf(missing, "rest.context")).evidence.category,
    "missing_surface",
  );
  assert.equal(
    (await checkOf(missing, "rest.skills")).evidence.category,
    "unsupported",
  );

  const stale = dependencies({
    abilities: {
      listAbilities: async () => abilityNames.map((name) => ({ name })),
      describe: async () => ({ name: "novamira/agent-context" }),
      agentContext: async () => {
        throw new CliError(
          "server_unsupported",
          "Authenticated compatibility does not match public metadata.",
        );
      },
    },
  });
  assert.equal(
    (await checkOf(stale, "server.features")).evidence.category,
    "unsupported",
  );
});

test("login repair requires confirmation and never broadens the prior grant", async () => {
  const attempts = [];
  const denied = dependencies({
    dependencies: {
      credentials: {
        diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
        read: async () => undefined,
      },
      confirmLogin: async (_profile, access) => {
        attempts.push(["confirm", access]);
        return false;
      },
      login: async (_profile, access) => attempts.push(["login", access]),
    },
  });
  await checkOf(denied, "oauth.scope", { fix: true });
  assert.deepEqual(attempts, [["confirm", "read"]]);

  attempts.length = 0;
  const preserved = dependencies({
    dependencies: {
      credentials: {
        diagnostic: () => ({ backend: "file", osBackedEncryption: false }),
        read: async () => ({
          version: 1,
          accessToken: "old",
          refreshToken: "old",
          scope: "abilities",
          expiresAt: "2026-07-21T11:00:00.000Z",
        }),
      },
      confirmLogin: async (_profile, access) => {
        attempts.push(["confirm", access]);
        return true;
      },
      login: async (_profile, access) => attempts.push(["login", access]),
    },
  });
  const fixed = await checkOf(preserved, "oauth.token", { fix: true });
  assert.equal(fixed.fixed, true);
  assert.deepEqual(attempts, [
    ["confirm", "full"],
    ["login", "full"],
  ]);
});
