// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile, readdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join, relative, resolve, sep } from "node:path";
import process from "node:process";
import test from "node:test";
import { pathToFileURL } from "node:url";

const distRoot =
  process.env.NOVAMIRA_ACCEPTANCE_DIST === undefined
    ? new URL("../dist/", import.meta.url)
    : pathToFileURL(`${resolve(process.env.NOVAMIRA_ACCEPTANCE_DIST)}${sep}`);
const { AbilityClient } = await import(
  new URL("abilities/client.js", distRoot)
);
const { FileCredentialBackend, LockedCredentialStore } = await import(
  new URL("auth/credentials.js", distRoot)
);
const { LoginService } = await import(new URL("auth/login.js", distRoot));
const { MetadataClient } = await import(new URL("auth/metadata.js", distRoot));
const { TokenLifecycle } = await import(
  new URL("auth/token-lifecycle.js", distRoot)
);
const { AbilityMetadataCache } = await import(
  new URL("cache/ability-cache.js", distRoot)
);
const { UnixFileSecurity } = await import(
  new URL("config/file-security.js", distRoot)
);
const { ProfileLockManager } = await import(
  new URL("config/lock.js", distRoot)
);
const { platformPaths } = await import(new URL("config/paths.js", distRoot));
const { ProfileStore } = await import(new URL("config/profiles.js", distRoot));
const { HttpClient } = await import(new URL("rest/http-client.js", distRoot));
const { getSiteSkill } = await import(new URL("skills/client.js", distRoot));

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

test("REST-only acceptance covers login, rotation, grants, extensions, capability loss, revoke, and re-login", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-security-acceptance-"));
  const siteUrl = "https://example.test/wordpress";
  const edge = new AcceptanceEdge(siteUrl);
  const security = new UnixFileSecurity();
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const locks = new ProfileLockManager(paths.stateDir, security);
  const profiles = new ProfileStore(paths.configFile, locks, security);
  const credentials = new LockedCredentialStore(
    locks,
    new FileCredentialBackend(paths.credentialsDir, security),
  );
  const cache = new AbilityMetadataCache(paths.cacheDir, locks, security);
  const http = new HttpClient({ fetch: edge.fetch });
  const metadata = new MetadataClient(http);
  const callbacks = new AcceptanceCallbacks();
  const login = new LoginService(
    profiles,
    locks,
    credentials,
    cache,
    metadata,
    http,
    callbacks,
    { open: async (url) => callbacks.open(url) },
    { showAuthorizationUrl: (url) => callbacks.open(url) },
  );

  try {
    const readonly = await login.login({
      siteUrl,
      name: "acceptance",
      access: "read",
      noOpen: false,
      timeoutMs: 1_000,
    });
    assert.equal(readonly.scope, "abilities:read");
    let profile = await profiles.get("acceptance");
    let lifecycle = new TokenLifecycle(
      profile,
      locks,
      credentials,
      cache,
      metadata,
      http,
      1_000,
    );
    let abilities = new AbilityClient(
      profile,
      metadata,
      lifecycle,
      cache,
      1_000,
    );
    const discovered = await abilities.discover();
    assert.deepEqual(
      discovered.abilities.map(({ name }) => name),
      [
        "novamira/agent-context",
        "novamira/read-value",
        "novamira/skill-get",
        "novamira/destructive-write",
        "vendor/extension-action",
      ],
    );
    assert.deepEqual((await abilities.run("novamira/read-value", null)).data, {
      value: "old-title",
    });
    assert.equal(
      (await getSiteSkill(abilities, "theme-maintenance")).data.found,
      true,
    );
    await assert.rejects(
      abilities.run("vendor/extension-action", { value: "blocked" }),
      { code: "insufficient_scope" },
    );

    const full = await login.login({
      siteUrl,
      name: "acceptance",
      access: "full",
      noOpen: true,
      timeoutMs: 1_000,
    });
    assert.equal(full.scope, "abilities");
    profile = await profiles.get("acceptance");
    lifecycle = new TokenLifecycle(
      profile,
      locks,
      credentials,
      cache,
      metadata,
      http,
      1_000,
    );
    abilities = new AbilityClient(profile, metadata, lifecycle, cache, 1_000);
    assert.deepEqual(
      (await abilities.run("vendor/extension-action", { value: "allowed" }))
        .data,
      { extension: "allowed" },
    );
    await assert.rejects(
      abilities.run("novamira/destructive-write", { value: "new-title" }),
      { code: "confirmation_required" },
    );
    assert.deepEqual(
      (
        await abilities.run(
          "novamira/destructive-write",
          { value: "new-title" },
          { confirmed: true },
        )
      ).data,
      { updated: true },
    );

    const target = { profileName: profile.name, origin: profile.origin };
    const expired = await credentials.read(target);
    await credentials.replace(target, {
      ...expired,
      expiresAt: new Date(Date.now() - 1_000).toISOString(),
    });
    assert.match(await lifecycle.getAccessToken(), /^access-refresh-/);
    assert.equal(edge.refreshes, 1);

    edge.canManage = false;
    await assert.rejects(abilities.describe("novamira/read-value"), {
      code: "insufficient_scope",
    });
    edge.canManage = true;

    assert.equal((await lifecycle.logout()).remoteRevoked, true);
    assert.equal(await credentials.read(target), undefined);
    assert.equal(edge.revocations, 1);
    await login.login({
      siteUrl,
      name: "acceptance",
      access: "read",
      noOpen: false,
      timeoutMs: 1_000,
    });
    assert.equal((await credentials.read(target)).scope, "abilities:read");
    assert.doesNotMatch(
      await readFile(paths.configFile, "utf8"),
      /access-(?:code|refresh)|refresh-(?:code|refresh)/,
    );

    assert.equal(
      edge.requests.some(({ path }) => path.includes("/mcp/")),
      false,
    );
    for (const request of edge.requests) {
      const authorization = request.headers.get("authorization");
      if (authorization !== null)
        assert.match(request.path, /\/wp-json\/(wp-abilities|novamira)\/v1\//);
      assert.equal(request.headers.get("cookie"), null);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("runtime dependencies and publish roots remain minimal and protocol-free", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  const lock = JSON.parse(
    (await readFile("bun.lock", "utf8")).replace(/,\s*([}\]])/g, "$1"),
  );
  assert.deepEqual(packageJson.dependencies, { commander: "^14.0.0" });
  assert.deepEqual(lock.workspaces[""].dependencies, packageJson.dependencies);
  assert.deepEqual(packageJson.files, [
    "dist",
    "guide-data",
    "skills",
    "README.md",
    "LICENSE",
  ]);
  for (const name of ["preinstall", "install", "postinstall", "prepare"])
    assert.equal(packageJson.scripts[name], undefined);
  assert.equal(packageJson.optionalDependencies, undefined);
  assert.equal(packageJson.bundledDependencies, undefined);

  const sourceFiles = await filesUnder("src");
  const source = (
    await Promise.all(sourceFiles.map((path) => readFile(path, "utf8")))
  ).join("\n");
  const externalImports = [
    ...source.matchAll(/(?:from|import)\s*\(?["']([^"']+)["']/g),
  ]
    .map((match) => match[1])
    .filter((name) => !name.startsWith(".") && !name.startsWith("node:"));
  assert.deepEqual([...new Set(externalImports)], ["commander"]);
  assert.doesNotMatch(
    source,
    /jsonrpc|@modelcontextprotocol|mcp[-_ ]?session/i,
  );
  assert.doesNotMatch(
    source,
    /postinstall|npm\s+(?:install|add)|bun\s+(?:install|add)/i,
  );

  const published = (
    await Promise.all(
      ["dist", "guide-data", "skills"].map((path) => filesUnder(path)),
    )
  ).flat();
  assert.equal(
    published.some((path) =>
      [".node", ".dll", ".dylib", ".so"].includes(extname(path)),
    ),
    false,
  );
  assert.equal(
    published.some((path) => relative(".", path).startsWith("..")),
    false,
  );
});

class AcceptanceCallbacks {
  authorizationUrl;

  async start() {
    return {
      redirectUri: "http://127.0.0.1:43117/callback",
      wait: async (state) => {
        const url = new URL(this.authorizationUrl);
        assert.equal(url.searchParams.get("state"), state);
        return { code: `code-${url.searchParams.get("scope")}` };
      },
      close: async () => undefined,
    };
  }

  open(url) {
    this.authorizationUrl = url;
  }
}

class AcceptanceEdge {
  requests = [];
  canManage = true;
  refreshes = 0;
  revocations = 0;
  issued = 0;
  tokenScopes = new Map();

  constructor(siteUrl) {
    this.siteUrl = siteUrl;
    this.basePath = new URL(siteUrl).pathname.replace(/\/$/, "");
    this.origin = new URL(siteUrl).origin;
  }

  fetch = async (input, init = {}) => {
    const url = new URL(input);
    const headers = new Headers(init.headers);
    const path = url.pathname;
    this.requests.push({ method: init.method ?? "GET", path, headers });
    if (path === `${this.basePath}/.well-known/oauth-protected-resource`)
      return Response.json({
        resource: `${this.siteUrl}/wp-json/mcp/novamira-oauth`,
        authorization_servers: [this.siteUrl],
        bearer_methods_supported: ["header"],
        scopes_supported: ["abilities:read", "abilities", "mcp"],
        novamira: compatibility,
      });
    if (path === `${this.basePath}/.well-known/oauth-authorization-server`)
      return Response.json({
        issuer: this.siteUrl,
        authorization_endpoint: `${this.siteUrl}/wp-admin/admin.php?page=novamira-oauth-authorize`,
        token_endpoint: `${this.siteUrl}/wp-json/novamira/v1/oauth/token`,
        registration_endpoint: `${this.siteUrl}/wp-json/novamira/v1/oauth/register`,
        revocation_endpoint: `${this.siteUrl}/wp-json/novamira/v1/oauth/revoke`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["abilities:read", "abilities", "mcp"],
      });
    if (path.endsWith("/oauth/register")) {
      const body = JSON.parse(init.body);
      return Response.json(
        {
          client_id: "acceptance-client",
          redirect_uris: body.redirect_uris,
          token_endpoint_auth_method: "none",
        },
        { status: 201 },
      );
    }
    if (path.endsWith("/oauth/token")) {
      const body = new URLSearchParams(init.body);
      const refresh = body.get("grant_type") === "refresh_token";
      if (refresh) this.refreshes += 1;
      const scope = refresh
        ? body.get("scope")
        : body.get("code")?.replace("code-", "");
      this.issued += 1;
      const accessToken = `access-${refresh ? "refresh" : "code"}-${this.issued}`;
      this.tokenScopes.set(accessToken, scope);
      return Response.json({
        access_token: accessToken,
        refresh_token: `refresh-${refresh ? "refresh" : "code"}-${this.issued}`,
        token_type: "Bearer",
        expires_in: 3_600,
        scope,
      });
    }
    if (path.endsWith("/oauth/revoke")) {
      this.revocations += 1;
      return Response.json(null);
    }

    const scope = this.scope(headers.get("authorization"));
    if (scope === undefined) return wpError("novamira_invalid_token", 401);
    if (!this.canManage) return wpError("rest_forbidden", 403);
    if (path.endsWith("/wp-abilities/v1/abilities"))
      return Response.json(abilities(), {
        headers: { "x-wp-totalpages": "1" },
      });
    const item = abilities().find(({ name }) => path.endsWith(`/${name}`));
    if (item !== undefined) return Response.json(item);
    if (path.endsWith("/novamira/agent-context/run"))
      return Response.json({
        server: compatibility,
        instructions: "Acceptance guidance",
        skills: [{ slug: "theme-maintenance", description: "Theme guidance" }],
        environment: { wordpress_version: "6.9.2", locale: "en_US" },
      });
    if (path.endsWith("/novamira/read-value/run"))
      return Response.json({ value: "old-title" });
    if (path.endsWith("/novamira/skill-get/run"))
      return Response.json({
        found: true,
        slug: "theme-maintenance",
        content: "# Theme Maintenance",
      });
    if (path.endsWith("/novamira/destructive-write/run")) {
      if (scope !== "abilities") return wpError("rest_oauth_error", 403);
      return Response.json({ updated: true });
    }
    if (path.endsWith("/vendor/extension-action/run")) {
      if (scope !== "abilities") return wpError("rest_oauth_error", 403);
      return Response.json({ extension: JSON.parse(init.body).input.value });
    }
    return wpError("rest_no_route", 404);
  };

  scope(authorization) {
    const token = authorization?.replace(/^Bearer /, "");
    return token === undefined ? undefined : this.tokenScopes.get(token);
  }
}

function abilities() {
  const readonly = {
    show_in_rest: true,
    annotations: { readonly: true, destructive: false, idempotent: true },
  };
  return [
    { name: "novamira/agent-context", meta: readonly },
    { name: "novamira/read-value", meta: readonly },
    { name: "novamira/skill-get", meta: readonly },
    {
      name: "novamira/destructive-write",
      meta: {
        show_in_rest: true,
        annotations: { readonly: false, destructive: true, idempotent: false },
      },
    },
    {
      name: "vendor/extension-action",
      meta: { show_in_rest: true, annotations: { readonly: false } },
    },
  ];
}

function wpError(code, status) {
  return Response.json(
    { code, message: "Acceptance request denied.", data: { status } },
    { status },
  );
}

async function filesUnder(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else if (entry.isFile()) files.push(path);
  }
  return files.sort();
}
