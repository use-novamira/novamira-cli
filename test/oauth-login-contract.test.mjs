// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  browserCommand,
  LoginService,
  TerminalLoginInteraction,
} from "../dist/auth/login.js";
import {
  LoopbackCallbackFactory,
  validateCallbackUrl,
} from "../dist/auth/loopback.js";
import { MetadataClient } from "../dist/auth/metadata.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import { ProfileStore } from "../dist/config/profiles.js";
import { createProgram } from "../dist/cli/program.js";
import { HttpClient } from "../dist/rest/http-client.js";

function commandHandlers(overrides = {}) {
  const noop = () => undefined;
  return {
    version: noop,
    authLogin: noop,
    authStatus: noop,
    authLogout: noop,
    sitesList: noop,
    sitesRemove: noop,
    discover: noop,
    describe: noop,
    run: noop,
    skillGet: noop,
    upload: noop,
    guideList: noop,
    guideGet: noop,
    update: noop,
    doctor: noop,
    ...overrides,
  };
}

const compatibility = {
  plugin_version: "1.11.1",
  rest_api_version: 1,
  wordpress_version: "6.9.2",
  minimum_wordpress_version: "6.9",
  features: {
    abilities_bearer_auth: true,
    agent_context: true,
    rest_skills: true,
    generalized_execution_shim: true,
  },
};

class MemoryCredentials {
  records = new Map();
  key(target) {
    return `${target.origin}\0${target.profileName}`;
  }
  async read(target) {
    return this.records.get(this.key(target));
  }
  async readUnderLock(target) {
    return this.read(target);
  }
  async replace(target, record) {
    this.records.set(this.key(target), structuredClone(record));
  }
  async replaceUnderLock(target, record) {
    await this.replace(target, record);
  }
  async delete(target) {
    this.records.delete(this.key(target));
  }
  async deleteUnderLock(target) {
    await this.delete(target);
  }
  diagnostic() {
    return { backend: "file", osBackedEncryption: false };
  }
}

class CallbackHarness {
  starts = 0;
  closes = 0;
  authorizationUrls = [];
  callbackError;
  async start() {
    this.starts += 1;
    const redirectUri = `http://127.0.0.1:${String(41000 + this.starts)}/callback`;
    return {
      redirectUri,
      wait: async (state) => {
        if (this.callbackError !== undefined) {
          const error = this.callbackError;
          this.callbackError = undefined;
          return { error };
        }
        const authorization = new URL(this.authorizationUrls.at(-1));
        assert.equal(authorization.searchParams.get("state"), state);
        return { code: `code-${authorization.searchParams.get("scope")}` };
      },
      close: async () => {
        this.closes += 1;
      },
    };
  }
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "novamira-login-"));
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const security = new UnixFileSecurity();
  const locks = new ProfileLockManager(paths.stateDir, security);
  const profiles = new ProfileStore(paths.configFile, locks, security);
  const credentials = new MemoryCredentials();
  const callbacks = new CallbackHarness();
  const invalidations = [];
  const cache = {
    invalidateProfile: async (origin, name) => {
      invalidations.push({ origin, name });
    },
  };
  const browserUrls = [];
  const shownUrls = [];
  let registrations = 0;
  let tokenRequests = 0;
  let invalidClientOnce = false;
  let narrowScopeOnce = false;
  const fetch = async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/.well-known/oauth-protected-resource"))
      return Response.json({
        resource: "https://example.test/wp-json/mcp/novamira-oauth",
        authorization_servers: ["https://example.test"],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp"],
        novamira: compatibility,
      });
    if (url.pathname.endsWith("/.well-known/oauth-authorization-server"))
      return Response.json({
        issuer: "https://example.test",
        authorization_endpoint:
          "https://example.test/wp-admin/admin.php?page=novamira-oauth-authorize",
        token_endpoint: "https://example.test/wp-json/novamira/v1/oauth/token",
        registration_endpoint:
          "https://example.test/wp-json/novamira/v1/oauth/register",
        revocation_endpoint:
          "https://example.test/wp-json/novamira/v1/oauth/revoke",
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["mcp"],
      });
    if (url.pathname.endsWith("/oauth/register")) {
      registrations += 1;
      const body = JSON.parse(init.body);
      assert.equal(body.client_name, "Novamira CLI");
      assert.deepEqual(body.redirect_uris, [body.redirect_uris[0]]);
      assert.match(
        body.redirect_uris[0],
        /^http:\/\/127\.0\.0\.1:\d+\/callback$/,
      );
      return Response.json(
        {
          client_id: `client-${String(registrations)}`,
          redirect_uris: body.redirect_uris,
          token_endpoint_auth_method: "none",
        },
        { status: 201 },
      );
    }
    if (url.pathname.endsWith("/oauth/token")) {
      tokenRequests += 1;
      const body = new URLSearchParams(init.body);
      if (invalidClientOnce) {
        invalidClientOnce = false;
        return Response.json({ error: "invalid_client" }, { status: 400 });
      }
      const authorization = new URL(callbacks.authorizationUrls.at(-1));
      assert.equal(
        body.get("redirect_uri"),
        authorization.searchParams.get("redirect_uri"),
      );
      assert.equal(
        body.get("resource"),
        "https://example.test/wp-json/mcp/novamira-oauth",
      );
      assert.equal(
        createHash("sha256")
          .update(body.get("code_verifier"))
          .digest("base64url"),
        authorization.searchParams.get("code_challenge"),
      );
      const requested = body.get("code")?.replace("code-", "");
      const scope = narrowScopeOnce ? "abilities:read" : requested;
      narrowScopeOnce = false;
      return Response.json({
        access_token: `access-${String(tokenRequests)}`,
        refresh_token: `refresh-${String(tokenRequests)}`,
        token_type: "Bearer",
        expires_in: 3600,
        scope,
      });
    }
    assert.match(init.headers.authorization, /^Bearer access-/);
    if (url.pathname.endsWith("/wp-abilities/v1/abilities"))
      return Response.json([{ name: "novamira/agent-context" }]);
    if (url.pathname.endsWith("/novamira/agent-context/run"))
      return Response.json({
        server: compatibility,
        instructions: "test",
        skills: [],
        environment: {},
      });
    throw new Error(`Unexpected request ${url}`);
  };
  const http = new HttpClient({ fetch });
  const interaction = {
    showAuthorizationUrl: (url) => {
      shownUrls.push(url);
      callbacks.authorizationUrls.push(url);
    },
  };
  const browser = {
    open: async (url) => {
      browserUrls.push(url);
      callbacks.authorizationUrls.push(url);
    },
  };
  const service = new LoginService(
    profiles,
    locks,
    credentials,
    cache,
    new MetadataClient(http),
    http,
    callbacks,
    browser,
    interaction,
    () => Date.parse("2026-07-20T12:00:00.000Z"),
  );
  return {
    root,
    profiles,
    credentials,
    callbacks,
    browserUrls,
    shownUrls,
    invalidations,
    service,
    counts: () => ({ registrations, tokenRequests }),
    failUnknownClient: () => {
      invalidClientOnce = true;
    },
    narrowScope: () => {
      narrowScopeOnce = true;
    },
  };
}

test("login performs PKCE DCR, reuses and repairs clients, verifies surfaces, and persists full access", async () => {
  let stderrOutput = "";
  new TerminalLoginInteraction((value) => {
    stderrOutput += value;
  }).showAuthorizationUrl("https://example.test/authorize?state=temporary");
  assert.match(stderrOutput, /authorize\?state=temporary/);

  let parsed;
  await createProgram(
    "test",
    commandHandlers({
      authLogin: (url, options) => {
        parsed = { url, options };
      },
    }),
  ).parseAsync(
    [
      "auth",
      "login",
      "https://example.test",
      "--name",
      "production",
      "--no-open",
    ],
    { from: "user" },
  );
  assert.equal(parsed.url, "https://example.test");
  assert.equal(parsed.options.name, "production");
  assert.equal(parsed.options.open, false);
  assert.equal(parsed.options.timeout, 300_000);

  await createProgram(
    "test",
    commandHandlers({
      authLogin: (url, options) => {
        parsed = { url, options };
      },
    }),
  ).parseAsync(
    ["--timeout", "45000", "auth", "login", "https://example.test"],
    { from: "user" },
  );
  assert.equal(parsed.options.timeout, 45_000);

  const authCommand = createProgram("test", commandHandlers()).commands.find(
    (command) => command.name() === "auth",
  );
  const loginCommand = authCommand?.commands.find(
    (command) => command.name() === "login",
  );
  assert.equal(
    loginCommand?.options.some((option) => option.long === "--manual"),
    false,
  );

  const current = await harness();
  try {
    const login = await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: false,
      timeoutMs: 1000,
    });
    assert.equal(login.expiresAt, "2026-07-20T13:00:00.000Z");
    assert.deepEqual(current.counts(), { registrations: 1, tokenRequests: 1 });
    assert.equal(current.browserUrls.length, 1);
    const authorization = new URL(current.browserUrls[0]);
    assert.equal(authorization.searchParams.get("scope"), "mcp");
    assert.equal(
      authorization.searchParams.get("code_challenge_method"),
      "S256",
    );
    assert.ok(authorization.searchParams.get("state").length >= 43);
    assert.equal(
      (await current.profiles.get("production")).clientId,
      "client-1",
    );
    assert.equal(
      (
        await current.credentials.read({
          profileName: "production",
          origin: "https://example.test",
        })
      ).scope,
      "mcp",
    );

    await current.service.login({
      siteUrl: "https://example.test/",
      name: "production",
      noOpen: true,
      timeoutMs: 1000,
    });
    assert.deepEqual(current.counts(), { registrations: 1, tokenRequests: 2 });
    assert.equal(current.shownUrls.length, 1);

    current.failUnknownClient();
    await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: true,
      timeoutMs: 1000,
    });
    assert.deepEqual(current.counts(), { registrations: 2, tokenRequests: 4 });
    assert.equal(
      (await current.profiles.get("production")).clientId,
      "client-2",
    );
    assert.equal(current.browserUrls.length, 1);
    const repaired = current.shownUrls.slice(-2).map((value) => new URL(value));
    assert.notEqual(
      repaired[0].searchParams.get("state"),
      repaired[1].searchParams.get("state"),
    );
    assert.notEqual(
      repaired[0].searchParams.get("code_challenge"),
      repaired[1].searchParams.get("code_challenge"),
    );
    assert.equal(current.callbacks.starts, current.callbacks.closes);
    assert.ok(current.invalidations.length >= 3);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("login fails closed on denial, scope substitution, invalid callbacks, timeout, and unsupported preflight", async () => {
  const current = await harness();
  try {
    await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: true,
      timeoutMs: 1000,
    });
    const before = await current.credentials.read({
      profileName: "production",
      origin: "https://example.test",
    });
    current.narrowScope();
    await assert.rejects(
      current.service.login({
        siteUrl: "https://example.test",
        name: "production",
        noOpen: true,
        timeoutMs: 1000,
      }),
      { code: "auth_denied" },
    );
    assert.deepEqual(
      await current.credentials.read({
        profileName: "production",
        origin: "https://example.test",
      }),
      before,
    );
    current.callbacks.callbackError = "access_denied";
    await assert.rejects(
      current.service.login({
        siteUrl: "https://example.test",
        name: "production",
        noOpen: true,
        timeoutMs: 1000,
      }),
      { code: "auth_denied", remoteCode: "access_denied" },
    );

    const redirect = "http://127.0.0.1:45678/callback";
    assert.throws(
      () =>
        validateCallbackUrl(
          `${redirect}?code=x&state=wrong`,
          redirect,
          "right",
        ),
      { code: "auth_denied" },
    );
    assert.throws(
      () =>
        validateCallbackUrl(
          "http://127.0.0.1:45678/other?code=x&state=right",
          redirect,
          "right",
        ),
      { code: "auth_denied" },
    );
    assert.throws(
      () =>
        validateCallbackUrl(
          `${redirect}?code=x&state=right&state=right`,
          redirect,
          "right",
        ),
      { code: "auth_denied" },
    );
    const loopback = await new LoopbackCallbackFactory().start();
    await assert.rejects(loopback.wait("state", 5), { code: "auth_denied" });
    await loopback.close();

    let sideEffects = 0;
    const unsupported = new LoginService(
      current.profiles,
      new ProfileLockManager(
        platformPaths({ NOVAMIRA_HOME: current.root }, "linux", current.root)
          .stateDir,
        new UnixFileSecurity(),
      ),
      current.credentials,
      { invalidateProfile: async () => {} },
      {
        protectedResource: async () => {
          throw Object.assign(new Error(), { code: "server_unsupported" });
        },
      },
      {},
      {
        start: async () => {
          sideEffects += 1;
        },
      },
      {
        open: async () => {
          sideEffects += 1;
        },
      },
      {
        showAuthorizationUrl: () => {
          sideEffects += 1;
        },
      },
    );
    await assert.rejects(
      unsupported.login({
        siteUrl: "https://example.test",
        noOpen: false,
        timeoutMs: 1000,
      }),
      { code: "server_unsupported" },
    );
    assert.equal(sideEffects, 0);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("the browser command never puts the authorization URL in executable text", () => {
  const url =
    "https://example.test/oauth/authorize?state=abc';Remove-Item%20C:%5C&scope=x";
  assert.deepEqual(browserCommand(url, "darwin"), {
    file: "open",
    args: [url],
    environment: {},
  });
  assert.deepEqual(browserCommand(url, "linux"), {
    file: "xdg-open",
    args: [url],
    environment: {},
  });
  const windows = browserCommand(url, "win32");
  assert.equal(windows.file, "powershell.exe");
  // $args never binds under -Command, and the URL is remote metadata, so it is
  // read from the environment rather than interpolated into the script.
  assert.deepEqual(windows.args, [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    "Start-Process -FilePath $env:NOVAMIRA_BROWSER_URL",
  ]);
  assert.deepEqual(windows.environment, { NOVAMIRA_BROWSER_URL: url });
  assert.ok(!windows.args.some((argument) => argument.includes(url)));
});
