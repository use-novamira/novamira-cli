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
import {
  DEVICE_CODE_GRANT,
  MetadataClient,
  supportsDeviceAuthorization,
  validateAuthorizationServerMetadata,
} from "../dist/auth/metadata.js";
import { validateDeviceAuthorization } from "../dist/auth/device.js";
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

async function harness(harnessOptions = {}) {
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
  const deviceSupported = harnessOptions.deviceSupported !== false;
  const deviceState = {
    pending: 0,
    slowDownOnce: false,
    tokenError: undefined,
    expiresIn: 600,
    interval: 5,
    // Simulated time spent inside a device token request, so a response that
    // arrives after the grant's deadline can be exercised without real waiting.
    tokenDelayMs: 0,
    verificationUri:
      "https://example.test/wp-admin/admin.php?page=novamira-device",
    ...harnessOptions.device,
  };
  let elapsedMs = 0;
  const deviceRequests = [];
  const deviceTokenRequests = [];
  const deviceInstructions = [];
  const remoteHints = [];
  const sleeps = [];
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
        grant_types_supported: [
          "authorization_code",
          "refresh_token",
          ...(deviceSupported ? [DEVICE_CODE_GRANT] : []),
        ],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["mcp"],
        ...(deviceSupported
          ? {
              device_authorization_endpoint:
                "https://example.test/wp-json/novamira/v1/oauth/device",
            }
          : {}),
      });
    if (url.pathname.endsWith("/oauth/register")) {
      registrations += 1;
      const body = JSON.parse(init.body);
      assert.equal(body.client_name, "Novamira CLI");
      assert.equal(body.token_endpoint_auth_method, "none");
      if (body.grant_types.includes(DEVICE_CODE_GRANT)) {
        // A device client never redirects, so RFC 7591 registration carries no
        // redirect URI at all.
        assert.equal(body.redirect_uris, undefined);
        assert.deepEqual(body.grant_types, [
          DEVICE_CODE_GRANT,
          "refresh_token",
        ]);
        return Response.json(
          {
            client_id: `device-client-${String(registrations)}`,
            token_endpoint_auth_method: "none",
            grant_types: body.grant_types,
          },
          { status: 201 },
        );
      }
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
    if (url.pathname.endsWith("/oauth/device")) {
      const body = new URLSearchParams(init.body);
      deviceRequests.push({
        clientId: body.get("client_id"),
        scope: body.get("scope"),
        resource: body.get("resource"),
      });
      return Response.json({
        device_code: `device-code-${String(deviceRequests.length)}`,
        user_code: "WDJB-MJHT",
        verification_uri: deviceState.verificationUri,
        expires_in: deviceState.expiresIn,
        interval: deviceState.interval,
      });
    }
    if (url.pathname.endsWith("/oauth/token")) {
      tokenRequests += 1;
      const body = new URLSearchParams(init.body);
      if (body.get("grant_type") === DEVICE_CODE_GRANT) {
        deviceTokenRequests.push({
          clientId: body.get("client_id"),
          deviceCode: body.get("device_code"),
          resource: body.get("resource"),
        });
        elapsedMs += deviceState.tokenDelayMs;
        if (deviceState.pending > 0) {
          deviceState.pending -= 1;
          return Response.json(
            { error: "authorization_pending" },
            { status: 400 },
          );
        }
        if (deviceState.slowDownOnce) {
          deviceState.slowDownOnce = false;
          return Response.json({ error: "slow_down" }, { status: 400 });
        }
        if (deviceState.tokenError !== undefined)
          return Response.json(
            { error: deviceState.tokenError },
            { status: 400 },
          );
        return Response.json({
          access_token: `access-${String(tokenRequests)}`,
          refresh_token: `refresh-${String(tokenRequests)}`,
          token_type: "Bearer",
          expires_in: 3600,
          scope: "mcp",
        });
      }
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
    showDeviceInstructions: (authorization) => {
      deviceInstructions.push(authorization);
    },
    showRemoteSessionHint: () => {
      remoteHints.push(true);
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
    // The clock advances with the simulated polling sleeps so device deadlines
    // are exercised without real waiting.
    () => Date.parse("2026-07-20T12:00:00.000Z") + elapsedMs,
    harnessOptions.environment ?? {},
    async (ms) => {
      sleeps.push(ms);
      elapsedMs += ms;
    },
  );
  return {
    root,
    profiles,
    credentials,
    callbacks,
    browserUrls,
    shownUrls,
    invalidations,
    deviceRequests,
    deviceTokenRequests,
    deviceInstructions,
    remoteHints,
    sleeps,
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

test("device authorization completes without a local browser or listener", async () => {
  let stderrOutput = "";
  new TerminalLoginInteraction((value) => {
    stderrOutput += value;
  }).showDeviceInstructions({
    deviceCode: "secret-device-code",
    userCode: "WDJB-MJHT",
    verificationUri: "https://example.test/device",
    expiresInSeconds: 600,
    intervalSeconds: 5,
  });
  assert.match(stderrOutput, /https:\/\/example\.test\/device/);
  assert.match(stderrOutput, /WDJB-MJHT/);
  assert.match(stderrOutput, /10 minutes/);
  // The device code authenticates the poll; only the user code is shown.
  assert.ok(!stderrOutput.includes("secret-device-code"));

  let parsed;
  const parse = async (argv) => {
    await createProgram(
      "test",
      commandHandlers({
        authLogin: (url, options) => {
          parsed = { url, options };
        },
      }),
    ).parseAsync(argv, { from: "user" });
  };
  await parse(["auth", "login", "https://example.test", "--device"]);
  assert.equal(parsed.options.device, true);
  await parse(["auth", "login", "https://example.test"]);
  assert.equal(parsed.options.device, false);

  const current = await harness({
    device: { pending: 1, slowDownOnce: true, interval: 5 },
  });
  try {
    const login = await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: false,
      device: true,
      timeoutMs: 300_000,
    });

    // No loopback listener is bound and no browser is launched: nothing has to
    // reach the host running the CLI.
    assert.equal(current.callbacks.starts, 0);
    assert.equal(current.browserUrls.length, 0);
    assert.equal(current.shownUrls.length, 0);

    assert.deepEqual(current.deviceRequests, [
      {
        clientId: "device-client-1",
        scope: "mcp",
        resource: "https://example.test/wp-json/mcp/novamira-oauth",
      },
    ]);
    assert.deepEqual(current.deviceInstructions, [
      {
        deviceCode: "device-code-1",
        userCode: "WDJB-MJHT",
        verificationUri:
          "https://example.test/wp-admin/admin.php?page=novamira-device",
        expiresInSeconds: 600,
        intervalSeconds: 5,
      },
    ]);
    // Every poll carries the device code and the audience, and `slow_down`
    // widens the interval instead of hammering the site.
    assert.equal(current.deviceTokenRequests.length, 3);
    for (const request of current.deviceTokenRequests)
      assert.deepEqual(request, {
        clientId: "device-client-1",
        deviceCode: "device-code-1",
        resource: "https://example.test/wp-json/mcp/novamira-oauth",
      });
    assert.deepEqual(current.sleeps, [5000, 5000, 10_000]);

    assert.equal(login.expiresAt, "2026-07-20T13:00:20.000Z");
    assert.equal(
      (await current.profiles.get("production")).clientId,
      "device-client-1",
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
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("device authorization fails closed on denial, expiry, timeout, and unsupported sites", async () => {
  const denied = await harness({ device: { tokenError: "access_denied" } });
  try {
    await assert.rejects(
      denied.service.login({
        siteUrl: "https://example.test",
        noOpen: true,
        device: true,
        timeoutMs: 300_000,
      }),
      { code: "auth_denied", remoteCode: "access_denied" },
    );
    assert.equal(await denied.profiles.get("example.test"), undefined);
  } finally {
    await rm(denied.root, { recursive: true, force: true });
  }

  const expired = await harness({ device: { tokenError: "expired_token" } });
  try {
    await assert.rejects(
      expired.service.login({
        siteUrl: "https://example.test",
        noOpen: true,
        device: true,
        timeoutMs: 300_000,
      }),
      { code: "auth_denied", remoteCode: "expired_token" },
    );
  } finally {
    await rm(expired.root, { recursive: true, force: true });
  }

  // Polling stops at whichever deadline comes first, and never sleeps past it.
  const impatient = await harness({
    device: { pending: 100, interval: 5, expiresIn: 600 },
  });
  try {
    await assert.rejects(
      impatient.service.login({
        siteUrl: "https://example.test",
        noOpen: true,
        device: true,
        timeoutMs: 12_000,
      }),
      { code: "auth_denied" },
    );
    assert.deepEqual(impatient.sleeps, [5000, 5000]);
  } finally {
    await rm(impatient.root, { recursive: true, force: true });
  }

  const shortLived = await harness({
    device: { pending: 100, interval: 5, expiresIn: 8 },
  });
  try {
    await assert.rejects(
      shortLived.service.login({
        siteUrl: "https://example.test",
        noOpen: true,
        device: true,
        timeoutMs: 300_000,
      }),
      { code: "auth_denied" },
    );
    assert.deepEqual(shortLived.sleeps, [5000]);
  } finally {
    await rm(shortLived.root, { recursive: true, force: true });
  }

  // An older site advertises neither the endpoint nor the grant: --device must
  // fail before registering a client or requesting a code.
  const unsupported = await harness({ deviceSupported: false });
  try {
    await assert.rejects(
      unsupported.service.login({
        siteUrl: "https://example.test",
        noOpen: true,
        device: true,
        timeoutMs: 300_000,
      }),
      { code: "server_unsupported" },
    );
    assert.deepEqual(unsupported.counts(), {
      registrations: 0,
      tokenRequests: 0,
    });
    assert.equal(unsupported.deviceRequests.length, 0);
  } finally {
    await rm(unsupported.root, { recursive: true, force: true });
  }
});

test("the device grant deadline bounds the poll, the request, and the answer", async () => {
  // A sleep that would end exactly on the deadline leaves no time to poll, so
  // the grant ends there rather than making a request it cannot use.
  const exact = await harness({
    device: { pending: 100, interval: 5, expiresIn: 5 },
  });
  try {
    await assert.rejects(
      exact.service.login({
        siteUrl: "https://example.test",
        noOpen: true,
        device: true,
        timeoutMs: 300_000,
      }),
      { code: "auth_denied" },
    );
    assert.deepEqual(exact.sleeps, []);
    assert.equal(exact.deviceTokenRequests.length, 0);
  } finally {
    await rm(exact.root, { recursive: true, force: true });
  }

  // The site approves the code, but the answer only lands after the device code
  // has expired. Credentials past the deadline are discarded, not stored.
  const late = await harness({
    device: { interval: 5, expiresIn: 8, tokenDelayMs: 5000 },
  });
  try {
    await assert.rejects(
      late.service.login({
        siteUrl: "https://example.test",
        name: "production",
        noOpen: true,
        device: true,
        timeoutMs: 300_000,
      }),
      { code: "auth_denied" },
    );
    assert.equal(late.deviceTokenRequests.length, 1);
    assert.equal(await late.profiles.get("production"), undefined);
    assert.equal(
      await late.credentials.read({
        profileName: "production",
        origin: "https://example.test",
      }),
      undefined,
    );
  } finally {
    await rm(late.root, { recursive: true, force: true });
  }
});

test("a client registered for one grant is never reused for the other", async () => {
  const current = await harness();
  try {
    await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: true,
      device: true,
      timeoutMs: 300_000,
    });
    const afterDevice = await current.profiles.get("production");
    assert.equal(afterDevice.clientId, "device-client-1");
    assert.equal(afterDevice.clientGrant, "device_code");

    // The device client has no redirect URI, so the site refuses to authorize it
    // in a browser without redirecting anything back to the loopback listener —
    // the CLI would wait out its timeout. The stored grant mode is what keeps
    // the browser flow from ever offering that client.
    await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: true,
      timeoutMs: 300_000,
    });
    const afterBrowser = await current.profiles.get("production");
    assert.equal(afterBrowser.clientId, "client-2");
    assert.equal(afterBrowser.clientGrant, "authorization_code");

    // Going back reuses neither: each mode keeps registering its own client
    // rather than presenting one the site will reject.
    await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: true,
      device: true,
      timeoutMs: 300_000,
    });
    assert.equal(
      (await current.profiles.get("production")).clientId,
      "device-client-3",
    );

    // Repeating the same mode still reuses the client it just stored, so the
    // grant check narrows reuse rather than disabling it.
    await current.service.login({
      siteUrl: "https://example.test",
      name: "production",
      noOpen: true,
      device: true,
      timeoutMs: 300_000,
    });
    assert.equal(
      (await current.profiles.get("production")).clientId,
      "device-client-3",
    );
    assert.equal(current.counts().registrations, 3);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("device metadata and responses are bound to the site origin", () => {
  const base = {
    issuer: "https://example.test",
    authorization_endpoint: "https://example.test/authorize",
    token_endpoint: "https://example.test/token",
    registration_endpoint: "https://example.test/register",
    revocation_endpoint: "https://example.test/revoke",
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      DEVICE_CODE_GRANT,
    ],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["mcp"],
  };
  assert.equal(
    supportsDeviceAuthorization(
      validateAuthorizationServerMetadata(base, "https://example.test"),
    ),
    false,
  );
  assert.equal(
    supportsDeviceAuthorization(
      validateAuthorizationServerMetadata(
        {
          ...base,
          device_authorization_endpoint: "https://example.test/device",
        },
        "https://example.test",
      ),
    ),
    true,
  );
  // The grant alone is not enough, and neither is a foreign endpoint.
  assert.equal(
    supportsDeviceAuthorization(
      validateAuthorizationServerMetadata(
        {
          ...base,
          grant_types_supported: ["authorization_code", "refresh_token"],
        },
        "https://example.test",
      ),
    ),
    false,
  );
  assert.throws(
    () =>
      validateAuthorizationServerMetadata(
        { ...base, device_authorization_endpoint: "https://evil.test/device" },
        "https://example.test",
      ),
    { code: "server_unsupported" },
  );

  const response = {
    device_code: "device-code",
    user_code: "WDJB-MJHT",
    verification_uri: "https://example.test/device",
    expires_in: 600,
  };
  assert.equal(
    validateDeviceAuthorization(response, "https://example.test")
      .intervalSeconds,
    5,
  );
  // A verification URI off-origin would send the operator's session somewhere
  // the site never vouched for.
  assert.throws(
    () =>
      validateDeviceAuthorization(
        { ...response, verification_uri: "https://evil.test/device" },
        "https://example.test",
      ),
    { code: "server_unsupported" },
  );
  for (const invalid of [
    { ...response, device_code: "" },
    { ...response, user_code: "code with spaces" },
    { ...response, expires_in: 0 },
    { ...response, expires_in: 60 * 60 },
    { ...response, interval: 0 },
    { ...response, interval: 600 },
  ])
    assert.throws(
      () => validateDeviceAuthorization(invalid, "https://example.test"),
      { code: "server_unsupported" },
    );
});

test("a remote shell is told about --device only when the site supports it", async () => {
  const remote = await harness({
    environment: { SSH_CONNECTION: "10.0.0.2 52000 10.0.0.9 22" },
  });
  try {
    await remote.service.login({
      siteUrl: "https://example.test",
      noOpen: true,
      timeoutMs: 1000,
    });
    assert.equal(remote.remoteHints.length, 1);
  } finally {
    await rm(remote.root, { recursive: true, force: true });
  }

  const local = await harness();
  try {
    await local.service.login({
      siteUrl: "https://example.test",
      noOpen: true,
      timeoutMs: 1000,
    });
    assert.equal(local.remoteHints.length, 0);
  } finally {
    await rm(local.root, { recursive: true, force: true });
  }

  const legacy = await harness({
    deviceSupported: false,
    environment: { SSH_TTY: "/dev/pts/3" },
  });
  try {
    await legacy.service.login({
      siteUrl: "https://example.test",
      noOpen: true,
      timeoutMs: 1000,
    });
    assert.equal(legacy.remoteHints.length, 0);
  } finally {
    await rm(legacy.root, { recursive: true, force: true });
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
