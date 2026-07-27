// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { TokenLifecycle } from "../dist/auth/token-lifecycle.js";
import {
  FileCredentialBackend,
  LockedCredentialStore,
} from "../dist/auth/credentials.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import { HttpClient } from "../dist/rest/http-client.js";
import { CliError } from "../dist/errors.js";

const now = Date.parse("2026-07-21T12:00:00.000Z");
const profile = {
  name: "production",
  siteUrl: "https://example.test",
  origin: "https://example.test",
  clientId: "client-1",
};
const target = { profileName: profile.name, origin: profile.origin };
const resource = {
  resource: `${profile.origin}/wp-json/mcp/novamira-oauth`,
  authorization_servers: [profile.origin],
  bearer_methods_supported: ["header"],
  scopes_supported: ["abilities:read", "abilities"],
  novamira: {},
};
const authorization = {
  token_endpoint: `${profile.origin}/token`,
  revocation_endpoint: `${profile.origin}/revoke`,
};

class MemoryCredentials {
  record;
  error;
  async read() {
    if (this.error) throw this.error;
    return this.record === undefined ? undefined : structuredClone(this.record);
  }
  async readUnderLock() {
    return this.read();
  }
  async replace(_target, record) {
    this.record = structuredClone(record);
  }
  async replaceUnderLock(target, record) {
    await this.replace(target, record);
  }
  async delete() {
    this.record = undefined;
  }
  async deleteUnderLock() {
    await this.delete();
  }
  diagnostic() {
    return { backend: "file", osBackedEncryption: false };
  }
}

async function setup(
  fetch,
  record = credential("access-1", "refresh-1", 3600),
) {
  const root = await mkdtemp(join(tmpdir(), "novamira-token-"));
  const security = new UnixFileSecurity();
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const locks = new ProfileLockManager(paths.stateDir, security);
  const credentials = new MemoryCredentials();
  credentials.record = record;
  const invalidations = [];
  const lifecycle = new TokenLifecycle(
    profile,
    locks,
    credentials,
    { invalidateProfile: async (...args) => invalidations.push(args) },
    {
      protectedResource: async () => resource,
      authorizationServer: async () => authorization,
    },
    new HttpClient({ fetch }),
    1_000,
    () => now,
  );
  return { root, credentials, invalidations, lifecycle };
}

function credential(accessToken, refreshToken, expiresIn, scope = "abilities") {
  return {
    version: 1,
    accessToken,
    refreshToken,
    scope,
    expiresAt: new Date(now + expiresIn * 1000).toISOString(),
  };
}

function token(scope = "abilities") {
  return Response.json({
    access_token: "access-2",
    refresh_token: "refresh-2",
    token_type: "Bearer",
    expires_in: 3600,
    scope,
  });
}

test("refresh rotates safely, narrows only, fails closed, and gates 401 replay", async () => {
  let refreshRequests = 0;
  let apiRequests = 0;
  let mode = "success";
  const current = await setup(async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname === "/token") {
      refreshRequests += 1;
      const body = new URLSearchParams(init.body);
      assert.equal(body.get("grant_type"), "refresh_token");
      assert.equal(body.get("refresh_token"), "refresh-1");
      assert.equal(
        body.get("scope"),
        mode === "broaden" ? "abilities:read" : "abilities",
      );
      if (mode === "invalid")
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      if (mode === "lost") throw new Error("response lost");
      return token(mode === "narrow" ? "abilities:read" : "abilities");
    }
    apiRequests += 1;
    if (apiRequests === 1)
      return Response.json(
        {
          code: "novamira_invalid_token",
          message: "secret",
          data: { status: 401 },
        },
        { status: 401 },
      );
    return Response.json({ value: true });
  });
  try {
    assert.equal(await current.lifecycle.getAccessToken(), "access-1");
    assert.equal(refreshRequests, 0);

    await current.lifecycle.requireScope("abilities");
    current.credentials.record = credential(
      "access-1",
      "refresh-1",
      3600,
      "abilities:read",
    );
    await assert.rejects(current.lifecycle.requireScope("abilities"), {
      code: "insufficient_scope",
    });
    assert.equal(refreshRequests, 0);

    current.credentials.record = credential("access-1", "refresh-1", 30);
    mode = "narrow";
    await assert.rejects(current.lifecycle.requireScope("abilities"), {
      code: "insufficient_scope",
    });
    assert.equal(current.credentials.record.scope, "abilities:read");

    current.credentials.record = credential("access-1", "refresh-1", 30);
    mode = "narrow";
    assert.equal(await current.lifecycle.getAccessToken(), "access-2");
    assert.equal(current.credentials.record.refreshToken, "refresh-2");
    assert.equal(current.credentials.record.scope, "abilities:read");

    current.credentials.record = credential(
      "access-1",
      "refresh-1",
      -1,
      "abilities:read",
    );
    mode = "broaden";
    await assert.rejects(current.lifecycle.getAccessToken(), {
      code: "auth_expired",
    });
    assert.equal(current.credentials.record, undefined);

    current.credentials.record = credential("access-1", "refresh-1", 3600);
    mode = "success";
    const result = await current.lifecycle.authenticatedJson(
      { url: `${profile.origin}/api`, expectedOrigin: profile.origin },
      { unauthorizedReplay: "known-not-accepted" },
    );
    assert.deepEqual(result, { value: true });
    assert.equal(apiRequests, 2);

    current.credentials.record = credential("access-1", "refresh-1", -1);
    mode = "invalid";
    await assert.rejects(current.lifecycle.getAccessToken(), {
      code: "auth_expired",
      remoteCode: "invalid_grant",
    });
    assert.equal(current.credentials.record, undefined);
    const afterInvalid = refreshRequests;
    await assert.rejects(current.lifecycle.getAccessToken(), {
      code: "auth_required",
    });
    assert.equal(refreshRequests, afterInvalid);

    current.credentials.record = credential("access-1", "refresh-1", -1);
    mode = "lost";
    await assert.rejects(current.lifecycle.getAccessToken(), {
      code: "auth_expired",
    });
    assert.equal(current.credentials.record, undefined);

    current.credentials.record = credential("access-1", "refresh-1", 3600);
    apiRequests = 0;
    const beforeNever = refreshRequests;
    await assert.rejects(
      current.lifecycle.authenticatedJson(
        { url: `${profile.origin}/api`, expectedOrigin: profile.origin },
        { unauthorizedReplay: "never" },
      ),
      { code: "auth_expired" },
    );
    assert.equal(refreshRequests, beforeNever);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("two processes submit one rotating refresh token", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-refresh-race-"));
  const security = new UnixFileSecurity();
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const locks = new ProfileLockManager(paths.stateDir, security);
  const credentials = new LockedCredentialStore(
    locks,
    new FileCredentialBackend(paths.credentialsDir, security),
  );
  let requests = 0;
  const server = createServer(async (request, response) => {
    requests += 1;
    let body = "";
    for await (const chunk of request) body += chunk;
    assert.equal(new URLSearchParams(body).get("refresh_token"), "refresh-1");
    await new Promise((resolve) => setTimeout(resolve, 100));
    response.setHeader("content-type", "application/json");
    response.end(
      JSON.stringify({
        access_token: "access-2",
        refresh_token: "refresh-2",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "abilities:read",
      }),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const origin = `http://127.0.0.1:${String(address.port)}`;
  try {
    await credentials.replace(
      { profileName: "production", origin },
      {
        ...credential("access-1", "refresh-1", -1, "abilities:read"),
      },
    );
    const worker = join(import.meta.dirname, "fixtures", "refresh-worker.mjs");
    const children = [1, 2].map(() =>
      spawn(process.execPath, [worker, root, origin], {
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
    const outputs = await Promise.all(children.map(collectChild));
    assert.deepEqual(outputs, ["access-2", "access-2"]);
    assert.equal(requests, 1);
    assert.equal(
      (await credentials.read({ profileName: "production", origin }))
        .refreshToken,
      "refresh-2",
    );
  } finally {
    server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("status discloses no tokens and logout always deletes local secrets", async () => {
  let revokeFails = false;
  let revokedToken;
  const current = await setup(async (input, init = {}) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/wp-abilities/v1/abilities"))
      return Response.json([]);
    if (url.pathname === "/revoke") {
      revokedToken = new URLSearchParams(init.body).get("token");
      if (revokeFails) throw new Error("offline");
      return Response.json(null);
    }
    throw new Error(`Unexpected request ${url}`);
  });
  try {
    const valid = await current.lifecycle.status();
    assert.deepEqual(valid, {
      site: "production",
      siteUrl: "https://example.test",
      access: "full",
      credentialState: "fresh",
      expiresAt: new Date(now + 3600_000).toISOString(),
      restReachable: true,
    });
    assert.doesNotMatch(JSON.stringify(valid), /access-1|refresh-1/);

    current.credentials.record = credential("access-1", "refresh-1", -1);
    assert.deepEqual(await current.lifecycle.status(), {
      site: "production",
      siteUrl: "https://example.test",
      access: "full",
      credentialState: "expired",
      expiresAt: new Date(now - 1000).toISOString(),
      restReachable: false,
      restError: "auth_expired",
    });
    current.credentials.record = undefined;
    assert.equal((await current.lifecycle.status()).credentialState, "absent");
    current.credentials.error = new CliError("auth_required", "corrupt");
    assert.equal((await current.lifecycle.status()).credentialState, "invalid");
    current.credentials.error = undefined;

    current.credentials.record = credential("access-1", "refresh-1", 3600);
    assert.equal((await current.lifecycle.logout()).remoteRevoked, true);
    assert.equal(revokedToken, "refresh-1");
    assert.equal(current.credentials.record, undefined);
    assert.deepEqual(current.invalidations, [[profile.origin, profile.name]]);

    current.credentials.record = credential("access-1", "refresh-1", 3600);
    revokeFails = true;
    const failed = await current.lifecycle.logout();
    assert.equal(failed.remoteRevoked, false);
    assert.match(failed.warning, /local credentials were removed/);
    assert.equal(current.credentials.record, undefined);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

function collectChild(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(`worker exited ${String(code)}: ${stderr}`));
    });
  });
}
