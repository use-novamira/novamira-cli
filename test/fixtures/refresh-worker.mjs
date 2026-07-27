// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { UnixFileSecurity } from "../../dist/config/file-security.js";
import { ProfileLockManager } from "../../dist/config/lock.js";
import { platformPaths } from "../../dist/config/paths.js";
import {
  FileCredentialBackend,
  LockedCredentialStore,
} from "../../dist/auth/credentials.js";
import { TokenLifecycle } from "../../dist/auth/token-lifecycle.js";
import { HttpClient } from "../../dist/rest/http-client.js";

const [root, origin] = process.argv.slice(2);
const security = new UnixFileSecurity();
const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
const locks = new ProfileLockManager(paths.stateDir, security);
const credentials = new LockedCredentialStore(
  locks,
  new FileCredentialBackend(paths.credentialsDir, security),
);
const profile = {
  name: "production",
  siteUrl: origin,
  origin,
  clientId: "client-1",
};
const resource = {
  resource: `${origin}/wp-json/mcp/novamira-oauth`,
  authorization_servers: [origin],
  bearer_methods_supported: ["header"],
  scopes_supported: ["abilities:read", "abilities"],
  novamira: {},
};
const authorization = {
  token_endpoint: `${origin}/token`,
};
const lifecycle = new TokenLifecycle(
  profile,
  locks,
  credentials,
  { invalidateProfile: async () => {} },
  {
    protectedResource: async () => resource,
    authorizationServer: async () => authorization,
  },
  new HttpClient(),
  5_000,
  () => Date.parse("2026-07-21T12:00:00.000Z"),
);

process.stdout.write(`${await lifecycle.getAccessToken()}\n`);
