// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";
import type { SiteUrlEnvironment } from "../config/site-url.js";
import {
  assertMatchingCompatibility,
  type ServerCompatibility,
} from "../auth/metadata.js";
import type { HttpClient } from "./http-client.js";
import { restUrlFromResource } from "./urls.js";

export interface LoginSurface {
  readonly abilities: readonly unknown[];
  readonly context: Readonly<Record<string, unknown>>;
}

export async function verifyLoginSurface(
  http: HttpClient,
  siteUrl: string,
  origin: string,
  accessToken: string,
  expected: ServerCompatibility,
  resource: string,
  environment?: SiteUrlEnvironment,
): Promise<LoginSurface> {
  const tokens = { getAccessToken: () => Promise.resolve(accessToken) };
  const listUrl = new URL(
    restUrlFromResource(
      siteUrl,
      resource,
      ["wp-abilities", "v1", "abilities"],
      environment,
    ),
  );
  listUrl.searchParams.set("per_page", "1");
  listUrl.searchParams.set("page", "1");
  const abilities = await http.authenticatedJson(
    { url: listUrl, expectedOrigin: origin },
    tokens,
  );
  if (!Array.isArray(abilities))
    throw unsupported("The WordPress Ability list is unavailable.");

  const context = await http.authenticatedJson(
    {
      url: restUrlFromResource(
        siteUrl,
        resource,
        ["novamira", "v1", "abilities", "novamira", "agent-context", "run"],
        environment,
      ),
      expectedOrigin: origin,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: null }),
    },
    tokens,
  );
  if (context === null || typeof context !== "object" || Array.isArray(context))
    throw unsupported("The Novamira agent context is unavailable.");
  const server = (context as Record<string, unknown>).server;
  assertMatchingCompatibility(expected, server);
  return { abilities, context: context as Record<string, unknown> };
}

function unsupported(message: string): CliError {
  return new CliError("server_unsupported", message);
}
