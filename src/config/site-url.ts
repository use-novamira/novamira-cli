// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";

function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

export interface SiteUrlEnvironment {
  readonly NOVAMIRA_ALLOW_INSECURE_HTTP?: string;
}

export interface NormalizedSite {
  readonly siteUrl: string;
  readonly origin: string;
}

export function normalizeSiteUrl(
  input: string,
  environment: SiteUrlEnvironment = process.env,
): NormalizedSite {
  let url: URL;
  try {
    url = new URL(input);
  } catch (cause) {
    throw new CliError("usage_error", "Site URL is invalid.", { cause });
  }

  if (
    url.protocol !== "https:" &&
    !(
      url.protocol === "http:" &&
      (isLoopback(url.hostname) ||
        environment.NOVAMIRA_ALLOW_INSECURE_HTTP === "1")
    )
  ) {
    throw new CliError(
      "usage_error",
      "Site URL must use HTTPS (HTTP is allowed only for loopback development).",
    );
  }
  if (url.username !== "" || url.password !== "") {
    throw new CliError("usage_error", "Site URL must not contain credentials.");
  }
  if (url.search !== "" || url.hash !== "") {
    throw new CliError(
      "usage_error",
      "Site URL must not contain a query string or fragment.",
    );
  }

  const path = url.pathname.replace(/\/{2,}/g, "/").replace(/\/$/, "");
  url.pathname = path === "" ? "/" : path;
  const origin = url.origin;
  const siteUrl = url.pathname === "/" ? origin : `${origin}${url.pathname}`;
  return { siteUrl, origin };
}
