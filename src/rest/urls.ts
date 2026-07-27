// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";
import { normalizeSiteUrl } from "../config/site-url.js";

export type WellKnownDocument =
  "oauth-protected-resource" | "oauth-authorization-server";

export function siteUrl(value: string): string {
  return normalizeSiteUrl(value).siteUrl;
}

export function wellKnownUrl(
  site: string,
  document: WellKnownDocument,
): string {
  return appendPath(siteUrl(site), [".well-known", document]);
}

export function restUrl(site: string, segments: readonly string[]): string {
  if (segments.length === 0 || segments.some((segment) => segment === ""))
    throw new CliError("usage_error", "A REST path must not be empty.");
  return appendPath(siteUrl(site), ["wp-json", ...segments]);
}

export function restUrlFromResource(
  site: string,
  resource: string,
  segments: readonly string[],
): string {
  const style = restResourceStyle(site, resource);
  return style === "pretty"
    ? restUrl(site, segments)
    : plainRestUrl(site, segments);
}

export function matchesRestUrl(
  site: string,
  value: string,
  segments: readonly string[],
): boolean {
  let candidate: URL;
  try {
    candidate = new URL(value);
  } catch {
    return false;
  }
  return [restUrl(site, segments), plainRestUrl(site, segments)].some(
    (expected) => equivalentUrl(candidate, new URL(expected)),
  );
}

export function abilityItemUrl(site: string, abilityName: string): string {
  const segments = abilityName.split("/");
  if (segments.length < 2 || segments.some((segment) => segment === ""))
    throw new CliError("usage_error", "Ability name is invalid.");
  return restUrl(site, ["wp-abilities", "v1", "abilities", ...segments]);
}

export function sameOriginEndpoint(
  value: unknown,
  expectedOrigin: string,
  label: string,
): URL {
  if (typeof value !== "string")
    throw new CliError("server_unsupported", `${label} is missing or invalid.`);
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new CliError("server_unsupported", `${label} is not a valid URL.`);
  }
  if (
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.hash !== "" ||
    endpoint.origin !== expectedOrigin ||
    !["https:", "http:"].includes(endpoint.protocol)
  ) {
    throw new CliError(
      "server_unsupported",
      `${label} must be a same-origin HTTP endpoint without credentials or a fragment.`,
    );
  }
  return endpoint;
}

function appendPath(base: string, segments: readonly string[]): string {
  const url = new URL(`${base.replace(/\/$/, "")}/`);
  const encoded = segments.map((segment) => encodeURIComponent(segment));
  url.pathname = `${url.pathname.replace(/\/$/, "")}/${encoded.join("/")}`;
  return url.toString();
}

function plainRestUrl(site: string, segments: readonly string[]): string {
  if (segments.length === 0 || segments.some((segment) => segment === ""))
    throw new CliError("usage_error", "A REST path must not be empty.");
  const url = new URL(`${siteUrl(site).replace(/\/$/, "")}/index.php`);
  url.searchParams.set("rest_route", `/${segments.join("/")}`);
  return url.toString();
}

function restResourceStyle(site: string, resource: string): "pretty" | "plain" {
  const candidate = new URL(resource);
  const route = ["mcp", "novamira-oauth"];
  if (equivalentUrl(candidate, new URL(restUrl(site, route)))) return "pretty";
  if (equivalentUrl(candidate, new URL(plainRestUrl(site, route))))
    return "plain";
  throw new CliError(
    "server_unsupported",
    "OAuth resource does not match this WordPress site.",
    {
      details: {
        expectedResources: [restUrl(site, route), plainRestUrl(site, route)],
        advertisedResource: candidate.toString(),
      },
    },
  );
}

function equivalentUrl(left: URL, right: URL): boolean {
  if (
    left.origin !== right.origin ||
    left.pathname.replace(/\/$/, "") !== right.pathname.replace(/\/$/, "") ||
    left.username !== "" ||
    left.password !== "" ||
    left.hash !== ""
  )
    return false;
  const leftEntries = [...left.searchParams.entries()].sort();
  const rightEntries = [...right.searchParams.entries()].sort();
  return JSON.stringify(leftEntries) === JSON.stringify(rightEntries);
}
