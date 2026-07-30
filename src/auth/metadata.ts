// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  normalizeSiteUrl,
  type SiteUrlEnvironment,
} from "../config/site-url.js";
import { CliError } from "../errors.js";
import type { HttpClient } from "../rest/http-client.js";
import {
  restUrlFromResource,
  sameOriginEndpoint,
  wellKnownUrl,
} from "../rest/urls.js";
import { compareSemver } from "../semver.js";

export const COMPATIBILITY_CACHE_TTL_MS = 5 * 60 * 1000;
export const MINIMUM_NOVAMIRA_VERSION = "1.11.0";
export const REQUIRED_FEATURES = [
  "abilities_bearer_auth",
  "agent_context",
  "rest_skills",
  "generalized_execution_shim",
] as const;

export interface ServerCompatibility {
  readonly plugin_version: string;
  readonly rest_api_version: number;
  readonly wordpress_version: string;
  readonly minimum_wordpress_version: string;
  readonly features: Readonly<Record<string, boolean>>;
}

export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorization_servers: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  readonly scopes_supported: readonly string[];
  readonly novamira: ServerCompatibility;
}

export interface AuthorizationServerMetadata {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly registration_endpoint: string;
  readonly revocation_endpoint: string;
  readonly introspection_endpoint?: string;
  readonly response_types_supported: readonly string[];
  readonly grant_types_supported: readonly string[];
  readonly code_challenge_methods_supported: readonly string[];
  readonly token_endpoint_auth_methods_supported: readonly string[];
  readonly scopes_supported: readonly string[];
}

interface CachedProtectedMetadata {
  readonly expiresAt: number;
  readonly value: ProtectedResourceMetadata;
}

export class MetadataClient {
  private readonly protectedCache = new Map<string, CachedProtectedMetadata>();

  constructor(
    private readonly http: HttpClient,
    private readonly now: () => number = Date.now,
    private readonly environment: SiteUrlEnvironment = process.env,
  ) {}

  async protectedResource(site: string): Promise<ProtectedResourceMetadata> {
    const base = normalizeSiteUrl(site, this.environment).siteUrl;
    const cached = this.protectedCache.get(base);
    if (cached !== undefined && cached.expiresAt > this.now())
      return cached.value;
    const raw = await this.metadataRequest(
      wellKnownUrl(base, "oauth-protected-resource", this.environment),
    );
    const value = validateProtectedResourceMetadata(
      raw,
      base,
      this.environment,
    );
    assertCompatible(value.novamira);
    this.protectedCache.set(base, {
      expiresAt: this.now() + COMPATIBILITY_CACHE_TTL_MS,
      value,
    });
    return value;
  }

  async probeProtectedResourceUnvalidated(
    site: string,
  ): Promise<ProtectedResourceMetadata> {
    const base = normalizeSiteUrl(site, this.environment).siteUrl;
    const raw = await this.metadataRequest(
      wellKnownUrl(base, "oauth-protected-resource", this.environment),
    );
    return validateProtectedResourceMetadata(raw, base, this.environment);
  }

  async authorizationServer(
    site: string,
    protectedMetadata?: ProtectedResourceMetadata,
  ): Promise<AuthorizationServerMetadata> {
    const base = normalizeSiteUrl(site, this.environment).siteUrl;
    const resource = protectedMetadata ?? (await this.protectedResource(base));
    const issuer = resource.authorization_servers[0];
    if (issuer === undefined)
      throw unsupported("Authorization server metadata is missing.");
    const raw = await this.metadataRequest(
      wellKnownUrl(issuer, "oauth-authorization-server", this.environment),
    );
    return validateAuthorizationServerMetadata(raw, base, this.environment);
  }

  clear(site?: string): void {
    if (site === undefined) this.protectedCache.clear();
    else
      this.protectedCache.delete(
        normalizeSiteUrl(site, this.environment).siteUrl,
      );
  }

  private async metadataRequest(url: string): Promise<unknown> {
    try {
      return await this.http.json({ url, redirectPolicy: "discovery" });
    } catch (cause) {
      if (cause instanceof CliError && cause.code === "network_error")
        throw cause;
      throw unsupported("OAuth metadata is malformed or unavailable.", cause);
    }
  }
}

export function validateProtectedResourceMetadata(
  value: unknown,
  site: string,
  environment?: SiteUrlEnvironment,
): ProtectedResourceMetadata {
  const object = record(value, "Protected-resource metadata");
  const { siteUrl: base, origin } = normalizeSiteUrl(site, environment);
  const resource = endpointString(object.resource, origin, "OAuth resource");
  restUrlFromResource(base, resource, ["mcp", "novamira-oauth"], environment);
  const authorizationServers = stringArray(
    object.authorization_servers,
    "authorization_servers",
  );
  let authorizationServer: string;
  try {
    authorizationServer = normalizeSiteUrl(
      authorizationServers[0] ?? "",
      environment,
    ).siteUrl;
  } catch (cause) {
    throw unsupported(
      "Authorization server must match this WordPress site.",
      cause,
    );
  }
  if (authorizationServers.length !== 1 || authorizationServer !== base)
    throw unsupported("Authorization server must match this WordPress site.");
  const bearerMethods = stringArray(
    object.bearer_methods_supported,
    "bearer_methods_supported",
  );
  const scopes = stringArray(object.scopes_supported, "scopes_supported");
  if (!bearerMethods.includes("header"))
    throw unsupported("Bearer header authentication is not advertised.");
  requireScopes(scopes);
  const compatibility = compatibilityObject(object.novamira);
  return {
    resource,
    authorization_servers: authorizationServers,
    bearer_methods_supported: bearerMethods,
    scopes_supported: scopes,
    novamira: compatibility,
  };
}

export function validateAuthorizationServerMetadata(
  value: unknown,
  site: string,
  environment?: SiteUrlEnvironment,
): AuthorizationServerMetadata {
  const object = record(value, "Authorization-server metadata");
  const { siteUrl: base, origin } = normalizeSiteUrl(site, environment);
  const issuer = endpointString(object.issuer, origin, "issuer").replace(
    /\/$/,
    "",
  );
  if (issuer !== base)
    throw unsupported("OAuth issuer does not match this WordPress site.");
  const endpoint = (name: string): string =>
    endpointString(object[name], origin, name);
  const responseTypes = stringArray(
    object.response_types_supported,
    "response_types_supported",
  );
  const grants = stringArray(
    object.grant_types_supported,
    "grant_types_supported",
  );
  const challenges = stringArray(
    object.code_challenge_methods_supported,
    "code_challenge_methods_supported",
  );
  const authMethods = stringArray(
    object.token_endpoint_auth_methods_supported,
    "token_endpoint_auth_methods_supported",
  );
  const scopes = stringArray(object.scopes_supported, "scopes_supported");
  if (!responseTypes.includes("code"))
    throw unsupported("Authorization code response type is not supported.");
  if (
    !grants.includes("authorization_code") ||
    !grants.includes("refresh_token")
  )
    throw unsupported("Required OAuth grants are not supported.");
  if (!challenges.includes("S256"))
    throw unsupported("PKCE S256 is not supported.");
  if (!authMethods.includes("none"))
    throw unsupported("Public OAuth clients are not supported.");
  requireScopes(scopes);
  return {
    issuer,
    authorization_endpoint: endpoint("authorization_endpoint"),
    token_endpoint: endpoint("token_endpoint"),
    registration_endpoint: endpoint("registration_endpoint"),
    revocation_endpoint: endpoint("revocation_endpoint"),
    ...(object.introspection_endpoint === undefined
      ? {}
      : { introspection_endpoint: endpoint("introspection_endpoint") }),
    response_types_supported: responseTypes,
    grant_types_supported: grants,
    code_challenge_methods_supported: challenges,
    token_endpoint_auth_methods_supported: authMethods,
    scopes_supported: scopes,
  };
}

export function assertCompatible(value: unknown): ServerCompatibility {
  const compatibility = compatibilityObject(value);
  assertWordPressCompatible(compatibility);
  assertPluginCompatible(compatibility);
  assertRestContractCompatible(compatibility);
  assertFeaturesCompatible(compatibility);
  return compatibility;
}

export function assertWordPressCompatible(value: ServerCompatibility): void {
  const compatibility = compatibilityObject(value);
  if (compareDotted(compatibility.wordpress_version, "6.9") < 0)
    throw unsupported("WordPress 6.9 or newer is required.");
  if (
    compareDotted(
      compatibility.minimum_wordpress_version,
      compatibility.wordpress_version,
    ) > 0
  )
    throw unsupported("WordPress compatibility metadata is inconsistent.");
}

export function assertPluginCompatible(value: ServerCompatibility): void {
  const compatibility = compatibilityObject(value);
  let comparison: number;
  try {
    comparison = compareSemver(
      compatibility.plugin_version,
      MINIMUM_NOVAMIRA_VERSION,
    );
  } catch (error) {
    throw unsupported("Novamira version metadata is invalid.", error);
  }
  if (comparison < 0)
    throw unsupported(
      `Novamira ${MINIMUM_NOVAMIRA_VERSION} or newer is required.`,
    );
}

export function assertRestContractCompatible(value: ServerCompatibility): void {
  const compatibility = compatibilityObject(value);
  if (compatibility.rest_api_version !== 1)
    throw unsupported("Novamira REST contract 1 is required.");
}

export function assertFeaturesCompatible(value: ServerCompatibility): void {
  const compatibility = compatibilityObject(value);
  for (const feature of REQUIRED_FEATURES) {
    if (compatibility.features[feature] !== true)
      throw unsupported(`Required server feature ${feature} is unavailable.`);
  }
}

export function assertMatchingCompatibility(
  expected: ServerCompatibility,
  actual: unknown,
): ServerCompatibility {
  const compatibility = assertCompatible(actual);
  if (
    expected.plugin_version !== compatibility.plugin_version ||
    expected.rest_api_version !== compatibility.rest_api_version ||
    expected.wordpress_version !== compatibility.wordpress_version ||
    expected.minimum_wordpress_version !==
      compatibility.minimum_wordpress_version ||
    JSON.stringify(sortedFeatures(expected.features)) !==
      JSON.stringify(sortedFeatures(compatibility.features))
  )
    throw unsupported(
      "Authenticated compatibility does not match public metadata.",
    );
  return compatibility;
}

function sortedFeatures(
  features: Readonly<Record<string, boolean>>,
): Record<string, boolean> {
  return Object.fromEntries(
    Object.entries(features).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
}

function compatibilityObject(value: unknown): ServerCompatibility {
  const object = record(value, "Novamira compatibility metadata");
  if (
    typeof object.plugin_version !== "string" ||
    typeof object.rest_api_version !== "number" ||
    !Number.isSafeInteger(object.rest_api_version) ||
    typeof object.wordpress_version !== "string" ||
    typeof object.minimum_wordpress_version !== "string"
  )
    throw unsupported("Novamira compatibility metadata is incomplete.");
  const features = record(object.features, "Novamira feature metadata");
  if (Object.values(features).some((feature) => typeof feature !== "boolean"))
    throw unsupported("Novamira feature metadata is invalid.");
  return {
    plugin_version: object.plugin_version,
    rest_api_version: object.rest_api_version,
    wordpress_version: object.wordpress_version,
    minimum_wordpress_version: object.minimum_wordpress_version,
    features: features as Record<string, boolean>,
  };
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw unsupported(`${label} is missing or invalid.`);
  return value as Record<string, unknown>;
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string"))
    throw unsupported(`${label} is missing or invalid.`);
  return value as string[];
}

function endpointString(value: unknown, origin: string, label: string): string {
  return sameOriginEndpoint(value, origin, label).toString();
}

function requireScopes(scopes: readonly string[]): void {
  if (!scopes.includes("mcp"))
    throw unsupported("The full-access OAuth scope is unavailable.");
}

function compareDotted(left: string, right: string): number {
  const parse = (value: string): number[] => {
    if (!/^\d+(?:\.\d+)*$/.test(value))
      throw unsupported("WordPress version metadata is invalid.");
    return value.split(".").map(Number);
  };
  const leftParts = parse(left);
  const rightParts = parse(right);
  for (
    let index = 0;
    index < Math.max(leftParts.length, rightParts.length);
    index += 1
  ) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

function unsupported(message: string, cause?: unknown): CliError {
  return new CliError("server_unsupported", message, {
    ...(cause === undefined ? {} : { cause }),
  });
}
