// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError, type ErrorCode } from "../errors.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import type { ProfileLockManager } from "../config/lock.js";
import type { SiteProfile } from "../config/profiles.js";
import type { SiteUrlEnvironment } from "../config/site-url.js";
import type {
  AccessTokenProvider,
  HttpClient,
  JsonRequest,
  JsonResponse,
} from "../rest/http-client.js";
import { restUrlFromResource } from "../rest/urls.js";
import type { CredentialRecord, CredentialStore } from "./credentials.js";
import type {
  AuthorizationServerMetadata,
  MetadataClient,
  ProtectedResourceMetadata,
} from "./metadata.js";

export const REFRESH_SAFETY_WINDOW_MS = 60_000;

interface TokenResponse {
  readonly access_token: string;
  readonly refresh_token: string;
  readonly token_type: string;
  readonly expires_in: number;
  readonly scope: string;
}

export interface AuthStatus {
  readonly site: string;
  readonly siteUrl: string;
  readonly credentialState:
    "absent" | "invalid" | "fresh" | "near_expiry" | "expired";
  readonly expiresAt?: string;
  readonly restReachable: boolean | null;
  readonly restError?: ErrorCode;
}

export interface LocalTokenStatus {
  readonly credentialState: "absent" | "fresh" | "near_expiry" | "expired";
  readonly expiresAt?: string;
}

export function localTokenStatus(
  credential: CredentialRecord | undefined,
  now = Date.now(),
): LocalTokenStatus {
  if (credential === undefined) return { credentialState: "absent" };
  const expires = Date.parse(credential.expiresAt);
  return {
    credentialState:
      expires <= now
        ? "expired"
        : expires <= now + REFRESH_SAFETY_WINDOW_MS
          ? "near_expiry"
          : "fresh",
    expiresAt: credential.expiresAt,
  };
}

export interface LogoutResult {
  readonly site: string;
  readonly localCredentialsRemoved: true;
  readonly remoteRevoked: boolean;
  readonly warning?: string;
}

export class TokenLifecycle implements AccessTokenProvider {
  private readonly target: {
    readonly profileName: string;
    readonly origin: string;
  };

  constructor(
    private readonly profile: SiteProfile,
    private readonly locks: ProfileLockManager,
    private readonly credentials: CredentialStore,
    private readonly abilityCache: AbilityMetadataCache,
    private readonly metadata: MetadataClient,
    private readonly http: HttpClient,
    private readonly timeoutMs = 30_000,
    private readonly now: () => number = Date.now,
    private readonly environment: SiteUrlEnvironment = process.env,
  ) {
    this.target = { profileName: profile.name, origin: profile.origin };
  }

  async getAccessToken(): Promise<string> {
    const current = await this.requiredCredential();
    if (!this.needsRefresh(current)) return current.accessToken;
    return (await this.refresh(current.accessToken, false)).accessToken;
  }

  async authenticatedJson<T = unknown>(
    request: Omit<JsonRequest, "redirectPolicy" | "headers"> & {
      readonly headers?: Readonly<Record<string, string>>;
      readonly expectedOrigin: string;
    },
    options: {
      readonly unauthorizedReplay: "known-not-accepted" | "never";
    },
  ): Promise<T> {
    return (await this.authenticatedJsonResponse<T>(request, options)).data;
  }

  async authenticatedJsonResponse<T = unknown>(
    request: Omit<JsonRequest, "redirectPolicy" | "headers"> & {
      readonly headers?: Readonly<Record<string, string>>;
      readonly expectedOrigin: string;
    },
    options: {
      readonly unauthorizedReplay: "known-not-accepted" | "never";
    },
  ): Promise<JsonResponse<T>> {
    let submittedToken: string | undefined;
    const capture: AccessTokenProvider = {
      getAccessToken: async () => {
        submittedToken = await this.getAccessToken();
        return submittedToken;
      },
    };
    try {
      return await this.http.authenticatedJsonResponse<T>(request, capture);
    } catch (error) {
      if (
        options.unauthorizedReplay !== "known-not-accepted" ||
        submittedToken === undefined ||
        !isConfirmedUnauthorized(error)
      )
        throw error;
      const refreshed = await this.refresh(submittedToken, true);
      return this.http.authenticatedJsonResponse<T>(request, {
        getAccessToken: () => Promise.resolve(refreshed.accessToken),
      });
    }
  }

  async status(): Promise<AuthStatus> {
    let credential: CredentialRecord | undefined;
    try {
      credential = await this.credentials.read(this.target);
    } catch (error) {
      if (error instanceof CliError && error.code === "auth_required")
        return this.statusWithoutCredential("invalid");
      throw error;
    }
    if (credential === undefined) return this.statusWithoutCredential("absent");

    const local = localTokenStatus(credential, this.now());
    const credentialState = local.credentialState;
    let restReachable = false;
    let restError: ErrorCode | undefined;
    if (credentialState === "expired") {
      restError = "auth_expired";
    } else {
      try {
        const resource = await this.metadata.protectedResource(
          this.profile.siteUrl,
        );
        const value = await this.http.authenticatedJson(
          {
            url: abilityListUrl(
              this.profile.siteUrl,
              resource.resource,
              this.environment,
            ),
            expectedOrigin: this.profile.origin,
            timeoutMs: this.timeoutMs,
          },
          { getAccessToken: () => Promise.resolve(credential.accessToken) },
        );
        if (!Array.isArray(value))
          throw new CliError(
            "server_unsupported",
            "The WordPress Ability list is unavailable.",
          );
        restReachable = true;
      } catch (error) {
        if (!(error instanceof CliError)) throw error;
        restError = error.code;
      }
    }
    return {
      site: this.profile.name,
      siteUrl: this.profile.siteUrl,
      credentialState,
      expiresAt: credential.expiresAt,
      restReachable,
      ...(restError === undefined ? {} : { restError }),
    };
  }

  async logout(): Promise<LogoutResult> {
    let remoteRevoked = false;
    let warning: string | undefined;
    await this.locks.withLock(this.profile.name, async () => {
      let credential: CredentialRecord | undefined;
      try {
        credential = await this.credentials.readUnderLock(this.target);
      } catch (error) {
        if (!(error instanceof CliError) || error.code !== "auth_required")
          throw error;
        warning =
          "Stored credentials were invalid; local credential data was removed.";
      }
      try {
        if (credential !== undefined) {
          if (this.profile.clientId === undefined) {
            warning =
              "Remote revocation was unavailable because the public client ID is missing.";
          } else {
            const resource = await this.metadata.protectedResource(
              this.profile.siteUrl,
            );
            const authorization = await this.metadata.authorizationServer(
              this.profile.siteUrl,
              resource,
            );
            await this.revoke(authorization, credential.refreshToken);
            remoteRevoked = true;
          }
        }
      } catch {
        warning =
          "Remote revocation was unavailable; local credentials were removed.";
      } finally {
        await this.credentials.deleteUnderLock(this.target);
      }
    });
    await this.abilityCache.invalidateProfile(
      this.profile.origin,
      this.profile.name,
    );
    return {
      site: this.profile.name,
      localCredentialsRemoved: true,
      remoteRevoked,
      ...(warning === undefined ? {} : { warning }),
    };
  }

  private async refresh(
    rejectedAccessToken: string,
    force: boolean,
  ): Promise<CredentialRecord> {
    const resource = await this.metadata.protectedResource(
      this.profile.siteUrl,
    );
    const authorization = await this.metadata.authorizationServer(
      this.profile.siteUrl,
      resource,
    );
    return this.locks.withLock(this.profile.name, async () => {
      const current = await this.requiredCredentialUnderLock();
      if (current.accessToken !== rejectedAccessToken) return current;
      if (!force && !this.needsRefresh(current)) return current;

      try {
        const token = await this.submitRefresh(
          authorization,
          resource,
          current,
        );
        if (!scopeTransitionAllowed(current.scope, token.scope))
          throw invalidRefresh();
        const expiresAt = expiryFrom(token.expires_in, this.now());
        const replacement: CredentialRecord = {
          version: 1,
          accessToken: token.access_token,
          refreshToken: token.refresh_token,
          scope: token.scope,
          expiresAt,
        };
        await this.credentials.replaceUnderLock(this.target, replacement);
        return replacement;
      } catch (cause) {
        // The refresh credential may already be consumed. Removing it prevents any replay.
        await this.credentials
          .deleteUnderLock(this.target)
          .catch(() => undefined);
        throw reauthorizationRequired(cause);
      }
    });
  }

  private async submitRefresh(
    authorization: AuthorizationServerMetadata,
    resource: ProtectedResourceMetadata,
    current: CredentialRecord,
  ): Promise<TokenResponse> {
    if (this.profile.clientId === undefined) throw invalidRefresh();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.profile.clientId,
      refresh_token: current.refreshToken,
      resource: resource.resource,
    });
    const raw = await this.http.json({
      url: authorization.token_endpoint,
      method: "POST",
      redirectPolicy: "oauth",
      responseKind: "oauth",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      timeoutMs: this.timeoutMs,
    });
    return validateTokenResponse(raw, current.scope);
  }

  private async revoke(
    authorization: AuthorizationServerMetadata,
    refreshToken: string,
  ): Promise<void> {
    const body = new URLSearchParams({
      token: refreshToken,
      token_type_hint: "refresh_token",
      client_id: this.profile.clientId ?? "",
    });
    await this.http.json({
      url: authorization.revocation_endpoint,
      method: "POST",
      redirectPolicy: "oauth",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      timeoutMs: this.timeoutMs,
    });
  }

  private async requiredCredential(): Promise<CredentialRecord> {
    return required(await this.credentials.read(this.target));
  }

  private async requiredCredentialUnderLock(): Promise<CredentialRecord> {
    return required(await this.credentials.readUnderLock(this.target));
  }

  private needsRefresh(credential: CredentialRecord): boolean {
    return (
      Date.parse(credential.expiresAt) <= this.now() + REFRESH_SAFETY_WINDOW_MS
    );
  }

  private statusWithoutCredential(state: "absent" | "invalid"): AuthStatus {
    return {
      site: this.profile.name,
      siteUrl: this.profile.siteUrl,
      credentialState: state,
      restReachable: null,
    };
  }
}

function validateTokenResponse(
  raw: unknown,
  currentScope: string,
): TokenResponse {
  if (raw === null || typeof raw !== "object") throw invalidRefresh();
  const token = raw as Partial<TokenResponse>;
  if (
    typeof token.access_token !== "string" ||
    token.access_token === "" ||
    typeof token.refresh_token !== "string" ||
    token.refresh_token === "" ||
    typeof token.token_type !== "string" ||
    token.token_type.toLowerCase() !== "bearer" ||
    typeof token.expires_in !== "number" ||
    !Number.isSafeInteger(token.expires_in) ||
    token.expires_in <= 0 ||
    (token.scope !== undefined && typeof token.scope !== "string")
  )
    throw invalidRefresh();
  return { ...(token as TokenResponse), scope: token.scope ?? currentScope };
}

function expiryFrom(expiresIn: number, now: number): string {
  const expiry = now + expiresIn * 1000;
  if (!Number.isSafeInteger(expiry) || expiry > 8_640_000_000_000_000)
    throw invalidRefresh();
  return new Date(expiry).toISOString();
}

function required(value: CredentialRecord | undefined): CredentialRecord {
  if (value === undefined)
    throw new CliError(
      "auth_required",
      "Authorize this site with novamira auth login before continuing.",
    );
  return value;
}

function invalidRefresh(): CliError {
  return new CliError("auth_expired", "The OAuth refresh response is invalid.");
}

function reauthorizationRequired(cause: unknown): CliError {
  return new CliError(
    "auth_expired",
    "Authorization can no longer be refreshed; run novamira auth login again.",
    {
      cause,
      ...(cause instanceof CliError && cause.remoteCode !== undefined
        ? { remoteCode: cause.remoteCode }
        : {}),
    },
  );
}

function scopeTransitionAllowed(previous: string, next: string): boolean {
  const fullAccessScopes = ["mcp", "abilities", "abilities:read"];
  return fullAccessScopes.includes(previous) && fullAccessScopes.includes(next);
}

function isConfirmedUnauthorized(error: unknown): boolean {
  return (
    error instanceof CliError &&
    (error.code === "auth_required" || error.code === "auth_expired") &&
    error.details?.status === 401
  );
}

function abilityListUrl(
  siteUrl: string,
  resource: string,
  environment?: SiteUrlEnvironment,
): string {
  const url = new URL(
    restUrlFromResource(
      siteUrl,
      resource,
      ["wp-abilities", "v1", "abilities"],
      environment,
    ),
  );
  url.searchParams.set("per_page", "1");
  url.searchParams.set("page", "1");
  return url.toString();
}
