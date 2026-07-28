// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { stderr } from "node:process";
import { CliError } from "../errors.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import type { ProfileLockManager } from "../config/lock.js";
import {
  validateProfileName,
  type ProfileStore,
  type SiteProfile,
} from "../config/profiles.js";
import { normalizeSiteUrl } from "../config/site-url.js";
import type { CredentialRecord, CredentialStore } from "./credentials.js";
import type {
  AuthorizationServerMetadata,
  MetadataClient,
  ProtectedResourceMetadata,
} from "./metadata.js";
import { createPkce } from "./pkce.js";
import { LoopbackCallbackFactory, type CallbackFactory } from "./loopback.js";
import type { HttpClient } from "../rest/http-client.js";
import { verifyLoginSurface } from "../rest/login-verification.js";

export type LoginAccess = "read" | "full";

export interface LoginOptions {
  readonly siteUrl: string;
  readonly name?: string;
  readonly access: LoginAccess;
  readonly noOpen: boolean;
  readonly timeoutMs: number;
}

export interface LoginResult {
  readonly profile: SiteProfile;
  readonly scope: "abilities:read" | "abilities";
  readonly expiresAt: string;
}

export interface BrowserLauncher {
  open(url: string): Promise<void>;
}

export interface LoginInteraction {
  showAuthorizationUrl(url: string): void;
}

interface RegistrationResponse {
  readonly client_id: string;
  readonly redirect_uris: readonly string[];
  readonly token_endpoint_auth_method: string;
}

interface TokenResponse {
  readonly access_token: string;
  readonly refresh_token: string;
  readonly token_type: string;
  readonly expires_in: number;
  readonly scope?: string;
}

export class LoginService {
  constructor(
    private readonly profiles: ProfileStore,
    private readonly locks: ProfileLockManager,
    private readonly credentials: CredentialStore,
    private readonly abilityCache: AbilityMetadataCache,
    private readonly metadata: MetadataClient,
    private readonly http: HttpClient,
    private readonly callbacks: CallbackFactory = new LoopbackCallbackFactory(),
    private readonly browser: BrowserLauncher = new SystemBrowserLauncher(),
    private readonly interaction: LoginInteraction = new TerminalLoginInteraction(),
    private readonly now: () => number = Date.now,
  ) {}

  async login(options: LoginOptions): Promise<LoginResult> {
    if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0)
      throw new CliError("usage_error", "Login timeout must be positive.");
    const { siteUrl: normalizedSite, origin } = normalizeSiteUrl(
      options.siteUrl,
    );
    const profileName = validateProfileName(
      options.name ?? defaultProfileName(normalizedSite),
    );
    const existing = await this.profiles.get(profileName);

    // This public gate deliberately precedes callback binding, DCR, browser launch, or prompting.
    const protectedMetadata =
      await this.metadata.protectedResource(normalizedSite);
    const authorization = await this.metadata.authorizationServer(
      normalizedSite,
      protectedMetadata,
    );
    const requestedScope =
      options.access === "full" ? "abilities" : "abilities:read";
    let clientId =
      existing?.siteUrl === normalizedSite && validClientId(existing.clientId)
        ? existing.clientId
        : undefined;
    let retriedUnknownClient = false;

    for (;;) {
      const callback = await this.callbacks.start();
      const reusedClient = clientId !== undefined;
      try {
        clientId ??= await this.registerClient(
          authorization,
          callback.redirectUri,
        );
        const pkce = createPkce();
        const authorizationUrl = buildAuthorizationUrl({
          metadata: authorization,
          resource: protectedMetadata.resource,
          clientId,
          redirectUri: callback.redirectUri,
          scope: requestedScope,
          state: pkce.state,
          challenge: pkce.challenge,
        });
        if (options.noOpen)
          this.interaction.showAuthorizationUrl(authorizationUrl);
        if (!options.noOpen) await this.browser.open(authorizationUrl);

        const result = await callback.wait(pkce.state, options.timeoutMs);
        if (result.error !== undefined) {
          if (
            result.error === "invalid_client" &&
            reusedClient &&
            !retriedUnknownClient
          ) {
            clientId = undefined;
            retriedUnknownClient = true;
            continue;
          }
          throw callbackError(result.error);
        }
        if (result.code === undefined)
          throw new CliError("auth_denied", "Authorization returned no code.");

        let token: TokenResponse;
        try {
          token = await this.exchangeCode(
            authorization,
            protectedMetadata,
            clientId,
            callback.redirectUri,
            result.code,
            pkce.verifier,
          );
        } catch (error) {
          if (
            error instanceof CliError &&
            error.remoteCode === "invalid_client" &&
            reusedClient &&
            !retriedUnknownClient
          ) {
            clientId = undefined;
            retriedUnknownClient = true;
            continue;
          }
          throw error;
        }
        const grantedScope = token.scope ?? requestedScope;
        if (grantedScope !== requestedScope)
          throw new CliError(
            "auth_denied",
            "The authorization server returned a different scope than requested.",
          );
        const expiry = this.now() + token.expires_in * 1000;
        if (!Number.isSafeInteger(expiry) || expiry > 8_640_000_000_000_000)
          throw invalidToken();
        const expiresAt = new Date(expiry).toISOString();
        await verifyLoginSurface(
          this.http,
          normalizedSite,
          origin,
          token.access_token,
          protectedMetadata.novamira,
          protectedMetadata.resource,
        );
        const credential: CredentialRecord = {
          version: 1,
          accessToken: token.access_token,
          refreshToken: token.refresh_token,
          scope: grantedScope,
          expiresAt,
        };
        const profile = await this.commitLogin(
          profileName,
          normalizedSite,
          origin,
          clientId,
          protectedMetadata,
          credential,
        );
        return { profile, scope: requestedScope, expiresAt };
      } finally {
        await callback.close();
      }
    }
  }

  private async registerClient(
    metadata: AuthorizationServerMetadata,
    redirectUri: string,
  ): Promise<string> {
    const raw = await this.http.json({
      url: metadata.registration_endpoint,
      method: "POST",
      redirectPolicy: "oauth",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Novamira CLI",
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    });
    if (raw === null || typeof raw !== "object") throw invalidRegistration();
    const response = raw as Partial<RegistrationResponse>;
    if (
      !validClientId(response.client_id) ||
      response.token_endpoint_auth_method !== "none" ||
      !Array.isArray(response.redirect_uris) ||
      response.redirect_uris.length !== 1 ||
      response.redirect_uris[0] !== redirectUri
    )
      throw invalidRegistration();
    return response.client_id;
  }

  private async exchangeCode(
    metadata: AuthorizationServerMetadata,
    resource: ProtectedResourceMetadata,
    clientId: string,
    redirectUri: string,
    code: string,
    verifier: string,
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code,
      code_verifier: verifier,
      resource: resource.resource,
    });
    const raw = await this.http.json({
      url: metadata.token_endpoint,
      method: "POST",
      redirectPolicy: "oauth",
      responseKind: "oauth",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (raw === null || typeof raw !== "object") throw invalidToken();
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
      throw invalidToken();
    return token as TokenResponse;
  }

  private async commitLogin(
    profileName: string,
    site: string,
    origin: string,
    clientId: string,
    metadata: ProtectedResourceMetadata,
    credential: CredentialRecord,
  ): Promise<SiteProfile> {
    const target = { profileName, origin };
    return this.locks.withLock(profileName, async () => {
      const previous = await this.profiles.get(profileName);
      const previousTarget =
        previous === undefined
          ? undefined
          : { profileName, origin: previous.origin };
      let previousCredential: CredentialRecord | undefined;
      if (previousTarget !== undefined) {
        try {
          previousCredential =
            await this.credentials.readUnderLock(previousTarget);
        } catch (error) {
          if (!(error instanceof CliError) || error.code !== "auth_required")
            throw error;
        }
      }
      await this.abilityCache.invalidateProfile(origin, profileName);
      if (previous !== undefined && previous.origin !== origin)
        await this.abilityCache.invalidateProfile(previous.origin, profileName);
      await this.credentials.replaceUnderLock(target, credential);
      try {
        if (previousTarget !== undefined && previousTarget.origin !== origin)
          await this.credentials.deleteUnderLock(previousTarget);
        return await this.profiles.upsertUnderLock({
          name: profileName,
          siteUrl: site,
          clientId,
          compatibility: {
            pluginVersion: metadata.novamira.plugin_version,
            restApiVersion: metadata.novamira.rest_api_version,
            wordpressVersion: metadata.novamira.wordpress_version,
            checkedAt: new Date(this.now()).toISOString(),
          },
        });
      } catch (error) {
        if (previousTarget?.origin !== origin)
          await this.credentials.deleteUnderLock(target).catch(() => undefined);
        if (previousTarget !== undefined && previousCredential !== undefined)
          await this.credentials
            .replaceUnderLock(previousTarget, previousCredential)
            .catch(() => undefined);
        else if (previousTarget?.origin === origin)
          await this.credentials.deleteUnderLock(target).catch(() => undefined);
        throw error;
      }
    });
  }
}

export function buildAuthorizationUrl(input: {
  readonly metadata: AuthorizationServerMetadata;
  readonly resource: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scope: string;
  readonly state: string;
  readonly challenge: string;
}): string {
  const url = new URL(input.metadata.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("scope", input.scope);
  url.searchParams.set("resource", input.resource);
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export class SystemBrowserLauncher implements BrowserLauncher {
  async open(url: string): Promise<void> {
    const command =
      process.platform === "darwin"
        ? { file: "open", args: [url] }
        : process.platform === "win32"
          ? {
              file: "powershell.exe",
              args: [
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Process -FilePath $args[0]",
                url,
              ],
            }
          : { file: "xdg-open", args: [url] };
    await new Promise<void>((resolve, reject) => {
      const child = spawn(command.file, command.args, {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
      });
      child.once("error", reject);
      child.once("spawn", () => {
        child.unref();
        resolve();
      });
    });
  }
}

export class TerminalLoginInteraction implements LoginInteraction {
  constructor(
    private readonly writeError: (value: string) => unknown = (value) =>
      stderr.write(value),
  ) {}

  showAuthorizationUrl(url: string): void {
    this.writeError(`Authorize this site in your browser:\n${url}\n`);
  }
}

function callbackError(remoteCode: string): CliError {
  return new CliError(
    "auth_denied",
    remoteCode === "access_denied"
      ? "Authorization was denied."
      : "The OAuth authorization callback returned an error.",
    { remoteCode },
  );
}

function invalidRegistration(): CliError {
  return new CliError(
    "server_unsupported",
    "Dynamic client registration returned an invalid public client.",
  );
}

function invalidToken(): CliError {
  return new CliError("auth_denied", "The OAuth token response is invalid.");
}

function validClientId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 191 &&
    /^[\x21-\x7e]+$/.test(value)
  );
}

function defaultProfileName(site: string): string {
  const url = new URL(site);
  const value = `${url.hostname}${url.pathname === "/" ? "" : url.pathname}`
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (value === "") return "site";
  if (value.length <= 64) return value;
  const suffix = createHash("sha256").update(site).digest("hex").slice(0, 8);
  return `${value.slice(0, 55)}-${suffix}`;
}
