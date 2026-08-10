// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { stderr } from "node:process";
import { setTimeout as setTimeoutPromise } from "node:timers/promises";
import { CliError } from "../errors.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import type { ProfileLockManager } from "../config/lock.js";
import {
  validateProfileName,
  DEFAULT_CLIENT_GRANT,
  type ClientGrant,
  type ProfileStore,
  type SiteProfile,
} from "../config/profiles.js";
import {
  POWERSHELL_PREFIX,
  powerShellEnvironment,
} from "../config/powershell.js";
import {
  normalizeSiteUrl,
  type SiteUrlEnvironment,
} from "../config/site-url.js";
import type { CredentialRecord, CredentialStore } from "./credentials.js";
import {
  DEVICE_CODE_GRANT,
  deviceAuthorizationEndpoint,
  supportsDeviceAuthorization,
  type AuthorizationServerMetadata,
  type MetadataClient,
  type ProtectedResourceMetadata,
} from "./metadata.js";
import {
  deviceGrantError,
  devicePollDecision,
  deviceTimeout,
  requestDeviceAuthorization,
  MAX_POLL_INTERVAL_SECONDS,
  SLOW_DOWN_INCREMENT_SECONDS,
  type DeviceAuthorization,
} from "./device.js";
import { createPkce } from "./pkce.js";
import { LoopbackCallbackFactory, type CallbackFactory } from "./loopback.js";
import type { HttpClient } from "../rest/http-client.js";
import { verifyLoginSurface } from "../rest/login-verification.js";

export interface LoginEnvironment extends SiteUrlEnvironment {
  readonly SSH_CONNECTION?: string;
  readonly SSH_TTY?: string;
}

export interface LoginOptions {
  readonly siteUrl: string;
  readonly name?: string;
  readonly noOpen: boolean;
  /** RFC 8628 device authorization, for shells with no reachable browser. */
  readonly device?: boolean;
  readonly timeoutMs: number;
}

export interface LoginResult {
  readonly profile: SiteProfile;
  readonly expiresAt: string;
}

export interface BrowserLauncher {
  open(url: string): Promise<void>;
}

export interface LoginInteraction {
  showAuthorizationUrl(url: string): void;
  showDeviceInstructions(authorization: DeviceAuthorization): void;
  showRemoteSessionHint(): void;
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

interface GrantResult {
  readonly clientId: string;
  readonly token: TokenResponse;
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
    private readonly environment: LoginEnvironment = process.env,
    private readonly sleep: (ms: number) => Promise<void> = defaultSleep,
  ) {}

  async login(options: LoginOptions): Promise<LoginResult> {
    if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0)
      throw new CliError("usage_error", "Login timeout must be positive.");
    const { siteUrl: normalizedSite, origin } = normalizeSiteUrl(
      options.siteUrl,
      this.environment,
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
    const device = options.device === true;
    // Resolving the endpoint here fails an unsupported site before any client
    // registration, listener, browser launch, or prompt.
    const deviceEndpoint = device
      ? deviceAuthorizationEndpoint(authorization)
      : undefined;
    if (
      !device &&
      this.remoteSession() &&
      supportsDeviceAuthorization(authorization)
    )
      this.interaction.showRemoteSessionHint();

    const requestedScope = "mcp";
    // A client registered for the other grant cannot complete this one, and the
    // site says so without redirecting anywhere the CLI is listening — the
    // browser flow would simply wait out its timeout. So the stored id is reused
    // only for the grant it was registered for.
    const clientGrant: ClientGrant = device
      ? "device_code"
      : "authorization_code";
    let clientId =
      existing?.siteUrl === normalizedSite &&
      validClientId(existing.clientId) &&
      (existing.clientGrant ?? DEFAULT_CLIENT_GRANT) === clientGrant
        ? existing.clientId
        : undefined;
    let retriedUnknownClient = false;

    for (;;) {
      const reusedClient = clientId !== undefined;
      let grant: GrantResult;
      try {
        grant =
          deviceEndpoint === undefined
            ? await this.authorizationCodeGrant(
                options,
                authorization,
                protectedMetadata,
                clientId,
                requestedScope,
              )
            : await this.deviceGrant(
                options,
                deviceEndpoint,
                authorization,
                protectedMetadata,
                clientId,
                requestedScope,
                origin,
              );
      } catch (error) {
        // A stored client can be unknown to the site, or registered for the
        // other grant; one fresh registration repairs both.
        if (reusedClient && !retriedUnknownClient && rejectedClient(error)) {
          clientId = undefined;
          retriedUnknownClient = true;
          continue;
        }
        throw error;
      }

      const token = grant.token;
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
        this.environment,
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
        grant.clientId,
        clientGrant,
        protectedMetadata,
        credential,
      );
      return { profile, expiresAt };
    }
  }

  private async authorizationCodeGrant(
    options: LoginOptions,
    authorization: AuthorizationServerMetadata,
    protectedMetadata: ProtectedResourceMetadata,
    knownClientId: string | undefined,
    scope: string,
  ): Promise<GrantResult> {
    const callback = await this.callbacks.start();
    try {
      const clientId =
        knownClientId ??
        (await this.registerClient(authorization, callback.redirectUri));
      const pkce = createPkce();
      const authorizationUrl = buildAuthorizationUrl({
        metadata: authorization,
        resource: protectedMetadata.resource,
        clientId,
        redirectUri: callback.redirectUri,
        scope,
        state: pkce.state,
        challenge: pkce.challenge,
      });
      if (options.noOpen)
        this.interaction.showAuthorizationUrl(authorizationUrl);
      if (!options.noOpen) await this.browser.open(authorizationUrl);

      const result = await callback.wait(pkce.state, options.timeoutMs);
      if (result.error !== undefined) throw callbackError(result.error);
      if (result.code === undefined)
        throw new CliError("auth_denied", "Authorization returned no code.");
      const token = await this.exchangeCode(
        authorization,
        protectedMetadata,
        clientId,
        callback.redirectUri,
        result.code,
        pkce.verifier,
      );
      return { clientId, token };
    } finally {
      await callback.close();
    }
  }

  /**
   * RFC 8628. Nothing has to reach this host: the operator approves the short
   * code in a browser anywhere, and the CLI polls the token endpoint.
   */
  private async deviceGrant(
    options: LoginOptions,
    endpoint: string,
    authorization: AuthorizationServerMetadata,
    protectedMetadata: ProtectedResourceMetadata,
    knownClientId: string | undefined,
    scope: string,
    origin: string,
  ): Promise<GrantResult> {
    const clientId =
      knownClientId ?? (await this.registerDeviceClient(authorization));
    const device = await requestDeviceAuthorization(this.http, {
      endpoint,
      origin,
      clientId,
      scope,
      resource: protectedMetadata.resource,
    });
    this.interaction.showDeviceInstructions(device);
    const token = await this.pollDeviceToken(
      authorization,
      protectedMetadata,
      clientId,
      device,
      options.timeoutMs,
    );
    return { clientId, token };
  }

  private async pollDeviceToken(
    authorization: AuthorizationServerMetadata,
    resource: ProtectedResourceMetadata,
    clientId: string,
    device: DeviceAuthorization,
    timeoutMs: number,
  ): Promise<TokenResponse> {
    // The grant dies at whichever comes first: the device code's own lifetime
    // or the operator's timeout. Nothing past that instant may become a stored
    // credential, so the deadline is enforced three times per poll — before
    // sleeping, as the token request's own budget, and against the response.
    const deadline =
      this.now() + Math.min(device.expiresInSeconds * 1000, timeoutMs);
    let intervalSeconds = device.intervalSeconds;
    for (;;) {
      // A sleep that ends exactly on the deadline leaves no time to poll.
      if (this.now() + intervalSeconds * 1000 >= deadline)
        throw deviceTimeout();
      await this.sleep(intervalSeconds * 1000);
      const remainingMs = deadline - this.now();
      if (remainingMs <= 0) throw deviceTimeout();
      let token: TokenResponse;
      try {
        token = await this.exchangeDeviceCode(
          authorization,
          resource,
          clientId,
          device.deviceCode,
          remainingMs,
        );
      } catch (error) {
        const decision = devicePollDecision(error);
        if (decision === "stop")
          throw error instanceof CliError ? deviceGrantError(error) : error;
        if (decision === "slow_down")
          intervalSeconds = Math.min(
            intervalSeconds + SLOW_DOWN_INCREMENT_SECONDS,
            MAX_POLL_INTERVAL_SECONDS,
          );
        continue;
      }
      // The request was bounded, but the clock still moves while the response is
      // read: a grant that lands after the deadline is discarded, not stored.
      if (this.now() >= deadline) throw deviceTimeout();
      return token;
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

  /**
   * RFC 7591 omits `redirect_uris` for grants that never redirect, so a device
   * client is registered separately from the loopback client.
   */
  private async registerDeviceClient(
    metadata: AuthorizationServerMetadata,
  ): Promise<string> {
    const raw = await this.http.json({
      url: metadata.registration_endpoint,
      method: "POST",
      redirectPolicy: "oauth",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Novamira CLI",
        token_endpoint_auth_method: "none",
        grant_types: [DEVICE_CODE_GRANT, "refresh_token"],
      }),
    });
    if (raw === null || typeof raw !== "object") throw invalidRegistration();
    const response = raw as Partial<RegistrationResponse> & {
      readonly grant_types?: readonly string[];
    };
    if (
      !validClientId(response.client_id) ||
      response.token_endpoint_auth_method !== "none" ||
      (response.redirect_uris !== undefined &&
        (!Array.isArray(response.redirect_uris) ||
          response.redirect_uris.length !== 0)) ||
      (response.grant_types !== undefined &&
        (!Array.isArray(response.grant_types) ||
          !response.grant_types.includes(DEVICE_CODE_GRANT)))
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
    return this.requestToken(metadata, body);
  }

  private async exchangeDeviceCode(
    metadata: AuthorizationServerMetadata,
    resource: ProtectedResourceMetadata,
    clientId: string,
    deviceCode: string,
    timeoutMs: number,
  ): Promise<TokenResponse> {
    return this.requestToken(
      metadata,
      new URLSearchParams({
        grant_type: DEVICE_CODE_GRANT,
        client_id: clientId,
        device_code: deviceCode,
        resource: resource.resource,
      }),
      timeoutMs,
    );
  }

  private async requestToken(
    metadata: AuthorizationServerMetadata,
    body: URLSearchParams,
    timeoutMs?: number,
  ): Promise<TokenResponse> {
    const raw = await this.http.json({
      url: metadata.token_endpoint,
      method: "POST",
      redirectPolicy: "oauth",
      responseKind: "oauth",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
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

  private remoteSession(): boolean {
    return (
      (this.environment.SSH_CONNECTION ?? "") !== "" ||
      (this.environment.SSH_TTY ?? "") !== ""
    );
  }

  private async commitLogin(
    profileName: string,
    site: string,
    origin: string,
    clientId: string,
    clientGrant: ClientGrant,
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
        return await this.profiles.upsertWithProfileLockHeld({
          name: profileName,
          siteUrl: site,
          clientId,
          clientGrant,
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

export interface BrowserCommand {
  readonly file: string;
  readonly args: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
}

// `$args` is never populated under `-Command`, and interpolating the URL into
// the script would make remote metadata executable text, so on Windows the URL
// travels in the child's environment instead.
export function browserCommand(
  url: string,
  platform: NodeJS.Platform,
): BrowserCommand {
  if (platform === "darwin")
    return { file: "open", args: [url], environment: {} };
  if (platform === "win32")
    return {
      file: "powershell.exe",
      args: [
        ...POWERSHELL_PREFIX,
        "Start-Process -FilePath $env:NOVAMIRA_BROWSER_URL",
      ],
      environment: { NOVAMIRA_BROWSER_URL: url },
    };
  return { file: "xdg-open", args: [url], environment: {} };
}

export class SystemBrowserLauncher implements BrowserLauncher {
  async open(url: string): Promise<void> {
    const command = browserCommand(url, process.platform);
    await new Promise<void>((resolve, reject) => {
      const child = spawn(command.file, [...command.args], {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
        env: { ...powerShellEnvironment(), ...command.environment },
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

  showDeviceInstructions(authorization: DeviceAuthorization): void {
    this.writeError(
      `Open this page in a browser on any device:\n${authorization.verificationUri}\n` +
        `Enter the code: ${authorization.userCode}\n` +
        `The code expires in ${lifetime(authorization.expiresInSeconds)}. Waiting for approval...\n`,
    );
  }

  showRemoteSessionHint(): void {
    this.writeError(
      "This looks like a remote shell. If the browser cannot reach this host, rerun with --device.\n",
    );
  }
}

function lifetime(seconds: number): string {
  if (seconds < 120) return `${String(seconds)} seconds`;
  return `${String(Math.floor(seconds / 60))} minutes`;
}

async function defaultSleep(ms: number): Promise<void> {
  await setTimeoutPromise(ms);
}

function rejectedClient(error: unknown): boolean {
  return (
    error instanceof CliError &&
    (error.remoteCode === "invalid_client" ||
      error.remoteCode === "unauthorized_client")
  );
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
