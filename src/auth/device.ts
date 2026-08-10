// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";
import type { HttpClient } from "../rest/http-client.js";
import { sameOriginEndpoint } from "../rest/urls.js";

export const DEFAULT_POLL_INTERVAL_SECONDS = 5;
export const MAX_POLL_INTERVAL_SECONDS = 60;
export const SLOW_DOWN_INCREMENT_SECONDS = 5;
export const MAX_DEVICE_CODE_LIFETIME_SECONDS = 30 * 60;
const MAX_DEVICE_CODE_LENGTH = 1024;
const MAX_USER_CODE_LENGTH = 64;

export interface DeviceAuthorization {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly expiresInSeconds: number;
  readonly intervalSeconds: number;
}

export interface DeviceAuthorizationRequest {
  readonly endpoint: string;
  readonly origin: string;
  readonly clientId: string;
  readonly scope: string;
  readonly resource: string;
}

/**
 * RFC 8628 device authorization request. The response is bound to the site
 * origin: a verification URI on any other host would send the operator's
 * credentials somewhere the site never vouched for.
 */
export async function requestDeviceAuthorization(
  http: HttpClient,
  request: DeviceAuthorizationRequest,
): Promise<DeviceAuthorization> {
  const body = new URLSearchParams({
    client_id: request.clientId,
    scope: request.scope,
    resource: request.resource,
  });
  const raw = await http.json({
    url: request.endpoint,
    method: "POST",
    redirectPolicy: "oauth",
    responseKind: "oauth",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  return validateDeviceAuthorization(raw, request.origin);
}

export function validateDeviceAuthorization(
  value: unknown,
  origin: string,
): DeviceAuthorization {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw invalidDeviceAuthorization();
  const object = value as Record<string, unknown>;
  const deviceCode = object.device_code;
  const userCode = object.user_code;
  const expiresIn = object.expires_in;
  const interval = object.interval;
  if (
    typeof deviceCode !== "string" ||
    !printable(deviceCode, MAX_DEVICE_CODE_LENGTH) ||
    typeof userCode !== "string" ||
    !printable(userCode, MAX_USER_CODE_LENGTH) ||
    typeof expiresIn !== "number" ||
    !Number.isSafeInteger(expiresIn) ||
    expiresIn <= 0 ||
    expiresIn > MAX_DEVICE_CODE_LIFETIME_SECONDS ||
    (interval !== undefined &&
      (typeof interval !== "number" ||
        !Number.isSafeInteger(interval) ||
        interval <= 0 ||
        interval > MAX_POLL_INTERVAL_SECONDS))
  )
    throw invalidDeviceAuthorization();
  const verificationUri = sameOriginEndpoint(
    object.verification_uri,
    origin,
    "verification_uri",
  ).toString();
  return {
    deviceCode,
    userCode,
    verificationUri,
    expiresInSeconds: expiresIn,
    // `verification_uri_complete` is deliberately ignored: the operator types
    // the short code into a page that always renders the consent text.
    intervalSeconds: interval ?? DEFAULT_POLL_INTERVAL_SECONDS,
  };
}

/**
 * Maps an RFC 8628 token-endpoint error to the next polling step. The CLI must
 * keep waiting on `authorization_pending`, back off on `slow_down`, and stop on
 * anything else so a broken grant never spins against the site.
 */
export function devicePollDecision(
  error: unknown,
): "pending" | "slow_down" | "stop" {
  if (!(error instanceof CliError)) return "stop";
  if (error.remoteCode === "authorization_pending") return "pending";
  if (error.remoteCode === "slow_down") return "slow_down";
  return "stop";
}

export function deviceGrantError(error: CliError): CliError {
  if (error.remoteCode === "access_denied")
    return new CliError("auth_denied", "Authorization was denied.", {
      remoteCode: error.remoteCode,
    });
  if (error.remoteCode === "expired_token")
    return new CliError(
      "auth_denied",
      "The device code expired before it was approved.",
      { remoteCode: error.remoteCode },
    );
  return error;
}

export function deviceTimeout(): CliError {
  return new CliError("auth_denied", "Device authorization timed out.");
}

function printable(value: string, maximumLength: number): boolean {
  return (
    value.length >= 1 &&
    value.length <= maximumLength &&
    /^[\x21-\x7e]+$/.test(value)
  );
}

function invalidDeviceAuthorization(): CliError {
  return new CliError(
    "server_unsupported",
    "The device authorization response is invalid.",
  );
}
