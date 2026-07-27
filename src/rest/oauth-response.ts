// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";

interface OAuthErrorResponse {
  readonly error: string;
  readonly error_description?: string;
}

export function parseOAuthResponse(status: number, text: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch (cause) {
    throw new CliError(
      "rest_error",
      "The OAuth server returned invalid JSON.",
      {
        cause,
      },
    );
  }
  if (status >= 200 && status < 300) return value;
  if (isOAuthError(value)) {
    return throwOAuthError(value, status);
  }
  throw new CliError(
    "rest_error",
    `The OAuth server returned HTTP ${String(status)}.`,
  );
}

function isOAuthError(value: unknown): value is OAuthErrorResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  const candidate = value as Partial<OAuthErrorResponse>;
  return (
    typeof candidate.error === "string" &&
    (candidate.error_description === undefined ||
      typeof candidate.error_description === "string")
  );
}

function throwOAuthError(error: OAuthErrorResponse, status: number): never {
  const code = error.error === "invalid_grant" ? "auth_expired" : "auth_denied";
  throw new CliError(
    code,
    code === "auth_expired"
      ? "The OAuth grant is invalid or expired."
      : "The OAuth request was denied.",
    {
      remoteCode: error.error,
      retryable: status >= 500,
      details: { status },
    },
  );
}
