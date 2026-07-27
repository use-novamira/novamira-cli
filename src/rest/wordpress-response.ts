// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError, type ErrorCode } from "../errors.js";

export interface WordPressRestError {
  readonly code: string;
  readonly message: string;
  readonly data?: {
    readonly status?: number;
    readonly [key: string]: unknown;
  };
}

export function isWordPressRestError(
  value: unknown,
): value is WordPressRestError {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  const candidate = value as Partial<WordPressRestError>;
  if (
    typeof candidate.code !== "string" ||
    typeof candidate.message !== "string"
  )
    return false;
  return (
    candidate.data === undefined ||
    (typeof candidate.data === "object" &&
      !Array.isArray(candidate.data) &&
      (candidate.data.status === undefined ||
        typeof candidate.data.status === "number"))
  );
}

export function parseWordPressResponse(status: number, text: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch (cause) {
    throw new CliError("rest_error", "The server returned invalid JSON.", {
      retryable: status >= 500,
      cause,
    });
  }

  if (status >= 200 && status < 300) return value;
  if (isWordPressRestError(value)) throw normalizeWordPressError(value, status);
  throw new CliError(
    "rest_error",
    `The server returned HTTP ${String(status)}.`,
    { retryable: status >= 500 },
  );
}

export function normalizeWordPressError(
  error: WordPressRestError,
  httpStatus: number,
): CliError {
  const code = mappedCode(error.code, httpStatus);
  return new CliError(code, safeMessage(code), {
    remoteCode: error.code,
    retryable: httpStatus >= 500,
    details:
      typeof error.data?.status === "number"
        ? { status: error.data.status }
        : { status: httpStatus },
  });
}

function mappedCode(remoteCode: string, status: number): ErrorCode {
  const code = remoteCode.toLowerCase();
  if (code.includes("insufficient_scope")) return "insufficient_scope";
  if (code.includes("invalid_token") || code.includes("expired_token"))
    return "auth_expired";
  if (status === 401) return "auth_required";
  if (code.includes("not_visible") || code.includes("hidden"))
    return "ability_hidden";
  if (code.includes("ability_not_found")) return "ability_not_found";
  if (
    code.includes("invalid_param") ||
    code.includes("invalid_input") ||
    code.includes("schema")
  )
    return "schema_validation_failed";
  if (status === 403) return "insufficient_scope";
  if (code.includes("execution") || code.includes("ability_failed"))
    return "remote_execution_failed";
  return "rest_error";
}

function safeMessage(code: ErrorCode): string {
  switch (code) {
    case "auth_required":
      return "Authentication is required.";
    case "auth_expired":
      return "Authentication has expired.";
    case "insufficient_scope":
      return "The current grant does not permit this request.";
    case "ability_not_found":
      return "The requested Ability was not found.";
    case "ability_hidden":
      return "The requested Ability is not REST-visible.";
    case "schema_validation_failed":
      return "The server rejected the Ability input schema.";
    case "remote_execution_failed":
      return "The remote Ability execution failed.";
    default:
      return "The WordPress REST request failed.";
  }
}
