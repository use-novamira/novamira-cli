// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

export const ERROR_CODES = [
  "usage_error",
  "site_required",
  "site_not_found",
  "auth_required",
  "auth_denied",
  "auth_expired",
  "insufficient_scope",
  "server_unsupported",
  "network_error",
  "rest_error",
  "ability_not_found",
  "ability_hidden",
  "schema_validation_failed",
  "confirmation_required",
  "remote_execution_failed",
  "internal_error",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

const EXIT_CODES: Readonly<Record<ErrorCode, number>> = {
  usage_error: 2,
  site_required: 2,
  site_not_found: 2,
  auth_required: 3,
  auth_denied: 3,
  auth_expired: 3,
  insufficient_scope: 3,
  server_unsupported: 4,
  network_error: 4,
  rest_error: 4,
  ability_not_found: 4,
  ability_hidden: 4,
  schema_validation_failed: 5,
  confirmation_required: 6,
  remote_execution_failed: 5,
  internal_error: 1,
};

export class CliError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly remoteCode: string | undefined;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(
    code: ErrorCode,
    message: string,
    options: {
      retryable?: boolean;
      remoteCode?: string;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    } = {},
  ) {
    super(
      message,
      options.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = "CliError";
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.remoteCode = options.remoteCode;
    this.details = options.details;
  }
}

export function exitCodeFor(error: CliError): number {
  return EXIT_CODES[error.code];
}

export function asCliError(error: unknown): CliError {
  return error instanceof CliError
    ? error
    : new CliError("internal_error", "An unexpected internal error occurred.", {
        cause: error,
      });
}
