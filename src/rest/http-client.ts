// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";
import {
  HTTP_RESPONSE_CEILING_BYTES,
  assertHttpResponseSize,
} from "../limits.js";
import { redact } from "../output/redact.js";
import { parseOAuthResponse } from "./oauth-response.js";
import { parseWordPressResponse } from "./wordpress-response.js";

export type RedirectPolicy = "discovery" | "oauth" | "authenticated" | "upload";

export interface AccessTokenProvider {
  getAccessToken(): Promise<string>;
}

export interface HttpDiagnostic {
  readonly method: string;
  readonly origin: string;
  readonly path: string;
  readonly status?: number;
  readonly redirectPolicy: RedirectPolicy;
}

export interface HttpClientOptions {
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
  readonly responseCeilingBytes?: number;
  readonly onDiagnostic?: (diagnostic: HttpDiagnostic) => void;
}

export interface JsonRequest {
  readonly url: string | URL;
  readonly method?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly redirectPolicy: RedirectPolicy;
  readonly responseKind?: "wordpress" | "oauth";
  readonly timeoutMs?: number;
}

export interface JsonResponse<T> {
  readonly data: T;
  readonly status: number;
  readonly headers: Headers;
  readonly url: string;
}

export interface StreamJsonRequest extends Omit<JsonRequest, "body"> {
  readonly body: BodyInit;
  readonly suppressDiagnostics?: boolean;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_DISCOVERY_REDIRECTS = 3;

export class HttpClient {
  private readonly fetchImplementation: typeof fetch;
  private readonly timeoutMs: number;
  private readonly responseCeilingBytes: number;
  private readonly onDiagnostic:
    ((diagnostic: HttpDiagnostic) => void) | undefined;

  constructor(options: HttpClientOptions = {}) {
    this.fetchImplementation = options.fetch ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.responseCeilingBytes =
      options.responseCeilingBytes ?? HTTP_RESPONSE_CEILING_BYTES;
    if (
      !Number.isSafeInteger(this.responseCeilingBytes) ||
      this.responseCeilingBytes < 1 ||
      this.responseCeilingBytes > HTTP_RESPONSE_CEILING_BYTES
    )
      throw new CliError(
        "usage_error",
        "HTTP response limit must be between 1 byte and 25 MiB.",
      );
    this.onDiagnostic = options.onDiagnostic;
  }

  async json<T = unknown>(request: JsonRequest): Promise<T> {
    return (await this.jsonResponse<T>(request)).data;
  }

  async jsonResponse<T = unknown>(
    request: JsonRequest,
  ): Promise<JsonResponse<T>> {
    return this.perform<T>(request, undefined);
  }

  async streamJsonResponse<T = unknown>(
    request: StreamJsonRequest,
    knownSecrets: readonly string[],
  ): Promise<JsonResponse<T>> {
    return this.perform<T>(request, knownSecrets, true);
  }

  async authenticatedJson<T = unknown>(
    request: Omit<JsonRequest, "redirectPolicy" | "headers"> & {
      readonly headers?: Readonly<Record<string, string>>;
      readonly expectedOrigin: string;
    },
    tokens: AccessTokenProvider,
  ): Promise<T> {
    return (await this.authenticatedJsonResponse<T>(request, tokens)).data;
  }

  async authenticatedJsonResponse<T = unknown>(
    request: Omit<JsonRequest, "redirectPolicy" | "headers"> & {
      readonly headers?: Readonly<Record<string, string>>;
      readonly expectedOrigin: string;
    },
    tokens: AccessTokenProvider,
  ): Promise<JsonResponse<T>> {
    const target = strictHttpUrl(request.url);
    const expected = strictHttpUrl(request.expectedOrigin);
    if (
      expected.origin !== request.expectedOrigin ||
      expected.pathname !== "/" ||
      expected.search !== "" ||
      target.origin !== request.expectedOrigin
    )
      throw new CliError(
        "server_unsupported",
        "Authenticated API endpoint must match the selected site origin.",
      );
    const accessToken = await tokens.getAccessToken();
    const { expectedOrigin: _expectedOrigin, ...safeRequest } = request;
    void _expectedOrigin;
    return this.perform<T>(
      {
        ...safeRequest,
        redirectPolicy: "authenticated",
        headers: {
          ...request.headers,
          authorization: `Bearer ${accessToken}`,
        },
      },
      [accessToken],
    );
  }

  private async perform<T>(
    request: JsonRequest | StreamJsonRequest,
    knownSecrets: readonly string[] | undefined,
    streamingBody = false,
  ): Promise<JsonResponse<T>> {
    let current = strictHttpUrl(request.url);
    const originalOrigin = current.origin;
    const timeoutMs = request.timeoutMs ?? this.timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)
      throw new CliError("usage_error", "Request timeout must be positive.");

    const deadline = Date.now() + timeoutMs;
    for (let redirects = 0; ; redirects += 1) {
      const remaining = deadline - Date.now();
      if (remaining <= 0)
        throw new CliError("network_error", "The HTTP request timed out.", {
          retryable: true,
        });
      const controller = new AbortController();
      const timer = setTimeout(() => {
        controller.abort();
      }, remaining);
      let response: Response;
      try {
        if (!diagnosticsSuppressed(request))
          this.diagnostic(request, current, knownSecrets);
        const init: RequestInit & { duplex?: "half" } = {
          method: request.method ?? "GET",
          ...(request.headers === undefined
            ? {}
            : { headers: request.headers }),
          ...(request.body === undefined ? {} : { body: request.body }),
          redirect: "manual",
          signal: controller.signal,
        };
        if (streamingBody) init.duplex = "half";
        response = await this.fetchImplementation(current, init);
      } catch (cause) {
        clearTimeout(timer);
        throw new CliError(
          "network_error",
          controller.signal.aborted
            ? "The HTTP request timed out or was aborted."
            : "The HTTP request failed.",
          { retryable: true, cause },
        );
      }

      try {
        if (!diagnosticsSuppressed(request))
          this.diagnostic(request, current, knownSecrets, response.status);
        if (REDIRECT_STATUSES.has(response.status)) {
          if (
            request.redirectPolicy !== "discovery" ||
            redirects >= MAX_DISCOVERY_REDIRECTS
          ) {
            await response.body?.cancel().catch(() => undefined);
            throw new CliError(
              "network_error",
              "The endpoint returned a disallowed redirect.",
            );
          }
          const location = response.headers.get("location");
          if (location === null) {
            throw new CliError(
              "network_error",
              "The discovery redirect did not include a location.",
            );
          }
          const target = strictHttpUrl(new URL(location, current));
          if (target.origin !== originalOrigin) {
            throw new CliError(
              "network_error",
              "The discovery endpoint attempted a cross-origin redirect.",
            );
          }
          current = target;
          continue;
        }

        const contentLength = Number(response.headers.get("content-length"));
        if (
          Number.isFinite(contentLength) &&
          contentLength > this.responseCeilingBytes
        ) {
          await response.body?.cancel().catch(() => undefined);
          throw oversizedResponse();
        }
        const text = await readBoundedBody(response, this.responseCeilingBytes);
        let data: T;
        try {
          data = (
            request.responseKind === "oauth"
              ? parseOAuthResponse(response.status, text)
              : parseWordPressResponse(response.status, text)
          ) as T;
        } catch (cause) {
          throw redactHttpError(cause, knownSecrets);
        }
        return {
          data,
          status: response.status,
          headers: response.headers,
          url: current.toString(),
        };
      } finally {
        clearTimeout(timer);
      }
    }
  }

  private diagnostic(
    request: JsonRequest | StreamJsonRequest,
    url: URL,
    knownSecrets: readonly string[] | undefined,
    status?: number,
  ): void {
    if (this.onDiagnostic === undefined) return;
    const value = redact(
      {
        method: request.method ?? "GET",
        origin: url.origin,
        path: url.pathname,
        ...(status === undefined ? {} : { status }),
        redirectPolicy: request.redirectPolicy,
      },
      knownSecrets,
    ) as HttpDiagnostic;
    this.onDiagnostic(value);
  }
}

function diagnosticsSuppressed(
  request: JsonRequest | StreamJsonRequest,
): boolean {
  return "suppressDiagnostics" in request
    ? (request.suppressDiagnostics ?? false)
    : false;
}

function redactHttpError(
  error: unknown,
  knownSecrets: readonly string[] | undefined,
): unknown {
  if (!(error instanceof CliError) || knownSecrets === undefined) return error;
  return new CliError(
    error.code,
    redact(error.message, knownSecrets) as string,
    {
      retryable: error.retryable,
      ...(error.remoteCode === undefined
        ? {}
        : { remoteCode: redact(error.remoteCode, knownSecrets) as string }),
      ...(error.details === undefined
        ? {}
        : {
            details: redact(error.details, knownSecrets) as Readonly<
              Record<string, unknown>
            >,
          }),
    },
  );
}

function strictHttpUrl(value: string | URL): URL {
  let url: URL;
  try {
    url = value instanceof URL ? new URL(value) : new URL(value);
  } catch {
    throw new CliError("usage_error", "Endpoint URL is invalid.");
  }
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== ""
  )
    throw new CliError(
      "usage_error",
      "Endpoint URL must be HTTP, contain no credentials, and contain no fragment.",
    );
  return url;
}

async function readBoundedBody(
  response: Response,
  ceilingBytes: number,
): Promise<string> {
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > ceilingBytes) {
        await reader.cancel().catch(() => undefined);
        throw oversizedResponse();
      }
      chunks.push(value);
    }
  } catch (cause) {
    if (cause instanceof CliError) throw cause;
    throw new CliError("network_error", "The HTTP response was interrupted.", {
      retryable: true,
      cause,
    });
  }
  assertHttpResponseSize(total);
  return Buffer.concat(chunks, total).toString("utf8");
}

function oversizedResponse(): CliError {
  return new CliError(
    "network_error",
    "The HTTP response exceeded the configured safety limit.",
  );
}
