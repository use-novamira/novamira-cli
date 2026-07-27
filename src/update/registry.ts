// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";
import { isSemver } from "../semver.js";

export const PACKAGE_NAME = "@novamira/cli";
export const DEFAULT_REGISTRY = "https://registry.npmjs.org";
const MAX_REGISTRY_RESPONSE_BYTES = 64 * 1024;

export interface RegistryOptions {
  readonly fetch?: typeof fetch;
  readonly registry?: string;
  readonly timeoutMs?: number;
  /** Set only by NOVAMIRA_ALLOW_INSECURE_HTTP=1 for a loopback test registry. */
  readonly allowInsecureHttp?: boolean;
}

function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

export function distTagsUrl(
  registry: string = DEFAULT_REGISTRY,
  allowInsecureHttp = false,
): URL {
  const base = new URL(registry.endsWith("/") ? registry : `${registry}/`);
  // Plain HTTP is accepted only for a loopback registry that the operator
  // explicitly opted into with NOVAMIRA_ALLOW_INSECURE_HTTP=1.
  if (
    base.protocol !== "https:" &&
    !(
      base.protocol === "http:" &&
      allowInsecureHttp &&
      isLoopback(base.hostname)
    )
  )
    throw new CliError("usage_error", "The package registry must use HTTPS.");
  if (base.username !== "" || base.password !== "")
    throw new CliError(
      "usage_error",
      "The package registry URL must not contain credentials.",
    );
  return new URL(
    `-/package/${encodeURIComponent(PACKAGE_NAME)}/dist-tags`,
    base,
  );
}

/**
 * Read the `latest` dist-tag of the published package. The request is
 * anonymous, sends no local state, and never follows a redirect.
 */
export async function fetchLatestVersion(
  options: RegistryOptions = {},
): Promise<string> {
  const fetchImplementation = options.fetch ?? fetch;
  const url = distTagsUrl(
    options.registry ?? DEFAULT_REGISTRY,
    options.allowInsecureHttp === true,
  );
  let response: Response;
  try {
    response = await fetchImplementation(url, {
      method: "GET",
      redirect: "error",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(options.timeoutMs ?? 5_000),
    });
  } catch (error) {
    throw new CliError(
      "network_error",
      "The package registry could not be reached.",
      { retryable: true, cause: error },
    );
  }
  if (!response.ok)
    throw new CliError(
      "network_error",
      `The package registry answered with status ${String(response.status)}.`,
      { retryable: response.status >= 500 },
    );
  const body = await readBounded(response);
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (error) {
    throw new CliError(
      "network_error",
      "The package registry returned an unreadable response.",
      { cause: error },
    );
  }
  const latest =
    value !== null && typeof value === "object"
      ? (value as Record<string, unknown>).latest
      : undefined;
  if (!isSemver(latest))
    throw new CliError(
      "network_error",
      "The package registry did not advertise a valid latest version.",
    );
  return latest;
}

async function readBounded(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_REGISTRY_RESPONSE_BYTES)
    throw new CliError(
      "network_error",
      "The package registry response exceeded the allowed size.",
    );
  // Read incrementally so an unbounded, chunked, or compressed body is
  // abandoned at the limit instead of being buffered in full.
  const reader = response.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_REGISTRY_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new CliError(
          "network_error",
          "The package registry response exceeded the allowed size.",
        );
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(
      "network_error",
      "The package registry response could not be read.",
      { retryable: true, cause: error },
    );
  }
  return Buffer.concat(chunks).toString("utf8");
}
