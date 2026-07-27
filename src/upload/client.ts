// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { Readable } from "node:stream";
import type { AbilityClient, AbilityWarning } from "../abilities/client.js";
import type { TokenLifecycle } from "../auth/token-lifecycle.js";
import type { SiteProfile } from "../config/profiles.js";
import { CliError } from "../errors.js";
import type { HttpClient } from "../rest/http-client.js";
import { matchesRestUrl, sameOriginEndpoint } from "../rest/urls.js";

export const UPLOAD_GRANT_ABILITY = "novamira/create-upload-link";
export const UPLOAD_TOKEN_HEADER = "x-novamira-upload-token";
export const MAX_UPLOAD_GRANT_LIFETIME_SECONDS = 3_600;

export interface UploadResult {
  readonly destination: string;
  readonly bytesTransferred: number;
}

export interface CompositeUploadResult {
  readonly data: UploadResult;
  readonly warnings: readonly AbilityWarning[];
}

interface UploadGrant {
  readonly url: URL;
  readonly token: string;
  readonly maxBytes: number;
  readonly expiresAt: number;
}

export class CompositeUploader {
  constructor(
    private readonly profile: SiteProfile,
    private readonly tokens: Pick<TokenLifecycle, "requireScope">,
    private readonly abilities: Pick<AbilityClient, "run">,
    private readonly http: Pick<HttpClient, "streamJsonResponse">,
    private readonly timeoutMs = 30_000,
    private readonly now: () => number = Date.now,
  ) {}

  async upload(
    localPath: string,
    remotePath: string,
  ): Promise<CompositeUploadResult> {
    validateLocalPath(localPath);
    validateRemotePath(remotePath);
    await this.tokens.requireScope("abilities");

    const created = await this.abilities.run(
      UPLOAD_GRANT_ABILITY,
      { path: remotePath },
      { fresh: true },
    );
    const grant = this.validateGrant(created.data);
    const file = await openLocalFile(localPath);
    try {
      const info = await file.stat();
      if (!info.isFile()) throw invalidLocalFile();
      if (!Number.isSafeInteger(info.size) || info.size < 0)
        throw invalidLocalFile();
      if (info.size > grant.maxBytes)
        throw new CliError(
          "usage_error",
          "The local file exceeds the temporary upload size limit.",
        );
      if (grantExpiresAtOrBefore(grant, this.now()))
        throw invalidGrant("The temporary upload grant has expired.");

      const source = file.createReadStream({ autoClose: false });
      try {
        const response = await this.http.streamJsonResponse(
          {
            url: grant.url,
            method: "PUT",
            redirectPolicy: "upload",
            headers: {
              "content-type": "application/octet-stream",
              "content-length": String(info.size),
              [UPLOAD_TOKEN_HEADER]: grant.token,
            },
            body: Readable.toWeb(source) as ReadableStream<Uint8Array>,
            timeoutMs: this.timeoutMs,
            suppressDiagnostics: true,
          },
          [grant.token, grant.url.toString()],
        );
        const bytesWritten = validateUploadResponse(response.data);
        if (bytesWritten !== info.size)
          throw new CliError(
            "network_error",
            "The upload response byte count did not match the local file.",
          );
        return {
          data: { destination: remotePath, bytesTransferred: bytesWritten },
          // Grant diagnostics may contain the temporary credential in untrusted property names.
          warnings: [],
        };
      } finally {
        source.destroy();
      }
    } finally {
      await closeFile(file);
    }
  }

  private validateGrant(value: unknown): UploadGrant {
    if (!isObject(value)) throw invalidGrant();
    const url = sameOriginEndpoint(
      value.upload_url,
      this.profile.origin,
      "Temporary upload endpoint",
    );
    if (
      !matchesRestUrl(this.profile.siteUrl, url.toString(), [
        "novamira",
        "v1",
        "upload",
      ])
    )
      throw invalidGrant("The temporary upload endpoint route is invalid.");
    if (
      typeof value.upload_token !== "string" ||
      value.upload_token.length > 8_192 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.upload_token)
    )
      throw invalidGrant("The temporary upload credential is invalid.");
    if (
      typeof value.token_header !== "string" ||
      value.token_header.toLowerCase() !== UPLOAD_TOKEN_HEADER
    )
      throw invalidGrant("The temporary upload credential header is invalid.");
    if (value.method !== "PUT")
      throw invalidGrant("The temporary upload method is invalid.");
    if (
      typeof value.max_bytes !== "number" ||
      !Number.isSafeInteger(value.max_bytes) ||
      value.max_bytes < 1
    )
      throw invalidGrant("The temporary upload size limit is invalid.");
    if (
      typeof value.expires_at !== "number" ||
      !Number.isSafeInteger(value.expires_at)
    )
      throw invalidGrant("The temporary upload expiry is invalid.");
    const nowSeconds = Math.floor(this.now() / 1_000);
    if (
      value.expires_at <= nowSeconds ||
      value.expires_at - nowSeconds > MAX_UPLOAD_GRANT_LIFETIME_SECONDS
    )
      throw invalidGrant(
        "The temporary upload expiry is outside the accepted range.",
      );
    return {
      url,
      token: value.upload_token,
      maxBytes: value.max_bytes,
      expiresAt: value.expires_at,
    };
  }
}

function validateLocalPath(value: string): void {
  if (value === "" || value.includes("\u0000")) throw invalidLocalFile();
}

function validateRemotePath(value: string): void {
  if (
    value === "" ||
    value !== value.trim() ||
    Buffer.byteLength(value, "utf8") > 4_096 ||
    /\p{Cc}/u.test(value)
  )
    throw new CliError(
      "usage_error",
      "Remote path must be 1-4096 UTF-8 bytes with no surrounding whitespace or control character.",
    );
}

async function openLocalFile(path: string): Promise<FileHandle> {
  try {
    return await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  } catch (cause) {
    throw new CliError(
      "usage_error",
      "The local upload file cannot be opened.",
      {
        cause,
      },
    );
  }
}

async function closeFile(file: FileHandle): Promise<void> {
  try {
    await file.close();
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code !== "EBADF") throw cause;
  }
}

function invalidLocalFile(): CliError {
  return new CliError(
    "usage_error",
    "The local upload source must be a readable regular file.",
  );
}

function invalidGrant(
  message = "The server returned an invalid temporary upload grant.",
): CliError {
  return new CliError("server_unsupported", message);
}

function grantExpiresAtOrBefore(grant: UploadGrant, now: number): boolean {
  return grant.expiresAt <= Math.floor(now / 1_000);
}

function validateUploadResponse(value: unknown): number {
  if (
    !isObject(value) ||
    typeof value.bytes_written !== "number" ||
    !Number.isSafeInteger(value.bytes_written) ||
    value.bytes_written < 0
  )
    throw new CliError("rest_error", "The upload response is invalid.");
  return value.bytes_written;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
