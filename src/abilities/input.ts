// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFile } from "node:fs/promises";
import { CliError } from "../errors.js";
import { HTTP_RESPONSE_CEILING_BYTES } from "../limits.js";

export interface InputReader {
  readonly file?: (path: string) => Promise<Buffer>;
  readonly stdin?: () => Promise<Buffer>;
}

export async function parseRunInput(
  source: string | undefined,
  reader: InputReader = {},
): Promise<unknown> {
  if (source === undefined) return null;

  let raw: Buffer;
  if (source === "-") {
    raw = await (reader.stdin ?? readStdin)();
  } else if (source.startsWith("@")) {
    if (source.length === 1)
      throw new CliError("usage_error", "The input file path is missing.");
    try {
      raw = await (reader.file ?? readFile)(source.slice(1));
    } catch (cause) {
      throw new CliError("usage_error", "The input file could not be read.", {
        cause,
      });
    }
  } else {
    raw = Buffer.from(source, "utf8");
  }

  if (raw.byteLength > HTTP_RESPONSE_CEILING_BYTES)
    throw new CliError(
      "usage_error",
      "Ability input exceeds the 25 MiB safety limit.",
    );
  try {
    return JSON.parse(raw.toString("utf8")) as unknown;
  } catch (cause) {
    throw new CliError("usage_error", "Ability input must be valid JSON.", {
      cause,
    });
  }
}

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > HTTP_RESPONSE_CEILING_BYTES)
      throw new CliError(
        "usage_error",
        "Ability input exceeds the 25 MiB safety limit.",
      );
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, total);
}
