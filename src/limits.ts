// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "./errors.js";

export const HTTP_RESPONSE_CEILING_BYTES = 25 * 1024 * 1024;

export function assertHttpResponseSize(byteLength: number): void {
  if (
    !Number.isSafeInteger(byteLength) ||
    byteLength < 0 ||
    byteLength > HTTP_RESPONSE_CEILING_BYTES
  ) {
    throw new CliError(
      "network_error",
      "The HTTP response exceeded the 25 MiB safety limit.",
    );
  }
}
