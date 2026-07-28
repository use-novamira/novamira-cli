// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { REDACTION_KEY_PATTERN } from "../security/classify.js";

const REDACTED = "[REDACTED]";

export function redact(
  value: unknown,
  knownSecrets: readonly string[] = [],
): unknown {
  if (typeof value === "string") {
    return knownSecrets.reduce(
      (safe, secret) =>
        secret === "" ? safe : safe.replaceAll(secret, REDACTED),
      value,
    );
  }
  if (Array.isArray(value)) {
    return value.map((item) => redact(item, knownSecrets));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        REDACTION_KEY_PATTERN.test(key) ? REDACTED : redact(item, knownSecrets),
      ]),
    );
  }
  return value;
}
