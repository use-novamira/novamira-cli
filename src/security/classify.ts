// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

const CREDENTIAL_KEY_SOURCE =
  "authorization|token|secret|password|verifier|credential";

export const CREDENTIAL_KEY_PATTERN = new RegExp(
  `(${CREDENTIAL_KEY_SOURCE})`,
  "i",
);

// Diagnostics also cover OAuth callback data. A generic `code` field is not
// credential-classified because it is common in cacheable metadata and results.
export const REDACTION_KEY_PATTERN = new RegExp(
  `(${CREDENTIAL_KEY_SOURCE}|code)`,
  "i",
);

export function isCredentialClassifiedResult(
  value: unknown,
  seen: Set<object> = new Set<object>(),
): boolean {
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value))
    return value.some((item) => isCredentialClassifiedResult(item, seen));
  return Object.entries(value).some(
    ([name, item]) =>
      (CREDENTIAL_KEY_PATTERN.test(name) &&
        (item === null || typeof item !== "object")) ||
      isCredentialClassifiedResult(item, seen),
  );
}
