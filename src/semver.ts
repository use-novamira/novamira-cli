// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

const IDENTIFIER = "(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)";
const SEMVER = new RegExp(
  `^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)` +
    `(?:-(${IDENTIFIER}(?:\\.${IDENTIFIER})*))?` +
    `(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`,
);
const NUMERIC = /^\d+$/;

export class InvalidSemverError extends Error {
  constructor(value: string) {
    super(`Version ${value} is not a valid semantic version.`);
    this.name = "InvalidSemverError";
  }
}

export function isSemver(value: unknown): value is string {
  return typeof value === "string" && SEMVER.test(value);
}

export function compareSemver(left: string, right: string): number {
  const leftMatch = SEMVER.exec(left);
  const rightMatch = SEMVER.exec(right);
  if (leftMatch === null) throw new InvalidSemverError(left);
  if (rightMatch === null) throw new InvalidSemverError(right);
  for (let index = 1; index <= 3; index += 1) {
    // Compare as digit strings so a release number beyond the safe integer
    // range keeps full precision.
    const difference = compareNumeric(
      leftMatch[index] ?? "0",
      rightMatch[index] ?? "0",
    );
    if (difference !== 0) return difference;
  }
  if (leftMatch[4] === undefined && rightMatch[4] !== undefined) return 1;
  if (leftMatch[4] !== undefined && rightMatch[4] === undefined) return -1;
  return comparePrerelease(leftMatch[4], rightMatch[4]);
}

/** Compare two unsigned decimal strings without converting them to numbers. */
function compareNumeric(left: string, right: string): number {
  const leftDigits = left.replace(/^0+(?=\d)/, "");
  const rightDigits = right.replace(/^0+(?=\d)/, "");
  if (leftDigits.length !== rightDigits.length)
    return leftDigits.length < rightDigits.length ? -1 : 1;
  if (leftDigits === rightDigits) return 0;
  return leftDigits < rightDigits ? -1 : 1;
}

function comparePrerelease(
  left: string | undefined,
  right: string | undefined,
): number {
  if (left === right) return 0;
  const leftParts = left?.split(".") ?? [];
  const rightParts = right?.split(".") ?? [];
  for (
    let index = 0;
    index < Math.max(leftParts.length, rightParts.length);
    index += 1
  ) {
    const leftPart = leftParts[index];
    const rightPart = rightParts[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumeric = NUMERIC.test(leftPart);
    const rightNumeric = NUMERIC.test(rightPart);
    if (leftNumeric && rightNumeric) return compareNumeric(leftPart, rightPart);
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    // SemVer orders alphanumeric identifiers by ASCII, not by locale.
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}
