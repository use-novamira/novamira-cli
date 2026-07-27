// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface SchemaFinding {
  readonly path: string;
  readonly keyword: string;
  readonly message: string;
}

const MAX_FINDINGS = 20;
const MAX_VISITS = 10_000;
const MAX_DEPTH = 32;
const MAX_FINDING_PATH_LENGTH = 512;
const MAX_FINDING_MESSAGE_LENGTH = 512;
const MAX_DIAGNOSTIC_TYPES = 32;
const MAX_DIAGNOSTIC_TYPE_LENGTH = 64;

export function diagnoseSchema(
  value: unknown,
  schema: unknown,
): readonly SchemaFinding[] {
  const findings: SchemaFinding[] = [];
  const state = { visits: 0 };
  visit(value, schema, "$", findings, state, 0);
  return findings;
}

function visit(
  value: unknown,
  schema: unknown,
  path: string,
  findings: SchemaFinding[],
  state: { visits: number },
  depth: number,
): void {
  state.visits += 1;
  if (findings.length >= MAX_FINDINGS) return;
  if (state.visits > MAX_VISITS || depth > MAX_DEPTH) {
    add(
      findings,
      path,
      "diagnosticLimit",
      "schema exceeds the local diagnostic complexity limit",
    );
    return;
  }
  if (schema === true) return;
  if (schema === false) {
    add(findings, path, "falseSchema", "value is disallowed by the schema");
    return;
  }
  if (!isObject(schema)) return;

  if (Array.isArray(schema.allOf))
    for (const child of schema.allOf)
      visit(value, child, path, findings, state, depth + 1);
  if (
    Array.isArray(schema.anyOf) &&
    !schema.anyOf.some(
      (child) => !branchFindings(value, child, path, state, depth).length,
    )
  )
    add(findings, path, "anyOf", "value does not match any allowed schema");
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter(
      (child) => !branchFindings(value, child, path, state, depth).length,
    ).length;
    if (matches !== 1)
      add(findings, path, "oneOf", "value must match exactly one schema");
  }

  if (Object.hasOwn(schema, "const") && !sameJson(value, schema.const))
    add(findings, path, "const", "value does not match the required constant");
  if (
    Array.isArray(schema.enum) &&
    !schema.enum.some((candidate) => sameJson(value, candidate))
  )
    add(findings, path, "enum", "value is not in the allowed set");

  const types = diagnosticTypes(schema.type);
  if (types.length > 0 && !types.some((type) => matchesType(value, type))) {
    add(
      findings,
      path,
      "type",
      `expected ${types.join(" or ")}, received ${jsonType(value)}`,
    );
    return;
  }

  if (typeof value === "string") {
    checkLength(value.length, schema, path, findings, "Length");
  } else if (Array.isArray(value)) {
    checkLength(value.length, schema, path, findings, "Items");
    if (Object.hasOwn(schema, "items"))
      value.forEach((item, index) => {
        visit(
          item,
          schema.items,
          `${path}[${String(index)}]`,
          findings,
          state,
          depth + 1,
        );
      });
  } else if (isObject(value)) {
    const properties = isObject(schema.properties)
      ? schema.properties
      : undefined;
    if (Array.isArray(schema.required)) {
      for (const name of schema.required) {
        if (typeof name === "string" && !Object.hasOwn(value, name))
          add(
            findings,
            findingPath(path, name),
            "required",
            "required property is missing",
          );
      }
    }
    for (const [name, item] of Object.entries(value)) {
      if (properties !== undefined && Object.hasOwn(properties, name))
        visit(
          item,
          properties[name],
          findingPath(path, name),
          findings,
          state,
          depth + 1,
        );
      else if (schema.additionalProperties === false)
        add(
          findings,
          findingPath(path, name),
          "additionalProperties",
          "additional property is not allowed",
        );
      else if (isObject(schema.additionalProperties))
        visit(
          item,
          schema.additionalProperties,
          findingPath(path, name),
          findings,
          state,
          depth + 1,
        );
    }
  } else if (typeof value === "number" && Number.isFinite(value)) {
    if (typeof schema.minimum === "number" && value < schema.minimum)
      add(findings, path, "minimum", "number is below the minimum");
    if (typeof schema.maximum === "number" && value > schema.maximum)
      add(findings, path, "maximum", "number is above the maximum");
  }
}

function diagnosticTypes(value: unknown): readonly string[] {
  if (typeof value === "string")
    return value.length <= MAX_DIAGNOSTIC_TYPE_LENGTH ? [value] : [];
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_TYPES) return [];
  const types: string[] = [];
  for (const item of value as unknown[]) {
    if (typeof item !== "string" || item.length > MAX_DIAGNOSTIC_TYPE_LENGTH)
      return [];
    types.push(item);
  }
  return types;
}

function findingPath(parent: string, property: string): string {
  const path = `${parent}.${property}`;
  return path.length <= MAX_FINDING_PATH_LENGTH
    ? path
    : `${path.slice(0, MAX_FINDING_PATH_LENGTH - 3)}...`;
}

function branchFindings(
  value: unknown,
  schema: unknown,
  path: string,
  state: { visits: number },
  depth: number,
): SchemaFinding[] {
  const findings: SchemaFinding[] = [];
  visit(value, schema, path, findings, state, depth + 1);
  return findings;
}

function checkLength(
  length: number,
  schema: Record<string, unknown>,
  path: string,
  findings: SchemaFinding[],
  suffix: "Length" | "Items",
): void {
  const minimum = schema[`min${suffix}`];
  const maximum = schema[`max${suffix}`];
  if (typeof minimum === "number" && length < minimum)
    add(findings, path, `min${suffix}`, "value is shorter than the minimum");
  if (typeof maximum === "number" && length > maximum)
    add(findings, path, `max${suffix}`, "value is longer than the maximum");
}

function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case "null":
      return value === null;
    case "array":
      return Array.isArray(value);
    case "object":
      return isObject(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "string":
    case "boolean":
      return typeof value === type;
    default:
      return true;
  }
}

function jsonType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number" && Number.isInteger(value)) return "integer";
  return typeof value;
}

function sameJson(left: unknown, right: unknown): boolean {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

function add(
  findings: SchemaFinding[],
  path: string,
  keyword: string,
  message: string,
): void {
  if (findings.length < MAX_FINDINGS)
    findings.push({
      path: path.slice(0, MAX_FINDING_PATH_LENGTH),
      keyword,
      message: message.slice(0, MAX_FINDING_MESSAGE_LENGTH),
    });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
