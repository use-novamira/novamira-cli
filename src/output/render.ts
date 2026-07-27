// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { CliError } from "../errors.js";

export interface InvocationMeta {
  readonly requestId: string;
  readonly site?: string;
  readonly origin?: string;
  readonly warnings?: readonly {
    readonly code: string;
    readonly message: string;
    readonly details?: Readonly<Record<string, unknown>>;
  }[];
  readonly truncated?: boolean;
  readonly bytes?: number;
  readonly artifact?: string;
}

export interface OutputStreams {
  readonly stdout: { write(chunk: string): unknown };
  readonly stderr: { write(chunk: string): unknown };
}

export function writeJsonSuccess(
  streams: OutputStreams,
  data: unknown,
  meta: InvocationMeta,
): void {
  streams.stdout.write(`${JSON.stringify({ ok: true, data, meta })}\n`);
}

export function writeJsonFailure(
  streams: OutputStreams,
  error: CliError,
): void {
  const body: Record<string, unknown> = {
    code: error.code,
    message: error.message,
    retryable: error.retryable,
  };
  if (error.remoteCode !== undefined) body.remoteCode = error.remoteCode;
  if (error.details !== undefined) body.details = error.details;
  streams.stdout.write(`${JSON.stringify({ ok: false, error: body })}\n`);
}

export function writeHumanSuccess(streams: OutputStreams, data: unknown): void {
  streams.stdout.write(
    `${typeof data === "string" ? data : JSON.stringify(data, null, 2)}\n`,
  );
}

export function writeHumanAbilityDescription(
  streams: OutputStreams,
  data: Readonly<Record<string, unknown>>,
): void {
  const meta = isRecord(data.meta) ? data.meta : undefined;
  const annotations = isRecord(data.annotations)
    ? data.annotations
    : isRecord(meta?.annotations)
      ? meta.annotations
      : undefined;
  const lines = [
    `Ability: ${String(data.name)}`,
    `readonly: ${annotationValue(annotations?.readonly)}`,
    `destructive: ${annotationValue(annotations?.destructive)}`,
    `idempotent: ${annotationValue(annotations?.idempotent)}`,
  ];
  if (typeof data.instructions === "string")
    lines.push(`instructions: ${data.instructions}`);
  lines.push("", JSON.stringify(data, null, 2));
  streams.stdout.write(`${lines.join("\n")}\n`);
}

export function writeHumanFailure(
  streams: OutputStreams,
  error: CliError,
): void {
  streams.stderr.write(`Error [${error.code}]: ${error.message}\n`);
}

function annotationValue(value: unknown): string {
  return typeof value === "boolean" ? String(value) : "not advertised";
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
