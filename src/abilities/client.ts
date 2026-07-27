// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { TokenLifecycle } from "../auth/token-lifecycle.js";
import {
  assertMatchingCompatibility,
  type MetadataClient,
  type ServerCompatibility,
} from "../auth/metadata.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import type { SiteProfile } from "../config/profiles.js";
import { CliError } from "../errors.js";
import type { JsonResponse } from "../rest/http-client.js";
import { restUrl, restUrlFromResource } from "../rest/urls.js";
import { diagnoseSchema, type SchemaFinding } from "./schema.js";

export const ABILITY_PAGE_SIZE = 100;
export const MAX_ABILITY_PAGES = 1_000;

export type AbilityRecord = Readonly<Record<string, unknown>>;

export interface CompactAbility {
  readonly name: string;
  readonly label?: string;
  readonly description?: string;
  readonly category?: string;
  readonly annotations?: Readonly<Record<string, boolean>>;
}

export interface DiscoverResult {
  readonly context: AbilityRecord;
  readonly abilities: readonly CompactAbility[];
}

export interface AbilityWarning {
  readonly code: "local_input_schema_mismatch" | "local_output_schema_mismatch";
  readonly message: string;
  readonly details: { readonly findings: readonly SchemaFinding[] };
}

export interface RunOptions {
  readonly fresh?: boolean;
  readonly confirmed?: boolean;
  readonly confirm?: (abilityName: string) => Promise<boolean>;
}

export interface RunResult {
  readonly data: unknown;
  readonly warnings: readonly AbilityWarning[];
}

export class AbilityClient {
  constructor(
    private readonly profile: SiteProfile,
    private readonly metadata: MetadataClient,
    private readonly tokens: TokenLifecycle,
    private readonly cache: AbilityMetadataCache,
    private readonly timeoutMs = 30_000,
  ) {}

  async discover(): Promise<DiscoverResult> {
    const publicMetadata = await this.metadata.protectedResource(
      this.profile.siteUrl,
    );
    const resource = routingResource(this.profile.siteUrl, publicMetadata);
    const records = await this.listAbilities(resource);
    let context: AbilityRecord;
    try {
      context = await this.agentContext(publicMetadata.novamira, resource);
    } catch (cause) {
      if (
        cause instanceof CliError &&
        ["auth_required", "auth_expired", "network_error"].includes(cause.code)
      )
        throw cause;
      throw unsupported(
        "The required Novamira agent context is unavailable.",
        cause,
      );
    }

    for (const record of records)
      await this.cacheRecord(record, publicMetadata.novamira.rest_api_version);

    return {
      context,
      abilities: records.map((record) => compactAbility(record)),
    };
  }

  async describe(abilityName: string): Promise<AbilityRecord> {
    const publicMetadata = await this.metadata.protectedResource(
      this.profile.siteUrl,
    );
    const raw = await this.tokens.authenticatedJson(
      {
        url: restUrlFromResource(
          this.profile.siteUrl,
          routingResource(this.profile.siteUrl, publicMetadata),
          ["wp-abilities", "v1", "abilities", ...abilityName.split("/")],
        ),
        expectedOrigin: this.profile.origin,
        timeoutMs: this.timeoutMs,
      },
      { unauthorizedReplay: "known-not-accepted" },
    );
    const record = abilityRecord(raw, "The Ability description is invalid.");
    if (record.name !== abilityName)
      throw unsupported(
        "The Ability description does not match the requested name.",
      );
    await this.cacheRecord(record, publicMetadata.novamira.rest_api_version);
    return record;
  }

  async run(
    abilityName: string,
    input: unknown,
    options: RunOptions = {},
  ): Promise<RunResult> {
    const publicMetadata = await this.metadata.protectedResource(
      this.profile.siteUrl,
    );
    let record: AbilityRecord | undefined;
    if (options.fresh !== true) {
      const cached = await this.cache.get(
        {
          origin: this.profile.origin,
          profileName: this.profile.name,
          abilityName,
        },
        publicMetadata.novamira.rest_api_version,
      );
      record = cachedRecord(cached, abilityName);
    }
    record ??= await this.describe(abilityName);
    const meta = isObject(record.meta) ? record.meta : undefined;
    if (meta?.show_in_rest !== true)
      throw new CliError(
        "ability_hidden",
        "The requested Ability is not REST-visible.",
      );
    const annotations = annotationsFor(record);
    if (
      annotations?.destructive === true &&
      options.confirmed !== true &&
      (options.confirm === undefined || !(await options.confirm(abilityName)))
    )
      throw new CliError(
        "confirmation_required",
        "Destructive Ability execution requires confirmation or --yes.",
      );

    const warnings: AbilityWarning[] = [];
    const inputFindings = diagnoseSchema(input, record.input_schema);
    if (inputFindings.length > 0)
      warnings.push({
        code: "local_input_schema_mismatch",
        message:
          "Local input schema diagnostics found a mismatch; the server remains authoritative.",
        details: { findings: inputFindings },
      });

    const data = await this.tokens.authenticatedJson(
      {
        url: restUrlFromResource(
          this.profile.siteUrl,
          routingResource(this.profile.siteUrl, publicMetadata),
          ["novamira", "v1", "abilities", ...abilityName.split("/"), "run"],
        ),
        expectedOrigin: this.profile.origin,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ input }),
        timeoutMs: this.timeoutMs,
      },
      {
        unauthorizedReplay:
          annotations?.idempotent === true ? "known-not-accepted" : "never",
      },
    );
    const outputFindings = diagnoseSchema(data, record.output_schema);
    if (outputFindings.length > 0)
      warnings.push({
        code: "local_output_schema_mismatch",
        message:
          "Successful output disagrees with the advertised local schema.",
        details: { findings: outputFindings },
      });
    return { data, warnings };
  }

  async listAbilities(resource?: string): Promise<AbilityRecord[]> {
    resource ??= routingResource(
      this.profile.siteUrl,
      await this.metadata.protectedResource(this.profile.siteUrl),
    );
    const records: AbilityRecord[] = [];
    const names = new Set<string>();
    let expectedTotal: number | undefined;
    let pagination: "total" | "link" | undefined;

    for (let page = 1; page <= MAX_ABILITY_PAGES; page += 1) {
      const response = await this.abilityPage(page, resource);
      if (!Array.isArray(response.data))
        throw unsupported("The WordPress Ability list is invalid.");
      const pageRecords = response.data.map((value) =>
        abilityRecord(
          value,
          "The WordPress Ability list contains an invalid record.",
        ),
      );
      for (const record of pageRecords) {
        const name = record.name as string;
        if (names.has(name))
          throw unsupported(
            "The WordPress Ability catalog changed during discovery.",
          );
        names.add(name);
        records.push(record);
      }

      const total = totalPages(response.headers.get("x-wp-totalpages"));
      const linkHeader = response.headers.get("link");
      pagination ??=
        total === undefined
          ? linkHeader === null
            ? undefined
            : "link"
          : "total";
      if (pagination === undefined)
        throw unsupported(
          "The WordPress Ability list lacks pagination metadata.",
        );
      if (pagination === "total" && total === undefined)
        throw unsupported(
          "The WordPress Ability page count changed during discovery.",
        );
      if (pagination === "link" && total !== undefined)
        throw unsupported(
          "The WordPress Ability pagination method changed during discovery.",
        );
      if (total !== undefined) {
        if (expectedTotal !== undefined && total !== expectedTotal)
          throw unsupported(
            "The WordPress Ability page count changed during discovery.",
          );
        expectedTotal = total;
        if (total > MAX_ABILITY_PAGES)
          throw unsupported(
            "The WordPress Ability catalog exceeds the page safety limit.",
          );
        if (total === 0 && (page !== 1 || pageRecords.length !== 0))
          throw unsupported(
            "The WordPress Ability page count is inconsistent.",
          );
        if (total > 0 && page > total)
          throw unsupported(
            "The WordPress Ability page count is inconsistent.",
          );
      }

      const next = linkHeader === null ? undefined : nextLink(linkHeader);
      if (next !== undefined) {
        this.assertNextPage(next, page + 1, resource);
      }
      if (
        expectedTotal !== undefined &&
        next !== undefined &&
        page >= expectedTotal
      )
        throw unsupported("Ability pagination metadata is inconsistent.");

      if (expectedTotal !== undefined) {
        if (expectedTotal === 0 || page === expectedTotal) return records;
        continue;
      }
      if (next !== undefined) continue;
      return records;
    }
    throw unsupported(
      "The WordPress Ability catalog exceeds the page safety limit.",
    );
  }

  private async abilityPage(
    page: number,
    resource: string,
  ): Promise<JsonResponse<unknown>> {
    const url = new URL(
      restUrlFromResource(this.profile.siteUrl, resource, [
        "wp-abilities",
        "v1",
        "abilities",
      ]),
    );
    url.searchParams.set("per_page", String(ABILITY_PAGE_SIZE));
    url.searchParams.set("page", String(page));
    return this.tokens.authenticatedJsonResponse(
      {
        url,
        expectedOrigin: this.profile.origin,
        timeoutMs: this.timeoutMs,
      },
      { unauthorizedReplay: "known-not-accepted" },
    );
  }

  private assertNextPage(
    value: string,
    expectedPage: number,
    resource: string,
  ): void {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw unsupported("Ability pagination contains an invalid next link.");
    }
    const expected = new URL(
      restUrlFromResource(this.profile.siteUrl, resource, [
        "wp-abilities",
        "v1",
        "abilities",
      ]),
    );
    if (
      url.origin !== this.profile.origin ||
      url.pathname !== expected.pathname ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      url.searchParams.get("rest_route") !==
        expected.searchParams.get("rest_route") ||
      url.searchParams.get("page") !== String(expectedPage) ||
      url.searchParams.get("per_page") !== String(ABILITY_PAGE_SIZE)
    )
      throw unsupported(
        "Ability pagination contains an unsafe or looping next link.",
      );
  }

  async agentContext(
    expected: ServerCompatibility,
    resource?: string,
  ): Promise<AbilityRecord> {
    resource ??= routingResource(
      this.profile.siteUrl,
      await this.metadata.protectedResource(this.profile.siteUrl),
    );
    const raw = await this.tokens.authenticatedJson(
      {
        url: restUrlFromResource(this.profile.siteUrl, resource, [
          "novamira",
          "v1",
          "abilities",
          "novamira",
          "agent-context",
          "run",
        ]),
        expectedOrigin: this.profile.origin,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ input: null }),
        timeoutMs: this.timeoutMs,
      },
      { unauthorizedReplay: "known-not-accepted" },
    );
    const context = object(raw, "The Novamira agent context is invalid.");
    if (
      typeof context.instructions !== "string" ||
      !Array.isArray(context.skills) ||
      context.skills.some((skill) => !isObject(skill)) ||
      !isObject(context.environment)
    )
      throw unsupported("The Novamira agent context is incomplete.");
    assertMatchingCompatibility(expected, context.server);
    return context;
  }

  private async cacheRecord(
    record: AbilityRecord,
    contractVersion: number,
  ): Promise<void> {
    await this.cache.put(
      {
        origin: this.profile.origin,
        profileName: this.profile.name,
        abilityName: record.name as string,
      },
      contractVersion,
      record,
    );
  }
}

function routingResource(
  site: string,
  metadata: { readonly resource?: string },
): string {
  return metadata.resource ?? restUrl(site, ["mcp", "novamira-oauth"]);
}

function cachedRecord(
  value: unknown,
  abilityName: string,
): AbilityRecord | undefined {
  if (!isObject(value) || value.name !== abilityName) return undefined;
  return value;
}

function annotationsFor(
  record: AbilityRecord,
): Readonly<Record<string, unknown>> | undefined {
  if (isObject(record.annotations)) return record.annotations;
  const meta = isObject(record.meta) ? record.meta : undefined;
  return isObject(meta?.annotations) ? meta.annotations : undefined;
}

function abilityRecord(value: unknown, message: string): AbilityRecord {
  const record = object(value, message);
  if (typeof record.name !== "string" || !validAbilityName(record.name))
    throw unsupported(message);
  return record;
}

function validAbilityName(value: string): boolean {
  const segments = value.split("/");
  return segments.length >= 2 && segments.every((segment) => segment !== "");
}

function compactAbility(record: AbilityRecord): CompactAbility {
  const compact: {
    name: string;
    label?: string;
    description?: string;
    category?: string;
    annotations?: Readonly<Record<string, boolean>>;
  } = { name: record.name as string };
  for (const field of ["label", "description", "category"] as const) {
    if (typeof record[field] === "string") compact[field] = record[field];
  }
  const meta = isObject(record.meta) ? record.meta : undefined;
  const source = isObject(record.annotations)
    ? record.annotations
    : isObject(meta?.annotations)
      ? meta.annotations
      : undefined;
  if (source !== undefined) {
    const annotations = Object.fromEntries(
      ["readonly", "destructive", "idempotent"].flatMap((name) =>
        typeof source[name] === "boolean" ? [[name, source[name]]] : [],
      ),
    ) as Record<string, boolean>;
    if (Object.keys(annotations).length > 0) compact.annotations = annotations;
  }
  return compact;
}

function totalPages(value: string | null): number | undefined {
  if (value === null) return undefined;
  if (!/^(0|[1-9]\d*)$/.test(value))
    throw unsupported("The WordPress Ability page count is invalid.");
  const total = Number(value);
  if (!Number.isSafeInteger(total))
    throw unsupported("The WordPress Ability page count is invalid.");
  return total;
}

function nextLink(value: string): string | undefined {
  if (value.trim() === "")
    throw unsupported("Ability pagination Link metadata is invalid.");
  let next: string | undefined;
  for (const part of value.split(/,(?=\s*<)/)) {
    const match = /^\s*<([^>]+)>\s*((?:;\s*[^;]+)*)\s*$/.exec(part);
    if (match === null)
      throw unsupported("Ability pagination Link metadata is invalid.");
    const parameters = match[2] ?? "";
    const relation = /(?:^|;)\s*rel\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(
      parameters,
    );
    const relations = (relation?.[1] ?? relation?.[2] ?? "").split(/\s+/);
    if (!relations.includes("next")) continue;
    if (next !== undefined)
      throw unsupported("Ability pagination contains multiple next links.");
    next = match[1];
  }
  return next;
}

function object(value: unknown, message: string): AbilityRecord {
  if (!isObject(value)) throw unsupported(message);
  return value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function unsupported(message: string, cause?: unknown): CliError {
  return new CliError("server_unsupported", message, {
    ...(cause === undefined ? {} : { cause }),
  });
}
