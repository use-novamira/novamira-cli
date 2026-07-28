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
import { restUrl, restUrlFromResource } from "../rest/urls.js";
import { WordPressPaginator } from "./paginator.js";
import { diagnoseSchema, type SchemaFinding } from "./schema.js";

export { ABILITY_PAGE_SIZE, MAX_ABILITY_PAGES } from "./paginator.js";

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
    const endpoint = new URL(
      restUrlFromResource(this.profile.siteUrl, resource, [
        "wp-abilities",
        "v1",
        "abilities",
      ]),
    );
    return new WordPressPaginator<AbilityRecord & { readonly name: string }>({
      endpoint,
      expectedOrigin: this.profile.origin,
      fetchPage: async (url) =>
        this.tokens.authenticatedJsonResponse(
          {
            url,
            expectedOrigin: this.profile.origin,
            timeoutMs: this.timeoutMs,
          },
          { unauthorizedReplay: "known-not-accepted" },
        ),
      parseRecord: (value) =>
        abilityRecord(
          value,
          "The WordPress Ability list contains an invalid record.",
        ) as AbilityRecord & { readonly name: string },
    }).collect();
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
