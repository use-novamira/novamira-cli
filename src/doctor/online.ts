// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { AbilityClient, AbilityRecord } from "../abilities/client.js";
import {
  localTokenStatus,
  type AuthStatus,
  type TokenLifecycle,
} from "../auth/token-lifecycle.js";
import {
  assertFeaturesCompatible,
  assertPluginCompatible,
  assertRestContractCompatible,
  assertWordPressCompatible,
  MINIMUM_NOVAMIRA_VERSION,
  REQUIRED_FEATURES,
  type AuthorizationServerMetadata,
  type MetadataClient,
  type ProtectedResourceMetadata,
} from "../auth/metadata.js";
import type { SiteProfile } from "../config/profiles.js";
import { CliError } from "../errors.js";
import {
  offlineDoctorDefinitions,
  runDoctorChecks,
  type DoctorCheck,
  type DoctorCheckDefinition,
  type DoctorReport,
  type OfflineDoctorDependencies,
} from "./engine.js";

const CONTEXT_ABILITY = "novamira/agent-context";
const SKILL_ABILITIES = [
  "novamira/skill-get",
  "novamira/skill-write",
  "novamira/skill-edit",
  "novamira/skill-delete",
] as const;

export interface OnlineDoctorDependencies extends OfflineDoctorDependencies {
  readonly metadata: MetadataClient;
  createTokenLifecycle(profile: SiteProfile): TokenLifecycle;
  createAbilityClient(
    profile: SiteProfile,
    lifecycle: TokenLifecycle,
  ): AbilityClient;
  readonly confirmLogin?: (
    profile: SiteProfile,
    access: "read" | "full",
  ) => Promise<boolean>;
  readonly login?: (
    profile: SiteProfile,
    access: "read" | "full",
  ) => Promise<void>;
}

interface ProbeFailure {
  readonly ok: false;
  readonly error: unknown;
}

interface ProbeSuccess<T> {
  readonly ok: true;
  readonly value: T;
}

type Probe<T> = ProbeSuccess<T> | ProbeFailure;

export function onlineDoctorDefinitions(
  dependencies: OnlineDoctorDependencies,
  options: { readonly fix: boolean; readonly site?: string },
): readonly DoctorCheckDefinition[] {
  const local = offlineDoctorDefinitions(dependencies, options);
  const profile = once(() =>
    dependencies.profiles.select(options.site, dependencies.environment),
  );
  const resource = once(async () => {
    const selected = await requireProbe(profile(), "profile.valid");
    return dependencies.metadata.probeProtectedResourceUnvalidated(
      selected.siteUrl,
    );
  });
  const authorization = once(async () => {
    const selected = await requireProbe(profile(), "profile.valid");
    return dependencies.metadata.authorizationServer(
      selected.siteUrl,
      await requireProbe(resource(), "oauth.resource_metadata"),
    );
  });
  const lifecycle = once(async () => {
    const selected = await requireProbe(profile(), "profile.valid");
    return dependencies.createTokenLifecycle(selected);
  });
  let repairedLogin = false;
  const repair = once(async () => {
    if (
      !options.fix ||
      dependencies.confirmLogin === undefined ||
      dependencies.login === undefined
    )
      return false;
    const selected = await requireProbe(profile(), "profile.valid");
    let localStatus: ReturnType<typeof localTokenStatus>;
    try {
      localStatus = localTokenStatus(
        await dependencies.credentials.read({
          profileName: selected.name,
          origin: selected.origin,
        }),
        dependencies.now?.() ?? Date.now(),
      );
    } catch {
      localStatus = { access: null, credentialState: "absent" };
    }
    if (
      localStatus.credentialState !== "absent" &&
      localStatus.credentialState !== "expired"
    )
      return false;
    const access = localStatus.access === "full" ? "full" : "read";
    if (!(await dependencies.confirmLogin(selected, access))) return false;
    await dependencies.login(selected, access);
    repairedLogin = true;
    return true;
  });
  const authStatus = once(async () => {
    await requireProbe(repair(), "oauth.token");
    return (await requireProbe(lifecycle(), "profile.valid")).status();
  });
  const abilities = once(async () => {
    const selected = await requireProbe(profile(), "profile.valid");
    return dependencies.createAbilityClient(
      selected,
      await requireProbe(lifecycle(), "profile.valid"),
    );
  });
  const list = once(async () =>
    (await requireProbe(abilities(), "profile.valid")).listAbilities(),
  );
  const item = once(async () =>
    (await requireProbe(abilities(), "profile.valid")).describe(
      CONTEXT_ABILITY,
    ),
  );
  const context = once(async () =>
    (await requireProbe(abilities(), "profile.valid")).agentContext(
      (await requireProbe(resource(), "oauth.resource_metadata")).novamira,
    ),
  );

  const compatibilityCheck = (
    id: string,
    label: string,
    validate: (metadata: ProtectedResourceMetadata) => void,
    evidence: (metadata: ProtectedResourceMetadata) => Record<string, unknown>,
  ): DoctorCheckDefinition => ({
    id,
    run: () =>
      checkProbe(resource(), `${label} is supported.`, (metadata) => {
        validate(metadata);
        return evidence(metadata);
      }),
  });

  return [
    ...local.filter(({ id }) => id !== "oauth.token"),
    {
      id: "oauth.resource_metadata",
      run: () =>
        checkProbe(
          resource(),
          "Protected-resource metadata is valid.",
          (value) => ({
            bearerHeader: value.bearer_methods_supported.includes("header"),
            scopes: advertisedScopes(value.scopes_supported),
          }),
        ),
    },
    {
      id: "oauth.server_metadata",
      run: () =>
        checkProbe(
          authorization(),
          "Authorization-server metadata is valid.",
          authorizationEvidence,
        ),
    },
    compatibilityCheck(
      "server.wordpress_version",
      "The WordPress version",
      ({ novamira }) => {
        assertWordPressCompatible(novamira);
      },
      ({ novamira }) => ({
        wordpressVersion: novamira.wordpress_version,
        minimumWordpressVersion: novamira.minimum_wordpress_version,
        requiredVersion: "6.9",
      }),
    ),
    compatibilityCheck(
      "server.plugin_version",
      "The Novamira plugin version",
      ({ novamira }) => {
        assertPluginCompatible(novamira);
      },
      ({ novamira }) => ({
        pluginVersion: novamira.plugin_version,
        requiredVersion: MINIMUM_NOVAMIRA_VERSION,
      }),
    ),
    compatibilityCheck(
      "server.rest_api_contract",
      "The REST API contract",
      ({ novamira }) => {
        assertRestContractCompatible(novamira);
      },
      ({ novamira }) => ({
        restApiVersion: novamira.rest_api_version,
        requiredVersion: 1,
      }),
    ),
    {
      id: "server.features",
      run: () =>
        checkProbe(
          context(),
          "Required features agree across public and authenticated metadata.",
          async (value) => {
            const metadata = await requireProbe(
              resource(),
              "oauth.resource_metadata",
            );
            assertFeaturesCompatible(metadata.novamira);
            return {
              required: [...REQUIRED_FEATURES],
              agreement: value.server !== undefined,
            };
          },
        ),
    },
    {
      id: "oauth.scope",
      run: async () => {
        const [resourceResult, authorizationResult, status] = await Promise.all(
          [resource(), authorization(), authStatus()],
        );
        if (!resourceResult.ok) return failedCheck(resourceResult.error);
        if (!authorizationResult.ok)
          return failedCheck(authorizationResult.error);
        if (!status.ok) return failedCheck(status.error);
        if (status.value.access !== "read" && status.value.access !== "full")
          return {
            status: "fail",
            summary: "No valid Ability scope is granted locally.",
            evidence: {
              category: "insufficient_scope",
              access: status.value.access,
            },
          };
        return {
          status: "pass",
          summary: "The selected Ability scope is advertised and granted.",
          evidence: {
            access: status.value.access,
            protectedResource: advertisedScopes(
              resourceResult.value.scopes_supported,
            ),
            authorizationServer: advertisedScopes(
              authorizationResult.value.scopes_supported,
            ),
          },
        };
      },
    },
    {
      id: "oauth.token",
      run: async () => {
        const status = await authStatus();
        if (!status.ok) return failedCheck(status.error);
        return tokenStatusCheck(status.value, repairedLogin);
      },
    },
    {
      id: "rest.abilities_list",
      run: () =>
        checkProbe(
          list(),
          "The authenticated Ability list is reachable.",
          (records) => ({
            abilities: records.length,
          }),
        ),
    },
    {
      id: "rest.ability_info",
      run: () =>
        checkProbe(
          item(),
          "The core Ability item route is reachable.",
          (record) => ({
            ability: record.name,
          }),
        ),
    },
    {
      id: "rest.shim",
      run: () =>
        checkProbe(
          context(),
          "The readonly execution shim is reachable.",
          () => ({
            ability: CONTEXT_ABILITY,
          }),
        ),
    },
    {
      id: "rest.context",
      run: () =>
        checkProbe(
          context(),
          "Agent context is valid and current.",
          contextEvidence,
        ),
    },
    {
      id: "rest.skills",
      run: () =>
        checkProbe(
          list(),
          "All site skill Abilities are REST-visible.",
          (records) => {
            const names = new Set(records.map(({ name }) => name));
            const missing = SKILL_ABILITIES.filter((name) => !names.has(name));
            if (missing.length > 0)
              throw new CliError(
                "server_unsupported",
                "Required site skill Abilities are missing.",
                {
                  details: { missing },
                },
              );
            return { abilities: [...SKILL_ABILITIES] };
          },
        ),
    },
    {
      id: "site.permission",
      run: async () => {
        const result = await list();
        if (!result.ok) {
          const failed = failedCheck(result.error);
          if (failed.evidence.category === "insufficient_scope")
            return {
              ...failed,
              summary:
                "The token subject lacks Novamira management permission.",
              evidence: {
                ...failed.evidence,
                category: "site_permission_denied",
              },
            };
          return failed;
        }
        return {
          status: "pass",
          summary: "The token subject retains Novamira management permission.",
          evidence: { managementPermission: true },
        };
      },
    },
  ];
}

export async function runOnlineDoctor(
  dependencies: OnlineDoctorDependencies,
  options: { readonly fix: boolean; readonly site?: string },
): Promise<DoctorReport> {
  return runDoctorChecks(onlineDoctorDefinitions(dependencies, options), {
    offline: false,
    fix: options.fix,
  });
}

function once<T>(operation: () => Promise<T>): () => Promise<Probe<T>> {
  let result: Promise<Probe<T>> | undefined;
  return () =>
    (result ??= operation().then(
      (value) => ({ ok: true, value }),
      (error: unknown) => ({ ok: false, error }),
    ));
}

async function requireProbe<T>(
  probe: Promise<Probe<T>>,
  source: string,
): Promise<T> {
  const result = await probe;
  if (result.ok) return result.value;
  throw new ProbeBlocked(source, result.error);
}

class ProbeBlocked extends Error {
  constructor(
    readonly source: string,
    readonly original: unknown,
  ) {
    super(`Probe blocked by ${source}`);
  }
}

async function checkProbe<T>(
  probe: Promise<Probe<T>>,
  summary: string,
  evidence: (
    value: T,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>,
): Promise<Omit<DoctorCheck, "id">> {
  const result = await probe;
  if (!result.ok) return failedCheck(result.error);
  try {
    return { status: "pass", summary, evidence: await evidence(result.value) };
  } catch (error) {
    return failedCheck(error);
  }
}

function failedCheck(error: unknown): Omit<DoctorCheck, "id"> {
  const blocked = error instanceof ProbeBlocked ? error : undefined;
  const cause = blocked?.original ?? error;
  const cliError = cause instanceof CliError ? cause : undefined;
  const category = errorCategory(cliError?.code);
  return {
    status: "fail",
    summary:
      blocked === undefined
        ? failureSummary(category)
        : `The check is blocked by ${blocked.source}.`,
    evidence: {
      category,
      ...(cliError === undefined
        ? {}
        : { code: cliError.code, retryable: cliError.retryable }),
      ...(blocked === undefined ? {} : { blockedBy: blocked.source }),
    },
  };
}

function errorCategory(code: CliError["code"] | undefined): string {
  if (code === "network_error") return "unreachable";
  if (code === "auth_required" || code === "auth_expired")
    return "unauthorized";
  if (code === "insufficient_scope") return "insufficient_scope";
  if (code === "ability_not_found" || code === "ability_hidden")
    return "missing_surface";
  if (code === "server_unsupported") return "unsupported";
  return "check_error";
}

function failureSummary(category: string): string {
  const fallback = "The check could not be completed safely.";
  const summaries: Record<string, string> = {
    unreachable: "The remote service is unreachable.",
    unauthorized: "Authentication is required or expired.",
    insufficient_scope: "The granted scope or site permission is insufficient.",
    missing_surface: "The required REST surface is missing or hidden.",
    unsupported: "The server surface is unsupported or inconsistent.",
    check_error: fallback,
  };
  return summaries[category] ?? fallback;
}

function advertisedScopes(scopes: readonly string[]): readonly string[] {
  return ["abilities:read", "abilities"].filter((scope) =>
    scopes.includes(scope),
  );
}

function authorizationEvidence(
  value: AuthorizationServerMetadata,
): Record<string, unknown> {
  return {
    authorizationCode: value.response_types_supported.includes("code"),
    refreshToken: value.grant_types_supported.includes("refresh_token"),
    pkceS256: value.code_challenge_methods_supported.includes("S256"),
    publicClient: value.token_endpoint_auth_methods_supported.includes("none"),
    registration: true,
    revocation: true,
  };
}

function tokenStatusCheck(
  status: AuthStatus,
  fixed: boolean,
): Omit<DoctorCheck, "id"> {
  const baseEvidence = {
    credentialState: status.credentialState,
    access: status.access,
    expiresAt: status.expiresAt ?? null,
    restReachable: status.restReachable,
    ...(status.restError === undefined ? {} : { restError: status.restError }),
  };
  if (
    status.credentialState === "absent" ||
    status.credentialState === "invalid"
  )
    return {
      status: "fail",
      summary: "No usable OAuth token is stored.",
      evidence: { ...baseEvidence, category: "unauthorized" },
    };
  if (status.credentialState === "expired")
    return {
      status: "fail",
      summary: "The OAuth token is expired.",
      evidence: { ...baseEvidence, category: "unauthorized" },
    };
  if (!status.restReachable) {
    const category = errorCategory(status.restError);
    return {
      status: "fail",
      summary: failureSummary(category),
      evidence: { ...baseEvidence, category },
    };
  }
  return {
    status: status.credentialState === "near_expiry" ? "warn" : "pass",
    summary: fixed
      ? "Interactive login repaired the OAuth token state."
      : status.credentialState === "near_expiry"
        ? "The OAuth token is near expiry but remains reachable."
        : "The OAuth token is valid and accepted.",
    evidence: baseEvidence,
    ...(fixed ? { fixed: true } : {}),
  };
}

function contextEvidence(value: AbilityRecord): Record<string, unknown> {
  return {
    instructions: typeof value.instructions === "string",
    skills: Array.isArray(value.skills) ? value.skills.length : 0,
    environment:
      value.environment !== null && typeof value.environment === "object",
    compatibilityAgreement: true,
  };
}
