// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createInterface } from "node:readline/promises";
import { AbilityClient } from "../abilities/client.js";
import { parseRunInput } from "../abilities/input.js";
import type { CredentialStore } from "../auth/credentials.js";
import {
  LoginService,
  SystemBrowserLauncher,
  TerminalLoginInteraction,
  type LoginEnvironment,
} from "../auth/login.js";
import { LoopbackCallbackFactory } from "../auth/loopback.js";
import type { MetadataClient } from "../auth/metadata.js";
import { TokenLifecycle } from "../auth/token-lifecycle.js";
import type { AbilityMetadataCache } from "../cache/ability-cache.js";
import type { VerifiedFileSecurity } from "../config/file-security.js";
import type { ProfileLockManager } from "../config/lock.js";
import type { PlatformPaths } from "../config/paths.js";
import type {
  ProfileStore,
  SelectionEnvironment,
  SiteProfile,
} from "../config/profiles.js";
import type { SiteUrlEnvironment } from "../config/site-url.js";
import { runOfflineDoctor } from "../doctor/engine.js";
import { runOnlineDoctor } from "../doctor/online.js";
import { GuideStore } from "../guides/store.js";
import { ArtifactStore } from "../output/artifacts.js";
import { isCredentialClassifiedResult } from "../security/classify.js";
import {
  writeHumanAbilityDescription,
  writeHumanSuccess,
  writeJsonSuccess,
  type InvocationMeta,
  type OutputStreams,
} from "../output/render.js";
import type { HttpClient } from "../rest/http-client.js";
import { getSiteSkill } from "../skills/client.js";
import { CompositeUploader } from "../upload/client.js";
import { installVersion, SpawnInstallRunner } from "../update/install.js";
import { updateNotice, type UpdateChecker } from "../update/notifier.js";
import { DEFAULT_REGISTRY } from "../update/registry.js";
import type {
  AuthLoginOptions,
  CommandHandlers,
  DoctorOptions,
  GlobalOptions,
  GuideGetOptions,
  RunOptions,
  UpdateOptions,
} from "./program.js";

type InvocationWarning = NonNullable<InvocationMeta["warnings"]>[number];
type CommandMeta = Omit<InvocationMeta, "requestId" | "warnings">;

interface CommandResult {
  readonly data: unknown;
  readonly meta?: CommandMeta;
  readonly warnings?: readonly InvocationWarning[];
  readonly humanData?: unknown;
  readonly humanPresentation?: "ability-description";
}

export interface CommandEnvironment
  extends SelectionEnvironment, SiteUrlEnvironment, LoginEnvironment {
  readonly NOVAMIRA_REGISTRY?: string;
}

export interface CommandDependencies {
  readonly version: string;
  readonly requestId: string;
  readonly paths: PlatformPaths;
  readonly security: VerifiedFileSecurity;
  readonly locks: ProfileLockManager;
  readonly profiles: ProfileStore;
  readonly abilityCache: AbilityMetadataCache;
  readonly artifacts: ArtifactStore;
  readonly metadata: MetadataClient;
  readonly http: HttpClient;
  readonly streams: OutputStreams;
  readonly environment: CommandEnvironment;
  getCredentialStore(): Promise<CredentialStore>;
  createUpdateChecker(timeoutMs?: number): UpdateChecker;
  onInvocation(options: GlobalOptions, suppressUpdateNotice: boolean): void;
}

export function createCommandHandlers(
  dependencies: CommandDependencies,
): CommandHandlers {
  const {
    version,
    requestId,
    paths,
    security,
    locks,
    profiles,
    abilityCache,
    artifacts,
    metadata,
    http,
    streams,
    environment,
  } = dependencies;

  const execute = async (
    options: GlobalOptions,
    run: () => Promise<CommandResult> | CommandResult,
    suppressUpdateNotice = false,
  ): Promise<void> => {
    dependencies.onInvocation(options, suppressUpdateNotice);
    const result = await run();
    const warnings =
      result.warnings === undefined || result.warnings.length === 0
        ? undefined
        : result.warnings;
    if (options.json) {
      writeJsonSuccess(streams, result.data, {
        requestId,
        ...result.meta,
        ...(warnings === undefined ? {} : { warnings }),
      });
      return;
    }
    if (!options.quiet && warnings !== undefined)
      for (const warning of warnings)
        streams.stderr.write(`Warning: ${warning.message}\n`);
    if (result.humanPresentation === "ability-description") {
      writeHumanAbilityDescription(
        streams,
        result.data as Readonly<Record<string, unknown>>,
      );
      return;
    }
    writeHumanSuccess(streams, result.humanData ?? result.data);
  };

  const createLoginService = async (
    credentials?: CredentialStore,
  ): Promise<LoginService> => {
    const resolvedCredentials =
      credentials ?? (await dependencies.getCredentialStore());
    return new LoginService(
      profiles,
      locks,
      resolvedCredentials,
      abilityCache,
      metadata,
      http,
      new LoopbackCallbackFactory(),
      new SystemBrowserLauncher(),
      new TerminalLoginInteraction((value) => streams.stderr.write(value)),
      Date.now,
      environment,
    );
  };

  const createSiteContext = async (options: GlobalOptions) => {
    const profile = await profiles.select(options.site, environment);
    const lifecycle = new TokenLifecycle(
      profile,
      locks,
      await dependencies.getCredentialStore(),
      abilityCache,
      metadata,
      http,
      options.timeout,
      Date.now,
      environment,
    );
    return {
      profile,
      lifecycle,
      meta: { site: profile.name, origin: profile.origin },
    };
  };

  const createAbilityContext = async (options: GlobalOptions) => {
    const context = await createSiteContext(options);
    return {
      ...context,
      abilities: new AbilityClient(
        context.profile,
        metadata,
        context.lifecycle,
        abilityCache,
        options.timeout,
        environment,
      ),
    };
  };

  const budgetResult = async (
    data: unknown,
    warnings: readonly InvocationWarning[],
    maxOutputBytes: number,
    meta: CommandMeta,
  ): Promise<CommandResult> => {
    const budgeted = await artifacts.budget(data, {
      maxOutputBytes,
      credentialClassified: isCredentialClassifiedResult(data),
    });
    return {
      data: budgeted.data,
      meta: {
        ...meta,
        ...(budgeted.truncated
          ? {
              truncated: true,
              bytes: budgeted.bytes,
              ...(budgeted.artifact === undefined
                ? {}
                : { artifact: budgeted.artifact }),
            }
          : {}),
      },
      warnings,
    };
  };

  return {
    version: (programVersion, options) =>
      execute(options, () => ({
        data: { version: programVersion },
        humanData: programVersion,
      })),

    authLogin: (siteUrl: string, options: AuthLoginOptions) =>
      execute(options, async () => {
        const result = await (
          await createLoginService()
        ).login({
          siteUrl,
          ...(options.name === undefined ? {} : { name: options.name }),
          noOpen: !options.open,
          device: options.device,
          timeoutMs: options.timeout,
        });
        return {
          data: {
            site: result.profile.name,
            siteUrl: result.profile.siteUrl,
            expiresAt: result.expiresAt,
          },
          meta: {
            site: result.profile.name,
            origin: result.profile.origin,
          },
        };
      }),

    authStatus: (options) =>
      execute(options, async () => {
        const { lifecycle, meta } = await createSiteContext(options);
        return { data: await lifecycle.status(), meta };
      }),

    authLogout: (options) =>
      execute(options, async () => {
        const { lifecycle, meta } = await createSiteContext(options);
        const data = await lifecycle.logout();
        return {
          data,
          meta,
          ...(data.warning === undefined
            ? {}
            : {
                warnings: [
                  {
                    code: "remote_revocation_unavailable",
                    message: data.warning,
                  },
                ],
              }),
        };
      }),

    sitesList: (options) =>
      execute(options, async () => ({ data: await profiles.list() })),

    sitesRemove: (name, options) =>
      execute(options, async () => {
        const removed = await profiles.remove(name);
        return {
          data: { removed: removed.name, siteUrl: removed.siteUrl },
        };
      }),

    discover: (options) =>
      execute(options, async () => {
        const { abilities, meta } = await createAbilityContext(options);
        return { data: await abilities.discover(), meta };
      }),

    describe: (ability, options) =>
      execute(options, async () => {
        const { abilities, meta } = await createAbilityContext(options);
        return {
          data: await abilities.describe(ability),
          meta,
          humanPresentation: "ability-description",
        };
      }),

    run: (ability, options: RunOptions) =>
      execute(options, async () => {
        const { abilities, meta } = await createAbilityContext(options);
        const input = await parseRunInput(options.input);
        const result = await abilities.run(ability, input, {
          fresh: options.fresh,
          confirmed: options.yes,
          ...(!options.json && process.stdin.isTTY && process.stderr.isTTY
            ? {
                confirm: async (name: string) => {
                  const prompt = createInterface({
                    input: process.stdin,
                    output: process.stderr,
                  });
                  try {
                    const answer = await prompt.question(
                      `Execute destructive Ability ${name}? [y/N] `,
                    );
                    return /^(y|yes)$/i.test(answer.trim());
                  } finally {
                    prompt.close();
                  }
                },
              }
            : {}),
        });
        return budgetResult(
          result.data,
          result.warnings,
          options.maxOutput,
          meta,
        );
      }),

    skillGet: (slug, options) =>
      execute(options, async () => {
        const { abilities, meta } = await createAbilityContext(options);
        const result = await getSiteSkill(abilities, slug);
        return budgetResult(
          result.data,
          result.warnings,
          options.maxOutput,
          meta,
        );
      }),

    upload: (localPath, remotePath, options) =>
      execute(options, async () => {
        const { profile, abilities, meta } =
          await createAbilityContext(options);
        const result = await new CompositeUploader(
          profile,
          abilities,
          http,
          options.timeout,
          Date.now,
          environment,
        ).upload(localPath, remotePath);
        return { data: result.data, meta, warnings: result.warnings };
      }),

    guideList: (options) =>
      execute(options, async () => ({
        data: { version, guides: await new GuideStore().list() },
      })),

    guideGet: (name, options: GuideGetOptions) =>
      execute(options, async () => {
        const guide = await new GuideStore().get(name, options.full);
        return {
          data: { ...guide, version },
          humanData: guide.content,
        };
      }),

    update: (options: UpdateOptions) =>
      execute(
        options,
        async () => {
          const status = await dependencies
            .createUpdateChecker(options.timeout)
            .check();
          if (options.check || !status.updateAvailable) {
            const data = {
              current: status.current,
              latest: status.latest,
              updateAvailable: status.updateAvailable,
              ...(options.check ? {} : { updated: false }),
            };
            if (!options.json && !options.quiet)
              streams.stderr.write(
                status.updateAvailable
                  ? `${updateNotice(status)}\n`
                  : `novamira ${status.current} is the latest release.\n`,
              );
            return { data };
          }
          if (!options.quiet)
            streams.stderr.write(
              `Updating novamira ${status.current} -> ${status.latest}...\n`,
            );
          const data = await installVersion(
            status.current,
            status.latest,
            new SpawnInstallRunner(
              options.timeoutExplicit ? options.timeout : undefined,
            ),
            (chunk) => {
              if (!options.quiet) streams.stderr.write(chunk);
            },
            undefined,
            environment.NOVAMIRA_REGISTRY ?? DEFAULT_REGISTRY,
          );
          return { data };
        },
        true,
      ),

    doctor: (options: DoctorOptions) =>
      execute(
        options,
        async () => {
          const credentials = await dependencies.getCredentialStore();
          const commonDoctor = {
            paths,
            security,
            profiles,
            credentials,
            abilityCache,
            artifacts,
            environment,
          };
          const doctorOptions = {
            fix: options.fix,
            ...(options.site === undefined ? {} : { site: options.site }),
          };
          const data = options.offline
            ? await runOfflineDoctor(commonDoctor, doctorOptions)
            : await runOnlineDoctor(
                {
                  ...commonDoctor,
                  metadata,
                  createTokenLifecycle: (profile: SiteProfile) =>
                    new TokenLifecycle(
                      profile,
                      locks,
                      credentials,
                      abilityCache,
                      metadata,
                      http,
                      options.timeout,
                      Date.now,
                      environment,
                    ),
                  createAbilityClient: (profile, lifecycle) =>
                    new AbilityClient(
                      profile,
                      metadata,
                      lifecycle,
                      abilityCache,
                      options.timeout,
                      environment,
                    ),
                  ...(!options.json &&
                  process.stdin.isTTY &&
                  process.stderr.isTTY
                    ? {
                        confirmLogin: async (profile: SiteProfile) => {
                          const prompt = createInterface({
                            input: process.stdin,
                            output: process.stderr,
                          });
                          try {
                            const answer = await prompt.question(
                              `OAuth login is required for ${profile.name}. Continue? [y/N] `,
                            );
                            return /^(y|yes)$/i.test(answer.trim());
                          } finally {
                            prompt.close();
                          }
                        },
                        login: async (profile: SiteProfile) => {
                          await (
                            await createLoginService(credentials)
                          ).login({
                            siteUrl: profile.siteUrl,
                            name: profile.name,
                            noOpen: false,
                            timeoutMs: options.timeout,
                          });
                        },
                      }
                    : {}),
                },
                doctorOptions,
              );
          return { data };
        },
        options.offline,
      ),
  } satisfies CommandHandlers;
}
