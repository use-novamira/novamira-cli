// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { asCliError, CliError, exitCodeFor } from "./errors.js";
import {
  createProgram,
  isCommanderUsageError,
  isHelpExit,
  type GlobalOptions,
} from "./cli/program.js";
import {
  writeHumanFailure,
  writeHumanAbilityDescription,
  writeHumanSuccess,
  writeJsonFailure,
  writeJsonSuccess,
  type OutputStreams,
} from "./output/render.js";
import { redact } from "./output/redact.js";
import { platformPaths, type PathEnvironment } from "./config/paths.js";
import { defaultFileSecurity } from "./config/file-security.js";
import { ProfileLockManager } from "./config/lock.js";
import { ProfileStore, type SelectionEnvironment } from "./config/profiles.js";
import { createCredentialStore } from "./auth/credential-store.js";
import { AbilityMetadataCache } from "./cache/ability-cache.js";
import { HttpClient } from "./rest/http-client.js";
import { MetadataClient } from "./auth/metadata.js";
import {
  LoginService,
  SystemBrowserLauncher,
  TerminalLoginInteraction,
} from "./auth/login.js";
import { LoopbackCallbackFactory } from "./auth/loopback.js";
import { TokenLifecycle } from "./auth/token-lifecycle.js";
import { AbilityClient } from "./abilities/client.js";
import { parseRunInput } from "./abilities/input.js";
import {
  ArtifactStore,
  isCredentialClassifiedResult,
} from "./output/artifacts.js";
import { getSiteSkill } from "./skills/client.js";
import { CompositeUploader } from "./upload/client.js";
import { runOfflineDoctor } from "./doctor/engine.js";
import { runOnlineDoctor } from "./doctor/online.js";
import { GuideStore } from "./guides/store.js";
import {
  UpdateChecker,
  updateCheckEnabled,
  updateNotice,
  type UpdateCheckEnvironment,
} from "./update/notifier.js";
import { installVersion, SpawnInstallRunner } from "./update/install.js";
import { DEFAULT_REGISTRY } from "./update/registry.js";

export const VERSION = "1.0.0-rc.3";

export interface RuntimeEnvironment
  extends PathEnvironment, SelectionEnvironment, UpdateCheckEnvironment {
  readonly NO_COLOR?: string;
  readonly NOVAMIRA_CREDENTIAL_BACKEND?: string;
}

export async function main(
  argv: readonly string[],
  streams: OutputStreams = { stdout: process.stdout, stderr: process.stderr },
  environment: RuntimeEnvironment = process.env,
): Promise<number> {
  const requestId = randomUUID();
  let options: GlobalOptions | undefined;
  let executedCommand: string | undefined;

  const paths = platformPaths(environment);
  const security = defaultFileSecurity();
  const locks = new ProfileLockManager(paths.stateDir, security);
  let credentialStore: ReturnType<typeof createCredentialStore> | undefined;
  const getCredentialStore = () => {
    credentialStore ??= createCredentialStore(
      paths.credentialsDir,
      locks,
      security,
      {
        preference:
          environment.NOVAMIRA_CREDENTIAL_BACKEND === "file" ? "file" : "auto",
        onWarning: (message) => {
          if (options?.quiet !== true)
            streams.stderr.write(`Warning: ${message}\n`);
        },
      },
    );
    return credentialStore;
  };
  const abilityCache = new AbilityMetadataCache(
    paths.cacheDir,
    locks,
    security,
  );
  const artifacts = new ArtifactStore(paths.cacheDir, locks, security);
  const createUpdateChecker = (timeoutMs?: number) =>
    new UpdateChecker(paths.stateDir, locks, security, {
      currentVersion: VERSION,
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
      ...(environment.NOVAMIRA_REGISTRY === undefined
        ? {}
        : { registry: environment.NOVAMIRA_REGISTRY }),
      allowInsecureHttp: environment.NOVAMIRA_ALLOW_INSECURE_HTTP === "1",
    });
  const http = new HttpClient({
    onDiagnostic: (diagnostic) => {
      if (options?.verbose === true && !options.quiet)
        streams.stderr.write(`HTTP: ${JSON.stringify(diagnostic)}\n`);
    },
  });
  const metadata = new MetadataClient(http);
  const profiles = new ProfileStore(paths.configFile, locks, security, [
    {
      cleanup: async (profile) => {
        await (
          await getCredentialStore()
        ).deleteUnderLock({
          profileName: profile.name,
          origin: profile.origin,
        });
      },
    },
    abilityCache,
  ]);

  const program = createProgram(
    VERSION,
    async (command, parsedOptions, args) => {
      options = parsedOptions;
      executedCommand = command;
      if (command.startsWith("version:")) {
        const version = command.slice("version:".length);
        if (parsedOptions.json)
          writeJsonSuccess(streams, { version }, { requestId });
        else writeHumanSuccess(streams, version);
        return;
      }
      if (command === "auth login") {
        const siteUrl = args[0];
        if (siteUrl === undefined)
          throw new CliError("usage_error", "A site URL is required.");
        const login = new LoginService(
          profiles,
          locks,
          await getCredentialStore(),
          abilityCache,
          metadata,
          http,
          new LoopbackCallbackFactory(),
          new SystemBrowserLauncher(),
          new TerminalLoginInteraction((value) => streams.stderr.write(value)),
        );
        const result = await login.login({
          siteUrl,
          ...(parsedOptions.name === undefined
            ? {}
            : { name: parsedOptions.name }),
          access: parsedOptions.access ?? "full",
          noOpen: parsedOptions.open === false,
          timeoutMs: parsedOptions.timeout,
        });
        const data = {
          site: result.profile.name,
          siteUrl: result.profile.siteUrl,
          scope: result.scope,
          expiresAt: result.expiresAt,
        };
        if (parsedOptions.json)
          writeJsonSuccess(streams, data, {
            requestId,
            site: result.profile.name,
            origin: result.profile.origin,
          });
        else writeHumanSuccess(streams, data);
        return;
      }
      if (command === "auth status" || command === "auth logout") {
        const profile = await profiles.select(parsedOptions.site, environment);
        const lifecycle = new TokenLifecycle(
          profile,
          locks,
          await getCredentialStore(),
          abilityCache,
          metadata,
          http,
          parsedOptions.timeout,
        );
        if (command === "auth status") {
          const data = await lifecycle.status();
          if (parsedOptions.json)
            writeJsonSuccess(streams, data, {
              requestId,
              site: profile.name,
              origin: profile.origin,
            });
          else writeHumanSuccess(streams, data);
          return;
        }
        const data = await lifecycle.logout();
        if (data.warning !== undefined && !parsedOptions.quiet)
          streams.stderr.write(`Warning: ${data.warning}\n`);
        const warnings =
          data.warning === undefined
            ? undefined
            : [
                {
                  code: "remote_revocation_unavailable",
                  message: data.warning,
                },
              ];
        if (parsedOptions.json)
          writeJsonSuccess(streams, data, {
            requestId,
            site: profile.name,
            origin: profile.origin,
            ...(warnings === undefined ? {} : { warnings }),
          });
        else writeHumanSuccess(streams, data);
        return;
      }
      if (
        command === "discover" ||
        command === "describe" ||
        command === "run" ||
        command === "skill get" ||
        command === "upload"
      ) {
        const profile = await profiles.select(parsedOptions.site, environment);
        const lifecycle = new TokenLifecycle(
          profile,
          locks,
          await getCredentialStore(),
          abilityCache,
          metadata,
          http,
          parsedOptions.timeout,
        );
        const abilities = new AbilityClient(
          profile,
          metadata,
          lifecycle,
          abilityCache,
          parsedOptions.timeout,
        );
        const meta = {
          requestId,
          site: profile.name,
          origin: profile.origin,
        };
        if (command === "discover") {
          const data = await abilities.discover();
          if (parsedOptions.json) writeJsonSuccess(streams, data, meta);
          else writeHumanSuccess(streams, data);
          return;
        }
        if (command === "skill get") {
          const slug = args[0];
          if (slug === undefined)
            throw new CliError("usage_error", "A skill slug is required.");
          const result = await getSiteSkill(abilities, slug);
          const budgeted = await artifacts.budget(result.data, {
            maxOutputBytes: parsedOptions.maxOutput,
            credentialClassified: isCredentialClassifiedResult(result.data),
          });
          const warnings =
            result.warnings.length === 0 ? undefined : result.warnings;
          if (!parsedOptions.json && !parsedOptions.quiet)
            for (const warning of result.warnings)
              streams.stderr.write(`Warning: ${warning.message}\n`);
          const skillMeta = {
            ...meta,
            ...(warnings === undefined ? {} : { warnings }),
            ...(budgeted.truncated
              ? {
                  truncated: true,
                  bytes: budgeted.bytes,
                  ...(budgeted.artifact === undefined
                    ? {}
                    : { artifact: budgeted.artifact }),
                }
              : {}),
          };
          if (parsedOptions.json)
            writeJsonSuccess(streams, budgeted.data, skillMeta);
          else writeHumanSuccess(streams, budgeted.data);
          return;
        }
        if (command === "upload") {
          const localPath = args[0];
          const remotePath = args[1];
          if (localPath === undefined || remotePath === undefined)
            throw new CliError(
              "usage_error",
              "Local and remote upload paths are required.",
            );
          const result = await new CompositeUploader(
            profile,
            lifecycle,
            abilities,
            http,
            parsedOptions.timeout,
          ).upload(localPath, remotePath);
          if (!parsedOptions.json && !parsedOptions.quiet)
            for (const warning of result.warnings)
              streams.stderr.write(`Warning: ${warning.message}\n`);
          const warnings =
            result.warnings.length === 0 ? undefined : result.warnings;
          if (parsedOptions.json)
            writeJsonSuccess(streams, result.data, {
              ...meta,
              ...(warnings === undefined ? {} : { warnings }),
            });
          else writeHumanSuccess(streams, result.data);
          return;
        }
        const abilityName = args[0];
        if (abilityName === undefined)
          throw new CliError("usage_error", "An Ability name is required.");
        if (command === "run") {
          const input = await parseRunInput(parsedOptions.input);
          const result = await abilities.run(abilityName, input, {
            fresh: parsedOptions.fresh === true,
            confirmed: parsedOptions.yes,
            ...(!parsedOptions.json &&
            process.stdin.isTTY &&
            process.stderr.isTTY
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
          const budgeted = await artifacts.budget(result.data, {
            maxOutputBytes: parsedOptions.maxOutput,
            credentialClassified: isCredentialClassifiedResult(result.data),
          });
          const warnings =
            result.warnings.length === 0 ? undefined : result.warnings;
          if (!parsedOptions.json && !parsedOptions.quiet)
            for (const warning of result.warnings)
              streams.stderr.write(`Warning: ${warning.message}\n`);
          const runMeta = {
            ...meta,
            ...(warnings === undefined ? {} : { warnings }),
            ...(budgeted.truncated
              ? {
                  truncated: true,
                  bytes: budgeted.bytes,
                  ...(budgeted.artifact === undefined
                    ? {}
                    : { artifact: budgeted.artifact }),
                }
              : {}),
          };
          if (parsedOptions.json)
            writeJsonSuccess(streams, budgeted.data, runMeta);
          else writeHumanSuccess(streams, budgeted.data);
          return;
        }
        const data = await abilities.describe(abilityName);
        if (parsedOptions.json) writeJsonSuccess(streams, data, meta);
        else writeHumanAbilityDescription(streams, data);
        return;
      }
      if (command === "sites list") {
        const data = await profiles.list();
        if (parsedOptions.json) writeJsonSuccess(streams, data, { requestId });
        else writeHumanSuccess(streams, data);
        return;
      }
      if (command === "sites remove") {
        const name = args[0];
        if (name === undefined)
          throw new CliError("usage_error", "A profile name is required.");
        const removed = await profiles.remove(name);
        const data = { removed: removed.name, siteUrl: removed.siteUrl };
        if (parsedOptions.json) writeJsonSuccess(streams, data, { requestId });
        else writeHumanSuccess(streams, data);
        return;
      }
      if (command === "guide list" || command === "guide get") {
        const guides = new GuideStore();
        if (command === "guide list") {
          const data = { version: VERSION, guides: await guides.list() };
          if (parsedOptions.json)
            writeJsonSuccess(streams, data, { requestId });
          else writeHumanSuccess(streams, data);
          return;
        }
        const name = args[0];
        if (name === undefined)
          throw new CliError("usage_error", "A guide name is required.");
        const guide = await guides.get(name, parsedOptions.full === true);
        if (parsedOptions.json)
          writeJsonSuccess(
            streams,
            { ...guide, version: VERSION },
            { requestId },
          );
        else writeHumanSuccess(streams, guide.content);
        return;
      }
      if (command === "update") {
        const status = await createUpdateChecker(parsedOptions.timeout).check();
        if (parsedOptions.check === true || !status.updateAvailable) {
          const data = {
            current: status.current,
            latest: status.latest,
            updateAvailable: status.updateAvailable,
            ...(parsedOptions.check === true ? {} : { updated: false }),
          };
          if (!parsedOptions.json && !parsedOptions.quiet)
            streams.stderr.write(
              status.updateAvailable
                ? `${updateNotice(status)}\n`
                : `novamira ${status.current} is the latest release.\n`,
            );
          if (parsedOptions.json)
            writeJsonSuccess(streams, data, { requestId });
          else writeHumanSuccess(streams, data);
          return;
        }
        if (!parsedOptions.quiet)
          streams.stderr.write(
            `Updating novamira ${status.current} -> ${status.latest}...\n`,
          );
        const data = await installVersion(
          status.current,
          status.latest,
          // An explicit --timeout bounds the installer too; otherwise the
          // installer keeps its own longer default.
          new SpawnInstallRunner(
            parsedOptions.timeoutExplicit ? parsedOptions.timeout : undefined,
          ),
          (chunk) => {
            if (!parsedOptions.quiet) streams.stderr.write(chunk);
          },
          undefined,
          environment.NOVAMIRA_REGISTRY ?? DEFAULT_REGISTRY,
        );
        if (parsedOptions.json) writeJsonSuccess(streams, data, { requestId });
        else writeHumanSuccess(streams, data);
        return;
      }
      if (command === "doctor") {
        const commonDoctor = {
          paths,
          security,
          profiles,
          credentials: await getCredentialStore(),
          abilityCache,
          artifacts,
          environment,
        };
        const doctorOptions = {
          fix: parsedOptions.fix === true,
          ...(parsedOptions.site === undefined
            ? {}
            : { site: parsedOptions.site }),
        };
        const data = parsedOptions.offline
          ? await runOfflineDoctor(commonDoctor, doctorOptions)
          : await runOnlineDoctor(
              {
                ...commonDoctor,
                metadata,
                createTokenLifecycle: (profile) =>
                  new TokenLifecycle(
                    profile,
                    locks,
                    commonDoctor.credentials,
                    abilityCache,
                    metadata,
                    http,
                    parsedOptions.timeout,
                  ),
                createAbilityClient: (profile, lifecycle) =>
                  new AbilityClient(
                    profile,
                    metadata,
                    lifecycle,
                    abilityCache,
                    parsedOptions.timeout,
                  ),
                ...(!parsedOptions.json &&
                process.stdin.isTTY &&
                process.stderr.isTTY
                  ? {
                      confirmLogin: async (profile, access) => {
                        const prompt = createInterface({
                          input: process.stdin,
                          output: process.stderr,
                        });
                        try {
                          const answer = await prompt.question(
                            `OAuth login is required for ${profile.name} with ${access} access. Continue? [y/N] `,
                          );
                          return /^(y|yes)$/i.test(answer.trim());
                        } finally {
                          prompt.close();
                        }
                      },
                      login: async (profile, access) => {
                        await new LoginService(
                          profiles,
                          locks,
                          commonDoctor.credentials,
                          abilityCache,
                          metadata,
                          http,
                          new LoopbackCallbackFactory(),
                          new SystemBrowserLauncher(),
                          new TerminalLoginInteraction((value) =>
                            streams.stderr.write(value),
                          ),
                        ).login({
                          siteUrl: profile.siteUrl,
                          name: profile.name,
                          access,
                          noOpen: false,
                          timeoutMs: parsedOptions.timeout,
                        });
                      },
                    }
                  : {}),
              },
              doctorOptions,
            );
        if (parsedOptions.json) writeJsonSuccess(streams, data, { requestId });
        else writeHumanSuccess(streams, data);
        return;
      }
      throw new CliError(
        "internal_error",
        `${command} is not implemented in this build.`,
      );
    },
  );
  program.configureOutput({
    writeOut: (value) => streams.stdout.write(value),
    writeErr: () => undefined,
  });

  const emitUpdateNotice = async (): Promise<void> => {
    if (
      options?.quiet === true ||
      options?.offline === true ||
      executedCommand === undefined ||
      executedCommand === "update" ||
      !updateCheckEnabled(environment)
    )
      return;
    const notice = await createUpdateChecker().notice();
    if (notice !== undefined) streams.stderr.write(`Warning: ${notice}\n`);
  };

  try {
    await program.parseAsync(argv, { from: "user" });
    await emitUpdateNotice();
    return 0;
  } catch (error) {
    if (isHelpExit(error)) return 0;
    const cliError = isCommanderUsageError(error)
      ? new CliError(
          "usage_error",
          "Invalid command usage. Run novamira --help.",
        )
      : asCliError(error);
    const resolvedOptions = options ?? program.opts<GlobalOptions>();
    const json = resolvedOptions.json || argv.includes("--json");
    const colorEnabled =
      resolvedOptions.color && environment.NO_COLOR === undefined && !json;

    if (resolvedOptions.verbose && !resolvedOptions.quiet) {
      const diagnostic = redact({
        requestId,
        error: cliError,
        colorEnabled,
      });
      streams.stderr.write(`Diagnostic: ${JSON.stringify(diagnostic)}\n`);
    }

    if (json) writeJsonFailure(streams, cliError);
    else writeHumanFailure(streams, cliError);
    return exitCodeFor(cliError);
  }
}
