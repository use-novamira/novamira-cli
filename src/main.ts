// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from "node:crypto";
import { createCredentialStore } from "./auth/credential-store.js";
import { MetadataClient } from "./auth/metadata.js";
import { AbilityMetadataCache } from "./cache/ability-cache.js";
import { createCommandHandlers } from "./cli/commands.js";
import {
  createProgram,
  isCommanderUsageError,
  isHelpExit,
  type GlobalOptions,
} from "./cli/program.js";
import { defaultFileSecurity } from "./config/file-security.js";
import { ProfileLockManager } from "./config/lock.js";
import { platformPaths, type PathEnvironment } from "./config/paths.js";
import { ProfileStore, type SelectionEnvironment } from "./config/profiles.js";
import type { SiteUrlEnvironment } from "./config/site-url.js";
import { asCliError, CliError, exitCodeFor } from "./errors.js";
import { ArtifactStore } from "./output/artifacts.js";
import { redact } from "./output/redact.js";
import {
  writeHumanFailure,
  writeJsonFailure,
  type OutputStreams,
} from "./output/render.js";
import { HttpClient } from "./rest/http-client.js";
import {
  UpdateChecker,
  updateCheckEnabled,
  type UpdateCheckEnvironment,
} from "./update/notifier.js";

export const VERSION = "1.0.0";

export interface RuntimeEnvironment
  extends
    PathEnvironment,
    SelectionEnvironment,
    SiteUrlEnvironment,
    UpdateCheckEnvironment {
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
  let commandExecuted = false;
  let updateNoticeSuppressed = false;

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
  const metadata = new MetadataClient(http, Date.now, environment);
  const profiles = new ProfileStore(
    paths.configFile,
    locks,
    security,
    [
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
    ],
    environment,
  );

  const handlers = createCommandHandlers({
    version: VERSION,
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
    getCredentialStore,
    createUpdateChecker,
    onInvocation: (parsedOptions, suppressUpdateNotice) => {
      options = parsedOptions;
      commandExecuted = true;
      updateNoticeSuppressed = suppressUpdateNotice;
    },
  });
  const program = createProgram(VERSION, handlers);
  program.configureOutput({
    writeOut: (value) => streams.stdout.write(value),
    writeErr: () => undefined,
  });

  const emitUpdateNotice = async (): Promise<void> => {
    if (
      options?.quiet === true ||
      updateNoticeSuppressed ||
      !commandExecuted ||
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
