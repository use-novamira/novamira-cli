// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Command, CommanderError, InvalidArgumentError } from "commander";
import { CliError } from "../errors.js";

const DEFAULT_OPERATION_TIMEOUT_MS = 30_000;
const DEFAULT_AUTHORIZATION_TIMEOUT_MS = 300_000;

export interface GlobalOptions {
  readonly site?: string;
  readonly json: boolean;
  readonly timeout: number;
  readonly yes: boolean;
  readonly maxOutput: number;
  readonly color: boolean;
  readonly quiet: boolean;
  readonly verbose: boolean;
}

export interface AuthLoginOptions extends GlobalOptions {
  readonly name?: string;
  readonly open: boolean;
  readonly device: boolean;
}

export interface RunOptions extends GlobalOptions {
  readonly input?: string;
  readonly fresh: boolean;
}

export interface DoctorOptions extends GlobalOptions {
  readonly offline: boolean;
  readonly fix: boolean;
}

export interface GuideGetOptions extends GlobalOptions {
  readonly full: boolean;
}

export interface UpdateOptions extends GlobalOptions {
  readonly check: boolean;
  /** True when --timeout was given, so the installer should inherit it. */
  readonly timeoutExplicit: boolean;
}

export interface CommandHandlers {
  version(version: string, options: GlobalOptions): void | Promise<void>;
  authLogin(url: string, options: AuthLoginOptions): void | Promise<void>;
  authStatus(options: GlobalOptions): void | Promise<void>;
  authLogout(options: GlobalOptions): void | Promise<void>;
  sitesList(options: GlobalOptions): void | Promise<void>;
  sitesRemove(name: string, options: GlobalOptions): void | Promise<void>;
  sitesRename(
    name: string,
    newName: string,
    options: GlobalOptions,
  ): void | Promise<void>;
  discover(options: GlobalOptions): void | Promise<void>;
  describe(ability: string, options: GlobalOptions): void | Promise<void>;
  run(ability: string, options: RunOptions): void | Promise<void>;
  skillGet(slug: string, options: GlobalOptions): void | Promise<void>;
  upload(
    localPath: string,
    remotePath: string,
    options: GlobalOptions,
  ): void | Promise<void>;
  guideList(options: GlobalOptions): void | Promise<void>;
  guideGet(name: string, options: GuideGetOptions): void | Promise<void>;
  update(options: UpdateOptions): void | Promise<void>;
  doctor(options: DoctorOptions): void | Promise<void>;
}

function positiveInteger(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError("must be a positive integer");
  }
  return parsed;
}

export function createProgram(
  version: string,
  handlers: CommandHandlers,
): Command {
  const program = new Command();
  program
    .name("novamira")
    .description("REST-first CLI for Novamira WordPress Abilities")
    .showSuggestionAfterError()
    .exitOverride()
    .option("--site <name>", "select a configured site profile")
    .option("--json", "emit exactly one JSON value on stdout", false)
    .option(
      "--timeout <ms>",
      "operation timeout in milliseconds",
      positiveInteger,
      DEFAULT_OPERATION_TIMEOUT_MS,
    )
    .option("--yes", "approve destructive operations", false)
    .option(
      "--max-output <bytes>",
      "maximum output budget",
      positiveInteger,
      1_048_576,
    )
    .option("--no-color", "disable ANSI color")
    .option("--quiet", "suppress nonessential diagnostics", false)
    .option("--verbose", "emit redacted diagnostics", false)
    .option("--version", "print the CLI version", false);

  const optionsFor = (
    values: readonly unknown[],
    authorization = false,
  ): GlobalOptions => {
    const active =
      values.findLast((value): value is Command => value instanceof Command) ??
      program;
    const explicitTimeout =
      active.getOptionValueSourceWithGlobals("timeout") !== "default";
    const parsedOptions = {
      ...active.optsWithGlobals<GlobalOptions>(),
      timeoutExplicit: explicitTimeout,
    };
    const options =
      authorization && !explicitTimeout
        ? {
            ...parsedOptions,
            timeout: DEFAULT_AUTHORIZATION_TIMEOUT_MS,
          }
        : parsedOptions;
    return options;
  };
  const authLoginOptions = (values: readonly unknown[]): AuthLoginOptions =>
    optionsFor(values, true) as AuthLoginOptions;
  const runOptions = (values: readonly unknown[]): RunOptions =>
    optionsFor(values) as RunOptions;
  const guideGetOptions = (values: readonly unknown[]): GuideGetOptions =>
    optionsFor(values) as GuideGetOptions;
  const updateOptions = (values: readonly unknown[]): UpdateOptions =>
    optionsFor(values) as UpdateOptions;
  const doctorOptions = (values: readonly unknown[]): DoctorOptions =>
    optionsFor(values) as DoctorOptions;

  const auth = program
    .command("auth")
    .description("manage OAuth authorization");
  auth
    .command("login <url>")
    .option("--name <name>", "profile name")
    .option("--no-open", "do not launch a browser")
    .option(
      "--device",
      "authorize with a device code instead of a local browser",
      false,
    )
    .action(async (url: string, ...values: unknown[]) =>
      handlers.authLogin(url, authLoginOptions(values)),
    );
  auth
    .command("status")
    .action(async (...values: unknown[]) =>
      handlers.authStatus(optionsFor(values)),
    );
  auth
    .command("logout")
    .action(async (...values: unknown[]) =>
      handlers.authLogout(optionsFor(values)),
    );

  const sites = program.command("sites").description("manage configured sites");
  sites
    .command("list")
    .action(async (...values: unknown[]) =>
      handlers.sitesList(optionsFor(values)),
    );
  sites
    .command("remove <name>")
    .action(async (name: string, ...values: unknown[]) =>
      handlers.sitesRemove(name, optionsFor(values)),
    );
  sites
    .command("rename <name> <new-name>")
    .action(async (name: string, newName: string, ...values: unknown[]) =>
      handlers.sitesRename(name, newName, optionsFor(values)),
    );

  program
    .command("discover")
    .action(async (...values: unknown[]) =>
      handlers.discover(optionsFor(values)),
    );
  program
    .command("describe <ability>")
    .action(async (ability: string, ...values: unknown[]) =>
      handlers.describe(ability, optionsFor(values)),
    );
  program
    .command("run <ability>")
    .option("--input <json|@file|->", "JSON input source")
    .option("--fresh", "bypass cached Ability metadata", false)
    .action(async (ability: string, ...values: unknown[]) =>
      handlers.run(ability, runOptions(values)),
    );

  const skill = program.command("skill").description("load site skills");
  skill
    .command("get <slug>")
    .action(async (slug: string, ...values: unknown[]) =>
      handlers.skillGet(slug, optionsFor(values)),
    );

  program
    .command("upload <local> <remote>")
    .action(
      async (localPath: string, remotePath: string, ...values: unknown[]) =>
        handlers.upload(localPath, remotePath, optionsFor(values)),
    );

  const guide = program.command("guide").description("read bundled guidance");
  guide
    .command("list")
    .action(async (...values: unknown[]) =>
      handlers.guideList(optionsFor(values)),
    );
  guide
    .command("get <name>")
    .option("--full", "include full references", false)
    .action(async (name: string, ...values: unknown[]) =>
      handlers.guideGet(name, guideGetOptions(values)),
    );

  program
    .command("update")
    .description("install the latest published CLI release")
    .option("--check", "report the published version without installing", false)
    .action(async (...values: unknown[]) =>
      handlers.update(updateOptions(values)),
    );

  program
    .command("doctor")
    .option("--offline", "forbid network access", false)
    .option("--fix", "apply narrowly safe repairs", false)
    .action(async (...values: unknown[]) =>
      handlers.doctor(doctorOptions(values)),
    );

  program.action(async () => {
    const options = program.opts<
      GlobalOptions & { readonly version: boolean }
    >();
    if (options.version) {
      await handlers.version(version, options);
      return;
    }
    throw new CliError(
      "usage_error",
      "A command is required. Run novamira --help.",
    );
  });

  return program;
}

export function isHelpExit(error: unknown): boolean {
  return (
    error instanceof CommanderError && error.code === "commander.helpDisplayed"
  );
}

export function isCommanderUsageError(error: unknown): boolean {
  return error instanceof CommanderError;
}
