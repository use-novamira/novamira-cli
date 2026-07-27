// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  Command,
  CommanderError,
  InvalidArgumentError,
  Option,
} from "commander";
import { CliError } from "../errors.js";

const DEFAULT_OPERATION_TIMEOUT_MS = 30_000;
const DEFAULT_AUTHORIZATION_TIMEOUT_MS = 300_000;

export interface GlobalOptions {
  readonly site?: string;
  readonly json: boolean;
  readonly timeout: number;
  /** True when --timeout was given, so a command default must not override it. */
  readonly timeoutExplicit: boolean;
  readonly yes: boolean;
  readonly maxOutput: number;
  readonly color: boolean;
  readonly quiet: boolean;
  readonly verbose: boolean;
  readonly version: boolean;
  readonly name?: string;
  readonly access?: "read" | "full";
  readonly open?: boolean;
  readonly input?: string;
  readonly fresh?: boolean;
  readonly offline?: boolean;
  readonly fix?: boolean;
  readonly full?: boolean;
  readonly check?: boolean;
}

export type CommandHandler = (
  command: string,
  options: GlobalOptions,
  args: readonly string[],
) => void | Promise<void>;

function positiveInteger(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError("must be a positive integer");
  }
  return parsed;
}

export function createProgram(
  version: string,
  handler: CommandHandler,
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

  const invoke =
    (label: string) =>
    async (...values: unknown[]): Promise<void> => {
      const active =
        values.findLast(
          (value): value is Command => value instanceof Command,
        ) ?? program;
      const args = values.filter(
        (value): value is string => typeof value === "string",
      );
      const explicitTimeout =
        active.getOptionValueSourceWithGlobals("timeout") !== "default";
      const parsedOptions = {
        ...active.optsWithGlobals<GlobalOptions>(),
        timeoutExplicit: explicitTimeout,
      };
      const options =
        label === "auth login" && !explicitTimeout
          ? {
              ...parsedOptions,
              timeout: DEFAULT_AUTHORIZATION_TIMEOUT_MS,
            }
          : parsedOptions;
      await handler(label, options, args);
    };

  const auth = program
    .command("auth")
    .description("manage OAuth authorization");
  auth
    .command("login <url>")
    .option("--name <name>", "profile name")
    .addOption(
      new Option("--access <level>", "requested access")
        .choices(["read", "full"])
        .default("full"),
    )
    .option("--no-open", "do not launch a browser")
    .action(invoke("auth login"));
  auth.command("status").action(invoke("auth status"));
  auth.command("logout").action(invoke("auth logout"));

  const sites = program.command("sites").description("manage configured sites");
  sites.command("list").action(invoke("sites list"));
  sites.command("remove <name>").action(invoke("sites remove"));

  program.command("discover").action(invoke("discover"));
  program.command("describe <ability>").action(invoke("describe"));
  program
    .command("run <ability>")
    .option("--input <json|@file|->", "JSON input source")
    .option("--fresh", "bypass cached Ability metadata", false)
    .action(invoke("run"));

  const skill = program.command("skill").description("load site skills");
  skill.command("get <slug>").action(invoke("skill get"));

  program.command("upload <local> <remote>").action(invoke("upload"));

  const guide = program.command("guide").description("read bundled guidance");
  guide.command("list").action(invoke("guide list"));
  guide
    .command("get <name>")
    .option("--full", "include full references", false)
    .action(invoke("guide get"));

  program
    .command("update")
    .description("install the latest published CLI release")
    .option("--check", "report the published version without installing", false)
    .action(invoke("update"));

  program
    .command("doctor")
    .option("--offline", "forbid network access", false)
    .option("--fix", "apply narrowly safe repairs", false)
    .action(invoke("doctor"));

  program.action(async () => {
    const options = program.opts<GlobalOptions>();
    if (options.version) {
      await handler(`version:${version}`, options, []);
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
