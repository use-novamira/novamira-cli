// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from "node:child_process";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { CliError } from "../errors.js";
import { DEFAULT_REGISTRY, PACKAGE_NAME } from "./registry.js";

export interface InstallCommand {
  readonly command: string;
  readonly args: readonly string[];
}

export interface InstallRunner {
  run(
    command: InstallCommand,
    onOutput: (chunk: string) => void,
  ): Promise<number>;
}

/**
 * Choose the package manager that owns this installation. The npm global
 * install used by the documented installers is the default; a Bun global
 * install is detected from the running module path. The registry that was
 * consulted for the version is passed through so the installed artifact comes
 * from the same registry, whatever the package manager is configured with.
 */
export function installCommandFor(
  version: string,
  modulePath: string = fileURLToPath(import.meta.url),
  registry: string = DEFAULT_REGISTRY,
  platform: string = process.platform,
): InstallCommand {
  const specifier = `${PACKAGE_NAME}@${version}`;
  const bunGlobal = `${sep}.bun${sep}install${sep}global${sep}`;
  if (modulePath.includes(bunGlobal))
    return {
      command: "bun",
      args: ["add", "--global", "--registry", registry, specifier],
    };
  return {
    // Windows resolves npm through a shim, and spawn without a shell needs it.
    command: platform === "win32" ? "npm.cmd" : "npm",
    args: [
      "install",
      "--global",
      "--ignore-scripts",
      "--registry",
      registry,
      specifier,
    ],
  };
}

export class SpawnInstallRunner implements InstallRunner {
  constructor(private readonly timeoutMs = 300_000) {}

  async run(
    command: InstallCommand,
    onOutput: (chunk: string) => void,
  ): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const child = spawn(command.command, [...command.args], {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill();
      }, this.timeoutMs);
      for (const stream of [child.stdout, child.stderr])
        stream.on("data", (chunk: Buffer) => {
          onOutput(chunk.toString("utf8"));
        });
      child.once("error", (error: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        reject(
          error.code === "ENOENT"
            ? new CliError(
                "usage_error",
                `${command.command} is required to update the CLI but was not found in PATH.`,
              )
            : new CliError(
                "internal_error",
                `${command.command} could not be started.`,
                { cause: error },
              ),
        );
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        if (timedOut)
          reject(
            new CliError(
              "network_error",
              `${command.command} did not finish within ${String(this.timeoutMs)} ms.`,
              { retryable: true },
            ),
          );
        else resolve(code ?? 1);
      });
    });
  }
}

export interface SelfUpdateResult {
  readonly updated: boolean;
  readonly from: string;
  readonly to: string;
  readonly command: string;
}

/** Install the requested published version with the detected package manager. */
export async function installVersion(
  currentVersion: string,
  targetVersion: string,
  runner: InstallRunner,
  onOutput: (chunk: string) => void,
  modulePath?: string,
  registry: string = DEFAULT_REGISTRY,
): Promise<SelfUpdateResult> {
  const command = installCommandFor(
    targetVersion,
    modulePath ?? fileURLToPath(import.meta.url),
    registry,
  );
  const printable = [command.command, ...command.args].join(" ");
  const code = await runner.run(command, onOutput);
  if (code !== 0)
    throw new CliError(
      "internal_error",
      `${printable} exited with status ${String(code)}.`,
    );
  return {
    updated: true,
    from: currentVersion,
    to: targetVersion,
    command: printable,
  };
}
