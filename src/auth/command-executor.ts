// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from "node:child_process";

export interface CommandResult {
  readonly code: number;
  readonly stdout: string;
}

export interface CommandExecutor {
  execute(
    command: string,
    args: readonly string[],
    stdin?: string,
  ): Promise<CommandResult>;
}

export class BackendUnavailableError extends Error {
  constructor() {
    super("Credential backend is unavailable.");
    this.name = "BackendUnavailableError";
  }
}

export class SpawnCommandExecutor implements CommandExecutor {
  constructor(private readonly timeoutMs = 5_000) {}

  async execute(
    command: string,
    args: readonly string[],
    stdin = "",
  ): Promise<CommandResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, [...args], {
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const chunks: Buffer[] = [];
      let size = 0;
      const timer = setTimeout(() => child.kill(), this.timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        size += chunk.byteLength;
        if (size <= 1024 * 1024) chunks.push(chunk);
        else child.kill();
      });
      child.once("error", (error: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        if (error.code === "ENOENT") reject(new BackendUnavailableError());
        else reject(new Error("Credential backend command failed to start."));
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        resolve({
          code: code ?? 1,
          stdout: Buffer.concat(chunks).toString("utf8"),
        });
      });
      child.stdin.end(stdin);
    });
  }
}
