// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { chmod, mkdir, stat } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";

import {
  POWERSHELL_PREFIX,
  powerShellEnvironment,
  powerShellLiteral,
  powerShellStdinLine,
} from "./powershell.js";

export interface FileSecurity {
  secureDirectory(path: string): Promise<void>;
  secureFile(path: string): Promise<void>;
}

export type AclTargetKind = "directory" | "file";

export interface AclTarget {
  readonly path: string;
  readonly kind: AclTargetKind;
}

export interface VerifiedFileSecurity extends FileSecurity {
  verifyDirectory(path: string): Promise<boolean>;
  verifyFile(path: string): Promise<boolean>;
  // Batch equivalents of the single-path methods, so that a caller inspecting
  // many paths costs one helper process instead of one per path. `result[i]`
  // always describes `targets[i]`, and a target whose ACL is unsafe or cannot
  // be read at all (missing, denied) is `false` without aborting the batch;
  // only a failure of the checker itself rejects. An empty list inspects
  // nothing and starts no process.
  verifyMany(targets: readonly AclTarget[]): Promise<readonly boolean[]>;
  // Hardens every target. Rejects unless every target ends owner-only.
  secureMany(targets: readonly AclTarget[]): Promise<void>;
}

export class UnixFileSecurity implements VerifiedFileSecurity {
  async secureDirectory(path: string): Promise<void> {
    await chmod(path, 0o700);
  }

  async secureFile(path: string): Promise<void> {
    await chmod(path, 0o600);
  }

  async verifyDirectory(path: string): Promise<boolean> {
    return this.verify(path, 0o700);
  }

  async verifyFile(path: string): Promise<boolean> {
    return this.verify(path, 0o600);
  }

  // A stat is already cheap enough that batching only has to preserve the
  // contract, not save work.
  async verifyMany(targets: readonly AclTarget[]): Promise<readonly boolean[]> {
    const results: boolean[] = [];
    for (const target of targets) {
      try {
        results.push(await this.verifyTarget(target));
      } catch {
        results.push(false);
      }
    }
    return results;
  }

  // Mirrors `WindowsFileSecurity.secureMany`: every target is hardened before
  // anything is reported, and the postcondition, not the `chmod` return, is
  // what decides. A `chmod` that fails over an already owner-only path is not
  // a failure, and a `chmod` that silently does nothing - exFAT and SMB mounts
  // accept it and keep the mode - still rejects, so `atomicWriteFiles` never
  // renames a temporary this call could not prove owner-only.
  async secureMany(targets: readonly AclTarget[]): Promise<void> {
    if (targets.length === 0) return;
    for (const target of targets)
      try {
        if (target.kind === "directory")
          await this.secureDirectory(target.path);
        else await this.secureFile(target.path);
      } catch {
        // Recorded by the verification below rather than raised here, so one
        // unrepairable target cannot stop the rest of the batch.
      }
    const verdicts = await this.verifyMany(targets);
    const failed = verdicts.filter((safe) => !safe).length;
    if (failed > 0)
      throw new Error(
        `could not apply owner-only permissions to ${String(failed)} of ${String(targets.length)} paths`,
      );
  }

  private async verifyTarget(target: AclTarget): Promise<boolean> {
    return target.kind === "directory"
      ? this.verifyDirectory(target.path)
      : this.verifyFile(target.path);
  }

  private async verify(path: string, expectedMode: number): Promise<boolean> {
    const info = await stat(path);
    const ownerMatches =
      process.getuid === undefined || info.uid === process.getuid();
    return ownerMatches && (info.mode & 0o777) === expectedMode;
  }
}

export interface CommandResult {
  readonly code: number;
  readonly stdout: string;
}

export interface CommandRunner {
  run(command: string, args: readonly string[]): Promise<number>;
  // Separate from `run` so that the existing exit-code-only call sites and
  // their stubs keep working unchanged.
  runWithInput(
    command: string,
    args: readonly string[],
    input: string,
  ): Promise<CommandResult>;
}

// An ACL helper that has not answered within this long is not going to.
const COMMAND_TIMEOUT_MS = 60_000;
// The ACL helper emits one short verdict per target; anything beyond this is a
// runaway process, not a result.
const MAX_COMMAND_OUTPUT_CHARS = 1_048_576;

// A CLI that is interrupted mid-check used to leave powershell.exe processes
// behind, still rewriting ACLs after the user had cancelled. One registry
// serves every spawn, and both ways a process can end reach it:
//
// - `exit` covers an explicit `process.exit()` or a natural exit while a check
//   is still in flight.
// - The termination signals cover the case that actually happens, Ctrl-C.
//   Node does not emit `exit` when the default signal handler terminates the
//   process, and the children are spawned with `windowsHide` (which implies
//   CREATE_NO_WINDOW), so they are not on the parent console and never see
//   CTRL_C_EVENT of their own. Without this listener they simply survive.
//
// The signal listener re-raises after killing, so the CLI still dies exactly
// as it would have; signal listeners do not hold the event loop open, so
// leaving them installed cannot keep an idle process alive.
const TERMINATION_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
const liveChildren = new Set<ChildProcess>();
let hooksInstalled = false;

function killLiveChildren(): void {
  for (const live of liveChildren) live.kill("SIGKILL");
  liveChildren.clear();
}

function installHooks(): void {
  if (hooksInstalled) return;
  hooksInstalled = true;
  process.on("exit", killLiveChildren);
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of TERMINATION_SIGNALS) {
    const handler = (): void => {
      killLiveChildren();
      for (const [installed, listener] of handlers)
        process.removeListener(installed, listener);
      process.kill(process.pid, signal);
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
}

function trackChild(child: ChildProcess): () => void {
  liveChildren.add(child);
  installHooks();
  return () => {
    liveChildren.delete(child);
  };
}

export class SpawnCommandRunner implements CommandRunner {
  constructor(private readonly timeoutMs: number = COMMAND_TIMEOUT_MS) {}

  async run(command: string, args: readonly string[]): Promise<number> {
    return (await this.execute(command, args)).code;
  }

  async runWithInput(
    command: string,
    args: readonly string[],
    input: string,
  ): Promise<CommandResult> {
    return this.execute(command, args, input);
  }

  private async execute(
    command: string,
    args: readonly string[],
    input?: string,
  ): Promise<CommandResult> {
    return new Promise<CommandResult>((resolve, reject) => {
      const child = spawn(command, [...args], {
        // Output is only captured when the caller supplies input, so the
        // existing single-path invocations still discard everything.
        stdio: input === undefined ? "ignore" : ["pipe", "pipe", "ignore"],
        windowsHide: true,
        env: powerShellEnvironment(),
      });
      const untrack = trackChild(child);
      let stdout = "";
      let settled = false;
      // `timer` is declared below; every path that reads it runs from a later
      // event loop turn.
      const finish = (settle: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        untrack();
        // However this promise settles, no child outlives it. A child that
        // never started has no pid and must not be signalled.
        if (
          child.pid !== undefined &&
          child.exitCode === null &&
          child.signalCode === null
        )
          child.kill("SIGKILL");
        settle();
      };
      const timer = setTimeout(() => {
        finish(() => {
          reject(
            new Error(
              `${command} timed out after ${String(this.timeoutMs)} ms`,
            ),
          );
        });
      }, this.timeoutMs);
      timer.unref();
      // `on`, not `once`: a later error must still find a listener, or Node
      // turns it into an uncaught exception.
      child.on("error", (error: Error) => {
        finish(() => {
          reject(error);
        });
      });
      // A child that exits before reading its input must surface as an exit
      // code, not as an unhandled EPIPE on the pipe we are writing.
      child.stdin?.on("error", () => undefined);
      child.stdout?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => {
        stdout += chunk;
        if (stdout.length > MAX_COMMAND_OUTPUT_CHARS)
          finish(() => {
            reject(
              new Error(
                `${command} produced more than ${String(MAX_COMMAND_OUTPUT_CHARS)} characters of output`,
              ),
            );
          });
      });
      // `close` rather than `exit`: the captured output must be complete.
      child.once("close", (code, signal) => {
        finish(() => {
          if (code === null)
            reject(
              new Error(`${command} terminated with signal ${String(signal)}`),
            );
          else resolve({ code, stdout });
        });
      });
      if (input !== undefined) child.stdin?.end(input);
    });
  }
}

const UNSAFE_ACL_EXIT_CODE = 3;
const SAFE_RESULT = "safe";
const UNSAFE_RESULT = "unsafe";

// The per-target ACL work, shared by the single-path and batch scripts. It
// reads `$sid`, `$path`, `$directory`, and `$action`, and leaves the verdict in
// `$safe`.
//
// `apply` mutates the object `Get-Acl` returns instead of constructing a fresh
// `DirectorySecurity`/`FileSecurity`. A newly constructed security object marks
// every section dirty, so `Set-Acl` also tries to write the SACL, which needs
// SeSecurityPrivilege and therefore fails for ordinary accounts even when the
// resulting DACL would have been correct. Mutating the fetched object marks
// only the owner and DACL sections.
//
// A `Set-Acl` failure is recorded rather than raised: the verification below is
// the authority, so a privilege error over an ACL that is already owner-only is
// not a failure, while a genuinely unsafe result still is.
const ACL_TARGET_BODY = [
  "$safe=$false",
  "$applyError=''",
  `if($action -eq 'apply'){try{${[
    "$acl=Get-Acl -LiteralPath $path",
    "$current=$acl.GetOwner([System.Security.Principal.SecurityIdentifier])",
    "if($null -eq $current -or $current.Value -ne $sid.Value){$acl.SetOwner($sid)}",
    "$acl.SetAccessRuleProtection($true,$false)",
    "foreach($existing in @($acl.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier]))){$acl.PurgeAccessRules($existing.IdentityReference)}",
    "$inherit=if($directory){[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[System.Security.AccessControl.InheritanceFlags]::None}",
    "$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid,[System.Security.AccessControl.FileSystemRights]::FullControl,$inherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow))",
    "Set-Acl -LiteralPath $path -AclObject $acl",
  ].join(";")}}catch{$applyError=$_.Exception.Message}}`,
  "$actual=Get-Acl -LiteralPath $path",
  "$rules=@($actual.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))",
  // `$actual.Owner` is the translated NTAccount form (`COMPUTER\user`),
  // which never equals an SID string. Compare SID to SID.
  "$owner=$actual.GetOwner([System.Security.Principal.SecurityIdentifier])",
  "$safe=$actual.AreAccessRulesProtected -and $null -ne $owner -and $owner.Value -eq $sid.Value -and $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $sid.Value -and $rules[0].AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and (($rules[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl)",
  // Single quotes only: a double quote here would have to survive Node's
  // Windows argument escaping on the way to powershell.exe.
  "if(-not $safe){[Console]::Error.WriteLine('unsafe path=' + $path + ' protected=' + $actual.AreAccessRulesProtected + ' owner=' + $owner.Value + ' expected=' + $sid.Value + ' rules=' + $rules.Count + ' identity=' + $rules[0].IdentityReference.Value + ' type=' + $rules[0].AccessControlType + ' rights=' + $rules[0].FileSystemRights + ' apply=' + $applyError)}",
].join(";");

const CURRENT_SID =
  "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User";

export class WindowsFileSecurity implements VerifiedFileSecurity {
  constructor(
    private readonly runner: CommandRunner = new SpawnCommandRunner(),
  ) {}

  async secureDirectory(path: string): Promise<void> {
    await this.apply(path, true);
  }

  async secureFile(path: string): Promise<void> {
    await this.apply(path, false);
  }

  async verifyDirectory(path: string): Promise<boolean> {
    return this.verify(path, true);
  }

  async verifyFile(path: string): Promise<boolean> {
    return this.verify(path, false);
  }

  async verifyMany(targets: readonly AclTarget[]): Promise<readonly boolean[]> {
    if (targets.length === 0) return [];
    return this.batch(targets, "verify");
  }

  async secureMany(targets: readonly AclTarget[]): Promise<void> {
    if (targets.length === 0) return;
    const results = await this.batch(targets, "apply");
    const failed = results.filter((safe) => !safe).length;
    if (failed > 0)
      throw new Error(
        `powershell.exe could not apply an owner-only ACL to ${String(failed)} of ${String(targets.length)} paths`,
      );
  }

  private async apply(path: string, directory: boolean): Promise<void> {
    const code = await this.runner.run(
      "powershell.exe",
      this.arguments(path, directory, "apply"),
    );
    if (code === 0) return;
    // Windows can refuse `Set-Acl` for want of SeSecurityPrivilege even when
    // the owner-only ACL it would have written is already in place. Only a
    // postcondition that verifies as safe rescues the failure; an unsafe or
    // unreadable one stays an error, so the security contract never weakens.
    let verified = false;
    try {
      verified = await this.verify(path, directory);
    } catch {
      verified = false;
    }
    if (!verified)
      throw new Error(`powershell.exe exited with status ${String(code)}`);
  }

  private async verify(path: string, directory: boolean): Promise<boolean> {
    const code = await this.runner.run(
      "powershell.exe",
      this.arguments(path, directory, "verify"),
    );
    if (code === UNSAFE_ACL_EXIT_CODE) return false;
    if (code !== 0)
      throw new Error(`powershell.exe exited with status ${String(code)}`);
    return true;
  }

  private async batch(
    targets: readonly AclTarget[],
    action: "apply" | "verify",
  ): Promise<readonly boolean[]> {
    const input = targets
      .map(
        (target) =>
          `${target.kind === "directory" ? "d" : "f"}${powerShellStdinLine(target.path)}\n`,
      )
      .join("");
    const result = await this.runner.runWithInput(
      "powershell.exe",
      this.batchArguments(action),
      input,
    );
    if (result.code !== 0)
      throw new Error(
        `powershell.exe exited with status ${String(result.code)}`,
      );
    const lines = result.stdout.split("\n").map((line) => line.trim());
    // Only the trailing newline of the last verdict is dropped: a blank line
    // anywhere else means the verdicts no longer line up with the inputs.
    while (lines.length > targets.length && lines.at(-1) === "") lines.pop();
    if (lines.length !== targets.length)
      throw new Error(
        `powershell.exe reported ${String(lines.length)} ACL results for ${String(targets.length)} paths`,
      );
    return lines.map((line) => {
      if (line !== SAFE_RESULT && line !== UNSAFE_RESULT)
        throw new Error("powershell.exe reported an unrecognized ACL result");
      return line === SAFE_RESULT;
    });
  }

  private arguments(
    path: string,
    directory: boolean,
    action: "apply" | "verify",
  ): string[] {
    const script = [
      "$ErrorActionPreference='Stop'",
      `$path=${powerShellLiteral(path)}`,
      `$directory=$${String(directory)}`,
      `$action=${powerShellLiteral(action)}`,
      "$code=0",
      // The runner discards the child's output, so this reaches nobody in
      // normal use; it exists for the Windows acceptance script.
      `try{${CURRENT_SID};${ACL_TARGET_BODY};if(-not $safe){$code=${String(UNSAFE_ACL_EXIT_CODE)}}}catch{[Console]::Error.WriteLine($_.Exception.Message);$code=1}`,
      "exit $code",
    ].join(";");
    return [...POWERSHELL_PREFIX, script];
  }

  // The batch script never names a path: the targets arrive on stdin as
  // `<kind><path>` lines, because a hundred paths would overrun the Windows
  // command-line limit. It answers with one verdict per input line, in order,
  // and a target that throws is reported unsafe instead of ending the batch.
  //
  // stdin is decoded as UTF-8 explicitly. Node writes the payload as UTF-8,
  // but `[Console]::In` decodes with `[Console]::InputEncoding`, which under
  // powershell.exe 5.1 is the console code page (437/850/1252) - `C:\Users\
  // José\...` would arrive as `JosÃ©` and every `Get-Acl` on it would fail.
  // The single-path scripts are unaffected because their path travels in the
  // `-Command` argument, which Windows hands over as UTF-16. Verdicts are
  // ASCII, so the output encoding needs no such care.
  private batchArguments(action: "apply" | "verify"): string[] {
    const script = [
      "$ErrorActionPreference='Stop'",
      `$action=${powerShellLiteral(action)}`,
      CURRENT_SID,
      "$out=[Console]::Out",
      "$reader=[System.IO.StreamReader]::new([Console]::OpenStandardInput(),[System.Text.UTF8Encoding]::new($false))",
      "$payload=$reader.ReadToEnd()",
      `foreach($line in $payload.Split([char]10)){${[
        "$line=$line.TrimEnd([char]13)",
        "if($line.Length -eq 0){continue}",
        "$directory=$line.Substring(0,1) -eq 'd'",
        "$path=$line.Substring(1)",
        `$status=${powerShellLiteral(UNSAFE_RESULT)}`,
        `try{${ACL_TARGET_BODY};if($safe){$status=${powerShellLiteral(SAFE_RESULT)}}}catch{[Console]::Error.WriteLine($_.Exception.Message)}`,
        "$out.WriteLine($status)",
      ].join(";")}}`,
      "exit 0",
    ].join(";");
    return [...POWERSHELL_PREFIX, script];
  }
}

export function defaultFileSecurity(
  platform: NodeJS.Platform = process.platform,
): VerifiedFileSecurity {
  return platform === "win32"
    ? new WindowsFileSecurity()
    : new UnixFileSecurity();
}

export async function secureDirectory(
  path: string,
  security: FileSecurity,
): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  await security.secureDirectory(path);
}
