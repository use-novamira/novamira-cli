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
  // Hardens every target. Rejects unless every target ends within the
  // platform's storage policy.
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

// The two administrative principals a private storage ACL may also grant, as
// literal SIDs: `S-1-5-18` is SYSTEM and `S-1-5-32-544` is the local
// Administrators group. They are well-known, machine-independent, and identical
// on every Windows installation, which is exactly why they are written as SIDs.
// A localized machine reports them as `NT AUTHORITY\SYSTEM` or `NT instans\
// SYSTEM`, and `BUILTIN\Administrators` or `BUILTIN\Administratörer`; comparing
// those names would make the policy depend on the display language.
//
// Neither is required. Owner-only remains a valid shape, and this list is the
// complete set of additions: every other principal fails.
const PERMITTED_ADMINISTRATIVE_SIDS = ["S-1-5-18", "S-1-5-32-544"] as const;

// Reads `$sid`, `$path`, and `$directory`, and leaves the verdict in `$safe`.
//
// A private storage object is safe when the DACL is protected from inheritance,
// the owner is the current user, and every access rule on it is one this policy
// permits. Each rule is judged on its own, and the administrative principals are
// held to exactly the requirements the owner's own rule is held to: explicit,
// Allow, FullControl, the inheritance shape the object kind requires, no
// propagation flags, and no second rule for the same principal. The current
// user's rule is mandatory; the other two are optional. Anything else - an
// unexpected principal, an inherited rule, a Deny, a partial right, a stray
// propagation flag, a duplicate - fails.
//
// Counting rules is not a policy. The previous predicate required exactly one
// rule, which rejected a DACL that granted SYSTEM and Administrators before it
// ever considered who those principals were; it also never examined Deny,
// inheritance flags, propagation flags, or duplicates, because one rule that
// matched the owner made all of that unreachable. Judging every rule is both
// stricter, on four properties that previously went unchecked, and narrower in
// exactly one respect: two named administrative SIDs may also appear.
const ACL_EVALUATE = [
  "$actual=Get-Acl -LiteralPath $path",
  // Explicit and inherited alike, translated to SIDs. An inherited rule is
  // rejected below rather than filtered out here: it must fail the policy, not
  // silently disappear from it.
  "$rules=@($actual.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))",
  // `$actual.Owner` is the translated NTAccount form (`COMPUTER\user`),
  // which never equals an SID string. Compare SID to SID.
  "$owner=$actual.GetOwner([System.Security.Principal.SecurityIdentifier])",
  `$permitted=@($sid.Value,${PERMITTED_ADMINISTRATIVE_SIDS.map((sid) => `'${sid}'`).join(",")})`,
  "$wantInherit=if($directory){[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[System.Security.AccessControl.InheritanceFlags]::None}",
  "$seen=@()",
  "$rulesOk=$true",
  `foreach($rule in $rules){${[
    "$identity=$rule.IdentityReference.Value",
    "if($rule.IsInherited){$rulesOk=$false}",
    "if($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow){$rulesOk=$false}",
    "if($permitted -notcontains $identity){$rulesOk=$false}",
    "if(($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl){$rulesOk=$false}",
    "if($rule.InheritanceFlags -ne $wantInherit){$rulesOk=$false}",
    "if($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None){$rulesOk=$false}",
    "if($seen -contains $identity){$rulesOk=$false}",
    "$seen+=$identity",
  ].join(";")}}`,
  "$safe=$actual.AreAccessRulesProtected -and $null -ne $owner -and $owner.Value -eq $sid.Value -and $rules.Count -ge 1 -and $rules.Count -le $permitted.Count -and $rulesOk -and ($seen -contains $sid.Value)",
].join(";");

// Brings an unsafe object to the exact shape `ACL_EVALUATE` accepts.
//
// Every explicit rule is purged and the accepted ones are re-added in canonical
// form, rather than edited in place. A rule that is preserved untouched would
// have to be proved correct in every respect first - rights, type, inheritance,
// propagation, uniqueness - and re-adding it canonically reaches the same state
// with no such proof, which is why an insufficient, denied, duplicated, or
// wrongly flagged administrative rule needs no separate repair path.
//
// An administrative principal is re-added only when the descriptor that arrived
// was already protected, denied nothing at all - explicitly or by inheritance -
// and held an explicit Allow for that exact SID. `Deny`-only means no access to
// preserve; a Deny alongside the Allow means access somebody explicitly
// refused, and granting it would broaden the descriptor rather than repair it;
// and an unprotected descriptor cannot be trusted to still show a refusal an
// ancestor's earlier repair may already have removed. An inherited grant is
// precisely what protecting the DACL is meant to sever - so a freshly created
// directory, which inherits rather than carries explicit rules, still hardens
// to owner-only exactly as before.
//
// It fetches and writes through `FileSystemInfo.GetAccessControl` and
// `SetAccessControl` with the owner and access sections named explicitly,
// rather than through `Get-Acl`/`Set-Acl`. `Set-Acl` decides for itself which
// sections to persist and reaches for the SACL, which needs SeSecurityPrivilege
// and fails for an ordinary account even when the DACL it would have written
// was correct - observed against a protected descriptor that had been built
// through this same API. Naming the sections keeps the write to exactly the
// owner and the DACL, and never the group or the SACL.
const ACL_REPAIR = [
  "$item=Get-Item -LiteralPath $path -Force",
  "$sections=[System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access",
  "$acl=$item.GetAccessControl($sections)",
  "$current=$acl.GetOwner([System.Security.Principal.SecurityIdentifier])",
  "if($null -eq $current -or $current.Value -ne $sid.Value){$acl.SetOwner($sid)}",
  // Read before anything is purged: the decision to keep an administrative
  // principal is made from the descriptor that arrived, not from the one being
  // built.
  //
  // An explicit Allow proposes an optional administrative principal, and ANY
  // Deny anywhere in the incoming DACL vetoes all of them. The veto is
  // deliberately global rather than per-SID:
  //
  //   - An inherited Deny is invisible to an explicit-only scan, and repair
  //     protects the DACL, which severs inheritance. Reading explicit rules
  //     alone would let an inherited refusal be dropped and the principal then
  //     re-added as FullControl.
  //   - A Deny naming some other principal can still constrain SYSTEM or
  //     Administrators through group membership, and resolving Windows tokens
  //     and nested groups is far outside what this predicate can do safely.
  //
  // So the conservative rule is the one that cannot escalate: if the incoming
  // descriptor denies anything at all, no optional administrative principal is
  // preserved. Repair may then narrow access, which is safe, but it can never
  // convert a refusal into full control. Both lists are collected in one pass
  // over the whole DACL, so ACE ordering cannot change the outcome.
  //
  // The incoming protection state is the third precondition, and it must be
  // read here, before `SetAccessRuleProtection` below makes every descriptor
  // look protected and the safeguard inert.
  //
  // It exists because `doctor --fix` repairs a whole storage tree in one pass,
  // parent before child, and repairing a parent strips its Deny. An unprotected
  // child that inherited that Deny would then be judged a moment later against
  // a descriptor from which the refusal had already vanished, and its own
  // explicit administrative Allows would be restored as FullControl - widening
  // access across the pair even though every single-target decision was
  // individually correct.
  //
  // An unprotected DACL is exactly the state in which that can happen, and it
  // is also a state this policy rejects outright, so nothing is lost by
  // refusing to preserve optional access from it: such a target is repaired
  // conservatively to owner-only. A protected descriptor cannot have inherited
  // anything, so what it carries is what its administrator wrote.
  "$wasProtected=$acl.AreAccessRulesProtected",
  // The current user is exempt from all three preconditions: their rule is the
  // mandatory policy boundary rather than optional preserved access, and it is
  // written unconditionally below whatever the previous descriptor said.
  `$allowed=@()`,
  "$anyDeny=$false",
  `foreach($existing in @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))){${[
    "if($existing.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny){$anyDeny=$true;continue}",
    "$identity=$existing.IdentityReference.Value",
    // Only an explicit Allow proposes a principal: an inherited grant is
    // exactly what protecting the DACL is meant to sever.
    "if($existing.IsInherited){continue}",
    `if(@(${PERMITTED_ADMINISTRATIVE_SIDS.map((sid) => `'${sid}'`).join(",")}) -notcontains $identity){continue}`,
    "if($allowed -notcontains $identity){$allowed+=$identity}",
  ].join(";")}}`,
  "$keep=@(if($wasProtected -and -not $anyDeny){$allowed}else{@()})",
  "$acl.SetAccessRuleProtection($true,$false)",
  "foreach($existing in @($acl.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier]))){$acl.PurgeAccessRules($existing.IdentityReference)}",
  "$inherit=if($directory){[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[System.Security.AccessControl.InheritanceFlags]::None}",
  // The owner's rule is mandatory and is written first.
  "$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid,[System.Security.AccessControl.FileSystemRights]::FullControl,$inherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow))",
  "foreach($identity in $keep){$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($identity),[System.Security.AccessControl.FileSystemRights]::FullControl,$inherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow))}",
  "$item.SetAccessControl($acl)",
].join(";");

// The per-target ACL work, shared by the single-path and batch scripts. It
// reads `$sid`, `$path`, `$directory`, and `$action`, and leaves the verdict in
// `$safe`.
//
// The object is judged before anything is written, and `apply` repairs only
// what the judgement rejected. An ACL that already verifies is left exactly as
// it is - no ACL write, no owner write, no descriptor change - which is what
// makes a second `apply`, and `doctor --fix` over already-safe storage, produce
// no churn at all.
//
// An apply failure is recorded rather than raised: the verification below is
// the authority, so a privilege error over an ACL that is already correct is
// not a failure, while a genuinely unsafe result still is.
const ACL_TARGET_BODY = [
  "$safe=$false",
  "$applyError=''",
  ACL_EVALUATE,
  `if($action -eq 'apply' -and -not $safe){try{${ACL_REPAIR}}catch{$applyError=$_.Exception.Message};${ACL_EVALUATE}}`,
  // Single quotes only: a double quote here would have to survive Node's
  // Windows argument escaping on the way to powershell.exe. The identities are
  // joined rather than indexed, so an empty DACL reports itself instead of
  // failing on `$rules[0]`.
  "if(-not $safe){[Console]::Error.WriteLine('unsafe path=' + $path + ' protected=' + $actual.AreAccessRulesProtected + ' owner=' + $owner.Value + ' expected=' + $sid.Value + ' rules=' + $rules.Count + ' identities=' + ($seen -join ',') + ' rulesOk=' + $rulesOk + ' apply=' + $applyError)}",
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
        `powershell.exe could not establish the required Windows storage ACL on ${String(failed)} of ${String(targets.length)} paths`,
      );
  }

  private async apply(path: string, directory: boolean): Promise<void> {
    const code = await this.runner.run(
      "powershell.exe",
      this.arguments(path, directory, "apply"),
    );
    if (code === 0) return;
    // Windows can refuse the ACL write for want of SeSecurityPrivilege even
    // when the ACL it would have written is already in place. Only a
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
