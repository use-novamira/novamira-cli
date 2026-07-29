// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { powerShellLiteral } from "../config/powershell.js";
import { CliError } from "../errors.js";
import {
  BackendUnavailableError,
  SpawnCommandExecutor,
  type CommandExecutor,
  type CommandResult,
} from "./command-executor.js";
import {
  CREDENTIAL_SERVICE,
  type CredentialBackend,
  type CredentialDiagnostic,
} from "./credentials.js";

abstract class CommandCredentialBackend implements CredentialBackend {
  constructor(
    protected readonly executor: CommandExecutor = new SpawnCommandExecutor(),
  ) {}

  abstract read(account: string): Promise<string | undefined>;
  abstract replace(account: string, serialized: string): Promise<void>;
  abstract delete(account: string): Promise<void>;
  abstract diagnostic(): CredentialDiagnostic;
  abstract probe(): Promise<boolean>;

  protected requireSuccess(result: CommandResult): void {
    if (result.code !== 0) {
      throw new CliError(
        "auth_required",
        "The OS credential service could not complete the operation.",
      );
    }
  }
}

export class MacOsKeychainBackend extends CommandCredentialBackend {
  async probe(): Promise<boolean> {
    return this.available("security", ["help"]);
  }

  async read(account: string): Promise<string | undefined> {
    const result = await this.executor.execute("security", [
      "find-generic-password",
      "-s",
      CREDENTIAL_SERVICE,
      "-a",
      account,
      "-w",
    ]);
    if (result.code === 44) return undefined;
    this.requireSuccess(result);
    return result.stdout.replace(/\r?\n$/, "");
  }

  async replace(account: string, serialized: string): Promise<void> {
    // The secret MUST be passed as the inline value of `-w`. `security
    // add-generic-password -w` with no inline value does not read the secret
    // from stdin; it drops into the interactive "password data" / "retype
    // password" prompt, which is backed by readpassphrase(3) and silently
    // truncates input at 128 bytes. A serialized credential (it carries a JWT
    // access token) is far longer than that, so any prompt/stdin approach
    // stores a truncated, unparseable record — and feeding it zero or one line
    // instead stores an empty one. Inline `-w <value>` has no length limit.
    //
    // Trade-off: the value is briefly visible in this process's argv (e.g. to
    // `ps`). That is unavoidable with the `security` CLI for secrets over 128
    // bytes, the exposure window is momentary, and macOS restricts argv
    // visibility to the same user. Linux (secret-tool) and Windows (CredWrite)
    // read the secret from stdin without a length cap and keep using it.
    const result = await this.executor.execute("security", [
      "add-generic-password",
      "-U",
      "-s",
      CREDENTIAL_SERVICE,
      "-a",
      account,
      "-w",
      serialized,
    ]);
    this.requireSuccess(result);
  }

  async delete(account: string): Promise<void> {
    const result = await this.executor.execute("security", [
      "delete-generic-password",
      "-s",
      CREDENTIAL_SERVICE,
      "-a",
      account,
    ]);
    if (result.code !== 0 && result.code !== 44) this.requireSuccess(result);
  }

  diagnostic(): CredentialDiagnostic {
    return { backend: "macos-keychain", osBackedEncryption: true };
  }

  private async available(command: string, args: string[]): Promise<boolean> {
    try {
      return (await this.executor.execute(command, args)).code === 0;
    } catch (error) {
      if (error instanceof BackendUnavailableError) return false;
      return false;
    }
  }
}

export class LinuxSecretServiceBackend extends CommandCredentialBackend {
  async probe(): Promise<boolean> {
    try {
      return (
        (await this.executor.execute("secret-tool", ["--version"])).code === 0
      );
    } catch (error) {
      if (error instanceof BackendUnavailableError) return false;
      return false;
    }
  }

  async read(account: string): Promise<string | undefined> {
    const result = await this.executor.execute("secret-tool", [
      "lookup",
      "service",
      CREDENTIAL_SERVICE,
      "account",
      account,
    ]);
    if (result.code === 1) return undefined;
    this.requireSuccess(result);
    return result.stdout.replace(/\r?\n$/, "");
  }

  async replace(account: string, serialized: string): Promise<void> {
    const result = await this.executor.execute(
      "secret-tool",
      [
        "store",
        "--label",
        "Novamira CLI",
        "service",
        CREDENTIAL_SERVICE,
        "account",
        account,
      ],
      serialized,
    );
    this.requireSuccess(result);
  }

  async delete(account: string): Promise<void> {
    const result = await this.executor.execute("secret-tool", [
      "clear",
      "service",
      CREDENTIAL_SERVICE,
      "account",
      account,
    ]);
    if (result.code !== 0 && result.code !== 1) this.requireSuccess(result);
  }

  diagnostic(): CredentialDiagnostic {
    return { backend: "linux-secret-service", osBackedEncryption: true };
  }
}

const WINDOWS_CREDENTIAL_SCRIPT = String.raw`
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class NovamiraCredential {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct CREDENTIAL {
    public uint Flags; public uint Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public uint CredentialBlobSize;
    public IntPtr CredentialBlob; public uint Persist; public uint AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredWrite(ref CREDENTIAL c, uint flags);
  [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
  [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredDelete(string target, uint type, uint flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr buffer);
  public static void Write(string target, string secret) {
    byte[] bytes=Encoding.Unicode.GetBytes(secret); IntPtr blob=Marshal.AllocCoTaskMem(bytes.Length);
    try { Marshal.Copy(bytes,0,blob,bytes.Length); var c=new CREDENTIAL { Type=1, TargetName=target, CredentialBlobSize=(uint)bytes.Length, CredentialBlob=blob, Persist=2, UserName=Environment.UserName }; if(!CredWrite(ref c,0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
    finally { for(int i=0;i<bytes.Length;i++) Marshal.WriteByte(blob,i,0); Marshal.FreeCoTaskMem(blob); }
  }
  public static string Read(string target) { IntPtr ptr; if(!CredRead(target,1,0,out ptr)) { if(Marshal.GetLastWin32Error()==1168) return null; throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); } try { var c=(CREDENTIAL)Marshal.PtrToStructure(ptr,typeof(CREDENTIAL)); return Marshal.PtrToStringUni(c.CredentialBlob,(int)c.CredentialBlobSize/2); } finally { CredFree(ptr); } }
  public static void Delete(string target) { if(!CredDelete(target,1,0) && Marshal.GetLastWin32Error()!=1168) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
}`;

export class WindowsCredentialManagerBackend extends CommandCredentialBackend {
  async probe(): Promise<boolean> {
    try {
      return (
        (
          await this.executor.execute("powershell.exe", [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
          ])
        ).code === 0
      );
    } catch (error) {
      if (error instanceof BackendUnavailableError) return false;
      return false;
    }
  }

  async read(account: string): Promise<string | undefined> {
    const result = await this.run("read", account);
    this.requireSuccess(result);
    const value = result.stdout.replace(/\r?\n$/, "");
    return value === "__NOVAMIRA_NOT_FOUND__" ? undefined : value;
  }

  async replace(account: string, serialized: string): Promise<void> {
    this.requireSuccess(await this.run("write", account, serialized));
  }

  async delete(account: string): Promise<void> {
    this.requireSuccess(await this.run("delete", account));
  }

  diagnostic(): CredentialDiagnostic {
    return { backend: "windows-credential-manager", osBackedEncryption: true };
  }

  private run(
    action: "read" | "write" | "delete",
    account: string,
    stdin = "",
  ): Promise<CommandResult> {
    const target = `${CREDENTIAL_SERVICE}/${account}`;
    const command = [
      "Add-Type -TypeDefinition $env:NOVAMIRA_CREDENTIAL_SOURCE",
      `$action=${powerShellLiteral(action)}`,
      `$target=${powerShellLiteral(target)}`,
      "if($action -eq 'write'){[NovamiraCredential]::Write($target,[Console]::In.ReadToEnd())}",
      "elseif($action -eq 'read'){$v=[NovamiraCredential]::Read($target);if($null -eq $v){Write-Output '__NOVAMIRA_NOT_FOUND__'}else{[Console]::Out.Write($v)}}",
      "else{[NovamiraCredential]::Delete($target)}",
    ].join(";");
    // Source is fixed code, not secret data. The secret record is supplied only on stdin.
    return this.executor.execute(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `$env:NOVAMIRA_CREDENTIAL_SOURCE=@'\n${WINDOWS_CREDENTIAL_SCRIPT}\n'@;${command}`,
      ],
      stdin,
    );
  }
}

export type OsCredentialBackend =
  | MacOsKeychainBackend
  | LinuxSecretServiceBackend
  | WindowsCredentialManagerBackend;

export function osCredentialBackend(
  platform: NodeJS.Platform,
  executor: CommandExecutor = new SpawnCommandExecutor(),
): OsCredentialBackend {
  if (platform === "darwin") return new MacOsKeychainBackend(executor);
  if (platform === "win32")
    return new WindowsCredentialManagerBackend(executor);
  return new LinuxSecretServiceBackend(executor);
}
