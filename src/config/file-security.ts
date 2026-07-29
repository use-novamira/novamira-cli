// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { chmod, mkdir, stat } from "node:fs/promises";
import { spawn } from "node:child_process";

import { POWERSHELL_PREFIX, powerShellLiteral } from "./powershell.js";

export interface FileSecurity {
  secureDirectory(path: string): Promise<void>;
  secureFile(path: string): Promise<void>;
}

export interface VerifiedFileSecurity extends FileSecurity {
  verifyDirectory(path: string): Promise<boolean>;
  verifyFile(path: string): Promise<boolean>;
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

  private async verify(path: string, expectedMode: number): Promise<boolean> {
    const info = await stat(path);
    const ownerMatches =
      process.getuid === undefined || info.uid === process.getuid();
    return ownerMatches && (info.mode & 0o777) === expectedMode;
  }
}

export interface CommandRunner {
  run(command: string, args: readonly string[]): Promise<number>;
}

export class SpawnCommandRunner implements CommandRunner {
  async run(command: string, args: readonly string[]): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const child = spawn(command, [...args], {
        stdio: "ignore",
        windowsHide: true,
      });
      child.once("error", reject);
      child.once("exit", (code, signal) => {
        if (code === null)
          reject(
            new Error(`${command} terminated with signal ${String(signal)}`),
          );
        else resolve(code);
      });
    });
  }
}

const UNSAFE_ACL_EXIT_CODE = 3;

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

  private async apply(path: string, directory: boolean): Promise<void> {
    const code = await this.runner.run(
      "powershell.exe",
      this.arguments(path, directory, "apply"),
    );
    if (code !== 0)
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

  private arguments(
    path: string,
    directory: boolean,
    action: "apply" | "verify",
  ): string[] {
    const body = [
      "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User",
      "if($action -eq 'apply'){$acl=if($directory){[System.Security.AccessControl.DirectorySecurity]::new()}else{[System.Security.AccessControl.FileSecurity]::new()};$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);$inherit=if($directory){[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[System.Security.AccessControl.InheritanceFlags]::None};$rule=[System.Security.AccessControl.FileSystemAccessRule]::new($sid,[System.Security.AccessControl.FileSystemRights]::FullControl,$inherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow);$acl.AddAccessRule($rule);Set-Acl -LiteralPath $path -AclObject $acl}",
      "$actual=Get-Acl -LiteralPath $path",
      "$rules=@($actual.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))",
      `if(-not $actual.AreAccessRulesProtected -or $actual.Owner -ne $sid.Value -or $rules.Count -ne 1 -or $rules[0].IdentityReference -ne $sid -or $rules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or (($rules[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl)){$code=${String(UNSAFE_ACL_EXIT_CODE)}}`,
    ].join(";");
    const script = [
      "$ErrorActionPreference='Stop'",
      `$path=${powerShellLiteral(path)}`,
      `$directory=$${String(directory)}`,
      `$action=${powerShellLiteral(action)}`,
      "$code=0",
      // The runner discards the child's output, so this reaches nobody in
      // normal use; it exists for the Windows acceptance script.
      `try{${body}}catch{[Console]::Error.WriteLine($_.Exception.Message);$code=1}`,
      "exit $code",
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
