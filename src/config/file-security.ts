// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { chmod, mkdir, stat } from "node:fs/promises";
import { spawn } from "node:child_process";

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
  run(command: string, args: readonly string[]): Promise<void>;
}

export class SpawnCommandRunner implements CommandRunner {
  async run(command: string, args: readonly string[]): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(command, [...args], {
        stdio: "ignore",
        windowsHide: true,
      });
      child.once("error", reject);
      child.once("exit", (code) => {
        if (code === 0) resolve();
        else reject(new Error(`${command} exited with status ${String(code)}`));
      });
    });
  }
}

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
    await this.verify(path);
    return true;
  }

  async verifyFile(path: string): Promise<boolean> {
    await this.verify(path);
    return true;
  }

  private async apply(path: string, directory: boolean): Promise<void> {
    await this.runner.run(
      "powershell.exe",
      this.arguments(path, directory, "apply"),
    );
  }

  private async verify(path: string): Promise<void> {
    await this.runner.run(
      "powershell.exe",
      this.arguments(path, false, "verify"),
    );
  }

  private arguments(
    path: string,
    directory: boolean,
    action: "apply" | "verify",
  ): string[] {
    const script = [
      "$path=$args[0]",
      "$directory=$args[1] -eq 'directory'",
      "$action=$args[2]",
      "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User",
      "if($action -eq 'apply'){$acl=if($directory){[System.Security.AccessControl.DirectorySecurity]::new()}else{[System.Security.AccessControl.FileSecurity]::new()};$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);$inherit=if($directory){[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[System.Security.AccessControl.InheritanceFlags]::None};$rule=[System.Security.AccessControl.FileSystemAccessRule]::new($sid,[System.Security.AccessControl.FileSystemRights]::FullControl,$inherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow);$acl.AddAccessRule($rule);Set-Acl -LiteralPath $path -AclObject $acl}",
      "$actual=Get-Acl -LiteralPath $path",
      "$rules=@($actual.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))",
      "if(-not $actual.AreAccessRulesProtected -or $actual.Owner -ne $sid.Value -or $rules.Count -ne 1 -or $rules[0].IdentityReference -ne $sid -or $rules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or (($rules[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl)){throw 'unsafe ACL'}",
    ].join(";");
    return [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
      path,
      directory ? "directory" : "file",
      action,
    ];
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
