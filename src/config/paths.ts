// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { homedir } from "node:os";
import { join, win32 } from "node:path";

export interface PlatformPaths {
  readonly configFile: string;
  readonly stateDir: string;
  readonly cacheDir: string;
  readonly credentialsDir: string;
}

export interface PathEnvironment {
  readonly NOVAMIRA_HOME?: string;
  readonly XDG_CONFIG_HOME?: string;
  readonly XDG_STATE_HOME?: string;
  readonly XDG_CACHE_HOME?: string;
  readonly APPDATA?: string;
  readonly LOCALAPPDATA?: string;
}

export function platformPaths(
  environment: PathEnvironment = process.env,
  platform: NodeJS.Platform = process.platform,
  home: string = homedir(),
): PlatformPaths {
  const combine =
    platform === "win32" ? (...parts: string[]) => win32.join(...parts) : join;
  if (
    environment.NOVAMIRA_HOME !== undefined &&
    environment.NOVAMIRA_HOME !== ""
  ) {
    const root = environment.NOVAMIRA_HOME;
    return {
      configFile: combine(root, "config.json"),
      stateDir: combine(root, "state"),
      cacheDir: combine(root, "cache"),
      credentialsDir: combine(root, "credentials"),
    };
  }

  if (platform === "win32") {
    const roaming = environment.APPDATA ?? combine(home, "AppData", "Roaming");
    const local = environment.LOCALAPPDATA ?? combine(home, "AppData", "Local");
    return {
      configFile: combine(roaming, "Novamira", "config.json"),
      stateDir: combine(local, "Novamira", "State"),
      cacheDir: combine(local, "Novamira", "Cache"),
      credentialsDir: combine(local, "Novamira", "Credentials"),
    };
  }

  if (platform === "darwin") {
    const support = join(home, "Library", "Application Support", "Novamira");
    return {
      configFile: join(support, "config.json"),
      stateDir: join(support, "State"),
      cacheDir: join(home, "Library", "Caches", "Novamira"),
      credentialsDir: join(support, "Credentials"),
    };
  }

  return {
    configFile: join(
      environment.XDG_CONFIG_HOME ?? join(home, ".config"),
      "novamira",
      "config.json",
    ),
    stateDir: join(
      environment.XDG_STATE_HOME ?? join(home, ".local", "state"),
      "novamira",
    ),
    cacheDir: join(
      environment.XDG_CACHE_HOME ?? join(home, ".cache"),
      "novamira",
    ),
    credentialsDir: join(
      environment.XDG_STATE_HOME ?? join(home, ".local", "state"),
      "novamira",
      "credentials",
    ),
  };
}
