// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFile } from "node:fs/promises";
import { CliError } from "../errors.js";
import { atomicWriteFile } from "./atomic-write.js";
import type { FileSecurity } from "./file-security.js";
import type { ProfileLockManager } from "./lock.js";
import { normalizeSiteUrl } from "./site-url.js";

export const PROFILE_FORMAT_VERSION = 1;

export interface ProfileCompatibility {
  readonly pluginVersion: string;
  readonly restApiVersion: number;
  readonly wordpressVersion?: string;
  readonly checkedAt?: string;
}

export interface SiteProfile {
  readonly name: string;
  readonly siteUrl: string;
  readonly origin: string;
  readonly clientId?: string;
  readonly compatibility?: ProfileCompatibility;
}

interface ProfileDocument {
  readonly version: 1;
  readonly profiles: Record<string, SiteProfile>;
}

export interface ProfileCleanupHook {
  cleanup(profile: SiteProfile): Promise<void>;
}

export interface SelectionEnvironment {
  readonly NOVAMIRA_SITE?: string;
}

export function validateProfileName(name: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
    throw new CliError(
      "usage_error",
      "Profile name must use 1-64 letters, numbers, dots, dashes, or underscores.",
    );
  }
  return name;
}

function emptyDocument(): ProfileDocument {
  return { version: PROFILE_FORMAT_VERSION, profiles: {} };
}

function isProfile(value: unknown): value is SiteProfile {
  if (value === null || typeof value !== "object") return false;
  const profile = value as Partial<SiteProfile>;
  const keys = Object.keys(profile);
  if (
    !keys.every((key) =>
      ["name", "siteUrl", "origin", "clientId", "compatibility"].includes(key),
    )
  ) {
    return false;
  }
  const compatibility = profile.compatibility;
  const validCompatibility =
    compatibility === undefined ||
    (typeof compatibility.pluginVersion === "string" &&
      typeof compatibility.restApiVersion === "number" &&
      Number.isSafeInteger(compatibility.restApiVersion) &&
      (compatibility.wordpressVersion === undefined ||
        typeof compatibility.wordpressVersion === "string") &&
      (compatibility.checkedAt === undefined ||
        (typeof compatibility.checkedAt === "string" &&
          Number.isFinite(Date.parse(compatibility.checkedAt)))) &&
      Object.keys(compatibility).every((key) =>
        [
          "pluginVersion",
          "restApiVersion",
          "wordpressVersion",
          "checkedAt",
        ].includes(key),
      ));
  if (!(
    validCompatibility &&
    typeof profile.name === "string" &&
    typeof profile.siteUrl === "string" &&
    typeof profile.origin === "string" &&
    (profile.clientId === undefined || typeof profile.clientId === "string")
  ))
    return false;
  try {
    validateProfileName(profile.name);
    // Loading local state is non-networking. Keep development HTTP profiles
    // manageable even when the per-invocation opt-in is not present; URL use
    // is validated again by the REST URL helpers before any request.
    const normalized = normalizeSiteUrl(profile.siteUrl, {
      NOVAMIRA_ALLOW_INSECURE_HTTP: "1",
    });
    return (
      normalized.siteUrl === profile.siteUrl &&
      normalized.origin === profile.origin
    );
  } catch {
    return false;
  }
}

export class ProfileStore {
  constructor(
    private readonly configFile: string,
    private readonly locks: ProfileLockManager,
    private readonly security: FileSecurity,
    private readonly cleanupHooks: readonly ProfileCleanupHook[] = [],
  ) {}

  async list(): Promise<SiteProfile[]> {
    const document = await this.readDocument();
    return Object.values(document.profiles).sort((left, right) =>
      left.name.localeCompare(right.name),
    );
  }

  async get(name: string): Promise<SiteProfile | undefined> {
    return (await this.readDocument()).profiles[name];
  }

  async upsert(input: {
    name: string;
    siteUrl: string;
    clientId?: string;
    compatibility?: ProfileCompatibility;
  }): Promise<SiteProfile> {
    const name = validateProfileName(input.name);
    return this.locks.withLock(name, async () => this.upsertUnderLock(input));
  }

  async upsertUnderLock(input: {
    name: string;
    siteUrl: string;
    clientId?: string;
    compatibility?: ProfileCompatibility;
  }): Promise<SiteProfile> {
    const name = validateProfileName(input.name);
    const normalized = normalizeSiteUrl(input.siteUrl);
    const profile: SiteProfile = {
      name,
      ...normalized,
      ...(input.clientId === undefined ? {} : { clientId: input.clientId }),
      ...(input.compatibility === undefined
        ? {}
        : { compatibility: input.compatibility }),
    };
    await this.locks.withLock("__profile_document__", async () => {
      const document = await this.readDocument();
      await this.writeDocument({
        ...document,
        profiles: { ...document.profiles, [name]: profile },
      });
    });
    return profile;
  }

  async remove(name: string): Promise<SiteProfile> {
    validateProfileName(name);
    return this.locks.withLock(name, async () => {
      const profile = await this.get(name);
      if (profile === undefined) {
        throw new CliError(
          "site_not_found",
          `Site profile ${name} was not found.`,
        );
      }
      for (const hook of this.cleanupHooks) await hook.cleanup(profile);
      await this.locks.withLock("__profile_document__", async () => {
        const document = await this.readDocument();
        if (document.profiles[name] === undefined) {
          throw new CliError(
            "site_not_found",
            `Site profile ${name} was not found.`,
          );
        }
        const profiles = Object.fromEntries(
          Object.entries(document.profiles).filter(
            ([profileName]) => profileName !== name,
          ),
        );
        await this.writeDocument({ ...document, profiles });
      });
      return profile;
    });
  }

  async select(
    explicitSite: string | undefined,
    environment: SelectionEnvironment,
  ): Promise<SiteProfile> {
    const profiles = await this.list();
    const requested = explicitSite ?? environment.NOVAMIRA_SITE;
    if (requested !== undefined && requested !== "") {
      const profile = profiles.find(
        (candidate) => candidate.name === requested,
      );
      if (profile === undefined) {
        throw new CliError(
          "site_not_found",
          `Site profile ${requested} was not found.`,
          {
            details: { profiles: profiles.map(({ name }) => name) },
          },
        );
      }
      return profile;
    }
    const soleProfile = profiles[0];
    if (profiles.length === 1 && soleProfile !== undefined) return soleProfile;
    throw new CliError(
      "site_required",
      "Select a site profile with --site or NOVAMIRA_SITE.",
      {
        details: { profiles: profiles.map(({ name }) => name) },
      },
    );
  }

  private async readDocument(): Promise<ProfileDocument> {
    let raw: string;
    try {
      raw = await readFile(this.configFile, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT")
        return emptyDocument();
      throw error;
    }
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed === null || typeof parsed !== "object")
        throw new Error("not an object");
      const candidate = parsed as Partial<ProfileDocument>;
      if (
        candidate.version !== PROFILE_FORMAT_VERSION ||
        candidate.profiles === undefined
      ) {
        throw new Error("unsupported profile format");
      }
      if (
        Object.entries(candidate.profiles).some(
          ([name, profile]) => !isProfile(profile) || profile.name !== name,
        )
      ) {
        throw new Error("invalid profile record");
      }
      return candidate as ProfileDocument;
    } catch (cause) {
      throw new CliError(
        "internal_error",
        "Profile configuration is corrupt or unsupported.",
        { cause },
      );
    }
  }

  private async writeDocument(document: ProfileDocument): Promise<void> {
    await atomicWriteFile(
      this.configFile,
      `${JSON.stringify(document, null, 2)}\n`,
      this.security,
    );
  }
}
