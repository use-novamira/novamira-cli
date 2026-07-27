// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { CliError } from "../errors.js";

const GUIDE_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

export interface GuideSummary {
  readonly name: string;
}

export interface GuideDocument {
  readonly name: string;
  readonly content: string;
  readonly references: readonly string[];
}

export class GuideStore {
  constructor(
    private readonly root = fileURLToPath(
      new URL("../../guide-data/", import.meta.url),
    ),
  ) {}

  async list(): Promise<readonly GuideSummary[]> {
    try {
      const entries = await readdir(this.root, { withFileTypes: true });
      const guides: GuideSummary[] = [];
      for (const entry of entries) {
        if (!entry.isDirectory() || !GUIDE_NAME.test(entry.name)) continue;
        try {
          await readFile(`${this.root}/${entry.name}/SKILL.md`, "utf8");
          guides.push({ name: entry.name });
        } catch (error) {
          if (!isMissing(error)) throw error;
          // Ignore package data directories that are not complete guides.
        }
      }
      return guides.sort((left, right) => left.name.localeCompare(right.name));
    } catch (error) {
      throw unavailable(error);
    }
  }

  async get(name: string, full = false): Promise<GuideDocument> {
    if (!GUIDE_NAME.test(name))
      throw new CliError("usage_error", "The guide name is invalid.");

    try {
      const directory = `${this.root}/${name}`;
      const content = (await readFile(`${directory}/SKILL.md`, "utf8")).trim();
      const references = await referenceNames(directory);
      if (!full) return { name, content, references };

      const sections = [content];
      for (const reference of references) {
        const text = await readFile(
          `${directory}/references/${reference}`,
          "utf8",
        );
        sections.push(
          `# Bundled reference: references/${reference}\n\n${text.trim()}`,
        );
      }
      return { name, content: sections.join("\n\n---\n\n"), references };
    } catch (error) {
      if (isMissing(error))
        throw new CliError("usage_error", `Guide ${name} is not installed.`);
      throw unavailable(error);
    }
  }
}

async function referenceNames(directory: string): Promise<readonly string[]> {
  try {
    const entries = await readdir(`${directory}/references`, {
      withFileTypes: true,
    });
    return entries
      .filter(
        (entry) =>
          entry.isFile() &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.md$/.test(entry.name),
      )
      .map((entry) => entry.name)
      .sort();
  } catch (error) {
    if (isMissing(error)) return [];
    throw error;
  }
}

function unavailable(cause: unknown): CliError {
  return new CliError("internal_error", "Bundled guidance is unavailable.", {
    cause,
  });
}

function isMissing(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as Error & { readonly code?: unknown }).code === "ENOENT"
  );
}
