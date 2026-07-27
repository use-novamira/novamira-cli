// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { AbilityClient, RunResult } from "../abilities/client.js";
import { CliError } from "../errors.js";

export const SITE_SKILL_ABILITY = "novamira/skill-get";
export const MAX_SKILL_SLUG_BYTES = 255;

export async function getSiteSkill(
  abilities: Pick<AbilityClient, "run">,
  slug: string,
): Promise<RunResult> {
  validateSkillSlug(slug);
  return abilities.run(SITE_SKILL_ABILITY, { slug });
}

export function validateSkillSlug(slug: string): string {
  if (
    slug === "" ||
    slug !== slug.trim() ||
    Buffer.byteLength(slug, "utf8") > MAX_SKILL_SLUG_BYTES ||
    slug.includes("/") ||
    /\p{Cc}/u.test(slug)
  ) {
    throw new CliError(
      "usage_error",
      "Skill slug must be 1-255 UTF-8 bytes with no surrounding whitespace, slash, or control character.",
    );
  }
  return slug;
}
