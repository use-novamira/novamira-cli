#!/bin/sh
# SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
# SPDX-License-Identifier: AGPL-3.0-or-later


set -eu

package=@novamira/cli
skills_package=skills@1.5.18

fail() {
  printf 'novamira installer: %s\n' "$*" >&2
  exit 1
}

for command_name in node npm npx; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name is required but was not found in PATH"
done

node -e 'const major = Number(process.versions.node.split(".")[0]); process.exit(major >= 22 ? 0 : 1)' ||
  fail "Node.js 22 or newer is required (found $(node --version))"

printf 'Installing %s with npm...\n' "$package"
npm install --global --ignore-scripts "$package"

npm_prefix=$(npm prefix --global)
novamira_bin=$npm_prefix/bin/novamira
[ -x "$novamira_bin" ] ||
  fail "npm installed Novamira, but novamira is not available in PATH (npm prefix: $npm_prefix)"

"$novamira_bin" --version
"$novamira_bin" doctor --offline

skill_source=$(npm root --global)/@novamira/cli
[ -f "$skill_source/skills/novamira/SKILL.md" ] ||
  fail "the installed npm package does not contain the Novamira agent skill"

printf '\nInstalling the Novamira agent skill globally...\n'
if [ -n "${NOVAMIRA_AGENT:-}" ]; then
  DISABLE_TELEMETRY=1 npm_config_ignore_scripts=true \
    npx --yes "$skills_package" add "$skill_source" \
    --skill novamira --global --agent "$NOVAMIRA_AGENT" --yes
elif [ -r /dev/tty ] && [ -w /dev/tty ]; then
  DISABLE_TELEMETRY=1 npm_config_ignore_scripts=true \
    npx --yes "$skills_package" add "$skill_source" \
    --skill novamira --global </dev/tty
else
  fail "skill installation needs a terminal or NOVAMIRA_AGENT (for example, NOVAMIRA_AGENT=opencode)"
fi

printf '\nNovamira CLI and agent skill installed successfully.\n'
