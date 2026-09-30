#!/bin/sh
# SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
# SPDX-License-Identifier: AGPL-3.0-or-later


set -eu

package=@novamira/cli
skills_package=skills@1.7.0

fail() {
  printf 'novamira installer: %s\n' "$*" >&2
  exit 1
}

for command_name in node npm npx; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name is required but was not found in PATH"
done

# The CLI runs on Node.js 22+, but the pinned skills package needs 22.20+.
node_version=$(node -p 'process.versions.node')
node_major=${node_version%%.*}
node_minor=${node_version#*.}
node_minor=${node_minor%%.*}
case "$node_major$node_minor" in
  '' | *[!0-9]*) fail "could not read the Node.js version (found $node_version)" ;;
esac
if [ "$node_major" -lt 22 ] || { [ "$node_major" -eq 22 ] && [ "$node_minor" -lt 20 ]; }; then
  fail "Node.js 22.20 or newer is required (found v$node_version)"
fi

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

if [ "${NOVAMIRA_SKIP_SKILL:-0}" = "1" ]; then
  printf '\nSkipping Novamira agent skill installation.\n'
else
  printf '\nInstalling the Novamira agent skill globally...\n'
  if [ -n "${NOVAMIRA_AGENT:-}" ]; then
    DISABLE_TELEMETRY=1 npm_config_ignore_scripts=true \
      npx --yes "$skills_package" add "$skill_source" \
      --skill novamira --global --agent "$NOVAMIRA_AGENT" --yes
  elif ( : </dev/tty ) 2>/dev/null; then
    DISABLE_TELEMETRY=1 npm_config_ignore_scripts=true \
      npx --yes "$skills_package" add "$skill_source" \
      --skill novamira --global </dev/tty
  else
    fail "set NOVAMIRA_AGENT for unattended skill installation, or NOVAMIRA_SKIP_SKILL=1"
  fi
fi

printf '\nNovamira CLI installation completed successfully.\n'
