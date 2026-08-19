// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("a verified npm publication creates a generated GitHub release", async () => {
  const workflow = await readFile(".github/workflows/release.yml", "utf8");
  const releaseJob = workflow.slice(workflow.indexOf("  github-release:"));

  assert.match(workflow, /^permissions:\n  contents: read$/m);
  assert.match(releaseJob, /^  github-release:\n    needs: publish$/m);
  assert.match(releaseJob, /^    permissions:\n      contents: write$/m);
  assert.match(releaseJob, /gh release create "\$GITHUB_REF_NAME"/);
  assert.match(releaseJob, /--verify-tag/);
  assert.match(releaseJob, /--generate-notes/);
});

async function runUnixInstaller(environment = {}) {
  const root = await mkdtemp(join(tmpdir(), "novamira-installer-"));
  const bin = join(root, "mock-bin");
  const npmRoot = join(root, "npm");
  const log = join(root, "npx.log");
  await mkdir(join(npmRoot, "bin"), { recursive: true });
  await mkdir(join(npmRoot, "node_modules/@novamira/cli/skills/novamira"), {
    recursive: true,
  });
  await writeFile(
    join(npmRoot, "node_modules/@novamira/cli/skills/novamira/SKILL.md"),
    "test",
  );
  await mkdir(bin);

  const commands = {
    node: "#!/bin/sh\nexit 0\n",
    npm: `#!/bin/sh
if [ "$1 $2" = "prefix --global" ]; then
  printf '%s\\n' '${npmRoot}'
elif [ "$1 $2" = "root --global" ]; then
  printf '%s\\n' '${join(npmRoot, "node_modules")}'
fi
`,
    npx: `#!/bin/sh
printf '%s\\n' "$*" >>'${log}'
`,
    [join(npmRoot, "bin/novamira")]: "#!/bin/sh\nexit 0\n",
  };
  for (const [name, contents] of Object.entries(commands)) {
    const path = name.includes("/") ? name : join(bin, name);
    await writeFile(path, contents);
    await chmod(path, 0o755);
  }

  const result = spawnSync("/bin/sh", ["install.sh"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PATH: bin, ...environment },
  });
  const npxLog = await readFile(log, "utf8").catch(() => "");
  await rm(root, { recursive: true, force: true });
  return { ...result, npxLog };
}

test("the Unix installer supports an unattended agent selection", async () => {
  const result = await runUnixInstaller({ NOVAMIRA_AGENT: "opencode" });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.npxLog, /--agent opencode --yes\n$/);
});

test("the Unix installer can skip skill installation", async () => {
  const result = await runUnixInstaller({ NOVAMIRA_SKIP_SKILL: "1" });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.npxLog, "");
  assert.match(result.stdout, /Skipping Novamira agent skill installation/);
});

test("the Unix installer reports non-interactive skill requirements", async () => {
  const result = await runUnixInstaller();

  assert.equal(result.status, 1);
  assert.match(result.stderr, /set NOVAMIRA_AGENT.*NOVAMIRA_SKIP_SKILL=1/);
  assert.doesNotMatch(result.stderr, /cannot open \/dev\/tty/);
});
