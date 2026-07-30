// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
