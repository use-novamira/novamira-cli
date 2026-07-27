// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { extname } from "node:path";
import { stdout } from "node:process";

const headers = {
  ".cjs": "//",
  ".js": "//",
  ".mjs": "//",
  ".ps1": "#",
  ".sh": "#",
  ".ts": "//",
  ".tsx": "//",
  ".yaml": "#",
  ".yml": "#",
};
const copyright =
  "SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>";
const license = "SPDX-License-Identifier: AGPL-3.0-or-later";

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "buffer" })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

for (const file of files) {
  const comment = headers[extname(file)];
  if (!comment) continue;

  const source = readFileSync(file, "utf8");
  if (source.includes(license)) continue;

  const shebang = source.startsWith("#!") ? source.indexOf("\n") + 1 : 0;
  const header = `${comment} ${copyright}\n${comment} ${license}\n\n`;
  writeFileSync(
    file,
    source.slice(0, shebang) + header + source.slice(shebang),
  );
  stdout.write(`Added SPDX header to ${file}\n`);
}
