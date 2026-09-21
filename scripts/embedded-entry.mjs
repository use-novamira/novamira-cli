// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { main } from "../dist/main.js";
import process from "node:process";

process.exitCode = await main(process.argv.slice(2), undefined, undefined, {
  managed: { updateHint: "Update the containing application instead." },
});
