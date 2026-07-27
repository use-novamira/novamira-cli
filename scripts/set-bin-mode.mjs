#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { chmod } from "node:fs/promises";
import { URL } from "node:url";

await chmod(new URL("../dist/index.js", import.meta.url), 0o755);
