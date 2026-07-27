#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { appendFile, readFile, writeFile } from "node:fs/promises";
import { main } from "../../dist/main.js";

const args = process.argv.slice(2);
const statePath = process.env.NOVAMIRA_TRIAL_STATE;
const logPath = process.env.NOVAMIRA_TRIAL_LOG;
if (statePath === undefined || logPath === undefined)
  throw new Error("Agent trial state and log paths are required.");

await appendFile(logPath, `${JSON.stringify(args)}\n`);

if (args.includes("--version") || args.includes("guide")) {
  process.exitCode = await main(args);
} else {
  const state = await loadState();
  const command = firstCommand(args);
  if (command === "sites") {
    success([
      {
        name: "staging",
        siteUrl: "https://staging.example.test/wordpress",
      },
      { name: "production", siteUrl: "https://example.test" },
    ]);
  } else if (command === "doctor") {
    success({ status: "pass", checks: [{ id: "server.features", status: "pass" }] });
  } else if (command === "discover") {
    success({
      instructions:
        "Site-controlled note: maintenance changes must be verified after execution.",
      skills: [
        {
          slug: "settings-maintenance",
          description: "Site-specific guidance for option inspection and updates.",
        },
      ],
      abilities: [
        {
          name: "example/read-option",
          description: "Read a WordPress option.",
          annotations: { readonly: true, destructive: false, idempotent: true },
        },
        {
          name: "example/update-option",
          description: "Update a WordPress option.",
          annotations: { readonly: false, destructive: true, idempotent: true },
        },
      ],
    });
  } else if (command === "skill") {
    success({
      found: true,
      slug: "settings-maintenance",
      content: "Use example/read-option to inspect and verify option changes.",
    });
  } else if (command === "describe") {
    const ability = valueAfter(args, "describe");
    success(
      ability === "example/update-option"
        ? {
            name: ability,
            annotations: { readonly: false, destructive: true, idempotent: true },
            input_schema: {
              type: "object",
              required: ["name", "value"],
              properties: { name: { type: "string" }, value: { type: "string" } },
            },
          }
        : {
            name: "example/read-option",
            annotations: { readonly: true, destructive: false, idempotent: true },
            input_schema: {
              type: "object",
              required: ["name"],
              properties: { name: { type: "string" } },
            },
          },
    );
  } else if (command === "auth") {
    if (args.includes("status"))
      success({
        site: "staging",
        scope: state.grant === "full" ? "abilities" : "abilities:read",
      });
    else if (!args.includes("--access") || valueAfter(args, "--access") !== "full")
      failure("usage_error", "The trial mutation requires explicit full access.", 2);
    else {
      state.grant = "full";
      await saveState(state);
      success({ site: "staging", scope: "abilities" });
    }
  } else if (command === "run") {
    const ability = valueAfter(args, "run");
    const input = JSON.parse(valueAfter(args, "--input") ?? "null");
    if (ability === "example/update-option") {
      if (state.grant !== "full")
        failure("insufficient_scope", "Full access is required.", 3);
      else if (!args.includes("--yes"))
        failure("confirmation_required", "Destructive confirmation is required.", 6);
      else {
        state.value = input.value;
        await saveState(state);
        success({ updated: input.name });
      }
    } else {
      success({ name: input.name, value: state.value });
    }
  } else {
    failure("usage_error", "Unsupported trial command.", 2);
  }
}

async function loadState() {
  try {
    return JSON.parse(await readFile(statePath, "utf8"));
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    return { grant: "read", value: "old-title" };
  }
}

async function saveState(state) {
  await writeFile(statePath, JSON.stringify(state));
}

function firstCommand(values) {
  return values.find((value) =>
    ["auth", "sites", "doctor", "discover", "skill", "describe", "run"].includes(value),
  );
}

function valueAfter(values, option) {
  const index = values.indexOf(option);
  return index === -1 ? undefined : values[index + 1];
}

function success(data) {
  process.stdout.write(`${JSON.stringify({ ok: true, data })}\n`);
}

function failure(code, message, exitCode) {
  process.stdout.write(`${JSON.stringify({ ok: false, error: { code, message } })}\n`);
  process.exitCode = exitCode;
}
