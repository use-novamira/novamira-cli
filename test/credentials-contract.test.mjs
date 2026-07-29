// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BackendUnavailableError } from "../dist/auth/command-executor.js";
import { createCredentialStore } from "../dist/auth/credential-store.js";
import { credentialAccount } from "../dist/auth/credentials.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import { redact } from "../dist/output/redact.js";

const target = { profileName: "production", origin: "https://example.test" };
const first = {
  version: 1,
  accessToken: "access-secret-one",
  refreshToken: "refresh-secret-one",
  scope: "abilities:read",
  expiresAt: "2026-07-20T15:00:00.000Z",
};
const second = {
  ...first,
  accessToken: "access-secret-two",
  refreshToken: "refresh-secret-two",
};

async function state() {
  const root = await mkdtemp(join(tmpdir(), "novamira-credentials-"));
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const security = new UnixFileSecurity();
  const locks = new ProfileLockManager(paths.stateDir, security);
  return { root, paths, security, locks };
}

test("owner-only file fallback atomically replaces, reads, deletes, and fails closed on corruption", async () => {
  const current = await state();
  const warnings = [];
  try {
    const store = await createCredentialStore(
      current.paths.credentialsDir,
      current.locks,
      current.security,
      {
        preference: "file",
        onWarning: (warning) => warnings.push(warning),
      },
    );
    await store.replace(target, first);
    assert.deepEqual(await store.read(target), first);
    const otherProfile = { ...target, profileName: "staging" };
    const otherOrigin = { ...target, origin: "https://other.example.test" };
    await store.replace(otherProfile, {
      ...first,
      accessToken: "profile-secret",
    });
    await store.replace(otherOrigin, {
      ...first,
      accessToken: "origin-secret",
    });
    assert.equal(
      (await store.read(otherProfile)).accessToken,
      "profile-secret",
    );
    assert.equal((await store.read(otherOrigin)).accessToken, "origin-secret");
    assert.equal(
      new Set([target, otherProfile, otherOrigin].map(credentialAccount)).size,
      3,
    );
    await store.replace(target, second);
    assert.deepEqual(await store.read(target), second);
    assert.equal(warnings.length, 1);
    assert.equal(store.diagnostic().osBackedEncryption, false);

    const path = join(
      current.paths.credentialsDir,
      "v1",
      `${credentialAccount(target)}.json`,
    );
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal(
      (await stat(join(current.paths.credentialsDir, "v1"))).mode & 0o777,
      0o700,
    );
    assert.doesNotMatch(
      await readFile(join(current.root, "config.json"), "utf8").catch(() => ""),
      /Token/,
    );

    await writeFile(path, '{"accessToken":"must-not-leak"}', { mode: 0o600 });
    await assert.rejects(store.read(target), (error) => {
      assert.equal(error.code, "auth_required");
      assert.doesNotMatch(JSON.stringify(error), /must-not-leak/);
      return true;
    });
    await store.delete(target);
    assert.equal(await store.read(target), undefined);
    assert.equal(
      (await store.read(otherProfile)).accessToken,
      "profile-secret",
    );
    assert.equal((await store.read(otherOrigin)).accessToken, "origin-secret");
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("backend selection prefers an available OS service, passes secrets only on stdin, and falls back when unavailable", async () => {
  const current = await state();
  try {
    let stored;
    const calls = [];
    const executor = {
      execute: async (command, args, stdin = "") => {
        calls.push({ command, args, stdin });
        if (args[0] === "--version") return { code: 0, stdout: "1\n" };
        if (args[0] === "store") {
          stored = stdin;
          return { code: 0, stdout: "" };
        }
        if (args[0] === "lookup")
          return {
            code: stored === undefined ? 1 : 0,
            stdout: `${stored ?? ""}\n`,
          };
        if (args[0] === "clear") {
          stored = undefined;
          return { code: 0, stdout: "" };
        }
        return { code: 1, stdout: "" };
      },
    };
    const keychain = await createCredentialStore(
      current.paths.credentialsDir,
      current.locks,
      current.security,
      {
        platform: "linux",
        executor,
      },
    );
    await keychain.replace(target, first);
    assert.deepEqual(await keychain.read(target), first);
    assert.equal(keychain.diagnostic().backend, "linux-secret-service");
    assert.equal(keychain.diagnostic().osBackedEncryption, true);
    assert.doesNotMatch(
      JSON.stringify(calls.map(({ args }) => args)),
      /access-secret|refresh-secret/,
    );
    assert.match(
      calls.find(({ args }) => args[0] === "store").stdin,
      /access-secret-one/,
    );
    await keychain.delete(target);

    const unavailable = {
      execute: async () => Promise.reject(new BackendUnavailableError()),
    };
    const fallback = await createCredentialStore(
      current.paths.credentialsDir,
      current.locks,
      current.security,
      {
        platform: "linux",
        executor: unavailable,
      },
    );
    assert.equal(fallback.diagnostic().backend, "file");

    assert.deepEqual(
      redact(
        { authorization: "Bearer access-secret-one", codeVerifier: "verifier" },
        ["access-secret-one"],
      ),
      {
        authorization: "[REDACTED]",
        codeVerifier: "[REDACTED]",
      },
    );
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("macOS keychain backend stores long secrets without truncation or emptying", async () => {
  const current = await state();
  try {
    // A realistic credential: the access token is a JWT, so the serialized
    // record is well over 128 bytes — the point where security's interactive
    // password prompt (readpassphrase) truncates. Guards against BOTH the
    // empty-write and the 128-byte-truncation regressions.
    const longToken = {
      version: 1,
      accessToken: `header.${"payloadsegment".repeat(30)}.signature`,
      refreshToken: "refresh-secret-one",
      scope: "abilities",
      expiresAt: "2026-07-20T15:00:00.000Z",
    };
    let stored;
    // Faithful stand-in for macOS `security add-generic-password`:
    //   - `-w <value>` inline  -> stores the value verbatim, no length limit.
    //   - `-w` with no inline value -> interactive readpassphrase prompt, which
    //     reads from stdin and truncates each line at 128 bytes. That is the
    //     only path a stdin-based backend could take, and it corrupts long
    //     secrets — so this mock refuses to store more than 128 bytes that way.
    const PROMPT_CAP = 128;
    const executor = {
      execute: async (command, args, stdin = "") => {
        if (args[0] === "help") return { code: 0, stdout: "" };
        if (args[0] === "add-generic-password") {
          const flagIndex = args.indexOf("-w");
          const inlineValue = args[flagIndex + 1];
          if (inlineValue !== undefined) {
            stored = inlineValue;
          } else {
            const [password, confirmation] = stdin
              .split("\n")
              .map((line) => line.slice(0, PROMPT_CAP));
            stored = password && password === confirmation ? password : "";
          }
          return { code: 0, stdout: "" };
        }
        if (args[0] === "find-generic-password") {
          if (stored === undefined) return { code: 44, stdout: "" };
          return { code: 0, stdout: `${stored}\n` };
        }
        if (args[0] === "delete-generic-password") {
          stored = undefined;
          return { code: 0, stdout: "" };
        }
        return { code: 1, stdout: "" };
      },
    };
    const keychain = await createCredentialStore(
      current.paths.credentialsDir,
      current.locks,
      current.security,
      {
        platform: "darwin",
        executor,
      },
    );
    await keychain.replace(target, longToken);
    assert.equal(keychain.diagnostic().backend, "macos-keychain");
    assert.notEqual(stored, "", "secret must not be stored empty");
    assert.equal(
      stored,
      JSON.stringify(longToken),
      "secret must be stored in full, not truncated",
    );
    assert.deepEqual(await keychain.read(target), longToken);
    await keychain.replace(target, second);
    assert.deepEqual(await keychain.read(target), second);
    await keychain.delete(target);
    assert.equal(await keychain.read(target), undefined);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("the Windows credential backend inlines its inputs instead of relying on $args", async () => {
  const current = await state();
  try {
    const records = new Map();
    // Faithful stand-in for `powershell.exe -Command`: $args is never populated,
    // so the mock reads the action and target only from the script text.
    const executor = {
      execute: async (command, args, stdin = "") => {
        assert.equal(command, "powershell.exe");
        assert.deepEqual(args.slice(0, 3), [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
        ]);
        assert.equal(
          args.length,
          4,
          "trailing values are appended to the command text, not bound to $args",
        );
        const script = args[3];
        if (script === "$PSVersionTable.PSVersion.ToString()")
          return { code: 0, stdout: "5.1\n" };
        assert.doesNotMatch(script, /\$args\[/);
        const action = /\$action='([a-z]+)'/.exec(script)?.[1];
        const target = /\$target='([^']+)'/.exec(script)?.[1];
        assert.ok(action, `script must inline its action: ${script}`);
        assert.ok(target, `script must inline its target: ${script}`);
        if (action === "write") {
          records.set(target, stdin);
          return { code: 0, stdout: "" };
        }
        if (action === "read")
          return {
            code: 0,
            stdout: records.get(target) ?? "__NOVAMIRA_NOT_FOUND__\n",
          };
        records.delete(target);
        return { code: 0, stdout: "" };
      },
    };
    const keychain = await createCredentialStore(
      current.paths.credentialsDir,
      current.locks,
      current.security,
      { platform: "win32", executor },
    );
    assert.equal(keychain.diagnostic().backend, "windows-credential-manager");
    await keychain.replace(target, first);
    assert.deepEqual(await keychain.read(target), first);
    await keychain.replace(target, second);
    assert.deepEqual(await keychain.read(target), second);
    await keychain.delete(target);
    assert.equal(await keychain.read(target), undefined);
    // The secret record travels on stdin only.
    assert.equal(records.size, 0);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});
