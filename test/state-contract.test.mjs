// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { atomicWriteFile } from "../dist/config/atomic-write.js";
import {
  UnixFileSecurity,
  WindowsFileSecurity,
} from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import { ProfileStore } from "../dist/config/profiles.js";
import { normalizeSiteUrl } from "../dist/config/site-url.js";
import { main } from "../dist/main.js";

async function isolatedState(cleanupHooks = []) {
  const root = await mkdtemp(join(tmpdir(), "novamira-state-"));
  const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
  const security = new UnixFileSecurity();
  const locks = new ProfileLockManager(paths.stateDir, security);
  return {
    root,
    paths,
    security,
    locks,
    store: new ProfileStore(paths.configFile, locks, security, cleanupHooks),
  };
}

test("platform paths and site URLs preserve isolation and WordPress subdirectories", () => {
  assert.equal(
    platformPaths({ XDG_CONFIG_HOME: "/xdg/config" }, "linux", "/home/test")
      .configFile,
    "/xdg/config/novamira/config.json",
  );
  assert.equal(
    platformPaths(
      { APPDATA: "C:\\Roaming", LOCALAPPDATA: "C:\\Local" },
      "win32",
      "C:\\Users\\test",
    ).cacheDir,
    "C:\\Local\\Novamira\\Cache",
  );
  assert.deepEqual(normalizeSiteUrl("https://Example.test/wordpress/"), {
    siteUrl: "https://example.test/wordpress",
    origin: "https://example.test",
  });
  assert.equal(
    normalizeSiteUrl("http://127.0.0.1:8080/blog").siteUrl,
    "http://127.0.0.1:8080/blog",
  );
  assert.throws(() => normalizeSiteUrl("http://example.test"), {
    code: "usage_error",
  });
  assert.equal(
    normalizeSiteUrl("http://tests:9000", {
      NOVAMIRA_ALLOW_INSECURE_HTTP: "1",
    }).siteUrl,
    "http://tests:9000",
  );
  assert.throws(
    () =>
      normalizeSiteUrl("http://tests:9000", {
        NOVAMIRA_ALLOW_INSECURE_HTTP: "true",
      }),
    { code: "usage_error" },
  );
  assert.throws(() => normalizeSiteUrl("https://user:pass@example.test"), {
    code: "usage_error",
  });
});

test("profiles update atomically, select deterministically, and invoke cleanup before removal", async () => {
  const cleaned = [];
  const state = await isolatedState([
    { cleanup: async (profile) => cleaned.push(profile.name) },
  ]);
  try {
    await Promise.all([
      state.store.upsert({
        name: "staging",
        siteUrl: "https://example.test/wp",
      }),
      state.store.upsert({
        name: "production",
        siteUrl: "https://example.com",
      }),
    ]);
    assert.deepEqual(
      (await state.store.list()).map(({ name }) => name),
      ["production", "staging"],
    );
    assert.equal(
      (await state.store.select("staging", { NOVAMIRA_SITE: "production" }))
        .name,
      "staging",
    );
    assert.equal(
      (await state.store.select(undefined, { NOVAMIRA_SITE: "production" }))
        .name,
      "production",
    );
    assert.equal(
      await state.store.trySelect("missing", {
        NOVAMIRA_SITE: "production",
      }),
      undefined,
    );
    assert.equal(await state.store.trySelect(undefined, {}), undefined);
    await assert.rejects(state.store.select(undefined, {}), {
      code: "site_required",
    });

    let listed = "";
    assert.equal(
      await main(
        ["--json", "sites", "list"],
        {
          stdout: { write: (value) => (listed += value) },
          stderr: { write: () => undefined },
        },
        { NOVAMIRA_HOME: state.root, NOVAMIRA_UPDATE_CHECK: "0" },
      ),
      0,
    );
    assert.deepEqual(
      JSON.parse(listed).data.map(({ name }) => name),
      ["production", "staging"],
    );

    await state.store.remove("staging");
    assert.deepEqual(cleaned, ["staging"]);
    assert.equal(
      (await state.store.trySelect(undefined, {})).name,
      "production",
    );
    assert.equal((await state.store.select(undefined, {})).name, "production");

    const config = JSON.parse(await readFile(state.paths.configFile, "utf8"));
    assert.deepEqual(Object.keys(config.profiles.production).sort(), [
      "name",
      "origin",
      "siteUrl",
    ]);
    assert.equal((await stat(state.paths.configFile)).mode & 0o777, 0o600);
    assert.equal((await stat(join(state.root))).mode & 0o077, 0);

    let removed = "";
    assert.equal(
      await main(
        ["--json", "sites", "remove", "production"],
        {
          stdout: { write: (value) => (removed += value) },
          stderr: { write: () => undefined },
        },
        { NOVAMIRA_HOME: state.root, NOVAMIRA_UPDATE_CHECK: "0" },
      ),
      0,
    );
    assert.equal(JSON.parse(removed).data.removed, "production");
  } finally {
    await rm(state.root, { recursive: true, force: true });
  }
});

test("locks coordinate independent managers, stale owners recover, and failed atomic writes preserve data", async () => {
  const state = await isolatedState();
  try {
    const release = await state.locks.acquire("production");
    const contender = new ProfileLockManager(
      state.paths.stateDir,
      state.security,
    );
    await assert.rejects(
      contender.acquire("production", { timeoutMs: 20, pollMs: 5 }),
      {
        code: "internal_error",
      },
    );
    await release();

    const nestedRelease = await state.locks.acquire("nested");
    await assert.rejects(state.locks.acquire("nested"), {
      code: "internal_error",
      message: "Profile lock nested is already held by this lock manager.",
    });
    await nestedRelease();
    await (
      await state.locks.acquire("nested")
    )();

    const lockDir = join(state.paths.stateDir, "locks");
    await mkdir(lockDir, { recursive: true });
    const { createHash } = await import("node:crypto");
    const stalePath = join(
      lockDir,
      `${createHash("sha256").update("stale").digest("hex")}.lock`,
    );
    await writeFile(
      stalePath,
      JSON.stringify({
        pid: 999_999_999,
        host: (await import("node:os")).hostname(),
      }),
    );
    const staleRelease = await contender.acquire("stale", {
      timeoutMs: 50,
      pollMs: 5,
    });
    await staleRelease();

    const destination = join(state.root, "atomic.json");
    await writeFile(destination, "original", { mode: 0o600 });
    const failingSecurity = {
      secureDirectory: async (path) => chmod(path, 0o700),
      secureFile: async () => {
        throw new Error("simulated ACL failure");
      },
    };
    await assert.rejects(
      atomicWriteFile(destination, "replacement", failingSecurity),
    );
    assert.equal(await readFile(destination, "utf8"), "original");

    const calls = [];
    const windows = new WindowsFileSecurity({
      run: async (command, args) => {
        calls.push([command, args]);
        return 0;
      },
    });
    await windows.secureDirectory("C:\\State");
    await windows.secureFile("C:\\State\\config.json");
    assert.equal(await windows.verifyDirectory("C:\\State"), true);
    assert.equal(await windows.verifyFile("C:\\State\\config.json"), true);
    assert.equal(calls.length, 4);
    assert.equal(calls[0][0], "powershell.exe");
    for (const [, args] of calls) {
      // `$args` never binds under `-Command`; every input must be inlined.
      assert.deepEqual(args.slice(0, 5), [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
      ]);
      assert.equal(args.length, 6);
      assert.ok(!args[5].includes("$args["));
    }
    assert.deepEqual(
      calls.map(([, args]) => /\$action='([a-z]+)'/.exec(args[5])[1]),
      ["apply", "apply", "verify", "verify"],
    );
    assert.deepEqual(
      calls.map(([, args]) => /\$directory=\$([a-z]+)/.exec(args[5])[1]),
      ["true", "false", "true", "false"],
    );
    assert.ok(calls[0][1][5].includes("$path='C:\\State'"));

    const unsafe = new WindowsFileSecurity({ run: async () => 3 });
    assert.equal(await unsafe.verifyDirectory("C:\\State"), false);
    assert.equal(await unsafe.verifyFile("C:\\State\\config.json"), false);
    await assert.rejects(unsafe.secureDirectory("C:\\State"));

    const broken = new WindowsFileSecurity({ run: async () => 1 });
    await assert.rejects(broken.verifyFile("C:\\State\\config.json"));
    await assert.rejects(broken.secureFile("C:\\State\\config.json"));

    const quoting = new WindowsFileSecurity({ run: async () => 0 });
    await assert.rejects(quoting.secureFile('C:\\State\\a"b.json'));
    const quoted = [];
    const escaping = new WindowsFileSecurity({
      run: async (_command, args) => {
        quoted.push(args[5]);
        return 0;
      },
    });
    await escaping.secureFile("C:\\State\\o'brien.json");
    assert.ok(quoted[0].includes("$path='C:\\State\\o''brien.json'"));
  } finally {
    await rm(state.root, { recursive: true, force: true });
  }
});
