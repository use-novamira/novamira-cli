// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmod,
  mkdir,
  readdir,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import {
  atomicWriteFile,
  atomicWriteFiles,
} from "../dist/config/atomic-write.js";
import {
  SpawnCommandRunner,
  UnixFileSecurity,
  WindowsFileSecurity,
} from "../dist/config/file-security.js";
import { powerShellEnvironment } from "../dist/config/powershell.js";
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

    // `Set-Acl` over a freshly constructed security object marks every section
    // dirty, so Windows demands SeSecurityPrivilege for the SACL and refuses
    // the write on ordinary accounts even when the resulting DACL would be
    // correct. The script must mutate the object `Get-Acl` returned, and must
    // let the verification below decide, rather than raising the Set-Acl error.
    const applyScript = calls[0][1][5];
    assert.ok(applyScript.includes("$acl=Get-Acl -LiteralPath $path"));
    assert.ok(!applyScript.includes("DirectorySecurity]::new()"));
    assert.ok(!applyScript.includes("FileSecurity]::new()"));
    assert.ok(
      applyScript.includes("$acl.SetAccessRuleProtection($true,$false)"),
    );
    assert.ok(applyScript.includes("$acl.PurgeAccessRules("));
    assert.ok(applyScript.includes("catch{$applyError=$_.Exception.Message}"));

    const unsafe = new WindowsFileSecurity({ run: async () => 3 });
    assert.equal(await unsafe.verifyDirectory("C:\\State"), false);
    assert.equal(await unsafe.verifyFile("C:\\State\\config.json"), false);
    await assert.rejects(unsafe.secureDirectory("C:\\State"));

    const broken = new WindowsFileSecurity({ run: async () => 1 });
    await assert.rejects(broken.verifyFile("C:\\State\\config.json"));
    await assert.rejects(broken.secureFile("C:\\State\\config.json"));

    // PowerShell 7 exports its own module tree; a powershell.exe 5.1 child that
    // inherits it cannot load the inbox modules Get-Acl lives in.
    const sanitized = powerShellEnvironment({
      PATH: "/usr/bin",
      PSModulePath: "C:\\Program Files\\PowerShell\\7\\Modules",
    });
    assert.equal(sanitized.PSModulePath, undefined);
    assert.equal(sanitized.PATH, "/usr/bin");

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

test("a batch that fails part way keeps the records it already replaced", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-batch-write-"));
  try {
    const security = new UnixFileSecurity();
    const path = (name) => join(root, name);

    // Two destinations already hold valid content; the third is new.
    await writeFile(path("one.json"), "old-one", { mode: 0o600 });
    await writeFile(path("two.json"), "old-two", { mode: 0o600 });

    // A directory cannot be replaced by renaming a file over it, so the third
    // entry fails after the first two have already been committed.
    await mkdir(path("three.json"), { mode: 0o700 });

    await assert.rejects(
      atomicWriteFiles(
        [
          { path: path("one.json"), content: "new-one" },
          { path: path("two.json"), content: "new-two" },
          { path: path("three.json"), content: "new-three" },
        ],
        security,
      ),
    );

    // The refreshed records survive the failure. Unlinking them here would
    // destroy content that was valid before the batch started.
    assert.equal(await readFile(path("one.json"), "utf8"), "new-one");
    assert.equal(await readFile(path("two.json"), "utf8"), "new-two");
    assert.equal(await security.verifyFile(path("one.json")), true);
    assert.equal(await security.verifyFile(path("two.json")), true);

    // No temporary is left behind for the entry that never landed.
    const leftovers = (await readdir(root)).filter((name) =>
      name.endsWith(".tmp"),
    );
    assert.deepEqual(leftovers, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a failed Set-Acl succeeds only when the postcondition verifies as safe", async () => {
  // Windows reports a missing SeSecurityPrivilege even when the owner-only ACL
  // it was asked to write is already in place.
  const scripts = [];
  const rescued = new WindowsFileSecurity({
    run: async (_command, args) => {
      scripts.push(args[5]);
      return /\$action='apply'/.test(args[5]) ? 1 : 0;
    },
    runWithInput: async () => {
      throw new Error("the single-path methods must not batch");
    },
  });
  await rescued.secureDirectory("C:\\State");
  assert.equal(scripts.length, 2);
  assert.ok(/\$action='verify'/.test(scripts[1]));
  assert.ok(/\$directory=\$true/.test(scripts[1]));

  // An unverified postcondition is never rescued, whatever Windows reported.
  const unsafe = new WindowsFileSecurity({
    run: async (_command, args) => (/\$action='apply'/.test(args[5]) ? 1 : 3),
    runWithInput: async () => {
      throw new Error("the single-path methods must not batch");
    },
  });
  await assert.rejects(unsafe.secureFile("C:\\State\\config.json"), /status 1/);

  const unreadable = new WindowsFileSecurity({
    run: async () => 1,
    runWithInput: async () => {
      throw new Error("the single-path methods must not batch");
    },
  });
  await assert.rejects(unreadable.secureDirectory("C:\\State"), /status 1/);
});

test("batched ACL checks answer per target, in order, without inlining paths", async () => {
  const targets = [
    { path: "C:\\State", kind: "directory" },
    { path: "C:\\State\\missing.json", kind: "file" },
    { path: "C:\\State\\config.json", kind: "file" },
  ];
  const batchOnly = {
    run: async () => {
      throw new Error("a batch must not fall back to one process per path");
    },
  };

  const batched = [];
  const security = new WindowsFileSecurity({
    ...batchOnly,
    runWithInput: async (command, args, input) => {
      batched.push([command, args, input]);
      // The middle target cannot be read; that is a `false`, not an abort.
      return { code: 0, stdout: "safe\nunsafe\nsafe\n" };
    },
  });
  assert.deepEqual(await security.verifyMany(targets), [true, false, true]);
  assert.equal(batched.length, 1);
  const [command, args, input] = batched[0];
  assert.equal(command, "powershell.exe");
  assert.deepEqual(args.slice(0, 5), [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
  ]);
  assert.equal(args.length, 6);
  // Windows caps a command line near 32k characters, so a hundred storage
  // paths cannot be inlined; they arrive on stdin as `<kind><path>` lines.
  for (const target of targets) assert.ok(!args[5].includes(target.path));
  // Node writes the payload as UTF-8, but `[Console]::In` decodes with the
  // console code page, which turns `C:\Users\José` into a path that does not
  // exist. The reader must name its encoding.
  assert.ok(!args[5].includes("[Console]::In"));
  assert.ok(
    args[5].includes(
      "[System.IO.StreamReader]::new([Console]::OpenStandardInput(),[System.Text.UTF8Encoding]::new($false))",
    ),
  );
  assert.ok(args[5].includes("$action='verify'"));
  assert.equal(
    input,
    "dC:\\State\nfC:\\State\\missing.json\nfC:\\State\\config.json\n",
  );

  // A non-ASCII path survives to stdin unchanged; nothing quotes or transcodes
  // it on the way out.
  const accented = [];
  const unicode = new WindowsFileSecurity({
    ...batchOnly,
    runWithInput: async (_command, _args, payload) => {
      accented.push(payload);
      return { code: 0, stdout: "safe\n" };
    },
  });
  await unicode.secureMany([
    { path: "C:\\Users\\José\\AppData\\Local\\Novamira\\Cache", kind: "file" },
  ]);
  assert.equal(
    accented[0],
    "fC:\\Users\\José\\AppData\\Local\\Novamira\\Cache\n",
  );

  // A newline would split one target into two verdicts.
  await assert.rejects(
    security.verifyMany([{ path: "C:\\State\nC:\\Windows", kind: "file" }]),
  );

  // An empty batch inspects nothing and starts nothing.
  const idle = new WindowsFileSecurity({
    ...batchOnly,
    runWithInput: async () => {
      throw new Error("an empty batch must not spawn");
    },
  });
  assert.deepEqual(await idle.verifyMany([]), []);
  await idle.secureMany([]);

  // Results that cannot be matched to inputs are a failure of the checker.
  for (const stdout of ["safe\n", "safe\n\nsafe\n", "safe\nmaybe\nsafe\n"]) {
    const garbled = new WindowsFileSecurity({
      ...batchOnly,
      runWithInput: async () => ({ code: 0, stdout }),
    });
    await assert.rejects(garbled.verifyMany(targets));
  }
  const failed = new WindowsFileSecurity({
    ...batchOnly,
    runWithInput: async () => ({ code: 1, stdout: "" }),
  });
  await assert.rejects(failed.verifyMany(targets), /status 1/);

  // A batched apply reports the postcondition of every target.
  const applied = [];
  const applier = new WindowsFileSecurity({
    ...batchOnly,
    runWithInput: async (_command, args, input) => {
      applied.push([args[5], input]);
      return { code: 0, stdout: "safe\nsafe\n" };
    },
  });
  await applier.secureMany(targets.slice(0, 2));
  assert.ok(applied[0][0].includes("$action='apply'"));
  assert.equal(applied[0][1], "dC:\\State\nfC:\\State\\missing.json\n");

  const stubborn = new WindowsFileSecurity({
    ...batchOnly,
    runWithInput: async () => ({ code: 0, stdout: "safe\nunsafe\n" }),
  });
  await assert.rejects(stubborn.secureMany(targets.slice(0, 2)), /1 of 2/);
});

test("unix batched ACL checks mirror the single-path verdicts", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-acl-"));
  try {
    const security = new UnixFileSecurity();
    const directory = join(root, "state");
    const file = join(directory, "config.json");
    const loose = join(root, "loose.json");
    await mkdir(directory, { recursive: true });
    await writeFile(file, "{}");
    await writeFile(loose, "{}");
    // Explicit modes: the process umask would otherwise decide the fixture.
    await chmod(directory, 0o755);
    await chmod(file, 0o644);
    await chmod(loose, 0o600);
    const targets = [
      { path: directory, kind: "directory" },
      { path: file, kind: "file" },
      { path: loose, kind: "file" },
      { path: join(root, "absent.json"), kind: "file" },
    ];
    // A target that cannot be inspected is `false`, not a rejection.
    assert.deepEqual(await security.verifyMany(targets), [
      false,
      false,
      true,
      false,
    ]);
    assert.deepEqual(await security.verifyMany([]), []);
    await security.secureMany(targets.slice(0, 3));
    assert.deepEqual(await security.verifyMany(targets), [
      true,
      true,
      true,
      false,
    ]);
    await assert.rejects(security.secureMany(targets.slice(3)));

    // The batch contract is the same on both platforms: every target is
    // hardened before anything is reported, and the postcondition decides. One
    // unrepairable target must not leave the rest of the batch untouched, and
    // a `chmod` that silently changed nothing must not pass for a success.
    await chmod(directory, 0o755);
    await chmod(file, 0o644);
    await assert.rejects(
      security.secureMany([
        { path: join(root, "absent.json"), kind: "file" },
        { path: directory, kind: "directory" },
        { path: file, kind: "file" },
      ]),
      /1 of 3/,
    );
    assert.deepEqual(
      await security.verifyMany([
        { path: directory, kind: "directory" },
        { path: file, kind: "file" },
      ]),
      [true, true],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the spawn runner delivers stdin, captures stdout, and bounds its own runtime", async () => {
  const runner = new SpawnCommandRunner(30_000);
  assert.deepEqual(
    await runner.runWithInput(
      process.execPath,
      ["-e", "process.stdin.pipe(process.stdout)"],
      "dC:\\State\nfC:\\State\\config.json\n",
    ),
    { code: 0, stdout: "dC:\\State\nfC:\\State\\config.json\n" },
  );
  assert.equal(
    await runner.run(process.execPath, ["-e", "process.exit(3)"]),
    3,
  );

  // An interrupted or wedged helper must never outlive the call that started
  // it: the timeout kills the child and rejects.
  const impatient = new SpawnCommandRunner(50);
  await assert.rejects(
    impatient.run(process.execPath, ["-e", "setTimeout(() => {}, 30000)"]),
    /timed out after 50 ms/,
  );
  await assert.rejects(
    impatient.runWithInput(
      process.execPath,
      ["-e", "setTimeout(() => {}, 30000)"],
      "",
    ),
    /timed out after 50 ms/,
  );
});

test("Ctrl-C kills the ACL helper the CLI started", async () => {
  const root = await mkdtemp(join(tmpdir(), "novamira-signal-"));
  try {
    const marker = join(root, "helper.pid");
    // The helper stands in for powershell.exe: it records its own pid and then
    // does nothing, exactly like a batch ACL pass that has not answered yet.
    const helper = `require("node:fs").writeFileSync(${JSON.stringify(marker)}, String(process.pid)); setInterval(() => {}, 1000);`;
    // Node does not emit `exit` when a default-handled signal terminates the
    // process, and the helper is started with `windowsHide`, so it is not on
    // the parent's console and never receives a console Ctrl-C of its own.
    // Only an explicit signal listener can reach it.
    const driver = `
      const { SpawnCommandRunner } = await import(${JSON.stringify(new URL("../dist/config/file-security.js", import.meta.url).href)});
      new SpawnCommandRunner(600000)
        .runWithInput(process.execPath, ["-e", ${JSON.stringify(helper)}], "")
        .catch(() => undefined);
      setInterval(() => {}, 1000);
    `;
    const cli = spawn(process.execPath, ["--input-type=module", "-e", driver], {
      stdio: "ignore",
    });
    let helperPid;
    for (let attempt = 0; attempt < 200 && helperPid === undefined; attempt++) {
      try {
        helperPid = Number(await readFile(marker, "utf8"));
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    assert.ok(helperPid !== undefined && Number.isInteger(helperPid));

    cli.kill("SIGINT");
    await new Promise((resolve) => {
      cli.once("close", resolve);
    });

    let alive = true;
    for (let attempt = 0; attempt < 200 && alive; attempt++) {
      try {
        process.kill(helperPid, 0);
        await new Promise((resolve) => setTimeout(resolve, 25));
      } catch {
        alive = false;
      }
    }
    assert.equal(alive, false, "the helper outlived the cancelled CLI");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
