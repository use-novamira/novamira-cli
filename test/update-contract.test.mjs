// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { main, VERSION } from "../dist/main.js";
import { UnixFileSecurity } from "../dist/config/file-security.js";
import { ProfileLockManager } from "../dist/config/lock.js";
import { platformPaths } from "../dist/config/paths.js";
import { compareSemver, isSemver } from "../dist/semver.js";
import {
  UPDATE_CHECK_INTERVAL_MS,
  UpdateChecker,
  isNewer,
  updateCheckEnabled,
} from "../dist/update/notifier.js";
import {
  DEFAULT_REGISTRY,
  distTagsUrl,
  fetchLatestVersion,
} from "../dist/update/registry.js";
import { installCommandFor, installVersion } from "../dist/update/install.js";

async function withHome(run) {
  const root = await mkdtemp(join(tmpdir(), "novamira-update-"));
  try {
    const paths = platformPaths({ NOVAMIRA_HOME: root }, "linux", root);
    const security = new UnixFileSecurity();
    return await run({
      root,
      paths,
      security,
      locks: new ProfileLockManager(paths.stateDir, security),
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function registryServer(handler) {
  const server = createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({
        url: `http://127.0.0.1:${String(server.address().port)}`,
        close: () => new Promise((done) => server.close(done)),
      }),
    );
  });
}

function capture() {
  let stdout = "";
  let stderr = "";
  return {
    streams: {
      stdout: { write: (value) => (stdout += value) },
      stderr: { write: (value) => (stderr += value) },
    },
    read: () => ({ stdout, stderr }),
  };
}

test("published version comparison orders releases and prereleases", () => {
  assert.equal(compareSemver("1.0.0", "1.0.0-rc.2"), 1);
  assert.equal(compareSemver("1.0.0-rc.2", "1.0.0-rc.10"), -1);
  assert.equal(compareSemver("1.2.3", "1.2.3"), 0);
  assert.ok(isSemver("1.0.0-rc.2"));
  assert.ok(!isSemver("v1.0.0"));
  assert.throws(() => compareSemver("latest", "1.0.0"));

  assert.ok(isNewer("1.1.0", "1.0.0-rc.2"));
  assert.ok(!isNewer("1.0.0", "1.0.0"));
  assert.ok(!isNewer("0.9.0", "1.0.0"));
  assert.ok(!isNewer("not-a-version", "1.0.0"));
  assert.ok(isSemver(VERSION));
});

test("the dist-tag request targets the scoped package over HTTPS only", () => {
  assert.equal(
    distTagsUrl().href,
    `${DEFAULT_REGISTRY}/-/package/%40novamira%2Fcli/dist-tags`,
  );
  assert.throws(() => distTagsUrl("http://registry.example.com"), {
    code: "usage_error",
  });
  assert.throws(() => distTagsUrl("https://user:secret@registry.example.com"), {
    code: "usage_error",
  });
  assert.throws(() => distTagsUrl("http://127.0.0.1:1234"), {
    code: "usage_error",
  });
  assert.equal(distTagsUrl("http://127.0.0.1:1234", true).protocol, "http:");
  assert.throws(() => distTagsUrl("http://registry.example.com", true), {
    code: "usage_error",
  });
});

test("an unusable registry answer is a typed network error", async () => {
  const notFound = await registryServer((_request, response) => {
    response.writeHead(404).end("{}");
  });
  const invalid = await registryServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ latest: "nightly" }));
  });
  try {
    await assert.rejects(
      fetchLatestVersion({ registry: notFound.url, allowInsecureHttp: true }),
      {
        code: "network_error",
      },
    );
    await assert.rejects(
      fetchLatestVersion({ registry: invalid.url, allowInsecureHttp: true }),
      {
        code: "network_error",
      },
    );
  } finally {
    await notFound.close();
    await invalid.close();
  }
});

test("the notice is cached, owner-only, and repeated at most once per interval", async () => {
  await withHome(async ({ paths, locks, security }) => {
    let requests = 0;
    const registry = await registryServer((_request, response) => {
      requests += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ latest: "9.9.9" }));
    });
    try {
      let clock = Date.parse("2026-07-27T00:00:00.000Z");
      const checker = new UpdateChecker(paths.stateDir, locks, security, {
        currentVersion: "1.0.0",
        registry: registry.url,
        allowInsecureHttp: true,
        now: () => clock,
      });

      assert.match(await checker.notice(), /9\.9\.9/);
      assert.equal(requests, 1);

      const record = join(paths.stateDir, "update-check.json");
      assert.deepEqual(JSON.parse(await readFile(record, "utf8")), {
        version: 1,
        registry: registry.url,
        latest: "9.9.9",
        checkedAt: new Date(clock).toISOString(),
      });
      assert.equal((await stat(record)).mode & 0o777, 0o600);

      assert.match(await checker.notice(), /9\.9\.9/);
      assert.equal(requests, 1, "a fresh record must not be refetched");

      clock += UPDATE_CHECK_INTERVAL_MS + 1;
      assert.match(await checker.notice(), /9\.9\.9/);
      assert.equal(requests, 2);

      const current = new UpdateChecker(paths.stateDir, locks, security, {
        currentVersion: "9.9.9",
        registry: registry.url,
        allowInsecureHttp: true,
        now: () => clock,
      });
      assert.equal(await current.notice(), undefined);
    } finally {
      await registry.close();
    }
  });
});

test("an unreachable registry stays silent and is not retried every run", async () => {
  await withHome(async ({ paths, locks, security }) => {
    let requests = 0;
    const registry = await registryServer((request, response) => {
      requests += 1;
      response.destroy();
      void request;
    });
    try {
      const clock = Date.parse("2026-07-27T00:00:00.000Z");
      const checker = new UpdateChecker(paths.stateDir, locks, security, {
        currentVersion: "1.0.0",
        registry: registry.url,
        allowInsecureHttp: true,
        now: () => clock,
        timeoutMs: 1_000,
      });
      assert.equal(await checker.notice(), undefined);
      assert.equal(await checker.notice(), undefined);
      assert.equal(requests, 1);
      assert.deepEqual(
        JSON.parse(
          await readFile(join(paths.stateDir, "update-check.json"), "utf8"),
        ),
        {
          version: 1,
          registry: registry.url,
          latest: null,
          checkedAt: new Date(clock).toISOString(),
        },
      );
    } finally {
      await registry.close();
    }
  });
});

test("commands warn on stderr only and keep one JSON value on stdout", async () => {
  await withHome(async ({ root }) => {
    const registry = await registryServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ latest: "9.9.9" }));
    });
    try {
      const environment = {
        NOVAMIRA_HOME: root,
        NOVAMIRA_REGISTRY: registry.url,
        NOVAMIRA_ALLOW_INSECURE_HTTP: "1",
      };
      const warned = capture();
      assert.equal(
        await main(["--json", "sites", "list"], warned.streams, environment),
        0,
      );
      assert.equal(JSON.parse(warned.read().stdout).ok, true);
      assert.match(
        warned.read().stderr,
        /^Warning: A new novamira release is available: .+ -> 9\.9\.9\. Run "novamira update" to install it\.\n$/,
      );

      const quiet = capture();
      assert.equal(
        await main(
          ["--json", "--quiet", "sites", "list"],
          quiet.streams,
          environment,
        ),
        0,
      );
      assert.equal(quiet.read().stderr, "");

      const disabled = capture();
      assert.equal(
        await main(["--json", "sites", "list"], disabled.streams, {
          ...environment,
          NOVAMIRA_UPDATE_CHECK: "0",
        }),
        0,
      );
      assert.equal(disabled.read().stderr, "");
      assert.ok(!updateCheckEnabled({ NOVAMIRA_UPDATE_CHECK: "0" }));
      assert.ok(updateCheckEnabled({}));
    } finally {
      await registry.close();
    }
  });
});

test("update --check reports the published version without installing", async () => {
  await withHome(async ({ root }) => {
    const registry = await registryServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ latest: "9.9.9" }));
    });
    try {
      const output = capture();
      assert.equal(
        await main(["--json", "update", "--check"], output.streams, {
          NOVAMIRA_HOME: root,
          NOVAMIRA_REGISTRY: registry.url,
          NOVAMIRA_ALLOW_INSECURE_HTTP: "1",
        }),
        0,
      );
      const envelope = JSON.parse(output.read().stdout);
      assert.equal(envelope.ok, true);
      assert.deepEqual(envelope.data, {
        current: VERSION,
        latest: "9.9.9",
        updateAvailable: true,
      });
      assert.equal(output.read().stderr, "", "JSON mode stays quiet");

      const human = capture();
      assert.equal(
        await main(["update", "--check"], human.streams, {
          NOVAMIRA_HOME: root,
          NOVAMIRA_REGISTRY: registry.url,
          NOVAMIRA_ALLOW_INSECURE_HTTP: "1",
        }),
        0,
      );
      assert.match(
        human.read().stderr,
        /Run "novamira update" to install it\./,
      );
      assert.equal(JSON.parse(human.read().stdout).latest, "9.9.9");
    } finally {
      await registry.close();
    }
  });
});

test("an already current installation reports no update and runs no installer", async () => {
  await withHome(async ({ root }) => {
    const registry = await registryServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ latest: "0.0.1" }));
    });
    try {
      const output = capture();
      assert.equal(
        await main(["--json", "update"], output.streams, {
          NOVAMIRA_HOME: root,
          NOVAMIRA_REGISTRY: registry.url,
          NOVAMIRA_ALLOW_INSECURE_HTTP: "1",
        }),
        0,
      );
      assert.deepEqual(JSON.parse(output.read().stdout).data, {
        current: VERSION,
        latest: "0.0.1",
        updateAvailable: false,
        updated: false,
      });
    } finally {
      await registry.close();
    }
  });
});

test("the installer command matches the detected installation manager", async () => {
  assert.deepEqual(installCommandFor("1.2.3", "/usr/lib/node_modules/x.js"), {
    command: "npm",
    args: [
      "install",
      "--global",
      "--ignore-scripts",
      "--registry",
      DEFAULT_REGISTRY,
      "@novamira/cli@1.2.3",
    ],
  });
  assert.deepEqual(
    installCommandFor(
      "1.2.3",
      "/home/user/.bun/install/global/node_modules/@novamira/cli/dist/x.js",
    ),
    {
      command: "bun",
      args: [
        "add",
        "--global",
        "--registry",
        DEFAULT_REGISTRY,
        "@novamira/cli@1.2.3",
      ],
    },
  );

  const calls = [];
  const result = await installVersion(
    "1.0.0",
    "1.2.3",
    {
      run: (command) => {
        calls.push(command);
        return Promise.resolve(0);
      },
    },
    () => undefined,
    "/usr/lib/node_modules/x.js",
  );
  assert.deepEqual(result, {
    updated: true,
    from: "1.0.0",
    to: "1.2.3",
    command: `npm install --global --ignore-scripts --registry ${DEFAULT_REGISTRY} @novamira/cli@1.2.3`,
  });
  assert.equal(calls.length, 1);

  await assert.rejects(
    installVersion(
      "1.0.0",
      "1.2.3",
      { run: () => Promise.resolve(1) },
      () => undefined,
      "/usr/lib/node_modules/x.js",
    ),
    { code: "internal_error" },
  );
});

test("the installer targets the queried registry and the Windows npm shim", () => {
  assert.deepEqual(
    installCommandFor(
      "1.2.3",
      "/usr/lib/node_modules/x.js",
      "https://registry.example.com",
    ),
    {
      command: "npm",
      args: [
        "install",
        "--global",
        "--ignore-scripts",
        "--registry",
        "https://registry.example.com",
        "@novamira/cli@1.2.3",
      ],
    },
  );
  assert.equal(
    installCommandFor(
      "1.2.3",
      "C:\\Users\\a\\AppData\\Roaming\\npm\\node_modules\\x.js",
      DEFAULT_REGISTRY,
      "win32",
    ).command,
    "npm.cmd",
  );
});

test("a cached record from another registry is never reused", async () => {
  await withHome(async ({ paths, locks, security }) => {
    let first = 0;
    let second = 0;
    const one = await registryServer((_request, response) => {
      first += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ latest: "9.9.9" }));
    });
    const two = await registryServer((_request, response) => {
      second += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ latest: "8.8.8" }));
    });
    try {
      const clock = Date.parse("2026-07-27T00:00:00.000Z");
      const options = {
        currentVersion: "1.0.0",
        allowInsecureHttp: true,
        now: () => clock,
      };
      const checkerOne = new UpdateChecker(paths.stateDir, locks, security, {
        ...options,
        registry: one.url,
      });
      const checkerTwo = new UpdateChecker(paths.stateDir, locks, security, {
        ...options,
        registry: two.url,
      });
      assert.match(await checkerOne.notice(), /9\.9\.9/);
      assert.match(await checkerTwo.notice(), /8\.8\.8/);
      assert.equal(first, 1);
      assert.equal(second, 1, "the other registry's record must not be reused");
      assert.match(await checkerTwo.notice(), /8\.8\.8/);
      assert.equal(second, 1, "its own fresh record is reused");
    } finally {
      await one.close();
      await two.close();
    }
  });
});

test("concurrent commands make one registry request per interval", async () => {
  await withHome(async ({ paths, locks, security }) => {
    let requests = 0;
    const registry = await registryServer((_request, response) => {
      requests += 1;
      setTimeout(() => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ latest: "9.9.9" }));
      }, 50);
    });
    try {
      const clock = Date.parse("2026-07-27T00:00:00.000Z");
      const make = () =>
        new UpdateChecker(paths.stateDir, locks, security, {
          currentVersion: "1.0.0",
          registry: registry.url,
          allowInsecureHttp: true,
          now: () => clock,
        });
      const notices = await Promise.all([
        make().notice(),
        make().notice(),
        make().notice(),
      ]);
      for (const notice of notices) assert.match(notice, /9\.9\.9/);
      assert.equal(requests, 1);
    } finally {
      await registry.close();
    }
  });
});

test("an oversized registry body is rejected before it is buffered", async () => {
  const flood = await registryServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    const chunk = "x".repeat(16 * 1024);
    let sent = 0;
    const write = () => {
      if (sent > 40) return;
      sent += 1;
      if (response.write(chunk)) setImmediate(write);
      else response.once("drain", write);
    };
    write();
  });
  try {
    await assert.rejects(
      fetchLatestVersion({ registry: flood.url, allowInsecureHttp: true }),
      { code: "network_error" },
    );
  } finally {
    await flood.close();
  }
});

test("version parsing rejects malformed identifiers and orders by ASCII", () => {
  assert.ok(!isSemver("1.0.0-alpha..1"));
  assert.ok(!isSemver("1.0.0-01"));
  assert.ok(!isSemver("1.0.0-"));
  assert.ok(!isSemver("1.0.0+"));
  assert.ok(isSemver("1.0.0-0A"));
  assert.ok(isSemver("1.0.0-alpha.1+build.5"));

  // Uppercase sorts before lowercase in ASCII, so RC.3 precedes rc.2.
  assert.equal(compareSemver("1.0.0-RC.3", "1.0.0-rc.2"), -1);
  assert.equal(compareSemver("1.0.0-alpha", "1.0.0-alpha.1"), -1);
  assert.equal(compareSemver("1.0.0-alpha.1", "1.0.0-alpha.beta"), -1);
  assert.equal(compareSemver("1.0.0+build.1", "1.0.0+build.2"), 0);

  // Release numbers past the safe integer range keep full precision.
  assert.equal(
    compareSemver("1.0.9007199254740993", "1.0.9007199254740992"),
    1,
  );
});
