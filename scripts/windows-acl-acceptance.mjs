#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Exercises the real Windows ACL path in src/config/file-security.ts against
// powershell.exe. The contract tests stub the command runner, so nothing else
// proves that the generated script binds its inputs and reads the actual ACLs.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";

if (process.platform !== "win32") {
  process.stdout.write(
    `windows acl acceptance: skipped on ${process.platform}\n`,
  );
  process.exit(0);
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const { WindowsFileSecurity, secureDirectory } = await import(
  new URL("../dist/config/file-security.js", import.meta.url).href
);
const { POWERSHELL_PREFIX, powerShellEnvironment, powerShellLiteral } =
  await import(new URL("../dist/config/powershell.js", import.meta.url).href);

// The storage root carries a space and a single quote: the two characters that
// break an unquoted or naively quoted script literal.
const home = await mkdtemp(join(tmpdir(), "novamira acl o'"));
const state = join(home, "state");
const locks = join(state, "locks");
const file = join(state, "credentials.json");

// The production runner discards output, which leaves a failing script with no
// explanation. This one reports what powershell.exe actually said.
function invoke(command, args, input) {
  // Must match the production runner's environment, or this script would
  // pass or fail for reasons the CLI itself never sees.
  const result = spawnSync(command, args, {
    encoding: "utf8",
    windowsHide: true,
    env: powerShellEnvironment(),
    ...(input === undefined ? {} : { input }),
  });
  if (result.error) throw result.error;
  // An unsafe verdict is a normal result, but it still explains itself on
  // stderr, and that explanation is the whole point when a hardened path is
  // rejected.
  if (result.status !== 0 || result.stderr !== "")
    process.stderr.write(
      `${command} exited with ${String(result.status)}\n` +
        `script: ${args[5]}\n` +
        `inherited PSModulePath: ${process.env.PSModulePath ?? "(unset)"}\n` +
        `stdin: ${input ?? "(none)"}\n` +
        `stdout: ${result.stdout}\nstderr: ${result.stderr}\n`,
    );
  return result;
}

const reportingRunner = {
  run: async (command, args) => invoke(command, args).status,
  runWithInput: async (command, args, input) => {
    // The batch script must carry its targets on stdin: a command line cannot
    // hold a hundred storage paths under the Windows 32k limit.
    assert.ok(
      !args.some((argument) => argument.includes(home)),
      "batch ACL invocations must not inline paths into the command line",
    );
    const result = invoke(command, args, input);
    return { code: result.status, stdout: result.stdout };
  },
};

try {
  const security = new WindowsFileSecurity(reportingRunner);

  // An inherited ACL must read as unsafe. While the script relied on $args it
  // errored for every path, so a false here also proves Get-Acl was reached.
  const inherited = join(home, "inherited");
  await mkdir(inherited, { recursive: true });
  assert.equal(
    await security.verifyDirectory(inherited),
    false,
    "an inherited directory ACL must not verify as safe",
  );

  // doctor inspects the config directory (the storage root under
  // NOVAMIRA_HOME), the state directory, and the lock directory.
  for (const directory of [home, state, locks]) {
    await secureDirectory(directory, security);
    assert.equal(
      await security.verifyDirectory(directory),
      true,
      `a hardened directory must verify as safe: ${directory}`,
    );
  }

  await writeFile(file, "{}");
  await security.secureFile(file);
  assert.equal(
    await security.verifyFile(file),
    true,
    "a hardened file must verify as safe",
  );

  // One helper process for every target, answering in input order. The batch
  // verdicts must agree with the single-path ones, including for a path that
  // cannot be read at all: a per-target failure is a `false`, not an abort.
  const missing = join(state, "absent.json");
  assert.deepEqual(
    await security.verifyMany([
      { path: state, kind: "directory" },
      { path: inherited, kind: "directory" },
      { path: file, kind: "file" },
      { path: missing, kind: "file" },
      { path: home, kind: "directory" },
    ]),
    [true, false, true, false, true],
    "batched verification must answer per target, in order",
  );
  assert.deepEqual(
    await security.verifyMany([]),
    [],
    "an empty batch must inspect nothing",
  );

  // The batch apply path hardens the inherited directory the single-path
  // checks left unsafe.
  await security.secureMany([
    { path: inherited, kind: "directory" },
    { path: file, kind: "file" },
  ]);
  assert.deepEqual(
    await security.verifyMany([
      { path: inherited, kind: "directory" },
      { path: file, kind: "file" },
    ]),
    [true, true],
    "a batched apply must leave every target owner-only",
  );

  // ------------------------------------------------------------------
  // The storage policy itself, evaluated by Windows rather than by reading
  // the generated script.
  //
  // Every descriptor below is built on a path this script created beneath its
  // own `mkdtemp` root, and every identity is compared as a SID. The
  // generated-script assertions in test/state-contract.test.mjs prove the
  // script's shape and its exit-code handling; only this section proves that
  // powershell.exe and the Windows ACL APIs agree with the policy, which is
  // the distinction the `$args` defect made expensive to learn.
  const matrix = join(home, "matrix");
  await mkdir(matrix, { recursive: true });

  const SYSTEM_SID = "S-1-5-18";
  const ADMINISTRATORS_SID = "S-1-5-32-544";
  // A real principal the policy does not permit, and a well-known one so the
  // case does not depend on this machine's accounts.
  const USERS_SID = "S-1-5-32-545";
  // Shaped like the sandbox group a hardened workstation adds to a user tree:
  // a domain-relative SID that resolves to nothing here, so the case proves
  // "not in the permitted set" without granting a real group anything.
  const SANDBOX_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002";
  const DIRECTORY_INHERIT = "ContainerInherit,ObjectInherit";

  // `powershell.exe` 5.1 writes stdout in the console code page, so a localized
  // account name such as `BUILTIN\Administratörer` would arrive here mangled
  // and would no longer resolve when sent back. Only this harness reads names
  // out of PowerShell - the CLI's own batch script emits ASCII verdicts - so
  // the encoding is forced here rather than in production.
  function script(lines) {
    const result = invoke("powershell.exe", [
      ...POWERSHELL_PREFIX,
      [
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)",
        ...lines,
      ].join(";"),
    ]);
    if (result.status !== 0)
      throw new Error(
        `ACL fixture script failed with ${String(result.status)}: ${result.stderr}`,
      );
    return result.stdout.trim();
  }

  const OWNER_SID = script([
    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
  ]);
  assert.match(OWNER_SID, /^S-1-5-21-/, "the current user must have a SID");

  // One access rule, expressed the way `FileSystemAccessRule` takes it. The
  // identity may be a SID string or an account name: passing a name is how the
  // localization case proves the policy never compares names.
  function rule({
    identity,
    rights = "FullControl",
    inheritance = DIRECTORY_INHERIT,
    propagation = "None",
    type = "Allow",
    byName = false,
  }) {
    const principal = byName
      ? `[System.Security.Principal.NTAccount]::new(${powerShellLiteral(identity)})`
      : `[System.Security.Principal.SecurityIdentifier]::new(${powerShellLiteral(identity)})`;
    return (
      `$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(${principal},` +
      `[System.Security.AccessControl.FileSystemRights]${powerShellLiteral(rights)},` +
      `[System.Security.AccessControl.InheritanceFlags]${powerShellLiteral(inheritance)},` +
      `[System.Security.AccessControl.PropagationFlags]${powerShellLiteral(propagation)},` +
      `[System.Security.AccessControl.AccessControlType]::${type}))`
    );
  }

  // Replaces a test-owned path's DACL with exactly these rules. `protect:false`
  // leaves the object inheriting from `matrix`, which is how the inherited
  // cases are built.
  // `Set-Acl` writes every section the security object carries, and once the
  // descriptor has been through a protect/purge cycle that includes the SACL,
  // which needs SeSecurityPrivilege and fails for an ordinary account. The
  // `FileSystemInfo.SetAccessControl` overload writes only the sections that
  // were modified, which is the same reason the CLI mutates the object
  // `Get-Acl` returned rather than building a fresh one.
  function setDacl(target, { protect = true, rules = [] }) {
    script([
      `$p=${powerShellLiteral(target)}`,
      "$item=Get-Item -LiteralPath $p -Force",
      "$acl=$item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)",
      `$acl.SetAccessRuleProtection($${String(protect)},$false)`,
      "foreach($e in @($acl.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier]))){$acl.PurgeAccessRules($e.IdentityReference)}",
      ...rules,
      "$item.SetAccessControl($acl)",
    ]);
  }

  function readDacl(target) {
    const raw = script([
      `$p=${powerShellLiteral(target)}`,
      "$a=Get-Acl -LiteralPath $p",
      "$rules=@()",
      "foreach($r in @($a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))){$rules+=[ordered]@{sid=$r.IdentityReference.Value;rights=[int]$r.FileSystemRights;type=[string]$r.AccessControlType;inherited=$r.IsInherited;inheritance=[string]$r.InheritanceFlags;propagation=[string]$r.PropagationFlags}}",
      "[ordered]@{protected=$a.AreAccessRulesProtected;owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value;sddl=$a.Sddl;rules=$rules} | ConvertTo-Json -Depth 5 -Compress",
    ]);
    const parsed = JSON.parse(raw);
    // A single-element array collapses to an object through ConvertTo-Json.
    parsed.rules = parsed.rules === null ? [] : [parsed.rules].flat();
    return parsed;
  }

  const cases = [];
  let sequence = 0;
  async function fixture(rules, { protect = true, kind = "directory" } = {}) {
    sequence += 1;
    const target = join(matrix, `case-${String(sequence)}`);
    if (kind === "directory") await mkdir(target, { recursive: true });
    else await writeFile(target, "{}");
    setDacl(target, { protect, rules });
    return target;
  }

  // `expected` is the verdict the policy must reach. Every case also records
  // what Windows actually retained, so a descriptor the platform normalized is
  // reported as such instead of being read as a passing policy case.
  async function expectVerdict(label, expected, rules, options = {}) {
    const kind = options.kind ?? "directory";
    const target = await fixture(rules, { ...options, kind });
    const before = readDacl(target);
    const verdict =
      kind === "directory"
        ? await security.verifyDirectory(target)
        : await security.verifyFile(target);
    cases.push({ label, expected, actual: verdict, retained: before.rules });
    // Several fixtures deliberately leave the current user no Allow rule at
    // all, which is exactly what makes them interesting and also what would
    // make the temporary tree undeletable. The verdict is already recorded, so
    // access is restored immediately; the owner keeps WRITE_DAC implicitly, so
    // this always succeeds.
    restore(target, kind);
    assert.equal(
      verdict,
      expected,
      `${label}: expected verify=${String(expected)}, got ${String(verdict)}; descriptor ${before.sddl}`,
    );
    return { target, before };
  }

  function restore(target, kind = "directory") {
    setDacl(target, {
      rules: [
        rule({
          identity: OWNER_SID,
          inheritance: kind === "directory" ? DIRECTORY_INHERIT : "None",
        }),
      ],
    });
  }

  const owner = (extra = {}) => rule({ identity: OWNER_SID, ...extra });
  const system = (extra = {}) => rule({ identity: SYSTEM_SID, ...extra });
  const admins = (extra = {}) =>
    rule({ identity: ADMINISTRATORS_SID, ...extra });

  // --- positive: the shapes a hardened installation is allowed to have ---
  await expectVerdict("protected owner-only directory", true, [owner()]);
  await expectVerdict("protected owner + SYSTEM directory", true, [
    owner(),
    system(),
  ]);
  await expectVerdict("protected owner + Administrators directory", true, [
    owner(),
    admins(),
  ]);
  await expectVerdict(
    "protected owner + SYSTEM + Administrators directory",
    true,
    [owner(), system(), admins()],
  );
  await expectVerdict(
    "protected owner-only file with file-specific flags",
    true,
    [owner({ inheritance: "None" })],
    { kind: "file" },
  );

  // Localization: the administrative principals are added through their
  // resolved account names, which on this machine may be localized, and the
  // verdict must be identical to the SID-built case above.
  const systemName = script([
    `[System.Security.Principal.SecurityIdentifier]::new(${powerShellLiteral(SYSTEM_SID)}).Translate([System.Security.Principal.NTAccount]).Value`,
  ]);
  const adminsName = script([
    `[System.Security.Principal.SecurityIdentifier]::new(${powerShellLiteral(ADMINISTRATORS_SID)}).Translate([System.Security.Principal.NTAccount]).Value`,
  ]);
  const localized = await expectVerdict(
    `permitted principals added by account name (${systemName} / ${adminsName})`,
    true,
    [
      owner(),
      rule({ identity: systemName, byName: true }),
      rule({ identity: adminsName, byName: true }),
    ],
  );
  assert.deepEqual(
    localized.before.rules.map((entry) => entry.sid).sort(),
    [OWNER_SID, SYSTEM_SID, ADMINISTRATORS_SID].sort(),
    "rules added by name must still be stored as the well-known SIDs",
  );

  // --- negative: everything the policy must refuse ---
  const unprotected = await expectVerdict(
    "unprotected DACL, inheriting a permitted principal",
    false,
    [],
    { protect: false },
  );
  assert.ok(
    unprotected.before.rules.some(
      (entry) => entry.inherited && entry.sid === OWNER_SID,
    ),
    "the unprotected case must actually inherit a permitted principal's rule",
  );

  await expectVerdict("unexpected principal (BUILTIN\\Users)", false, [
    owner(),
    rule({ identity: USERS_SID }),
  ]);
  await expectVerdict("sandbox-style unresolvable principal", false, [
    owner(),
    rule({ identity: SANDBOX_SID }),
  ]);

  // A Deny is refused wherever it appears, and for whichever principal. The
  // owner's Deny is narrow on purpose: the owner keeps WRITE_DAC implicitly, so
  // the descriptor is always recoverable, and a broad Deny would risk leaving
  // an undeletable fixture behind.
  await expectVerdict("Deny rule for the owner", false, [
    owner(),
    owner({ rights: "AppendData", type: "Deny" }),
  ]);
  await expectVerdict("Deny rule for SYSTEM", false, [
    owner(),
    system({ type: "Deny" }),
  ]);
  await expectVerdict("Deny rule for Administrators", false, [
    owner(),
    admins({ type: "Deny" }),
  ]);

  await expectVerdict("no rule for the current user", false, [system()]);
  await expectVerdict("insufficient rights for the owner", false, [
    owner({ rights: "ReadAndExecute" }),
  ]);
  await expectVerdict("insufficient rights for SYSTEM", false, [
    owner(),
    system({ rights: "ReadAndExecute" }),
  ]);
  await expectVerdict("insufficient rights for Administrators", false, [
    owner(),
    admins({ rights: "ReadAndExecute" }),
  ]);

  await expectVerdict("directory inheritance flags wrong on the owner", false, [
    owner({ inheritance: "ContainerInherit" }),
  ]);
  await expectVerdict("directory inheritance flags wrong on SYSTEM", false, [
    owner(),
    system({ inheritance: "ContainerInherit" }),
  ]);
  await expectVerdict(
    "directory inheritance flags wrong on Administrators",
    false,
    [owner(), admins({ inheritance: "None" })],
  );
  await expectVerdict("propagation flags present on the owner", false, [
    owner({ propagation: "NoPropagateInherit" }),
  ]);
  await expectVerdict("propagation flags present on SYSTEM", false, [
    owner(),
    system({ propagation: "NoPropagateInherit" }),
  ]);

  // Windows merges two access rules that name the same principal with the same
  // rights, type, and flags, so an identical duplicate cannot survive to be
  // judged. The attempt is made anyway, and what the platform retained is
  // recorded: a case that normalized to one rule is reported as normalized, not
  // as a duplicate the policy accepted.
  const duplicates = [];
  for (const [label, rules] of [
    ["owner", [owner(), owner()]],
    ["SYSTEM", [owner(), system(), system()]],
    ["Administrators", [owner(), admins(), admins()]],
  ]) {
    sequence += 1;
    const target = join(matrix, `duplicate-${label}`);
    await mkdir(target, { recursive: true });
    setDacl(target, { rules });
    const state = readDacl(target);
    const counted = state.rules.filter(
      (entry) =>
        entry.sid ===
        (label === "owner"
          ? OWNER_SID
          : label === "SYSTEM"
            ? SYSTEM_SID
            : ADMINISTRATORS_SID),
    ).length;
    const verdict = await security.verifyDirectory(target);
    duplicates.push({ label, retained: counted, verdict });
    restore(target);
    if (counted > 1)
      assert.equal(
        verdict,
        false,
        `a retained duplicate ${label} rule must be refused`,
      );
  }

  // A duplicate that differs only in inheritance is also merged: Windows folds
  // the flags together into one ACE rather than keeping two. Recorded the same
  // way, so the run reports what the platform retained instead of asserting a
  // verdict over a descriptor that cannot exist.
  sequence += 1;
  const distinctTarget = join(matrix, "duplicate-distinct-flags");
  await mkdir(distinctTarget, { recursive: true });
  setDacl(distinctTarget, {
    rules: [owner(), owner({ inheritance: "ContainerInherit" })],
  });
  const distinctState = readDacl(distinctTarget);
  const ownerRules = distinctState.rules.filter(
    (entry) => entry.sid === OWNER_SID,
  ).length;
  const distinctVerdict = await security.verifyDirectory(distinctTarget);
  restore(distinctTarget);
  if (ownerRules > 1)
    assert.equal(
      distinctVerdict,
      false,
      "a retained duplicate owner rule must be refused",
    );

  // A leaf file cannot carry container inheritance, and Windows refuses to
  // build such a rule at all rather than storing one the policy could then
  // reject. The probe is made against an in-memory `FileSecurity`, so nothing
  // on disk is left in a state the cleanup would have to recover from, and the
  // platform's refusal is the finding.
  const fileInheritanceConstructible =
    script([
      "$ok='no'",
      `try{$fs=[System.Security.AccessControl.FileSecurity]::new();$fs.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new(${powerShellLiteral(OWNER_SID)}),[System.Security.AccessControl.FileSystemRights]::FullControl,[System.Security.AccessControl.InheritanceFlags]${powerShellLiteral(DIRECTORY_INHERIT)},[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow));$ok='yes'}catch{$ok='no'}`,
      "$ok",
    ]) === "yes";
  assert.equal(
    fileInheritanceConstructible,
    false,
    "if Windows ever accepts inheritance flags on a file rule, this case must " +
      "become a real rejection test instead of a recorded platform limit",
  );

  // --- apply: convergence without destroying an accepted posture ---
  async function applied(label, rules, options = {}) {
    const kind = options.kind ?? "directory";
    const target = await fixture(rules, { ...options, kind });
    const before = readDacl(target);
    if (kind === "directory") await security.secureDirectory(target);
    else await security.secureFile(target);
    const after = readDacl(target);
    assert.equal(
      kind === "directory"
        ? await security.verifyDirectory(target)
        : await security.verifyFile(target),
      true,
      `${label}: everything apply writes must verify`,
    );
    // Idempotence, measured on the descriptor rather than on the verdict.
    if (kind === "directory") await security.secureDirectory(target);
    else await security.secureFile(target);
    const again = readDacl(target);
    assert.equal(
      again.sddl,
      after.sddl,
      `${label}: a second apply must not change the descriptor`,
    );
    return { target, before, after };
  }

  const untouchedOwnerOnly = await applied("already valid owner-only", [
    owner(),
  ]);
  assert.equal(
    untouchedOwnerOnly.after.sddl,
    untouchedOwnerOnly.before.sddl,
    "an already valid owner-only ACL must not be rewritten",
  );

  const untouchedThree = await applied("already valid three-principal", [
    owner(),
    system(),
    admins(),
  ]);
  assert.equal(
    untouchedThree.after.sddl,
    untouchedThree.before.sddl,
    "an already valid three-principal ACL must not be rewritten",
  );

  const sids = (state) => state.rules.map((entry) => entry.sid).sort();

  const repaired = await applied("repair keeps permitted, drops unexpected", [
    owner(),
    system(),
    admins(),
    rule({ identity: USERS_SID }),
    rule({ identity: SANDBOX_SID }),
  ]);
  assert.deepEqual(
    sids(repaired.after),
    [OWNER_SID, SYSTEM_SID, ADMINISTRATORS_SID].sort(),
    "apply must preserve SYSTEM and Administrators and remove every other principal",
  );

  const deniedOnly = await applied("Deny-only SYSTEM is removed, not granted", [
    owner(),
    system({ type: "Deny" }),
  ]);
  assert.deepEqual(
    sids(deniedOnly.after),
    [OWNER_SID],
    "a principal that only held a Deny must not be re-added as an Allow",
  );

  // An explicit Allow proposes an optional administrative principal and an
  // explicit Deny vetoes it. Repairing such a descriptor by purging both and
  // re-adding a canonical Allow would turn an administrator's explicit refusal
  // into FullControl - the one way this repair could broaden access rather than
  // restore it - so a denied principal is dropped instead of canonicalized.
  // The Deny is narrow so the fixture stays recoverable and deletable; the
  // policy refuses any Deny regardless of the right it names.
  const conflicted = [];
  for (const [label, sid, extra] of [
    ["SYSTEM", SYSTEM_SID, system],
    ["Administrators", ADMINISTRATORS_SID, admins],
  ]) {
    const target = await fixture([
      owner(),
      extra(),
      extra({ rights: "AppendData", type: "Deny" }),
    ]);
    const before = readDacl(target);
    const retainedDeny = before.rules.some(
      (entry) => entry.sid === sid && entry.type === "Deny",
    );
    const retainedAllow = before.rules.some(
      (entry) => entry.sid === sid && entry.type === "Allow",
    );
    conflicted.push({ label, retainedAllow, retainedDeny });
    if (!(retainedAllow && retainedDeny)) {
      restore(target);
      continue;
    }
    assert.equal(
      await security.verifyDirectory(target),
      false,
      `${label} holding both an Allow and a Deny must be refused`,
    );
    await security.secureDirectory(target);
    const after = readDacl(target);
    assert.deepEqual(
      sids(after),
      [OWNER_SID],
      `${label} must not be granted after repair when it was explicitly denied`,
    );
    assert.equal(
      after.rules.some((entry) => entry.type === "Deny"),
      false,
      `${label}: repair must remove the conflicting Deny rather than keep it`,
    );
    assert.equal(
      await security.verifyDirectory(target),
      true,
      `${label}: the repaired descriptor must carry the mandatory owner rule`,
    );
    // Idempotence over the corrected descriptor.
    await security.secureDirectory(target);
    assert.equal(
      readDacl(target).sddl,
      after.sddl,
      `${label}: a second repair must not change the descriptor`,
    );
  }

  // Both optional principals conflicted at once: neither may survive.
  const bothConflicted = await fixture([
    owner(),
    system(),
    system({ rights: "AppendData", type: "Deny" }),
    admins(),
    admins({ rights: "AppendData", type: "Deny" }),
  ]);
  const bothBefore = readDacl(bothConflicted);
  const bothConstructible = [SYSTEM_SID, ADMINISTRATORS_SID].every(
    (sid) =>
      bothBefore.rules.some(
        (entry) => entry.sid === sid && entry.type === "Allow",
      ) &&
      bothBefore.rules.some(
        (entry) => entry.sid === sid && entry.type === "Deny",
      ),
  );
  conflicted.push({
    label: "both",
    retainedAllow: bothConstructible,
    retainedDeny: bothConstructible,
  });
  if (bothConstructible) {
    assert.equal(await security.verifyDirectory(bothConflicted), false);
    await security.secureDirectory(bothConflicted);
    const bothAfter = readDacl(bothConflicted);
    assert.deepEqual(
      sids(bothAfter),
      [OWNER_SID],
      "neither denied administrative principal may be granted by repair",
    );
    assert.equal(await security.verifyDirectory(bothConflicted), true);
    await security.secureDirectory(bothConflicted);
    assert.equal(
      readDacl(bothConflicted).sddl,
      bothAfter.sddl,
      "a second repair over the combined case must not change the descriptor",
    );
  } else {
    restore(bothConflicted);
  }

  // An explicit-only Deny scan cannot see an inherited refusal, and repair
  // protects the DACL, which severs inheritance. Reading explicit rules alone
  // would therefore drop the inherited Deny and re-add the principal as
  // FullControl. A Deny naming a different principal is the same hazard by
  // another route, because group membership can carry it to SYSTEM or
  // Administrators. Both are proved here against real inherited descriptors
  // built from a test-owned parent.
  const denyVeto = [];
  async function inheritedDenyCase(label, denyRule, allowRules) {
    sequence += 1;
    const parent = join(matrix, `veto-parent-${String(sequence)}`);
    const child = join(parent, "child");
    // The child is created before the Deny exists: this account belongs to
    // groups a Deny may name, and denying AppendData on the parent would
    // otherwise block the very mkdir that builds the fixture.
    await mkdir(child, { recursive: true });
    // The parent grants the owner so the tree stays traversable and deletable,
    // and carries the inheritable Deny the child must pick up.
    setDacl(parent, { rules: [owner(), denyRule] });
    // The child stays unprotected so the parent's Deny reaches it as an
    // inherited ACE, and adds its own explicit administrative Allow.
    setDacl(child, { protect: false, rules: allowRules });
    const before = readDacl(child);
    const inheritedDeny = before.rules.some(
      (entry) => entry.inherited && entry.type === "Deny",
    );
    const explicitAllow = before.rules.some(
      (entry) => !entry.inherited && entry.type === "Allow",
    );
    denyVeto.push({ label, constructed: inheritedDeny && explicitAllow });
    if (!(inheritedDeny && explicitAllow)) {
      restore(child);
      restore(parent);
      return;
    }
    assert.equal(
      await security.verifyDirectory(child),
      false,
      `${label}: an inherited Deny must be refused`,
    );
    await security.secureDirectory(child);
    const after = readDacl(child);
    assert.deepEqual(
      sids(after),
      [OWNER_SID],
      `${label}: no optional administrative principal may survive an inherited Deny`,
    );
    assert.equal(
      after.rules.some((entry) => entry.type === "Deny" || entry.inherited),
      false,
      `${label}: repair must leave no Deny and no inherited rule`,
    );
    assert.equal(
      await security.verifyDirectory(child),
      true,
      `${label}: the repaired descriptor must carry the mandatory owner rule`,
    );
    await security.secureDirectory(child);
    assert.equal(
      readDacl(child).sddl,
      after.sddl,
      `${label}: a second repair must not change the descriptor`,
    );
    restore(parent);
  }

  await inheritedDenyCase(
    "explicit SYSTEM Allow + inherited SYSTEM Deny",
    system({ rights: "AppendData", type: "Deny" }),
    [owner(), system()],
  );
  await inheritedDenyCase(
    "explicit Administrators Allow + inherited Administrators Deny",
    admins({ rights: "AppendData", type: "Deny" }),
    [owner(), admins()],
  );
  await inheritedDenyCase(
    "explicit administrative Allow + inherited Deny for another principal",
    rule({ identity: USERS_SID, rights: "AppendData", type: "Deny" }),
    [owner(), system(), admins()],
  );

  // The same veto from an explicit Deny that names a different principal
  // entirely: SYSTEM and Administrators are otherwise eligible here.
  const foreignDeny = await fixture([
    owner(),
    system(),
    admins(),
    rule({ identity: USERS_SID, rights: "AppendData", type: "Deny" }),
  ]);
  const foreignBefore = readDacl(foreignDeny);
  const foreignConstructed = foreignBefore.rules.some(
    (entry) => entry.sid === USERS_SID && entry.type === "Deny",
  );
  denyVeto.push({
    label: "explicit Deny for another principal",
    constructed: foreignConstructed,
  });
  if (foreignConstructed) {
    assert.equal(await security.verifyDirectory(foreignDeny), false);
    await security.secureDirectory(foreignDeny);
    const foreignAfter = readDacl(foreignDeny);
    assert.deepEqual(
      sids(foreignAfter),
      [OWNER_SID],
      "a Deny naming another principal must veto both optional administrative SIDs",
    );
    assert.equal(await security.verifyDirectory(foreignDeny), true);
    await security.secureDirectory(foreignDeny);
    assert.equal(
      readDacl(foreignDeny).sddl,
      foreignAfter.sddl,
      "a second repair over the foreign-Deny case must not change the descriptor",
    );
  } else {
    restore(foreignDeny);
  }

  // An unprotected target denies nothing and carries otherwise eligible
  // explicit administrative Allows, and is still repaired to owner-only. This
  // is the direct form of the tree-order safeguard: an unprotected descriptor
  // may have inherited what it shows, or may have had an inherited refusal
  // removed by an ancestor's repair moments earlier, so nothing optional is
  // preserved from it.
  const unprotectedEligible = await fixture([owner(), system(), admins()], {
    protect: false,
  });
  const unprotectedBefore = readDacl(unprotectedEligible);
  assert.equal(
    unprotectedBefore.protected,
    false,
    "the fixture must genuinely be unprotected",
  );
  assert.equal(
    unprotectedBefore.rules.some((entry) => entry.type === "Deny"),
    false,
    "this case must carry no Deny at all, so protection alone is what decides",
  );
  assert.equal(
    await security.verifyDirectory(unprotectedEligible),
    false,
    "an unprotected DACL must be refused",
  );
  await security.secureDirectory(unprotectedEligible);
  const unprotectedAfter = readDacl(unprotectedEligible);
  assert.deepEqual(
    sids(unprotectedAfter),
    [OWNER_SID],
    "no optional principal may be preserved from an unprotected descriptor",
  );
  assert.equal(await security.verifyDirectory(unprotectedEligible), true);
  await security.secureDirectory(unprotectedEligible);
  assert.equal(
    readDacl(unprotectedEligible).sddl,
    unprotectedAfter.sddl,
    "a second repair of the unprotected case must not change the descriptor",
  );

  // The parent-first sequence doctor actually performs, driven explicitly so
  // the intermediate state is observable: repair the parent, then confirm the
  // child's inherited Deny has already vanished while the child is still
  // unprotected, then repair the child.
  sequence += 1;
  const orderParent = join(matrix, `order-parent-${String(sequence)}`);
  const orderChild = join(orderParent, "child");
  await mkdir(orderChild, { recursive: true });
  setDacl(orderParent, {
    rules: [owner(), system({ rights: "AppendData", type: "Deny" })],
  });
  setDacl(orderChild, { protect: false, rules: [owner(), system(), admins()] });
  const orderBefore = readDacl(orderChild);
  const orderConstructible =
    orderBefore.protected === false &&
    orderBefore.rules.some((entry) => entry.inherited && entry.type === "Deny");
  denyVeto.push({
    label: "parent-first sequence",
    constructed: orderConstructible,
  });
  if (orderConstructible) {
    await security.secureDirectory(orderParent);
    const midChild = readDacl(orderChild);
    // The exact hazard, observed rather than assumed.
    assert.equal(
      midChild.rules.some((entry) => entry.type === "Deny"),
      false,
      "repairing the parent must have removed the child's inherited Deny",
    );
    assert.equal(
      midChild.protected,
      false,
      "the child must still be unprotected at the moment it is judged",
    );
    assert.ok(
      [SYSTEM_SID, ADMINISTRATORS_SID].every((sid) =>
        midChild.rules.some((entry) => !entry.inherited && entry.sid === sid),
      ),
      "the child must still carry its explicit administrative Allows",
    );
    await security.secureDirectory(orderChild);
    const orderAfter = readDacl(orderChild);
    assert.deepEqual(
      sids(orderAfter),
      [OWNER_SID],
      "a child repaired after its parent must not gain administrative access",
    );
    assert.equal(await security.verifyDirectory(orderChild), true);
    await security.secureDirectory(orderChild);
    assert.equal(
      readDacl(orderChild).sddl,
      orderAfter.sddl,
      "a second repair of the child must not change the descriptor",
    );
    restore(orderParent);
  } else {
    restore(orderChild);
    restore(orderParent);
  }

  // Positive control: the broader veto must not have disabled the accepted
  // three-principal policy. With only eligible explicit Allows and no Deny
  // anywhere, all three principals survive and an already-valid descriptor is
  // not written at all.
  const noDeny = await fixture([owner(), system(), admins()]);
  const noDenyBefore = readDacl(noDeny);
  assert.equal(
    await security.verifyDirectory(noDeny),
    true,
    "an eligible three-principal descriptor must still verify",
  );
  await security.secureDirectory(noDeny);
  const noDenyAfter = readDacl(noDeny);
  assert.equal(
    noDenyAfter.sddl,
    noDenyBefore.sddl,
    "an already valid three-principal descriptor must not be rewritten",
  );
  assert.deepEqual(
    sids(noDenyAfter),
    [OWNER_SID, SYSTEM_SID, ADMINISTRATORS_SID].sort(),
    "the Deny veto must not remove principals from a descriptor that denies nothing",
  );
  // And an eligible-but-malformed three-principal descriptor still repairs into
  // all three, which is the behaviour the earlier stage approved.
  const repairedThree = await applied(
    "malformed but undenied three-principal descriptor",
    [owner(), system({ rights: "ReadAndExecute" }), admins()],
  );
  assert.deepEqual(
    sids(repairedThree.after),
    [OWNER_SID, SYSTEM_SID, ADMINISTRATORS_SID].sort(),
    "an undenied administrative Allow must still be canonicalized, not dropped",
  );

  const rightsRepaired = await applied("insufficient SYSTEM rights repaired", [
    owner(),
    system({ rights: "ReadAndExecute" }),
  ]);
  assert.deepEqual(
    sids(rightsRepaired.after),
    [OWNER_SID, SYSTEM_SID].sort(),
    "apply must re-add SYSTEM canonically rather than drop it",
  );
  // `[string]` on a flags enum renders `ContainerInherit, ObjectInherit`, with
  // a space the constructor spelling does not use.
  const flags = (value) => value.replaceAll(" ", "");
  assert.ok(
    rightsRepaired.after.rules.every(
      (entry) =>
        flags(entry.inheritance) === DIRECTORY_INHERIT &&
        entry.propagation === "None",
    ),
    `every repaired directory rule must carry the canonical flags: ${JSON.stringify(rightsRepaired.after.rules)}`,
  );

  const flagsRepaired = await applied(
    "incorrect Administrators flags repaired",
    [
      owner(),
      admins({
        inheritance: "ContainerInherit",
        propagation: "NoPropagateInherit",
      }),
    ],
  );
  assert.deepEqual(
    sids(flagsRepaired.after),
    [OWNER_SID, ADMINISTRATORS_SID].sort(),
    "apply must repair an administrative rule's flags rather than remove it",
  );

  const ownerEstablished = await applied("missing owner rule established", [
    system(),
  ]);
  assert.deepEqual(
    sids(ownerEstablished.after),
    [OWNER_SID, SYSTEM_SID].sort(),
    "apply must add the mandatory owner rule and keep SYSTEM",
  );

  const unprotectedRepaired = await applied(
    "unprotected DACL protected and canonicalized",
    [],
    { protect: false },
  );
  assert.equal(
    unprotectedRepaired.after.protected,
    true,
    "apply must protect the DACL",
  );
  assert.ok(
    unprotectedRepaired.after.rules.every((entry) => !entry.inherited),
    "apply must leave no inherited rule behind",
  );

  await applied("file repaired to file-specific flags", [owner()], {
    kind: "file",
  });

  // Owner repair needs a foreign owner to repair from, and setting one
  // generally requires SeRestorePrivilege. Attempt it; if this session cannot,
  // that is reported rather than claimed.
  let ownerRepairConstructible = false;
  const foreignOwner = join(matrix, "foreign-owner");
  await mkdir(foreignOwner, { recursive: true });
  try {
    script([
      `$p=${powerShellLiteral(foreignOwner)}`,
      "$acl=Get-Acl -LiteralPath $p",
      `$acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new(${powerShellLiteral(ADMINISTRATORS_SID)}))`,
      "Set-Acl -LiteralPath $p -AclObject $acl",
    ]);
    ownerRepairConstructible =
      readDacl(foreignOwner).owner === ADMINISTRATORS_SID;
  } catch {
    ownerRepairConstructible = false;
  }
  if (ownerRepairConstructible) {
    setDacl(foreignOwner, { rules: [owner()] });
    assert.equal(
      await security.verifyDirectory(foreignOwner),
      false,
      "a foreign owner must be refused",
    );
    await security.secureDirectory(foreignOwner);
    assert.equal(
      readDacl(foreignOwner).owner,
      OWNER_SID,
      "apply must reclaim ownership",
    );
    assert.equal(await security.verifyDirectory(foreignOwner), true);
  }

  process.stdout.write(
    `windows acl policy: ${String(cases.length)} verdict cases, ` +
      `duplicates ${duplicates.map((entry) => `${entry.label}=${String(entry.retained)}`).join(" ")}, ` +
      `distinct-flag duplicate retained ${String(ownerRules)} owner rules, ` +
      `file-inheritance constructible ${String(fileInheritanceConstructible)}, ` +
      `owner-repair constructible ${String(ownerRepairConstructible)}\n`,
  );

  // doctor reads the same code through its own storage.permissions check.
  const doctorEnvironment = {
    ...process.env,
    NOVAMIRA_HOME: home,
    NOVAMIRA_CREDENTIAL_BACKEND: "file",
    NOVAMIRA_UPDATE_CHECK: "0",
  };
  function runDoctor(extra = []) {
    const result = spawnSync(
      process.execPath,
      [
        join(root, "dist", "index.js"),
        "doctor",
        "--offline",
        "--json",
        ...extra,
      ],
      { cwd: root, encoding: "utf8", env: doctorEnvironment },
    );
    assert.ok(result.stdout, `doctor produced no report: ${result.stderr}`);
    const parsed = JSON.parse(result.stdout);
    const check = parsed.data.checks.find(
      (entry) => entry.id === "storage.permissions",
    );
    assert.ok(check, "doctor must report storage.permissions");
    return check;
  }

  // The matrix tree is deliberately full of rejected descriptors, and doctor
  // only inspects its own storage paths, so it is removed before doctor reads
  // the same root.
  await rm(matrix, { recursive: true, force: true });

  assert.equal(
    runDoctor().status,
    "pass",
    "storage.permissions must pass on hardened storage",
  );

  // The accepted three-principal posture must satisfy doctor itself, not only
  // the verifier called directly.
  for (const directory of [home, state, locks]) {
    setDacl(directory, { rules: [owner(), system(), admins()] });
  }
  assert.equal(
    runDoctor().status,
    "pass",
    "storage.permissions must accept owner + SYSTEM + Administrators",
  );

  // And doctor --fix must converge from a genuinely unsafe descriptor without
  // discarding the administrative principals it found there.
  setDacl(state, {
    rules: [owner(), system(), admins(), rule({ identity: USERS_SID })],
  });
  assert.equal(runDoctor().status, "fail", "an unexpected principal must fail");
  const fixed = runDoctor(["--fix"]);
  assert.equal(
    fixed.status,
    "pass",
    `doctor --fix must converge: ${JSON.stringify(fixed)}`,
  );
  assert.deepEqual(
    readDacl(state)
      .rules.map((entry) => entry.sid)
      .sort(),
    [OWNER_SID, SYSTEM_SID, ADMINISTRATORS_SID].sort(),
    "doctor --fix must keep the permitted principals it found",
  );
  const settled = readDacl(state).sddl;
  assert.equal(runDoctor(["--fix"]).status, "pass");
  assert.equal(
    readDacl(state).sddl,
    settled,
    "a second doctor --fix must not change the descriptor",
  );

  // The same convergence, from an explicitly denied optional principal. doctor
  // must repair the check without turning that Deny into FullControl, and this
  // runs against the temporary NOVAMIRA_HOME only.
  setDacl(state, {
    rules: [
      owner(),
      system(),
      system({ rights: "AppendData", type: "Deny" }),
      admins(),
    ],
  });
  const conflictedState = readDacl(state);
  const doctorConflictConstructible =
    conflictedState.rules.some(
      (entry) => entry.sid === SYSTEM_SID && entry.type === "Deny",
    ) &&
    conflictedState.rules.some(
      (entry) => entry.sid === SYSTEM_SID && entry.type === "Allow",
    );
  if (doctorConflictConstructible) {
    assert.notEqual(
      runDoctor().status,
      "pass",
      "a Deny on an optional principal must not report as safe storage",
    );
    const converged = runDoctor(["--fix"]);
    assert.equal(
      converged.status,
      "pass",
      `doctor --fix must converge from a denied principal: ${JSON.stringify(converged)}`,
    );
    const repaired = readDacl(state);
    assert.equal(
      repaired.rules.some((entry) => entry.sid === SYSTEM_SID),
      false,
      "doctor --fix must not grant a principal the descriptor explicitly denied",
    );
    assert.equal(
      repaired.rules.some((entry) => entry.type === "Deny"),
      false,
      "doctor --fix must leave no Deny behind",
    );
    assert.deepEqual(
      repaired.rules.map((entry) => entry.sid).sort(),
      [OWNER_SID],
      "a Deny anywhere in the descriptor vetoes every optional principal, " +
        "including the one that was not itself denied",
    );
  }

  // The same convergence from an INHERITED Deny that originates on a directory
  // doctor itself repairs, which is the hard case.
  //
  // `permissionCandidates` enumerates the storage root first and its
  // descendants after, and `secureMany` repairs them in that order, so the
  // parent's Deny is stripped before the child is judged. A predicate that
  // looked only at what the child's DACL says at its own repair moment would
  // see no Deny at all and would restore the child's explicit administrative
  // Allows as FullControl - widening access across the pair while every
  // individual decision looked correct. The incoming-protection precondition is
  // what closes that: the child is unprotected, which is precisely the state in
  // which an ancestor's repair can have rewritten history, so no optional
  // principal is preserved from it.
  setDacl(home, {
    rules: [owner(), system({ rights: "AppendData", type: "Deny" })],
  });
  setDacl(state, { protect: false, rules: [owner(), system(), admins()] });
  const inheritedState = readDacl(state);
  const doctorInheritedConstructible =
    inheritedState.protected === false &&
    inheritedState.rules.some(
      (entry) => entry.inherited && entry.type === "Deny",
    ) &&
    [SYSTEM_SID, ADMINISTRATORS_SID].every((sid) =>
      inheritedState.rules.some(
        (entry) =>
          !entry.inherited && entry.type === "Allow" && entry.sid === sid,
      ),
    );
  if (doctorInheritedConstructible) {
    assert.notEqual(
      runDoctor().status,
      "pass",
      "an inherited Deny must not report as safe storage",
    );
    const converged = runDoctor(["--fix"]);
    assert.equal(
      converged.status,
      "pass",
      `doctor --fix must converge from an inherited Deny: ${JSON.stringify(converged)}`,
    );
    // The parent was repaired too, which is what removes the child's inherited
    // Deny mid-pass.
    assert.equal(
      readDacl(home).protected,
      true,
      "the inspected parent must itself have been repaired",
    );
    const repaired = readDacl(state);
    assert.deepEqual(
      sids(repaired),
      [OWNER_SID],
      "doctor --fix must not restore an optional principal on a child whose " +
        "inherited Deny an earlier parent repair removed",
    );
    assert.equal(
      repaired.rules.some((entry) => entry.type === "Deny" || entry.inherited),
      false,
      "doctor --fix must leave no Deny and no inherited rule",
    );
    const settledInherited = readDacl(state).sddl;
    assert.equal(runDoctor(["--fix"]).status, "pass");
    assert.equal(
      readDacl(state).sddl,
      settledInherited,
      "a second doctor --fix must not change the descriptor",
    );
  }

  process.stdout.write(
    `windows acl deny-preservation: ` +
      `${conflicted.map((entry) => `${entry.label}=${entry.retainedAllow && entry.retainedDeny ? "constructed" : "not-constructible"}`).join(" ")}, ` +
      `doctor conflict ${doctorConflictConstructible ? "constructed" : "not-constructible"}\n`,
  );
  process.stdout.write(
    `windows acl deny-veto: ` +
      `${denyVeto.map((entry) => `${entry.label.replace(/ /g, "-")}=${entry.constructed ? "constructed" : "not-constructible"}`).join(" ")}, ` +
      `doctor inherited ${doctorInheritedConstructible ? "constructed" : "not-constructible"}\n`,
  );

  process.stdout.write("windows acl acceptance: ok\n");
} finally {
  await rm(home, { recursive: true, force: true });
}
