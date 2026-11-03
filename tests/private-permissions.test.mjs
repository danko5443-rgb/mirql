import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { getOrCreateQueueKeypair } from "../packages/queue/ledger.mjs";
import { resolveTrustRoot } from "../packages/core/trust-root.mjs";
import { protectPrivatePaths, writePrivateFile, writePrivateFiles } from "../packages/core/private-files.mjs";

function readWindowsAcl(path) {
  const encoded = Buffer.from(path, "utf8").toString("base64");
  const script = `
$ErrorActionPreference="Stop"
$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${encoded}"))
if ([IO.Directory]::Exists($path)) { $acl=[IO.Directory]::GetAccessControl($path) }
else { $acl=[IO.File]::GetAccessControl($path) }
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
  @{ sid=$_.IdentityReference.Value; rights=$_.FileSystemRights.ToString(); type=$_.AccessControlType.ToString() }
})
@{ user=$user; owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; protected=$acl.AreAccessRulesProtected; rules=$rules } | ConvertTo-Json -Depth 5 -Compress
`;
  const result = spawnSync(join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")],
    { encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertOwnerOnly(path) {
  const acl = readWindowsAcl(path);
  assert.equal(acl.owner, acl.user);
  assert.equal(acl.protected, true);
  assert.deepEqual(acl.rules, [{ sid: acl.user, rights: "FullControl", type: "Allow" }]);
}

test("private publication protects real files and preserves unrelated parent permissions", () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-permissions-"));
  try {
    const file = join(root, "key ; $literal ' name.json");
    const parentAcl = process.platform === "win32" ? readWindowsAcl(root) : null;
    writePrivateFile(file, "private bytes naïve 🔐");
    assert.equal(readFileSync(file, "utf8"), "private bytes naïve 🔐");
    if (process.platform === "win32") {
      assertOwnerOnly(file);
      assert.deepEqual(readWindowsAcl(root), parentAcl);
    } else {
      assert.equal(statSync(file).mode & 0o777, 0o600);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("batch provisioning protects dedicated credential directories", () => {
  const temp = mkdtempSync(join(tmpdir(), "mirql-permission-batch-"));
  try {
    const root = join(temp, "trust");
    const keys = join(root, "keys");
    const files = [{ path: join(keys, "machine.json"), contents: "machine" },
      { path: join(root, "human.json"), contents: "human" }];
    writePrivateFiles(files, { directories: [root, keys] });
    for (const path of [root, keys, ...files.map(file => file.path)]) {
      if (process.platform === "win32") assertOwnerOnly(path);
      else assert.equal(statSync(path).mode & 0o777, statSync(path).isDirectory() ? 0o700 : 0o600);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test("relaxing an ACL invalidates the verified metadata snapshot", { skip: process.platform !== "win32" }, () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-permission-cache-"));
  try {
    const file = join(root, "key.json");
    writePrivateFile(file, "test bytes");
    const before = statSync(file, { bigint: true }).ctimeNs;
    const result = spawnSync("icacls.exe", [file, "/grant", "*S-1-1-0:(R)"], { encoding: "utf8", windowsHide: true });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(readWindowsAcl(file).rules.some(rule => rule.sid === "S-1-1-0"));
    assert.notEqual(statSync(file, { bigint: true }).ctimeNs, before);
    protectPrivatePaths([file]);
    assertOwnerOnly(file);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("unavailable ACL enforcement refuses publication and preserves existing bytes", {
  skip: process.platform !== "win32",
}, () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-permission-denial-"));
  const original = process.env.SystemRoot;
  const existing = join(root, "existing.json");
  const fresh = join(root, "fresh.json");
  writeFileSync(existing, "original bytes");
  try {
    process.env.SystemRoot = join(root, "missing-windows");
    assert.throws(() => writePrivateFile(existing, "replacement"), /PRIVATE_PERMISSIONS/);
    assert.throws(() => writePrivateFile(fresh, "new secret"), /PRIVATE_PERMISSIONS/);
    assert.throws(() => getOrCreateQueueKeypair(join(root, "workspace", ".mirql"), existing),
      error => error.code === "PRIVATE_PERMISSIONS" && error.exitCode === 3);
    assert.equal(readFileSync(existing, "utf8"), "original bytes");
    assert.equal(existsSync(fresh), false);
    assert.deepEqual(readdirSync(root), ["existing.json"]);
  } finally {
    process.env.SystemRoot = original;
    rmSync(root, { recursive: true, force: true });
  }
});

test("exclusive credential publication never replaces an existing owner pin", () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-permission-exclusive-"));
  try {
    const file = join(root, "owner.pub.json");
    writePrivateFile(file, "first", { exclusive: true });
    assert.throws(() => writePrivateFile(file, "second", { exclusive: true }));
    assert.equal(readFileSync(file, "utf8"), "first");
    assert.deepEqual(readdirSync(root), ["owner.pub.json"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("genesis refuses unavailable Windows ACL enforcement before publishing keys", {
  skip: process.platform !== "win32",
}, () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-genesis-permission-"));
  try {
    const metadata = join(root, "workspace", ".mirql");
    const trustBase = join(root, "trust");
    // Initialize Node with a valid Windows environment, then simulate the
    // unavailable ACL engine at the CLI dispatch boundary.
    const script = `process.env.SystemRoot=process.argv[1];
      process.env.MIRQL_TRUST_ROOT=process.argv[2];
      const {runCli}=await import("./packages/inbox/index.mjs");
      process.exitCode=runCli(["genesis","--dir",process.argv[3]]);`;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", script,
      join(root, "missing-windows"), trustBase, metadata], { encoding: "utf8" });
    assert.equal(result.status, 3, result.stderr);
    assert.equal(JSON.parse(result.stderr).error, "PRIVATE_PERMISSIONS");
    const trust = resolveTrustRoot(metadata, { trustRoot: trustBase });
    assert.equal(existsSync(join(trust, "keys", "queue.key.json")), false);
    assert.equal(existsSync(join(trust, "human_owner.key.private.json")), false);
    assert.equal(existsSync(join(trust, "owner.pub.json")), false);
    assert.equal(existsSync(join(metadata, "ledger", "events.jsonl")), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";

test("replacing a verified temporary pathname cannot redirect credential bytes", {
  skip: process.platform === "win32",
}, () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-permission-race-"));
  const destination = join(root, "key.json");
  const leaked = join(root, "attacker-file");
  writeFileSync(leaked, "unchanged");
  const originalWrite = fs.writeFileSync;
  let swapped = false;
  try {
    fs.writeFileSync = (target, contents, ...options) => {
      if (contents === "race-test-secret" && !swapped) {
        const temp = readdirSync(root).find(name => name.endsWith(".tmp"));
        fs.unlinkSync(join(root, temp));
        fs.symlinkSync(leaked, join(root, temp));
        swapped = true;
      }
      return originalWrite(target, contents, ...options);
    };
    syncBuiltinESMExports();
    assert.throws(() => writePrivateFile(destination, "race-test-secret"));
    assert.equal(swapped, true);
    assert.equal(readFileSync(leaked, "utf8"), "unchanged");
  } finally {
    fs.writeFileSync = originalWrite;
    syncBuiltinESMExports();
    rmSync(root, { recursive: true, force: true });
  }
});
test("protecting an owned path never rewrites the owner", { skip: process.platform !== "win32" }, () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-owner-rewrite-"));
  try {
    const dir = join(root, "keys");
    mkdirSync(dir);
    const file = join(dir, "key.json");
    writeFileSync(file, "{}");
    // Data drives often grant read + WRITE_DAC without WRITE_OWNER; the
    // recorded owner is already correct there and must not be rewritten.
    const sid = readWindowsAcl(dir).user;
    for (const target of [dir, file]) {
      const grant = spawnSync("icacls.exe", [target, "/inheritance:r", "/grant", `*${sid}:(RD,WDAC)`], { encoding: "utf8", windowsHide: true });
      assert.equal(grant.status, 0, grant.stderr);
    }
    protectPrivatePaths([dir, file]);
    assertOwnerOnly(dir);
    assertOwnerOnly(file);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
