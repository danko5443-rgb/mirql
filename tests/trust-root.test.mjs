import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, existsSync, rmSync, symlinkSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { resolveTrustRoot, assertExternalTrustPath, trustFile } from "../packages/core/trust-root.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { loadKeyring } from "../packages/core/fold.mjs";
import { getOrCreateQueueKeypair } from "../packages/queue/ledger.mjs";

test("genesis stores machine keys externally and ignores a workspace keyring", () => {
  const temp = mkdtempSync(join(tmpdir(), "mirql-trust-test-"));
  const prior = process.env.MIRQL_TRUST_ROOT;
  process.env.MIRQL_TRUST_ROOT = join(temp, "trust");
  try {
    const workspace = join(temp, "workspace");
    const metadata = join(workspace, ".mirql");
    mkdirSync(workspace);
    const genesis = runGenesis(metadata);
    assert.equal(genesis.status, "initialized");
    const root = resolveTrustRoot(metadata);
    assert.ok(existsSync(join(root, "keys", "queue.key.json")));
    assert.equal(existsSync(join(metadata, "keys")), false);
    assert.ok(existsSync(join(metadata, "ledger", "events.jsonl")));
    const queue = getOrCreateQueueKeypair(metadata);
    assert.equal(loadKeyring(metadata)[queue.keyId].publicKey, queue.publicKey);
    writeFileSync(join(metadata, "ledger", "keyring.json"), JSON.stringify({ attacker: "evil" }));
    assert.equal(loadKeyring(metadata).attacker, undefined);
    assert.equal(JSON.parse(readFileSync(trustFile(metadata, "keyring.json"))).attacker, undefined);
    assert.notEqual(resolveTrustRoot(metadata), resolveTrustRoot(join(temp, "another", ".mirql")));
  } finally {
    if (prior === undefined) delete process.env.MIRQL_TRUST_ROOT;
    else process.env.MIRQL_TRUST_ROOT = prior;
    rmSync(temp, { recursive: true, force: true });
  }
});

test("trust roots reject workspaces, other worktrees, and symlinks back into them", () => {
  const temp = mkdtempSync(join(tmpdir(), "mirql-trust-test-"));
  try {
    const workspace = join(temp, "workspace");
    mkdirSync(workspace);
    assert.throws(() => assertExternalTrustPath(join(workspace, "keys"), workspace), /UNSAFE_TRUST_ROOT/);
    const other = join(temp, "other");
    mkdirSync(other);
    const git = spawnSync("git", ["init", other], { encoding: "utf8" });
    assert.equal(git.status, 0, git.stderr);
    assert.throws(() => assertExternalTrustPath(join(other, "new", "keys"), workspace), /UNSAFE_TRUST_ROOT/);
    const alias = join(temp, "alias");
    symlinkSync(workspace, alias, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => assertExternalTrustPath(join(alias, "new", "keys"), workspace), /UNSAFE_TRUST_ROOT/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("an existing ledger never silently adopts a new keyring", () => {
  const temp = mkdtempSync(join(tmpdir(), "mirql-trust-migration-"));
  const prior = process.env.MIRQL_TRUST_ROOT;
  process.env.MIRQL_TRUST_ROOT = join(temp, "trust");
  try {
    const metadata = join(temp, "workspace", ".mirql");
    mkdirSync(join(metadata, "ledger"), { recursive: true });
    writeFileSync(join(metadata, "ledger", "events.jsonl"), "{}\n");
    writeFileSync(join(metadata, "ledger", "keyring.json"), "{}");
    assert.throws(() => getOrCreateQueueKeypair(metadata), /TRUST_MIGRATION_REQUIRED/);
    assert.equal(existsSync(join(metadata, "keys")), false);
  } finally {
    if (prior === undefined) delete process.env.MIRQL_TRUST_ROOT;
    else process.env.MIRQL_TRUST_ROOT = prior;
    rmSync(temp, { recursive: true, force: true });
  }
});

test("a dangling credentials symlink cannot create a key outside the trust root", { skip: process.platform === "win32" }, () => {
  const temp = mkdtempSync(join(tmpdir(), "mirql-trust-link-"));
  const prior = process.env.MIRQL_TRUST_ROOT;
  process.env.MIRQL_TRUST_ROOT = join(temp, "trust");
  try {
    const metadata = join(temp, "workspace", ".mirql");
    const root = resolveTrustRoot(metadata);
    mkdirSync(join(root, "keys"), { recursive: true });
    const victim = join(temp, "outside-key.json");
    symlinkSync(victim, join(root, "keys", "queue.key.json"), "file");
    assert.throws(() => getOrCreateQueueKeypair(metadata));
    assert.equal(existsSync(victim), false);
  } finally {
    if (prior === undefined) delete process.env.MIRQL_TRUST_ROOT;
    else process.env.MIRQL_TRUST_ROOT = prior;
    rmSync(temp, { recursive: true, force: true });
  }
});

test("one ledger cannot redirect its trust directory to another ledger", () => {
  const temp = mkdtempSync(join(tmpdir(), "mirql-trust-tenant-"));
  const prior = process.env.MIRQL_TRUST_ROOT;
  process.env.MIRQL_TRUST_ROOT = join(temp, "trust");
  try {
    const metadata = join(temp, "workspace", ".mirql");
    const root = resolveTrustRoot(metadata);
    const other = resolveTrustRoot(join(temp, "other", ".mirql"));
    mkdirSync(other, { recursive: true });
    symlinkSync(other, root, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => resolveTrustRoot(metadata), /UNSAFE_TRUST_ROOT/);
  } finally {
    if (prior === undefined) delete process.env.MIRQL_TRUST_ROOT;
    else process.env.MIRQL_TRUST_ROOT = prior;
    rmSync(temp, { recursive: true, force: true });
  }
});
