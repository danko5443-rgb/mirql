// tests/owner-key-encryption.test.mjs — Owner key encryption at rest (Law 6).
//
// The human:owner signing key is written as a scrypt + AES-256-GCM envelope
// whenever a passphrase is available, so a stolen key file alone cannot sign
// a warrant or a merge approval. Every test pins HOME/USERPROFILE to a temp
// dir and clears MIRQL_TRUST_ROOT / MIRQL_HUMAN_KEY / MIRQL_HUMAN_PASSPHRASE
// (and MIRQL_ALLOW_PLAINTEXT_OWNER_KEY unless a case exercises that switch),
// so no real credential under ~/.mirql-trust is ever read or listed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runGenesis } from "../packages/inbox/genesis.mjs";
import { sendIntent } from "../packages/inbox/send.mjs";
import {
  requireHumanKey,
  protectOwnerKey,
  findUnprotectedOwnerKey,
  resolveHumanKeyPath,
} from "../packages/inbox/keys.mjs";
import { signEvent, verifyEvent, EXIT_CODES } from "../packages/core/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN_MIRQL = join(ROOT, "bin", "mirql.mjs");
const PASSPHRASE = "correct horse battery staple";
const ENV_KEYS = [
  "MIRQL_TRUST_ROOT",
  "MIRQL_HUMAN_KEY",
  "MIRQL_HUMAN_PASSPHRASE",
  "MIRQL_ALLOW_PLAINTEXT_OWNER_KEY",
];

let sandbox = null;

/** Fresh home + workspace with a clean credential environment per test. */
function setUp() {
  const dir = mkdtempSync(join(tmpdir(), "mirql-owner-key-"));
  sandbox = { dir, home: join(dir, "home"), workspace: join(dir, "ws"), savedEnv: { ...process.env } };
  mkdirSync(sandbox.home, { recursive: true });
  mkdirSync(sandbox.workspace, { recursive: true });
  process.env.HOME = sandbox.home;
  process.env.USERPROFILE = sandbox.home;
  for (const key of ENV_KEYS) delete process.env[key];
}

function tearDown() {
  for (const key of Object.keys(process.env)) {
    if (!(key in sandbox.savedEnv)) delete process.env[key];
  }
  Object.assign(process.env, sandbox.savedEnv);
  rmSync(sandbox.dir, { recursive: true, force: true });
  sandbox = null;
}

/** Child-process env: same isolation, with optional explicit overrides. */
function childEnv(overrides = {}) {
  const env = { ...process.env };
  for (const key of ENV_KEYS) delete env[key];
  env.HOME = sandbox.home;
  env.USERPROFILE = sandbox.home;
  return { ...env, ...overrides };
}

function runCli(args, overrides = {}) {
  return spawnSync(process.execPath, [BIN_MIRQL, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 120000,
    env: childEnv(overrides),
  });
}

function readAllEvents(mirqlDir) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8").split("\n").map((l) => l.trim()).filter(Boolean).map((l) => JSON.parse(l));
}

function assertOwnerLocked(fn) {
  assert.throws(fn, (err) => {
    assert.equal(err.errorCode, "OWNER_KEY_LOCKED");
    assert.equal(err.exitCode, EXIT_CODES.POLICY_DENIAL);
    return true;
  });
}

test("genesis with a passphrase writes an encrypted owner key and the send/sign round trip works", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    const res = runGenesis(mirqlDir, { passphrase: PASSPHRASE });
    assert.equal(res.status, "initialized");

    const doc = JSON.parse(readFileSync(res.human_key_path, "utf8"));
    assert.equal(doc.encrypted, true);
    assert.equal(doc.v, 1);
    assert.equal(doc.kdf, "scrypt");
    assert.equal(typeof doc.kdfParams.N, "number");
    assert.ok(doc.kdfParams.N >= 1 << 15, "scrypt N must be at least 2^15");
    assert.equal(typeof doc.privateKey, "undefined", "no plaintext private key at rest");
    assert.equal(doc.keyId, `ed25519:${doc.publicKey}`);

    // send (human.intent + warrant.created) unlocks the key via the passphrase.
    const sent = sendIntent(
      mirqlDir,
      { title: "Round trip with an encrypted owner key", summary: "signs via passphrase" },
      { key: res.human_key_path, passphrase: PASSPHRASE },
    );
    assert.equal(sent.status, "sent");
    assert.equal(readAllEvents(mirqlDir).length, 3);

    // Direct load + signature round trip through the encrypted file.
    const kp = requireHumanKey(mirqlDir, { key: res.human_key_path, passphrase: PASSPHRASE });
    assert.equal(kp.keyId, doc.keyId);
    const event = signEvent(
      { v: 1, seq: 99, type: "human.approval", payload: { decision: "approve" } },
      kp.privateKey,
      kp.keyId,
    );
    assert.equal(verifyEvent(event, kp.publicKey).ok, true);
  } finally {
    tearDown();
  }
});

test("MIRQL_HUMAN_PASSPHRASE encrypts at genesis and unlocks the key on later reads", () => {
  setUp();
  try {
    process.env.MIRQL_HUMAN_PASSPHRASE = PASSPHRASE;
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    const res = runGenesis(mirqlDir);
    const doc = JSON.parse(readFileSync(res.human_key_path, "utf8"));
    assert.equal(doc.encrypted, true);
    assert.equal(typeof doc.privateKey, "undefined");

    // Explicit passphrase option also unlocks an env-encrypted file.
    const kp = requireHumanKey(mirqlDir, { key: res.human_key_path, passphrase: PASSPHRASE });
    assert.equal(kp.publicKey, doc.publicKey);

    // ...and the env alone unlocks it when no option is given.
    const kpEnv = requireHumanKey(mirqlDir, { key: res.human_key_path });
    assert.equal(kpEnv.publicKey, doc.publicKey);
  } finally {
    tearDown();
  }
});

test("a copied encrypted key file cannot sign without the passphrase", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    const res = runGenesis(mirqlDir, { passphrase: PASSPHRASE });
    const stolen = join(sandbox.dir, "stolen-key.json");
    copyFileSync(res.human_key_path, stolen);

    assertOwnerLocked(() => requireHumanKey(mirqlDir, { key: stolen }));
    assertOwnerLocked(() =>
      sendIntent(mirqlDir, { title: "Forged intent" }, { key: stolen }));
    assert.equal(readAllEvents(mirqlDir).length, 1, "no event may be appended by a locked key");
  } finally {
    tearDown();
  }
});

test("a wrong passphrase, a missing passphrase, and a tampered envelope share one OWNER_KEY_LOCKED error", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    const res = runGenesis(mirqlDir, { passphrase: PASSPHRASE });
    const keyPath = res.human_key_path;

    const messages = [];
    for (const attempt of [
      () => requireHumanKey(mirqlDir, { key: keyPath, passphrase: "definitely-not-the-passphrase" }),
      () => requireHumanKey(mirqlDir, { key: keyPath }),
    ]) {
      try {
        attempt();
        assert.fail("expected OWNER_KEY_LOCKED");
      } catch (err) {
        assert.equal(err.errorCode, "OWNER_KEY_LOCKED");
        messages.push(err.message);
      }
    }
    assert.equal(messages[0], messages[1], "no detail may distinguish wrong vs missing passphrase");

    // Editing the envelope publicKey (AAD-bound) breaks decryption the same way.
    const doc = JSON.parse(readFileSync(keyPath, "utf8"));
    doc.publicKey = doc.publicKey.slice(0, -1) + (doc.publicKey.endsWith("A") ? "B" : "A");
    doc.keyId = `ed25519:${doc.publicKey}`;
    writeFileSync(keyPath, JSON.stringify(doc, null, 2) + "\n");
    try {
      requireHumanKey(mirqlDir, { key: keyPath, passphrase: PASSPHRASE });
      assert.fail("expected OWNER_KEY_LOCKED for a tampered publicKey");
    } catch (err) {
      assert.equal(err.errorCode, "OWNER_KEY_LOCKED");
      assert.equal(err.message, messages[0]);
    }
  } finally {
    tearDown();
  }
});

test("a locked owner key is never regenerated and the file is unchanged afterwards", () => {
  setUp();
  try {
    const mirqlDirA = join(sandbox.workspace, "a", ".mirql");
    const resA = runGenesis(mirqlDirA, { passphrase: PASSPHRASE });

    // A second ledger whose trust root already holds the encrypted owner key.
    const mirqlDirB = join(sandbox.workspace, "b", ".mirql");
    const keyPathB = resolveHumanKeyPath(mirqlDirB);
    mkdirSync(dirname(keyPathB), { recursive: true });
    copyFileSync(resA.human_key_path, keyPathB);
    const before = readFileSync(keyPathB);

    assertOwnerLocked(() => runGenesis(mirqlDirB));
    assert.deepEqual(readFileSync(keyPathB), before, "the locked key file must be untouched");
    assert.equal(existsSync(join(dirname(keyPathB), "keyring.json")), false, "no keyring may be minted");
    assert.equal(existsSync(join(dirname(keyPathB), "owner.pub.json")), false, "no owner pin may be minted");
    assert.equal(existsSync(join(mirqlDirB, "ledger", "events.jsonl")), false, "no genesis event may be signed");

    // With the passphrase the SAME key is reused (registered, not regenerated).
    const resB = runGenesis(mirqlDirB, { passphrase: PASSPHRASE });
    assert.equal(resB.status, "initialized");
    assert.equal(resB.event.writer.key_id, resA.event.writer.key_id);
  } finally {
    tearDown();
  }
});

test("a tampered file cannot downgrade the scrypt cost parameter", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    const res = runGenesis(mirqlDir, { passphrase: PASSPHRASE });
    const keyPath = res.human_key_path;

    const doc = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.ok(doc.kdfParams.N >= 1 << 15);
    doc.kdfParams.N = 1 << 14;
    writeFileSync(keyPath, JSON.stringify(doc, null, 2) + "\n");

    assertOwnerLocked(() => requireHumanKey(mirqlDir, { key: keyPath, passphrase: PASSPHRASE }));
  } finally {
    tearDown();
  }
});

test("creating a key with a too-short passphrase is refused and writes nothing", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    assert.throws(
      () => runGenesis(mirqlDir, { passphrase: "short" }),
      (err) => err.errorCode === "OWNER_KEY_PASSPHRASE_REQUIRED" &&
        err.exitCode === EXIT_CODES.POLICY_DENIAL,
    );
    assert.equal(existsSync(join(mirqlDir, "ledger", "events.jsonl")), false, "no genesis event");
    const trustDir = dirname(resolveHumanKeyPath(mirqlDir));
    assert.equal(existsSync(join(trustDir, "keyring.json")), false, "no keyring");
    assert.equal(existsSync(join(trustDir, "owner.pub.json")), false, "no owner pin");
    assert.equal(existsSync(resolveHumanKeyPath(mirqlDir)), false, "no owner key file");
  } finally {
    tearDown();
  }
});

test("CLI genesis refuses without a passphrase and writes nothing", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "cli", ".mirql");
    const res = runCli(["i", "genesis", "--dir", mirqlDir]);
    assert.equal(res.status, EXIT_CODES.POLICY_DENIAL, res.stderr);
    assert.equal(JSON.parse(res.stderr).error, "OWNER_KEY_PASSPHRASE_REQUIRED");
    assert.equal(existsSync(join(sandbox.home, ".mirql-trust")), false, "trust root must not exist");
    assert.equal(existsSync(mirqlDir), false, "nothing may be written into the workspace");
  } finally {
    tearDown();
  }
});

test("CLI genesis writes an encrypted key when MIRQL_HUMAN_PASSPHRASE is set", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "cli", ".mirql");
    const res = runCli(["i", "genesis", "--dir", mirqlDir], { MIRQL_HUMAN_PASSPHRASE: PASSPHRASE });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(JSON.parse(res.stdout).status, "initialized");
    const keyPath = JSON.parse(res.stdout).human_key_path;
    const doc = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(doc.encrypted, true);
    assert.equal(typeof doc.privateKey, "undefined");
  } finally {
    tearDown();
  }
});

test("MIRQL_ALLOW_PLAINTEXT_OWNER_KEY=1 keeps the legacy plaintext behavior", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "cli", ".mirql");
    const res = runCli(["i", "genesis", "--dir", mirqlDir], { MIRQL_ALLOW_PLAINTEXT_OWNER_KEY: "1" });
    assert.equal(res.status, 0, res.stderr);
    const keyPath = JSON.parse(res.stdout).human_key_path;
    const doc = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(doc.encrypted, undefined);
    assert.equal(typeof doc.privateKey, "string");
  } finally {
    tearDown();
  }
});

test("protect-key migrates a plaintext key, is idempotent, and signing still works", () => {
  setUp();
  try {
    const mirqlDir = join(sandbox.workspace, "a", ".mirql");
    const res = runGenesis(mirqlDir);
    const keyPath = res.human_key_path;
    const plaintext = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(typeof plaintext.privateKey, "string");

    // Without a passphrase the migration refuses and leaves the file alone.
    const denied = runCli(["i", "protect-key", "--dir", mirqlDir]);
    assert.equal(denied.status, EXIT_CODES.POLICY_DENIAL, denied.stderr);
    assert.equal(JSON.parse(denied.stderr).error, "OWNER_KEY_PASSPHRASE_REQUIRED");
    assert.equal(typeof JSON.parse(readFileSync(keyPath, "utf8")).privateKey, "string");

    // With a passphrase the key is encrypted in place...
    const migrated = runCli(["i", "protect-key", "--dir", mirqlDir, "--passphrase", PASSPHRASE]);
    assert.equal(migrated.status, 0, migrated.stderr);
    assert.equal(JSON.parse(migrated.stdout).status, "protected");
    const doc = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(doc.encrypted, true);
    assert.equal(typeof doc.privateKey, "undefined");
    assert.equal(doc.publicKey, plaintext.publicKey);

    // ...re-running reports already_protected without touching the file...
    const again = runCli(["i", "protect-key", "--dir", mirqlDir, "--passphrase", PASSPHRASE]);
    assert.equal(again.status, 0, again.stderr);
    assert.equal(JSON.parse(again.stdout).status, "already_protected");

    // ...and the owner can still sign with the passphrase.
    const kp = requireHumanKey(mirqlDir, { key: keyPath, passphrase: PASSPHRASE });
    assert.equal(kp.publicKey, plaintext.publicKey);
    const sent = sendIntent(
      mirqlDir,
      { title: "Signing after protect-key" },
      { key: keyPath, passphrase: PASSPHRASE },
    );
    assert.equal(sent.status, "sent");
    assert.equal(readAllEvents(mirqlDir).length, 3);
  } finally {
    tearDown();
  }
});

test("findUnprotectedOwnerKey finds plaintext keys, skips encrypted ones, and honors the switch", () => {
  setUp();
  try {
    const mirqlA = join(sandbox.workspace, "a", ".mirql");
    const mirqlB = join(sandbox.workspace, "b", ".mirql");
    const mirqlC = join(sandbox.workspace, "c", ".mirql");
    runGenesis(mirqlA);
    runGenesis(mirqlB);

    // Its own ledger: the plaintext key path is reported directly.
    assert.equal(findUnprotectedOwnerKey(mirqlA), resolveHumanKeyPath(mirqlA));

    // A caller with no key of its own still finds any ledger's plaintext key
    // via the <trust root>/*/human_owner.key.private.json scan.
    const found = findUnprotectedOwnerKey(mirqlC);
    assert.ok(
      found === resolveHumanKeyPath(mirqlA) || found === resolveHumanKeyPath(mirqlB),
      `expected a scanned plaintext key, got ${found}`,
    );

    // Encrypting both keys clears the report — encrypted keys do not count.
    protectOwnerKey(mirqlA, { passphrase: PASSPHRASE });
    assert.equal(findUnprotectedOwnerKey(mirqlC), resolveHumanKeyPath(mirqlB));
    protectOwnerKey(mirqlB, { passphrase: PASSPHRASE });
    assert.equal(findUnprotectedOwnerKey(mirqlC), null);
    assert.equal(findUnprotectedOwnerKey(mirqlA), null);

    // The explicit plaintext switch opts out entirely.
    const mirqlD = join(sandbox.workspace, "d", ".mirql");
    runGenesis(mirqlD);
    process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY = "1";
    assert.equal(findUnprotectedOwnerKey(mirqlD), null);
    delete process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY;
    assert.equal(findUnprotectedOwnerKey(mirqlD), resolveHumanKeyPath(mirqlD));
  } finally {
    tearDown();
  }
});
