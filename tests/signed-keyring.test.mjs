import { authorizeTestWarrant } from "./helpers/warrant.mjs";
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { execFile, spawnSync } from "node:child_process";
import { generateFactoryKeypairs } from "../packages/inbox/keys.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { generateEd25519Keypair, signEvent } from "../packages/core/ed25519.mjs";
import { readSignedKeyring, enrollKey, sealKeyring } from "../packages/core/keyring.mjs";
import { trustFile } from "../packages/core/trust-root.mjs";
import { getOrCreateQueueKeypair } from "../packages/queue/ledger.mjs";
import { runSupervisor } from "../packages/run/supervisor.mjs";
import { appendSupervisorEvent } from "../packages/run/ledger.mjs";

let temp, metadata, owner, prior;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "mirql-signed-ring-"));
  prior = process.env.MIRQL_TRUST_ROOT;
  process.env.MIRQL_TRUST_ROOT = join(temp, "trust");
  metadata = join(temp, "workspace", ".mirql");
  const genesis = runGenesis(metadata);
  owner = JSON.parse(readFileSync(genesis.human_key_path, "utf8"));
});
afterEach(() => {
  if (prior === undefined) delete process.env.MIRQL_TRUST_ROOT;
  else process.env.MIRQL_TRUST_ROOT = prior;
  rmSync(temp, { recursive: true, force: true });
});

test("genesis pins the human key and signs the factory keyring", () => {
  assert.equal(readSignedKeyring(metadata)["human:owner"].publicKey, owner.publicKey);
  const queue = getOrCreateQueueKeypair(metadata);
  assert.equal(readSignedKeyring(metadata)[queue.keyId].publicKey, queue.publicKey);
});

test("editing the public keyring fails verification and machine key loading", () => {
  const file = trustFile(metadata, "keyring.json");
  const ring = JSON.parse(readFileSync(file));
  ring.attacker = generateEd25519Keypair().publicKey;
  writeFileSync(file, JSON.stringify(ring));
  assert.throws(() => readSignedKeyring(metadata), /modified without/);
  assert.throws(() => getOrCreateQueueKeypair(metadata), /modified without/);
});

test("an unregistered machine key cannot write an outcome or enroll itself", () => {
  const stranger = generateEd25519Keypair();
  const log = join(metadata, "ledger", "events.jsonl");
  const original = readFileSync(log, "utf8");
  assert.throws(() => appendSupervisorEvent(metadata, {
    type: "attempt.outcome", payload: {},
  }, stranger), /not enrolled/);
  assert.equal(readFileSync(log, "utf8"), original);
  assert.throws(() => enrollKey(metadata, "tool:reviewer", stranger.publicKey, stranger), /pinned human key/);
  assert.equal(readSignedKeyring(metadata)["tool:reviewer"], undefined);
});

test("an owner can enroll a namespace and repair only the signed state", () => {
  const approved = generateEd25519Keypair();
  const attacker = generateEd25519Keypair();
  const ring = readSignedKeyring(metadata);
  ring["tool:intruder"] = { ns: "tool:intruder", publicKey: attacker.publicKey };
  writeFileSync(trustFile(metadata, "keyring.json"), JSON.stringify(ring));
  enrollKey(metadata, "tool:reviewer", approved.publicKey, owner);
  const repaired = readSignedKeyring(metadata);
  assert.equal(repaired["tool:reviewer"].publicKey, approved.publicKey);
  assert.equal(repaired["tool:intruder"], undefined);
});

test("a signature cannot be transplanted into another ledger", () => {
  const second = join(temp, "second", ".mirql");
  runGenesis(second);
  writeFileSync(trustFile(second, "keyring.sig"), readFileSync(trustFile(metadata, "keyring.sig")));
  assert.throws(() => readSignedKeyring(second), /does not match/);
});

test("the public CLI requires the explicit human key for enrollment", () => {
  const key = generateEd25519Keypair();
  const args = ["bin/mirql.mjs", "i", "enroll-key", "tool:reviewer", key.publicKey, "--dir", metadata];
  const denied = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.notEqual(denied.status, 0);
  const allowed = spawnSync(process.execPath, [...args, "--key", trustFile(metadata, "human_owner.key.private.json")],
    { encoding: "utf8" });
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(JSON.parse(allowed.stdout).status, "enrolled");
  assert.equal(readSignedKeyring(metadata)["tool:reviewer"].publicKey, key.publicKey);
});

test("a cold machine key never enrolls itself", () => {
  const cold = join(temp, "cold", ".mirql");
  assert.throws(() => getOrCreateQueueKeypair(cold), /not enrolled/);
  assert.deepEqual(readSignedKeyring(cold), {});
  assert.equal(spawnSync(process.execPath, ["bin/mirql.mjs", "q", "status", "--dir", cold],
    { encoding: "utf8" }).status, 0);
});

test("owner enrollment retries an interrupted publication from signed contents", () => {
  const prepared = generateEd25519Keypair();
  const next = generateEd25519Keypair();
  const document = JSON.parse(readFileSync(trustFile(metadata, "keyring.sig")));
  delete document.hash;
  delete document.sig;
  document.keyring["tool:prepared"] = { ns: "tool:prepared", publicKey: prepared.publicKey };
  const authorized = signEvent(document, owner.privateKey, owner.keyId);
  writeFileSync(trustFile(metadata, "keyring.sig"), JSON.stringify(authorized));
  assert.throws(() => readSignedKeyring(metadata), /modified without/);
  enrollKey(metadata, "tool:next", next.publicKey, owner);
  const ring = readSignedKeyring(metadata);
  assert.equal(ring["tool:prepared"].publicKey, prepared.publicKey);
  assert.equal(ring["tool:next"].publicKey, next.publicKey);
});

test("concurrent CLI enrollments preserve both namespace registrations", async () => {
  const execute = promisify(execFile);
  const keys = [generateEd25519Keypair(), generateEd25519Keypair()];
  await Promise.all(keys.map((key, index) => execute(process.execPath, [
    "bin/mirql.mjs", "i", "enroll-key", "tool:parallel" + index, key.publicKey,
    "--dir", metadata, "--key", trustFile(metadata, "human_owner.key.private.json"),
  ])));
  const ring = readSignedKeyring(metadata);
  keys.forEach((key, index) => assert.equal(ring["tool:parallel" + index].publicKey, key.publicKey));
});

test("relocated signed storage requires a new explicit owner authorization", () => {
  const relocated = join(temp, "moved", ".mirql");
  const sourceRoot = trustFile(metadata);
  cpSync(metadata, relocated, { recursive: true });
  // Path resolution is available to the operator even before trust is established.
  const targetRoot = trustFile(relocated);
  cpSync(sourceRoot, targetRoot, { recursive: true });
  assert.throws(() => readSignedKeyring(relocated), /does not match/);
  const queue = readSignedKeyring(metadata)["tool:queue"];
  enrollKey(relocated, "tool:queue", queue.publicKey, owner, { initialize: true });
  assert.equal(readSignedKeyring(relocated)["tool:queue"].publicKey, queue.publicKey);
});

test("a damaged machine key is refused without overwriting its bytes", () => {
  const file = trustFile(metadata, "keys", "queue.key.json");
  writeFileSync(file, "{damaged");
  assert.throws(() => getOrCreateQueueKeypair(metadata), /Invalid persisted queue key/);
  assert.equal(readFileSync(file, "utf8"), "{damaged");
  assert.ok(readSignedKeyring(metadata)["tool:queue"].publicKey);
});

test("an unregistered supervisor key is refused before the worker command runs", () => {
  authorizeTestWarrant(metadata, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
  const marker = join(temp, "worker-ran");
  const script = join(temp, "worker.mjs");
  writeFileSync(script, `import {writeFileSync} from "node:fs";writeFileSync(${JSON.stringify(marker)}, "ran");`);
  assert.throws(() => runSupervisor({
    mirqlDir: metadata, workspaceDir: join(temp, "workspace"),
    warrantId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    keypair: generateEd25519Keypair(),
    builderCommand: `"${process.execPath}" "${script}"`,
  }), /not enrolled/);
  assert.equal(existsSync(marker), false);
});

test("legacy unsigned keyrings require explicit initialization by their matching owner", () => {
  const legacy = join(temp, "legacy", ".mirql");
  const path = trustFile(legacy, "keyring.json");
  const oldOwner = generateEd25519Keypair();
  const worker = generateEd25519Keypair();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ "human:owner": oldOwner.publicKey, "tool:queue": worker.publicKey }));
  assert.throws(() => readSignedKeyring(legacy), /Cannot read trusted keyring material/);
  assert.throws(() => enrollKey(legacy, "tool:queue", worker.publicKey, owner, { initialize: true }), /Legacy owner key/);
  enrollKey(legacy, "tool:queue", worker.publicKey, oldOwner, { initialize: true });
  assert.equal(readSignedKeyring(legacy)["human:owner"].publicKey, oldOwner.publicKey);
});

test("the human owner can assign a namespace to a signed legacy unbound key", () => {
  const worker = generateEd25519Keypair();
  const ring = readSignedKeyring(metadata);
  ring[worker.keyId] = worker.publicKey;
  sealKeyring(metadata, ring, owner);
  enrollKey(metadata, "tool:legacy", worker.publicKey, owner);
  assert.equal(readSignedKeyring(metadata)["tool:legacy"].publicKey, worker.publicKey);
  const queue = readSignedKeyring(metadata)["tool:queue"];
  assert.throws(() => enrollKey(metadata, "tool:duplicate", queue.publicKey, owner), /multiple writer namespaces/);
  assert.equal(readSignedKeyring(metadata)["tool:duplicate"], undefined);
});

test("public verification and signing commands report keyring integrity failures", () => {
  const log = join(metadata, "ledger", "events.jsonl");
  const original = readFileSync(log, "utf8");
  const ring = readSignedKeyring(metadata);
  ring["tool:intruder"] = { ns: "tool:intruder", publicKey: generateEd25519Keypair().publicKey };
  writeFileSync(trustFile(metadata, "keyring.json"), JSON.stringify(ring));
  const doc = JSON.stringify({ proof: { causal_cycle_completed: true }, phi: { delta_phi: 0 } });
  for (const args of [
    ["l", "verify", "--dir", metadata],
    ["m", "check", "--pr", doc, "--sign", "--dir", metadata],
  ]) {
    const result = spawnSync(process.execPath, ["bin/mirql.mjs", ...args], { encoding: "utf8" });
    assert.equal(result.status, 3, result.stderr);
    assert.equal(JSON.parse(result.stderr).error, "KEYRING_INTEGRITY");
  }
  assert.equal(readFileSync(log, "utf8"), original);
});

test("the enrollment CLI accepts leading hyphens in base64url public keys", () => {
  for (const [index, publicKey] of ["-".padEnd(43, "A"), "--".padEnd(43, "A")].entries()) {
    const result = spawnSync(process.execPath, [
      "bin/mirql.mjs", "i", "enroll-key", "tool:hyphen" + index, publicKey,
      "--dir", metadata, "--key", trustFile(metadata, "human_owner.key.private.json"),
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readSignedKeyring(metadata)["tool:hyphen" + index].publicKey, publicKey);
  }
});

test("factory bootstrap cannot silently reseal an established keyring", () => {
  const signature = readFileSync(trustFile(metadata, "keyring.sig"), "utf8");
  assert.throws(() => generateFactoryKeypairs(metadata), /explicit human enrollment/);
  assert.equal(readFileSync(trustFile(metadata, "keyring.sig"), "utf8"), signature);
});
