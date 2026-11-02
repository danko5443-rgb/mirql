import { trustFile } from "../packages/core/trust-root.mjs";
// tests/inbox.test.mjs — Comprehensive test suite for packages/inbox (W5b hardened).
// Covers: drop-in genesis (idempotent & integrity-fail-closed), externalized
// human private key (Law 6), explicit-only human credentials (fail closed),
// keyring namespace binding (Law 3), warrant document anchoring (B7),
// ULID target confinement (B8), mirql.resume halt lifting (B5), Law 17
// integer-only formatting, read-only keyless digest, and the bounded
// proposer intake gate.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EXIT_CODES,
  canWriteEvent,
  validateDocument,
  verifyEvent,
  signEvent,
  sha256,
  jcs,
  ulid,
  hlcTick,
  generateEd25519Keypair,
} from "../packages/core/index.mjs";
import { verifyLedger } from "../packages/log/index.mjs";
import {
  runGenesis,
  sendIntent,
  renderDigest,
  formatMicroUsd,
  actOnItem,
  createProposal,
  loadKeyring,
  loadWriterKey,
  keyringEntry,
  foldState,
  generateFactoryKeypairs,
  FACTORY_WRITERS,
} from "../packages/inbox/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN_MIRQL = join(ROOT, "bin", "mirql.mjs");
const BIN_INBOX = join(ROOT, "bin", "mirql-inbox.mjs");

const CROCKFORD_ULID = /^[0-9A-HJKMNPQRSTVWXYZ]{26}$/;

function makeTmpDir() {
  return mkdtempSync(join(tmpdir(), "mirql-inbox-test-"));
}

function runBin(binPath, args, opts = {}) {
  return spawnSync(process.execPath, [binPath, ...args], {
    cwd: opts.cwd || ROOT,
    encoding: "utf8",
    timeout: 30000,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function readAllEvents(mirqlDir) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

describe("Work Package W5b: mirql-inbox test suite (hardened)", () => {
  // -----------------------------------------------------------------------
  // Genesis: layout, external human key, keyring namespace binding, idempotency
  // -----------------------------------------------------------------------
  it("genesis initializes the layout, externalizes the human key, and binds keyring namespaces", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const res = runGenesis(mirqlDir, { idempotencyKey: "test-genesis-1" });
      assert.equal(res.status, "initialized");
      assert.equal(res.seq, 1);
      assert.ok(res.hash.startsWith("sha256:"));

      // Directory layout
      assert.ok(existsSync(join(mirqlDir, "ledger", "events.jsonl")));
      assert.ok(existsSync(trustFile(mirqlDir, "keyring.json")));
      assert.ok(existsSync(join(mirqlDir, "ledger", "snapshots")));
      assert.ok(existsSync(join(mirqlDir, "cache", "state.json")));
      assert.ok(existsSync(trustFile(mirqlDir, "keys", "queue.key.json")));
      assert.ok(existsSync(trustFile(mirqlDir, "keys", "run_supervisor.key.json")));
      assert.ok(existsSync(trustFile(mirqlDir, "keys", "log.key.json")));
      assert.ok(existsSync(trustFile(mirqlDir, "keys", "inbox.key.json")));
      assert.ok(existsSync(trustFile(mirqlDir, "keys", "notary.key.json")));
      assert.ok(existsSync(trustFile(mirqlDir, "keys", "lifeguard.key.json")));
      assert.ok(existsSync(join(mirqlDir, "consensus")));
      assert.ok(existsSync(join(mirqlDir, "proposals")));
      assert.ok(existsSync(join(mirqlDir, "warrants")));

      // Law 6: the human private key NEVER lives inside .mirql/keys/
      assert.equal(existsSync(join(mirqlDir, "keys", "human.key.json")), false);
      assert.equal(existsSync(join(mirqlDir, "keys", "human_owner.key.json")), false);

      // The human private key is written outside .mirql/ with mode 0o600.
      const humanKeyPath = res.human_key_path;
      assert.ok(humanKeyPath, "genesis result must report human_key_path");
      assert.notEqual(
        resolve(humanKeyPath).startsWith(resolve(mirqlDir)), true,
        "human key must live outside .mirql/",
      );
      assert.ok(existsSync(humanKeyPath));
      const humanKeyDoc = JSON.parse(readFileSync(humanKeyPath, "utf8"));
      assert.ok(typeof humanKeyDoc.privateKey === "string" && humanKeyDoc.privateKey.length > 0);
      assert.equal(humanKeyDoc.writer?.ns, "human:owner");
      if (process.platform !== "win32") {
        assert.equal(statSync(humanKeyPath).mode & 0o777, 0o600);
      }

      // Genesis event envelope
      const events = readAllEvents(mirqlDir);
      assert.equal(events.length, 1);
      const evt = events[0];
      assert.equal(evt.seq, 1);
      assert.equal(evt.type, "mirql.genesis");
      assert.equal(evt.writer.ns, "human:owner");
      assert.equal(evt.prev_hash, "sha256:" + "0".repeat(64));
      assert.ok(CROCKFORD_ULID.test(evt.id));

      // Keyring: every entry is namespace-bound { ns, publicKey }
      const keyring = loadKeyring(mirqlDir);
      for (const [entryKey, raw] of Object.entries(keyring)) {
        const entry = keyringEntry(raw, entryKey);
        assert.ok(entry, `keyring entry ${entryKey} must be a string or {ns, publicKey}`);
        if (entryKey.includes(":") && !entryKey.startsWith("ed25519:")) {
          assert.equal(entry.ns, entryKey);
        }
        assert.match(entry.publicKey, /^[A-Za-z0-9_-]{43}$/);
      }
      assert.equal(keyring["human:owner"].ns, "human:owner");
      assert.equal(keyring[evt.writer.key_id].ns, "human:owner");
      assert.equal(keyring["tool:queue"].ns, "tool:queue");

      // Genesis signature verifies against the keyring-registered public key
      assert.equal(verifyEvent(evt, keyring[evt.writer.key_id].publicKey).ok, true);

      // Law 3: the reconciled ACL authorizes human:owner for mirql.genesis
      // (policy/writers.yaml parity, no runtime monkey-patching).
      assert.equal(canWriteEvent("human:owner", "mirql.genesis"), true);
      assert.equal(canWriteEvent("human:owner", "mirql.halt"), true);
      assert.equal(canWriteEvent("human:owner", "mirql.resume"), true);
      assert.equal(canWriteEvent("human:owner", "warrant.created"), true);
      assert.equal(canWriteEvent("human:owner", "verdict.accepted"), false);

      // Idempotency: a second genesis is a no-op, never a second event.
      const again = runGenesis(mirqlDir, { idempotencyKey: "test-genesis-1" });
      assert.equal(again.status, "already_initialized");
      assert.equal(again.seq, 1);
      assert.equal(again.hash, res.hash);
      const third = runGenesis(mirqlDir, { idempotencyKey: "different-key" });
      assert.equal(third.status, "already_initialized");
      assert.equal(readAllEvents(mirqlDir).length, 1);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("genesis fails closed (INTEGRITY_VIOLATION) on a non-empty ledger without a valid genesis", () => {
    const tmp = makeTmpDir();

    try {
      // Case 1: first event is valid JSON but not a genesis event.
      const dirA = join(tmp, "a", ".mirql");
      mkdirSync(join(dirA, "ledger"), { recursive: true });
      const foreignLedger = join(dirA, "ledger", "events.jsonl");
      const foreignLine = JSON.stringify({
        seq: 1,
        type: "job.enqueued",
        writer: "tool:queue",
        payload: { job_id: ulid() },
      });
      writeFileSync(foreignLedger, foreignLine + "\n", "utf8");

      assert.throws(
        () => runGenesis(dirA, {}),
        (err) => {
          assert.equal(err.exitCode, EXIT_CODES.INTEGRITY_VIOLATION);
          assert.equal(err.errorCode, "INTEGRITY_VIOLATION");
          return true;
        },
      );
      // The foreign ledger is neither appended to nor overwritten.
      assert.equal(readFileSync(foreignLedger, "utf8"), foreignLine + "\n");

      // Case 2: the first line is not even parsable JSON.
      const dirB = join(tmp, "b", ".mirql");
      mkdirSync(join(dirB, "ledger"), { recursive: true });
      const garbageLedger = join(dirB, "ledger", "events.jsonl");
      writeFileSync(garbageLedger, "this is not json\n", "utf8");

      assert.throws(
        () => runGenesis(dirB, {}),
        (err) => err.exitCode === EXIT_CODES.INTEGRITY_VIOLATION,
      );
      assert.equal(readFileSync(garbageLedger, "utf8"), "this is not json\n");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("genesis rebuilds a pre-existing keyring.json so planted entries cannot survive", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      mkdirSync(join(mirqlDir, "ledger"), { recursive: true });
      mkdirSync(join(mirqlDir, "keys"), { recursive: true });
      // Attacker plants a bogus keyring (and a stale human key inside .mirql/keys).
      writeFileSync(
        join(mirqlDir, "ledger", "keyring.json"),
        JSON.stringify({
          "attacker-key": "AAAA",
          "ed25519:planted": "BBBB",
          "human:owner": "CCCC",
        }) + "\n",
        "utf8",
      );
      writeFileSync(
        join(mirqlDir, "keys", "human.key.json"),
        JSON.stringify({ privateKey: "stale", publicKey: "stale", keyId: "stale" }),
        "utf8",
      );

      const res = runGenesis(mirqlDir, {});
      assert.equal(res.status, "initialized");

      const keyring = loadKeyring(mirqlDir);
      assert.equal("attacker-key" in keyring, false);
      assert.equal("ed25519:planted" in keyring, false);
      assert.notEqual(keyring["human:owner"], "CCCC");
      assert.equal(keyring["human:owner"].ns, "human:owner");
      assert.match(keyring["human:owner"].publicKey, /^[A-Za-z0-9_-]{43}$/);
      // The stale in-.mirql human key is purged (Law 6).
      assert.equal(existsSync(join(mirqlDir, "keys", "human.key.json")), false);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // send: warrant anchoring + explicit credentials
  // -----------------------------------------------------------------------
  it("send mints a schema-valid warrant anchored in the human.intent event (B7)", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const gen = runGenesis(mirqlDir);
      const humanKeyPath = gen.human_key_path;

      const sendRes = sendIntent(
        mirqlDir,
        {
          kind: "bug",
          title: "Fix off-by-one in sequence counter",
          summary: "Ensure seq starts strictly at 1",
          scope: ["packages/core/**", "packages/inbox/**"],
          red_check: "node scripts/run-tests.mjs",
          budget_micro_usd: 1200000,
        },
        { key: humanKeyPath },
      );

      assert.equal(sendRes.status, "sent");
      assert.equal(sendRes.seq, 2);
      assert.ok(sendRes.warrant_id);
      assert.ok(sendRes.intent_id.startsWith("intent_"));

      // Warrant document on disk is schema-valid
      const warrantPath = join(mirqlDir, "warrants", `${sendRes.warrant_id}.json`);
      assert.ok(existsSync(warrantPath));
      const warrant = JSON.parse(readFileSync(warrantPath, "utf8"));
      const val = validateDocument("warrant", warrant);
      assert.equal(val.valid, true, `Warrant invalid: ${val.errors.join("; ")}`);
      assert.equal(warrant.created_by, "human:owner");
      assert.equal(warrant.budget_micro_usd, 1200000);
      assert.equal(warrant.class, "surgical");

      // B7: the event payload anchors the warrant document
      const expectedHash = sha256(jcs(warrant));
      assert.equal(sendRes.warrant_hash, expectedHash);
      assert.equal(sendRes.event.payload.warrant_hash, expectedHash);
      assert.equal(sendRes.event.payload.semantic_fingerprint, warrant.semantic_fingerprint);

      // Event verifies against the keyring-registered human:owner public key
      const events = readAllEvents(mirqlDir);
      assert.equal(events.length, 2);
      const evt2 = events[1];
      assert.equal(evt2.type, "human.intent");
      assert.equal(evt2.writer.ns, "human:owner");
      assert.equal(evt2.payload.warrant_id, sendRes.warrant_id);
      const keyring = loadKeyring(mirqlDir);
      assert.equal(verifyEvent(evt2, keyring[evt2.writer.key_id].publicKey).ok, true);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("send fails closed without explicit human credentials (Law 6)", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);
      const intent = {
        title: "Must not be accepted without a signature",
        summary: "Silence is never consent",
      };

      // Programmatic: no key anywhere -> credentials_required, POLICY_DENIAL.
      assert.throws(
        () => sendIntent(mirqlDir, intent, {}),
        (err) => {
          assert.equal(err.errorCode, "credentials_required");
          assert.equal(err.exitCode, EXIT_CODES.POLICY_DENIAL);
          assert.ok(err.hint.includes("--key"));
          return true;
        },
      );
      // Fail closed left no trace: no warrant document, ledger still 1 line.
      const warrantsDir = join(mirqlDir, "warrants");
      const warrantFiles = existsSync(warrantsDir)
        ? readdirSync(warrantsDir).filter((f) => f.endsWith(".json"))
        : [];
      assert.equal(warrantFiles.length, 0);
      assert.equal(readAllEvents(mirqlDir).length, 1);

      // CLI: exit 4 with { error: "credentials_required", hint } on stderr.
      const res = runBin(BIN_INBOX, [
        "send", "--dir", mirqlDir, "--title", "CLI no-key attempt",
      ]);
      assert.equal(res.status, EXIT_CODES.POLICY_DENIAL);
      const errDoc = JSON.parse(res.stderr);
      assert.equal(errDoc.error, "credentials_required");
      assert.ok(typeof errDoc.hint === "string" && errDoc.hint.length > 0);
      assert.equal(readAllEvents(mirqlDir).length, 1);

      // A key file planted INSIDE .mirql must never be usable as a credential.
      mkdirSync(join(mirqlDir, "keys"), { recursive: true });
      const planted = join(mirqlDir, "keys", "human.key.json");
      writeFileSync(planted, JSON.stringify(generateEd25519Keypair()), "utf8");
      assert.throws(
        () => sendIntent(mirqlDir, intent, { key: planted }),
        (err) => {
          assert.equal(err.errorCode, "credentials_location_forbidden");
          assert.equal(err.exitCode, EXIT_CODES.POLICY_DENIAL);
          return true;
        },
      );
      assert.equal(readAllEvents(mirqlDir).length, 1);

      // MIRQL_HUMAN_KEY pointing inside .mirql is likewise forbidden.
      const envRes = runBin(BIN_INBOX, [
        "send", "--dir", mirqlDir, "--title", "Env no-key attempt",
      ], { env: { MIRQL_HUMAN_KEY: planted } });
      assert.equal(envRes.status, EXIT_CODES.POLICY_DENIAL);
      assert.equal(JSON.parse(envRes.stderr).error, "credentials_location_forbidden");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // act: explicit credentials, non-human key rejection, target confinement
  // -----------------------------------------------------------------------
  it("act fails closed without credentials or with a non-human key (Law 6 / Law 3)", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const gen = runGenesis(mirqlDir);
      const humanKeyPath = gen.human_key_path;
      const proposal = createProposal(mirqlDir, {
        roadmap_ref: "M1",
        title: "Deterministic wake trigger harness",
        description: "Zero unprompted polling with pure reactive supervisor wake",
      });
      const targetId = proposal.proposal_id;

      // 1. No credentials at all -> credentials_required (POLICY_DENIAL).
      assert.throws(
        () => actOnItem(mirqlDir, { decision: "approve", target_id: targetId }, {}),
        (err) => {
          assert.equal(err.errorCode, "credentials_required");
          assert.equal(err.exitCode, EXIT_CODES.POLICY_DENIAL);
          return true;
        },
      );

      // CLI variant: exit 4, structured JSON error on stderr.
      const res = runBin(BIN_INBOX, [
        "act", "--dir", mirqlDir, "--decision", "approve", "--target-id", targetId,
      ]);
      assert.equal(res.status, EXIT_CODES.POLICY_DENIAL);
      const errDoc = JSON.parse(res.stderr);
      assert.equal(errDoc.error, "credentials_required");
      assert.ok(errDoc.hint.includes("MIRQL_HUMAN_KEY"));

      // 2. The factory (queue) key is NOT a human key: fail closed.
      const queueKp = loadWriterKey(mirqlDir, "tool:queue");
      assert.ok(queueKp);
      assert.throws(
        () =>
          actOnItem(
            mirqlDir,
            { decision: "approve", target_id: targetId },
            { signingKey: queueKp.privateKey },
          ),
        (err) => {
          assert.equal(err.exitCode, EXIT_CODES.POLICY_DENIAL);
          assert.ok(
            err.errorCode === "namespace_binding_violation" || err.errorCode === "key_mismatch",
            `unexpected errorCode ${err.errorCode}`,
          );
          return true;
        },
      );

      // Removing the human entry without its signature invalidates the keyring.
      const keyring = loadKeyring(mirqlDir);
      const stripped = {};
      for (const [k, v] of Object.entries(keyring)) {
        const entry = keyringEntry(v, k);
        if (entry?.ns === "human:owner") continue;
        stripped[k] = v;
      }
      writeFileSync(
        trustFile(mirqlDir, "keyring.json"),
        JSON.stringify(stripped, null, 2) + "\n",
        "utf8",
      );
      assert.throws(
        () =>
          actOnItem(
            mirqlDir,
            { decision: "approve", target_id: targetId },
            { signingKey: queueKp.privateKey },
          ),
        (err) => {
          assert.equal(err.errorCode, "KEYRING_INTEGRITY");
          assert.equal(err.exitCode, EXIT_CODES.INTEGRITY_VIOLATION);
          return true;
        },
      );

      // Restore the full keyring for subsequent checks.
      writeFileSync(
        trustFile(mirqlDir, "keyring.json"),
        JSON.stringify(keyring, null, 2) + "\n",
        "utf8",
      );

      // 3. A forged foreign key is rejected too.
      const forgedKp = generateEd25519Keypair();
      assert.throws(
        () =>
          actOnItem(
            mirqlDir,
            { decision: "approve", target_id: targetId },
            { signingKey: forgedKp.privateKey },
          ),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL,
      );

      // 4. Explicitly claiming a non-human writer is denied outright.
      assert.throws(
        () =>
          actOnItem(
            mirqlDir,
            { decision: "approve", target_id: targetId },
            { key: humanKeyPath, writer: "tool:queue" },
          ),
        (err) => err.errorCode === "writer_forbidden",
      );

      // 5. The legitimate human key succeeds and updates the proposal.
      const actRes = actOnItem(
        mirqlDir,
        { decision: "approve", target_id: targetId, reason: "Affirmative human approval verified" },
        { key: humanKeyPath },
      );
      assert.equal(actRes.status, "acted");
      assert.equal(actRes.decision, "approve");
      assert.equal(actRes.event.type, "human.approval");
      assert.equal(actRes.event.writer.ns, "human:owner");
      const proposalDoc = JSON.parse(
        readFileSync(join(mirqlDir, "proposals", `${targetId}.json`), "utf8"),
      );
      assert.equal(proposalDoc.status, "approved");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("act validates and confines --target-id (B8: ULID-only, no traversal, existing proposal)", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const gen = runGenesis(mirqlDir);
      const humanKeyPath = gen.human_key_path;
      const proposal = createProposal(mirqlDir, {
        roadmap_ref: "M2",
        title: "Potential Phi collection ratchet",
        description: "Enforce monotone potential non-increasing invariant",
      });
      assert.match(proposal.proposal_id, CROCKFORD_ULID);

      // Traversal and malformed ids are rejected before anything is read.
      const badIds = [
        "..",
        "../outside",
        "..\\outside",
        "a/b",
        `..\\${proposal.proposal_id}`,
        `${proposal.proposal_id}/../${proposal.proposal_id}`,
        "not_a_ulid",
        "01ARZ3N5K6TS6P8Z3R2K8EXFX",       // 25 chars (too short)
        "01ARZ3N5K6TS6P8Z3R2K8EXFXF1",      // 27 chars (too long)
        "01arz3n5k6ts6p8z3r2k8exfx0",       // lowercase
        "01ARI3N5K6TS6P8Z3R2K8EXFXF",       // contains non-Crockford 'I'
      ];
      for (const bad of badIds) {
        assert.throws(
          () =>
            actOnItem(
              mirqlDir,
              { decision: "approve", target_id: bad },
              { key: humanKeyPath },
            ),
          (err) => {
            assert.equal(err.errorCode, "invalid_target_id");
            assert.equal(err.exitCode, EXIT_CODES.USAGE_ERROR);
            return true;
          },
          `expected invalid_target_id for ${JSON.stringify(bad)}`,
        );
      }
      // CLI traversal exits 2 with structured JSON on stderr.
      const res = runBin(BIN_INBOX, [
        "act", "--dir", mirqlDir, "--decision", "approve",
        "--target-id", "../" + proposal.proposal_id, "--key", humanKeyPath,
      ]);
      assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
      assert.equal(JSON.parse(res.stderr).error, "invalid_target_id");

      // A well-formed ULID with no matching proposal document fails closed.
      const ghost = ulid();
      assert.throws(
        () => actOnItem(mirqlDir, { decision: "approve", target_id: ghost }, { key: humanKeyPath }),
        (err) => {
          assert.equal(err.errorCode, "target_not_found");
          assert.equal(err.exitCode, EXIT_CODES.USAGE_ERROR);
          return true;
        },
      );

      // Nothing has been appended by any rejected attempt.
      assert.equal(readAllEvents(mirqlDir).length, 1);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("act --decision resume emits mirql.resume (B5) authorized for human:owner", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const gen = runGenesis(mirqlDir);
      const humanKeyPath = gen.human_key_path;
      const proposal = createProposal(mirqlDir, {
        roadmap_ref: "M3",
        title: "Claim-check drift detection harness",
        description: "Verify public surface claims mechanically",
      });

      const res = actOnItem(
        mirqlDir,
        { decision: "resume", target_id: proposal.proposal_id, reason: "Factory resumed by owner" },
        { key: humanKeyPath },
      );
      assert.equal(res.status, "acted");
      assert.equal(res.event.type, "mirql.resume");
      assert.equal(res.event.writer.ns, "human:owner");
      assert.equal(res.event.payload.decision, "resume");
      assert.equal(res.event.payload.target_id, proposal.proposal_id);

      // Law 3: the reconciled ACL grants this (writer, type) pair.
      assert.equal(canWriteEvent("human:owner", "mirql.resume"), true);

      // The inbox fold lifts a halt on mirql.resume.
      const state = foldState([
        { seq: 1, type: "mirql.genesis", hash: "sha256:a", payload: {} },
        { seq: 2, type: "factory.halted", hash: "sha256:b", payload: {} },
        { seq: 3, type: "mirql.resume", hash: "sha256:c", payload: {} },
      ]);
      assert.equal(state.halted, false);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // B3/T3: keyring namespace binding through mirql-log verification
  // -----------------------------------------------------------------------
  it("keyring namespace binding: a tool:queue key signing as human:owner fails log verify", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);
      const queueKp = loadWriterKey(mirqlDir, "tool:queue");
      const events = readAllEvents(mirqlDir);

      // Chain-correct, correctly-hashed, validly-signed event — but signed by
      // the tool:queue key while claiming writer ns human:owner.
      const forged = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "test"),
          ts: new Date().toISOString(),
          type: "human.approval",
          writer: { ns: "human:owner", key_id: queueKp.keyId },
          idempotency_key: "forged-ns-binding",
          prev_hash: events.at(-1).hash,
          payload: { decision: "approve", target_id: ulid() },
        },
        queueKp.privateKey,
        queueKp.keyId,
      );
      const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
      writeFileSync(eventsFile, readFileSync(eventsFile, "utf8") + jcs(forged) + "\n", "utf8");

      const verdict = verifyLedger(mirqlDir);
      assert.equal(verdict.valid, false, "namespace binding violation must fail verify");
      assert.equal(verdict.seq, 2);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("a legitimate human:owner event chain still verifies via mirql-log", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const gen = runGenesis(mirqlDir);
      sendIntent(
        mirqlDir,
        { title: "Verified intent", summary: "Positive binding control" },
        { key: gen.human_key_path },
      );
      const verdict = verifyLedger(mirqlDir);
      assert.equal(verdict.valid, true);
      assert.equal(verdict.event_count, 2);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // Law 17: integer-only micro-USD formatting
  // -----------------------------------------------------------------------
  it("formatMicroUsd uses pure integer math with no floats (Law 17)", () => {
    assert.equal(formatMicroUsd(0), "$0.00");
    assert.equal(formatMicroUsd(1), "$0.00");
    assert.equal(formatMicroUsd(999999), "$0.99");
    assert.equal(formatMicroUsd(1000000), "$1.00");
    assert.equal(formatMicroUsd(1500000), "$1.50");
    assert.equal(formatMicroUsd(1200000), "$1.20");
    assert.equal(formatMicroUsd(450000), "$0.45");
    assert.equal(formatMicroUsd(123456789), "$123.45");
    assert.equal(formatMicroUsd(9007199254740991), "$9007199254.74");
    assert.throws(() => formatMicroUsd(1.5), TypeError);
    assert.throws(() => formatMicroUsd("100"), TypeError);
  });

  // -----------------------------------------------------------------------
  // Digest: keyless, read-only
  // -----------------------------------------------------------------------
  it("digest is strictly keyless and does not mutate events.jsonl", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const gen = runGenesis(mirqlDir);
      sendIntent(
        mirqlDir,
        { title: "Test intent for digest", summary: "Inspect digest stability" },
        { key: gen.human_key_path },
      );

      const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
      const hashBefore = sha256(readFileSync(eventsFile, "utf8"));

      const digest = renderDigest(mirqlDir);
      assert.equal(digest.tool, "inbox");
      assert.equal(digest.mode, "BUILD");
      assert.equal(digest.seq, 2);
      assert.equal(digest.mutates_ledger, false);
      assert.ok(Array.isArray(digest.pending_approvals));
      assert.ok(Array.isArray(digest.pending_proposals));
      assert.ok(Array.isArray(digest.recent_outcomes));

      const md = renderDigest(mirqlDir, { format: "markdown" });
      assert.match(md, /# mirql Factory Digest/);
      assert.match(md, /Macro Mode/);
      assert.match(md, /\$0\.00/);

      assert.equal(sha256(readFileSync(eventsFile, "utf8")), hashBefore);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // Proposer intake gate (unchanged behavior)
  // -----------------------------------------------------------------------
  it("propose enforces ROADMAP.md citation, NOT-ROADMAP filter, and max 3 quota", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);

      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M99",
            title: "Invalid milestone ref",
            description: "Should fail roadmap citation gate",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL,
      );

      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M1",
            title: "Add auto-approve timeout to inbox",
            description: "Configure auto_approve_timeout_s when human is offline",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL,
      );

      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M1",
            title: "Allow builder direct agent git push",
            description: "Execute git_push to origin without notary proof",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL,
      );

      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M2",
            title: "Support floating-point budgets",
            description: "Allow float_numbers and fractional_cents in ledger math",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL,
      );

      const p1 = createProposal(mirqlDir, {
        roadmap_ref: "M1",
        title: "Deterministic wake trigger harness",
        description: "Zero unprompted polling with pure reactive supervisor wake",
      });
      assert.equal(p1.status, "proposed");
      assert.ok(existsSync(join(mirqlDir, "proposals", `${p1.proposal_id}.json`)));

      const p2 = createProposal(mirqlDir, {
        roadmap_ref: "M2",
        title: "Potential Phi collection ratchet",
        description: "Enforce monotone potential non-increasing invariant",
      });
      assert.equal(p2.status, "proposed");

      const p3 = createProposal(mirqlDir, {
        roadmap_ref: "M3",
        title: "Claim-check drift detection harness",
        description: "Verify public surface claims mechanically",
      });
      assert.equal(p3.status, "proposed");

      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M4",
            title: "Incremental mutation tester",
            description: "Generate AST mutants on changed lines",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL,
      );

      const digest = renderDigest(mirqlDir);
      assert.equal(digest.pending_proposals.length, 3);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // CLI end-to-end (kebab & camel flags, stub contract)
  // -----------------------------------------------------------------------
  it("CLI subcommands work through bin/mirql.mjs and bin/mirql-inbox.mjs with explicit keys", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");
    const humanKeyPath = join(tmp, "operator", "human.key.private.json");

    try {
      // 1. Genesis with an explicit external human key path.
      const resGen = runBin(BIN_MIRQL, [
        "i", "genesis", "--dir", mirqlDir, "--human-key-out", humanKeyPath,
      ]);
      assert.equal(resGen.status, 0, `Genesis failed: ${resGen.stderr}`);
      const genDoc = JSON.parse(resGen.stdout);
      assert.equal(genDoc.status, "initialized");
      assert.equal(genDoc.seq, 1);
      assert.equal(resolve(genDoc.human_key_path), resolve(humanKeyPath));
      assert.ok(existsSync(humanKeyPath));
      assert.equal(existsSync(join(mirqlDir, "keys", "human.key.json")), false);

      // 2. Send via mirql-inbox with --key (kebab flag).
      const resSend = runBin(BIN_INBOX, [
        "send",
        "--dir", mirqlDir,
        "--key", humanKeyPath,
        "--title", "CLI submission test",
        "--summary", "Testing CLI flags",
        "--kind", "feature",
        "--budget", "2000000",
      ]);
      assert.equal(resSend.status, 0, `Send failed: ${resSend.stderr}`);
      const sendDoc = JSON.parse(resSend.stdout);
      assert.equal(sendDoc.status, "sent");
      assert.equal(sendDoc.seq, 2);
      assert.ok(sendDoc.warrant_hash.startsWith("sha256:"));

      // 3. Propose via mirql i propose.
      const resProp = runBin(BIN_MIRQL, [
        "i", "propose",
        "--dir", mirqlDir,
        "--roadmap-ref", "M1",
        "--title", "Proposer CLI test",
        "--description", "Testing proposal submission via CLI router",
      ]);
      assert.equal(resProp.status, 0, `Propose failed: ${resProp.stderr}`);
      const propDoc = JSON.parse(resProp.stdout);
      assert.equal(propDoc.status, "proposed");

      // 4. Digest via mirql i digest.
      const resDigest = runBin(BIN_MIRQL, ["i", "digest", "--dir", mirqlDir]);
      assert.equal(resDigest.status, 0, `Digest failed: ${resDigest.stderr}`);
      const digDoc = JSON.parse(resDigest.stdout);
      assert.equal(digDoc.seq, 2);
      assert.equal(digDoc.pending_proposals.length, 1);

      // 5. Act via mirql-inbox act with --key and --target-id (kebab flags).
      const resAct = runBin(BIN_INBOX, [
        "act",
        "--dir", mirqlDir,
        "--decision", "approve",
        "--target-id", propDoc.proposal_id,
        "--key", humanKeyPath,
        "--reason", "CLI human approval test",
      ]);
      assert.equal(resAct.status, 0, `Act failed: ${resAct.stderr}`);
      const actDoc = JSON.parse(resAct.stdout);
      assert.equal(actDoc.status, "acted");
      assert.equal(actDoc.seq, 3);

      // 6. Without the key the same act fails closed with exit 4.
      const resNoKey = runBin(BIN_INBOX, [
        "act", "--dir", mirqlDir, "--decision", "approve", "--target-id", propDoc.proposal_id,
      ]);
      assert.equal(resNoKey.status, EXIT_CODES.POLICY_DENIAL);
      assert.equal(JSON.parse(resNoKey.stderr).error, "credentials_required");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("keeps the W1 stub contract and exposes usage for help", () => {
    for (const args of [[], ["--help"], ["-h"], ["status"]]) {
      const res = runBin(BIN_INBOX, args);
      assert.equal(res.status, 0);
      assert.equal(JSON.parse(res.stdout).tool, "inbox");
    }
    const help = runBin(BIN_INBOX, ["help"]);
    assert.equal(help.status, 0);
    assert.equal(JSON.parse(help.stdout).tool, "inbox");
    assert.ok(JSON.parse(help.stdout).subcommands);

    const routerStatus = runBin(BIN_MIRQL, ["i", "status"]);
    assert.equal(routerStatus.status, 0);
    assert.equal(JSON.parse(routerStatus.stdout).status, "stub");

    const unknown = runBin(BIN_INBOX, ["frobnicate"]);
    assert.equal(unknown.status, EXIT_CODES.USAGE_ERROR);
    assert.equal(JSON.parse(unknown.stderr).error, "unknown_subcommand");
  });

  // -----------------------------------------------------------------------
  // P0 Remediation H4: unified private key permissions (0o600 / 0o700)
  // -----------------------------------------------------------------------
  it("H4: factory writer private keys are written 0o600 inside a 0o700 keys directory", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      generateFactoryKeypairs(mirqlDir);

      for (const w of FACTORY_WRITERS) {
        const keyPath = trustFile(mirqlDir, "keys", w.file);
        assert.ok(existsSync(keyPath), `${w.file} must exist`);
        const doc = JSON.parse(readFileSync(keyPath, "utf8"));
        assert.ok(typeof doc.privateKey === "string" && doc.privateKey.length > 0);
        if (process.platform !== "win32") {
          assert.equal(
            statSync(keyPath).mode & 0o777,
            0o600,
            `${w.file} must be mode 0o600`,
          );
        }
      }

      // The notary alias file carries the same private key and permissions.
      const aliasPath = trustFile(mirqlDir, "keys", "mergeproof.key.json");
      assert.ok(existsSync(aliasPath), "notary alias key must exist");
      if (process.platform !== "win32") {
        assert.equal(statSync(aliasPath).mode & 0o777, 0o600);
        assert.equal(statSync(trustFile(mirqlDir, "keys")).mode & 0o777, 0o700);
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
