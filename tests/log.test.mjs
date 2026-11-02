import { saveTestKeyring } from "./helpers/keyring.mjs";
import { trustFile, resolveTrustRoot } from "../packages/core/trust-root.mjs";
// W3 tests: packages/log — the cryptographic append-only ledger and its
// deterministic projections. Covers signed appends and hash chaining,
// idempotency dedup, the Law 3 single-writer ACL, Law 4 tamper detection and
// the rebuildable cache, all five projections, snapshots, conformance
// fixture ledgers, and the CLI surface through bin/mirql.mjs + bin/mirql-log.mjs.
import { describe, test } from "node:test";
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
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  computeEventHash,
  generateEd25519Keypair,
  jcs,
  jcsHash,
  sha256,
  signEvent,
  ulid,
  verifyEvent,
} from "../packages/core/index.mjs";
import {
  GENESIS_PREV_HASH,
  LedgerError,
  ORCHESTRATOR_DIGEST_MAX_BYTES,
  PROJECTIONS,
  TOOL,
  appendEvent,
  createSnapshot,
  foldEvents,
  getView,
  replayCache,
  runCli,
  verifyLedger,
} from "../packages/log/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN_MIRQL = join(ROOT, "bin", "mirql.mjs");
const BIN_LOG = join(ROOT, "bin", "mirql-log.mjs");
const GOLDEN_LEDGER = join(ROOT, "conformance", "golden_ledger", "events.jsonl");

const BASE_MS = 1_700_000_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fresh isolated `.mirql` root. */
function makeTmp() {
  return mkdtempSync(join(tmpdir(), "mirql-log-test-"));
}

/** Create an object with null prototype to match fold state (Fix B5). */
function nullObject(entries = {}) {
  return Object.assign(Object.create(null), entries);
}

/**
 * Spawn `node <bin> <args...>`. `opts.env` is merged over process.env,
 * `opts.input` is piped to stdin, `opts.cwd` defaults to ROOT.
 */
function runBin(bin, args, opts = {}) {
  return spawnSync(process.execPath, [bin, ...args], {
    encoding: "utf8",
    timeout: 30_000,
    cwd: opts.cwd ?? ROOT,
    env: { ...process.env, ...(opts.env ?? {}) },
    input: opts.input,
  });
}

/** Parse the ledger into { lines, events }. */
function readLedgerFile(mirqlDir) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  const lines = readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0);
  return { lines, events: lines.map((l) => JSON.parse(l)) };
}

/** Overwrite one ledger line (0-based) with a mutated version of itself. */
function mutateLine(mirqlDir, index, mutate) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  const lines = readFileSync(file, "utf8").split("\n");
  const event = JSON.parse(lines[index]);
  mutate(event);
  lines[index] = jcs(event);
  writeFileSync(file, lines.join("\n"), "utf8");
}

// One keypair per writer namespace (key ids embed the public key).
const QUEUE_KP = generateEd25519Keypair(); // tool:queue
const RUN_KP = generateEd25519Keypair(); // tool:run_supervisor
const NOTARY_KP = generateEd25519Keypair(); // notary:mergeproof
const INBOX_KP = generateEd25519Keypair(); // tool:inbox
const LIFEGUARD_KP = generateEd25519Keypair(); // daemon:lifeguard
const LOG_KP = generateEd25519Keypair(); // tool:log

/** Keypair owning each event type used by the fixtures below. */
const KP_BY_TYPE = {
  "mirql.genesis": QUEUE_KP,
  "warrant.created": RUN_KP,
  "job.leased": QUEUE_KP,
  "attempt.outcome": RUN_KP,
  "verdict.accepted": NOTARY_KP,
  "verdict.needs_human": NOTARY_KP,
  "promotion.completed": NOTARY_KP,
  "promotion.rollback": LIFEGUARD_KP,
  "factory.halted": QUEUE_KP,
  "factory.resumed": QUEUE_KP,
  "human.approval_requested": INBOX_KP,
};

/**
 * Phase 0.4: without a keyring nothing verifies, so ledgers that tests expect
 * to verify register every test key (legacy plain entries, so the ACL gate —
 * not the keyring's namespace binding — still judges forged namespaces).
 */
function trustTestKeys(mirqlDir) {
  mkdirSync(join(mirqlDir, "ledger"), { recursive: true });
  const keyring = {};
  for (const kp of [QUEUE_KP, RUN_KP, NOTARY_KP, INBOX_KP, LIFEGUARD_KP, LOG_KP]) {
    keyring[kp.keyId] = kp.publicKey;
  }
  mkdirSync(resolveTrustRoot(mirqlDir), { recursive: true });
  saveTestKeyring(mirqlDir, keyring);
}

/**
 * The five-event spec sequence: genesis -> warrant -> lease -> outcome ->
 * verdict. Each entry carries the writer namespace its ACL row grants.
 */
function specFiveInputs() {
  return [
    {
      type: "mirql.genesis",
      writer: { ns: "tool:queue" },
      idempotency_key: "genesis-1",
      payload: { macro_state: "BUILD", version: 1, tenant_id: "mirql-core" },
    },
    {
      type: "warrant.created",
      writer: { ns: "tool:run_supervisor" },
      idempotency_key: "warrant-1",
      payload: {
        warrant_id: "warrant_001",
        intent_id: "intent_001",
        role: "builder",
        tier: "mid",
        budget_micro_usd: 1_500_000,
        status: "active",
      },
    },
    {
      type: "job.leased",
      writer: { ns: "tool:queue" },
      idempotency_key: "job-1",
      payload: {
        job_id: "job_001",
        warrant_id: "warrant_001",
        worker_id: "worker_1",
        status: "leased",
      },
    },
    {
      type: "attempt.outcome",
      writer: { ns: "tool:run_supervisor" },
      idempotency_key: "outcome-1",
      payload: {
        job_id: "job_001",
        warrant_id: "warrant_001",
        status: "completed",
        verdict: "auto_merge",
        cost_micro_usd: 450_000,
        tokens_consumed: 1_420,
        phi_before: 100,
        phi_after: 95,
      },
    },
    {
      type: "verdict.accepted",
      writer: { ns: "notary:mergeproof" },
      idempotency_key: "verdict-1",
      payload: { job_id: "job_001", verdict: "accepted" },
    },
  ];
}

/**
 * Append `inputs` programmatically with signing options (each event signed
 * by its owning namespace's key), with deterministic wall-clock input.
 * @returns {Array<object>} appendEvent results
 */
function appendSigned(mirqlDir, inputs, startMs = BASE_MS) {
  return inputs.map((input, i) =>
    appendEvent(mirqlDir, input, {
      signingKey: KP_BY_TYPE[input.type].privateKey,
      keyId: KP_BY_TYPE[input.type].keyId,
      nowMs: startMs + i * 1_000,
    }),
  );
}

/** Seed a ledger with the five spec events; returns the mirqlDir. */
function seedSpecFive() {
  const dir = makeTmp();
  trustTestKeys(dir);
  appendSigned(dir, specFiveInputs());
  return dir;
}

/** The 15-event extended sequence exercising every fold rule. */
function extendedInputs() {
  return [
    ...specFiveInputs(),
    {
      type: "job.leased",
      writer: { ns: "tool:queue" },
      idempotency_key: "job-2",
      payload: { job_id: "job_002", warrant_id: "warrant_001", worker_id: "worker_2" },
    },
    {
      type: "attempt.outcome",
      writer: { ns: "tool:run_supervisor" },
      idempotency_key: "outcome-2",
      payload: {
        job_id: "job_002",
        warrant_id: "warrant_001",
        status: "failed",
        verdict: "needs_human",
        cost_micro_usd: 100_000,
        tokens_consumed: 900,
        phi_before: 95,
        phi_after: 93,
      },
    },
    {
      type: "verdict.needs_human",
      writer: { ns: "notary:mergeproof" },
      idempotency_key: "verdict-2",
      payload: { job_id: "job_002" },
    },
    {
      type: "verdict.accepted",
      writer: { ns: "notary:mergeproof" },
      idempotency_key: "verdict-3",
      payload: { job_id: "job_002", verdict: "accepted" },
    },
    {
      type: "job.leased",
      writer: { ns: "tool:queue" },
      idempotency_key: "job-3",
      payload: { job_id: "job_003", warrant_id: "warrant_001", worker_id: "worker_3" },
    },
    {
      type: "human.approval_requested",
      writer: { ns: "tool:inbox" },
      idempotency_key: "approval-1",
      payload: { request_id: "req_001" },
    },
    {
      type: "promotion.completed",
      writer: { ns: "notary:mergeproof" },
      idempotency_key: "promo-1",
      payload: { promotion_id: "promo_001", job_id: "job_002" },
    },
    {
      type: "promotion.rollback",
      writer: { ns: "daemon:lifeguard" },
      idempotency_key: "rollback-1",
      payload: { promotion_id: "promo_001" },
    },
    {
      type: "factory.halted",
      writer: { ns: "tool:queue" },
      idempotency_key: "halt-1",
      payload: { reason: "lifeguard drill" },
    },
    {
      type: "factory.resumed",
      writer: { ns: "tool:queue" },
      idempotency_key: "resume-1",
      payload: {},
    },
  ];
}

/** Seed a ledger with the full 14-event extended sequence. */
function seedExtended() {
  const dir = makeTmp();
  appendSigned(dir, extendedInputs());
  return dir;
}

/** Copy the raw conformance fixture ledger into a fresh mirql dir. */
function seedGoldenFixture() {
  const dir = makeTmp();
  mkdirSync(join(dir, "ledger"), { recursive: true });
  copyFileSync(GOLDEN_LEDGER, join(dir, "ledger", "events.jsonl"));
  return dir;
}

// ---------------------------------------------------------------------------
// 1. Signed appends & the hash chain (Law 4)
// ---------------------------------------------------------------------------

describe("appendEvent — signed appends and hash chaining", () => {
  test("appends the five spec events with seq 1..5 and a linked prev_hash chain", () => {
    const dir = makeTmp();
    trustTestKeys(dir);
    const inputs = specFiveInputs();
    const results = appendSigned(dir, inputs);

    assert.equal(results.length, 5);
    results.forEach((res, i) => {
      assert.deepEqual(
        { status: res.status, seq: res.seq },
        { status: "appended", seq: i + 1 },
      );
      assert.match(res.hash, /^sha256:[0-9a-f]{64}$/);
    });

    const { lines, events } = readLedgerFile(dir);
    assert.equal(lines.length, 5);

    // Lines are canonical JSON: raw bytes == jcs of the parsed event.
    lines.forEach((line, i) => assert.equal(line, jcs(events[i]), `line ${i + 1}`));

    // seq runs 1..5; hash chain anchors at 64 zeros then links hash-to-hash.
    const ZERO = `sha256:${"0".repeat(64)}`;
    assert.equal(ZERO, GENESIS_PREV_HASH);
    events.forEach((event, i) => {
      assert.equal(event.seq, i + 1, `seq ${i + 1}`);
      assert.equal(event.type, inputs[i].type);
      if (i === 0) {
        assert.equal(event.prev_hash, GENESIS_PREV_HASH);
      } else {
        assert.equal(event.prev_hash, events[i - 1].hash);
      }
      assert.equal(event.hash, computeEventHash(event));
    });

    // Each envelope carries its writer's embedded key id and a valid sig.
    events.forEach((event) => {
      const embedded = event.writer.key_id.slice("ed25519:".length);
      assert.equal(verifyEvent(event, embedded).ok, true, event.type);
      assert.equal(results[event.seq - 1].hash, event.hash);
    });

    const verdict = verifyLedger(dir);
    assert.deepEqual(verdict, {
      valid: true,
      event_count: 5,
      head_hash: events[4].hash,
    });
  });

  test("auto-fills id, ts, hlc, tenant and envelope defaults when signing", () => {
    const dir = makeTmp();
    appendEvent(
      dir,
      { type: "mirql.genesis", writer: { ns: "tool:queue" }, payload: {} },
      { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS },
    );
    const { events } = readLedgerFile(dir);
    const [event] = events;
    assert.equal(event.v, 1);
    assert.equal(event.tenant_id, "mirql-core");
    assert.equal(event.epoch, 1);
    assert.match(event.id, /^[0-9A-HJKMNPQRSTVWXYZ]{26}$/);
    assert.equal(event.ts, new Date(BASE_MS).toISOString());
    assert.deepEqual(event.hlc, { wall_ms: BASE_MS, logical: 0, node: "local" });
    assert.deepEqual(event.payload, {});
    assert.match(event.idempotency_key, /^auto:1$/);
    assert.equal(event.writer.key_id, QUEUE_KP.keyId);

    // Determinism (Law 4): two identical signed appends to separate ledgers
    // produce byte-identical envelopes (Ed25519 is deterministic; a pinned
    // input id bypasses the process-global monotonic ULID counter).
    const fixedId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const dirA = makeTmp();
    const dirB = makeTmp();
    const opts = { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS };
    const input = {
      id: fixedId,
      idempotency_key: "det-1",
      type: "mirql.genesis",
      writer: { ns: "tool:queue" },
      payload: {},
    };
    appendEvent(dirA, input, opts);
    appendEvent(dirB, input, opts);
    const lineA = readFileSync(join(dirA, "ledger", "events.jsonl"), "utf8");
    const lineB = readFileSync(join(dirB, "ledger", "events.jsonl"), "utf8");
    assert.equal(lineA, lineB);
    assert.match(JSON.parse(lineA).id, /^[0-9A-HJKMNPQRSTVWXYZ]{26}$/);
  });

  test("HLC ticks forward and prev_hash follows the last event across appends", () => {
    const dir = makeTmp();
    const opts = { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS };
    appendEvent(dir, { type: "mirql.genesis", writer: { ns: "tool:queue" }, payload: {} }, opts);
    appendEvent(dir, { type: "factory.resumed", writer: { ns: "tool:queue" }, payload: {} }, opts);
    appendEvent(dir, { type: "factory.resumed", writer: { ns: "tool:queue" }, payload: {} }, opts);

    const { events } = readLedgerFile(dir);
    assert.equal(events.length, 3);
    assert.deepEqual(events[1].hlc, { wall_ms: BASE_MS, logical: 1, node: "local" });
    assert.deepEqual(events[2].hlc, { wall_ms: BASE_MS, logical: 2, node: "local" });
    assert.equal(events[1].prev_hash, events[0].hash);
    assert.equal(events[2].prev_hash, events[1].hash);
  });

  test("verifyLedger accepts an empty or missing ledger as trivially valid", () => {
    const dir = makeTmp();
    assert.deepEqual(verifyLedger(dir), {
      valid: true,
      event_count: 0,
      head_hash: GENESIS_PREV_HASH,
    });
    mkdirSync(join(dir, "ledger"), { recursive: true });
    writeFileSync(join(dir, "ledger", "events.jsonl"), "", "utf8");
    assert.deepEqual(verifyLedger(dir), {
      valid: true,
      event_count: 0,
      head_hash: GENESIS_PREV_HASH,
    });
  });

  test("appendEvent refuses to touch a corrupt ledger (fail closed)", () => {
    const dir = makeTmp();
    mkdirSync(join(dir, "ledger"), { recursive: true });
    writeFileSync(join(dir, "ledger", "events.jsonl"), "{not json at all\n", "utf8");
    assert.throws(
      () =>
        appendEvent(
          dir,
          { type: "mirql.genesis", writer: { ns: "tool:queue" }, payload: {} },
          { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId },
        ),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
    assert.deepEqual(verifyLedger(dir), { valid: false, error: "json_parse", seq: 1 });
  });
});

// ---------------------------------------------------------------------------
// 2. Idempotency dedup (Law 4)
// ---------------------------------------------------------------------------

describe("appendEvent — idempotency dedup", () => {
  test("a repeated idempotency_key dedupes and returns the existing event", () => {
    const dir = seedSpecFive();
    const before = readFileSync(join(dir, "ledger", "events.jsonl"), "utf8");

    const retry = specFiveInputs()[2]; // job.leased, idempotency_key "job-1"
    const result = appendEvent(dir, retry, {
      signingKey: QUEUE_KP.privateKey,
      keyId: QUEUE_KP.keyId,
      nowMs: BASE_MS + 999_999,
    });

    assert.equal(result.status, "deduped");
    assert.equal(result.event.idempotency_key, "job-1");
    assert.equal(result.event.seq, 3);
    assert.deepEqual(result.event, JSON.parse(before.split("\n")[2]));

    // The ledger did not grow: byte-identical file.
    const after = readFileSync(join(dir, "ledger", "events.jsonl"), "utf8");
    assert.equal(after, before);
    assert.equal(readLedgerFile(dir).events.length, 5);
  });

  test("dedup works through the CLI too (exit 0, no new line)", () => {
    const dir = seedSpecFive();
    const before = readFileSync(join(dir, "ledger", "events.jsonl"), "utf8");
    const existing = JSON.parse(before.split("\n")[2]);

    const res = runBin(
      BIN_LOG,
      ["append", "--event", JSON.stringify(existing), "--dir", dir],
    );
    assert.equal(res.status, 0, res.stderr);
    const out = JSON.parse(res.stdout);
    assert.equal(out.status, "deduped");
    assert.equal(out.event.seq, 3);
    assert.equal(readFileSync(join(dir, "ledger", "events.jsonl"), "utf8"), before);
  });

  test("different idempotency keys with equal payloads still append", () => {
    const dir = makeTmp();
    const opts = { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS };
    const a = appendEvent(dir, { type: "mirql.genesis", writer: { ns: "tool:queue" }, idempotency_key: "a", payload: {} }, opts);
    const b = appendEvent(dir, { type: "factory.resumed", writer: { ns: "tool:queue" }, idempotency_key: "b", payload: {} }, opts);
    assert.equal(a.status, "appended");
    assert.equal(b.status, "appended");
    assert.equal(readLedgerFile(dir).events.length, 2);
  });
});

// ---------------------------------------------------------------------------
// 3. Law 3 — single-writer ACL
// ---------------------------------------------------------------------------

describe("appendEvent — Law 3 single-writer ACL", () => {
  test("tool:log may not emit job.leased (POLICY_DENIAL, ledger untouched)", () => {
    const dir = seedSpecFive();
    const before = readFileSync(join(dir, "ledger", "events.jsonl"), "utf8");
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "job.leased",
            writer: { ns: "tool:log" },
            idempotency_key: "evil-1",
            payload: { job_id: "job_x" },
          },
          { signingKey: LOG_KP.privateKey, keyId: LOG_KP.keyId, nowMs: BASE_MS },
        ),
      (err) =>
        err instanceof LedgerError &&
        err.code === "POLICY_DENIAL" &&
        err.exitCode === 4,
    );
    assert.equal(readFileSync(join(dir, "ledger", "events.jsonl"), "utf8"), before);
  });

  test("tool:queue may not emit verdict.accepted", () => {
    const dir = seedSpecFive();
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "verdict.accepted",
            writer: { ns: "tool:queue" },
            idempotency_key: "evil-2",
            payload: { job_id: "job_001" },
          },
          { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS },
        ),
      (err) => err instanceof LedgerError && err.code === "POLICY_DENIAL",
    );
  });

  test("CLI append denial exits 4 with JSON { error: POLICY_DENIAL } on stderr", () => {
    const dir = seedSpecFive();
    const before = readFileSync(join(dir, "ledger", "events.jsonl"), "utf8");
    const evil = {
      type: "job.leased",
      writer: { ns: "tool:log" },
      idempotency_key: "evil-cli",
      payload: { job_id: "job_x" },
    };
    for (const bin of [BIN_LOG, BIN_MIRQL]) {
      const args = bin === BIN_MIRQL ? ["l"] : [];
      const res = runBin(bin, [
        ...args,
        "append",
        "--event",
        JSON.stringify(evil),
        "--sign-key",
        LOG_KP.privateKey,
        "--key-id",
        LOG_KP.keyId,
        "--dir",
        dir,
      ]);
      assert.equal(res.status, 4, `${bin} exited ${res.status}`);
      assert.equal(res.stdout, "");
      const errDoc = JSON.parse(res.stderr);
      assert.equal(errDoc.error, "POLICY_DENIAL");
      assert.match(errDoc.reason, /single-writer ACL/);
    }
    assert.equal(readFileSync(join(dir, "ledger", "events.jsonl"), "utf8"), before);
  });
});

// ---------------------------------------------------------------------------
// 4. Law 4 — tamper detection
// ---------------------------------------------------------------------------

describe("verifyLedger — Law 4 tamper detection", () => {
  test("a flipped payload byte fails verification with hash_mismatch (exit 3)", () => {
    const dir = seedSpecFive();
    mutateLine(dir, 3, (event) => {
      event.payload.cost_micro_usd += 1;
    });
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "hash_mismatch",
      seq: 4,
    });
    const res = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(res.status, 3);
    assert.deepEqual(JSON.parse(res.stdout), { valid: false, error: "hash_mismatch", seq: 4 });
  });

  test("a broken prev_hash link fails with chain_break (exit 3)", () => {
    const dir = seedSpecFive();
    mutateLine(dir, 2, (event) => {
      event.prev_hash = sha256("evil");
    });
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "chain_break",
      seq: 3,
    });
    const res = runBin(BIN_MIRQL, ["l", "verify", "--dir", dir]);
    assert.equal(res.status, 3);
    assert.equal(JSON.parse(res.stdout).error, "chain_break");
  });

  test("a corrupted Ed25519 signature fails with signature_invalid (exit 3)", () => {
    const dir = seedSpecFive();
    mutateLine(dir, 1, (event) => {
      event.sig = (event.sig[0] === "A" ? "B" : "A") + event.sig.slice(1);
    });
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "signature_invalid",
      seq: 2,
    });
    const res = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(res.status, 3);
    assert.equal(JSON.parse(res.stdout).error, "signature_invalid");
  });

  test("a forged writer namespace fails the ACL gate with acl_denial (exit 3)", () => {
    const dir = seedSpecFive();
    mutateLine(dir, 4, (event) => {
      event.writer = { ns: "tool:log", key_id: event.writer.key_id };
    });
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "acl_denial",
      seq: 5,
    });
    const res = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(res.status, 3);
    assert.equal(JSON.parse(res.stdout).error, "acl_denial");
  });

  test("a rewritten seq fails with seq_break and a non-integer line fails Law 17", () => {
    const dir = seedSpecFive();
    mutateLine(dir, 3, (event) => {
      event.seq = 99;
    });
    assert.deepEqual(verifyLedger(dir), { valid: false, error: "seq_break", seq: 4 });

    const dir2 = seedSpecFive();
    const file = join(dir2, "ledger", "events.jsonl");
    const lines = readFileSync(file, "utf8").split("\n");
    lines[0] = lines[0].replace('"seq":1', '"seq":1.5');
    writeFileSync(file, lines.join("\n"), "utf8");
    assert.deepEqual(verifyLedger(dir2), {
      valid: false,
      error: "law17_violation",
      seq: 1,
    });
  });
});

// ---------------------------------------------------------------------------
// 5. Law 4 — rebuildable cache
// ---------------------------------------------------------------------------

describe("replayCache — the disposable cache is byte-reproducible", () => {
  test("deleting cache/state.json and replaying reproduces identical bytes", () => {
    const dir = seedSpecFive();
    const cachePath = join(dir, "cache", "state.json");
    assert.equal(existsSync(cachePath), true, "appendEvent must maintain the cache");
    const before = readFileSync(cachePath, "utf8");
    const stateBefore = getView(dir, "job_state");

    rmSync(cachePath);
    assert.equal(existsSync(cachePath), false);

    const res = runBin(BIN_MIRQL, ["l", "replay", "--rebuild-cache", "--dir", dir]);
    assert.equal(res.status, 0, res.stderr);
    const out = JSON.parse(res.stdout);
    assert.equal(out.rebuilt, true);
    assert.equal(out.seq, 5);
    assert.equal(out.state_hash, jcsHash(JSON.parse(before)));
    assert.equal(readFileSync(cachePath, "utf8"), before); // byte-identical

    // The projection is unchanged by the round-trip.
    assert.deepEqual(getView(dir, "job_state"), stateBefore);
    assert.deepEqual(foldEvents(dir), stateBefore);
  });

  test("mirql-log replay (bare) rebuilds as well and matches jcsHash(state)", () => {
    const dir = seedExtended();
    rmSync(join(dir, "cache", "state.json"), { force: true });
    const res = runBin(BIN_LOG, ["replay", "--dir", dir]);
    assert.equal(res.status, 0, res.stderr);
    const out = JSON.parse(res.stdout);
    const state = getView(dir, "job_state");
    assert.deepEqual(out, { rebuilt: true, seq: 15, state_hash: jcsHash(state) });
    assert.equal(existsSync(join(dir, "cache", "state.json")), true);
  });

  test("replayCache is available programmatically with the same contract", () => {
    const dir = seedSpecFive();
    const a = replayCache(dir);
    const b = replayCache(dir);
    assert.deepEqual(a, b);
    assert.equal(a.rebuilt, true);
    assert.equal(a.seq, 5);
    assert.equal(a.state_hash, jcsHash(getView(dir, "job_state")));
  });
});

// ---------------------------------------------------------------------------
// 6. Projections
// ---------------------------------------------------------------------------

describe("getView — the five named projections", () => {
  test("PROJECTIONS pins the five canonical names", () => {
    assert.deepEqual([...PROJECTIONS], [
      "job_state",
      "orchestrator_digest",
      "human_digest",
      "phi",
      "budget",
    ]);
    assert.equal(TOOL, "log");
  });

  test("folds the raw conformance fixture ledger into expected state", () => {
    const dir = seedGoldenFixture();
    const rawLines = readFileSync(GOLDEN_LEDGER, "utf8").trim().split("\n");

    const state = getView(dir, "job_state");
    assert.equal(state.version, 1);
    assert.equal(state.mode, "BUILD");
    assert.equal(state.epoch, 1);
    assert.equal(state.seq, 5);
    // Raw-line linkage: the fixture head is the sha256 of the last raw line.
    assert.equal(state.last_event_hash, sha256(rawLines[4]));
    assert.equal(state.budget_spent_micro_usd, 450_000);
    assert.equal(state.phi_last, 95);
    assert.equal(state.halted, false);
    assert.equal(state.needs_human, false);
    assert.deepEqual(state.warrants["warrant_001"], {
      id: "warrant_001",
      intent_id: "intent_001",
      role: "builder",
      tier: "mid",
      status: "completed",
      budget_micro_usd: 1_500_000,
    });
    assert.deepEqual(state.jobs["job_001"], {
      id: "job_001",
      warrant_id: "warrant_001",
      worker_id: "worker_node_1",
      status: "completed",
      outcome_verdict: "auto_merge",
    });
    assert.deepEqual(foldEvents(dir), state);
  });

  test("verifyLedger validates the conformance fixture ledger (raw-line linkage)", () => {
    const dir = seedGoldenFixture();
    const rawLines = readFileSync(GOLDEN_LEDGER, "utf8").trim().split("\n");
    assert.deepEqual(verifyLedger(dir, { conformance: true }), {
      valid: true,
      event_count: 5,
      head_hash: sha256(rawLines[4]),
    });
    // Without --conformance, raw-line linkage fails closed (Fix B2)
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "unhashed_line",
      seq: 1,
    });
  });

  test("tampering with a fixture line breaks the raw-line chain at seq 3", () => {
    const dir = seedGoldenFixture();
    mutateLine(dir, 1, (event) => {
      event.payload.title = "tampered title";
    });
    assert.deepEqual(verifyLedger(dir, { conformance: true }), {
      valid: false,
      error: "chain_break",
      seq: 3,
    });
    const res = runBin(BIN_LOG, ["verify", "--conformance", "--dir", dir]);
    assert.equal(res.status, 3);
    assert.equal(JSON.parse(res.stdout).error, "chain_break");
  });

  test("orchestrator_digest is bounded and summarizes queue-relevant state", () => {
    const dir = seedExtended();
    const digest = getView(dir, "orchestrator_digest");
    assert.deepEqual(digest, {
      mode: "BUILD",
      epoch: 1,
      seq: 15,
      active_warrants: 0,
      queued_jobs: 0,
      leased_jobs: 1,
      phi_last: 93,
      budget_spent_micro_usd: 550_000,
      halted: false,
    });
    assert.equal(
      Buffer.byteLength(jcs(digest), "utf8") <= ORCHESTRATOR_DIGEST_MAX_BYTES,
      true,
      "digest must stay within its 2048-byte budget",
    );
    // Mid-history fold: the factory is halted right after the halt event.
    const events = readLedgerFile(dir).events;
    assert.equal(events.length, 15);
    assert.equal(foldEvents(events.slice(0, 14)).halted, true);
    assert.equal(getView(dir, "job_state").halted, false); // resumed at seq 15
  });

  test("human_digest reports pending items, promotions and rollbacks", () => {
    const dir = seedExtended();
    assert.deepEqual(getView(dir, "human_digest"), {
      mode: "BUILD",
      epoch: 1,
      seq: 15,
      pending_human_items: 1,
      recent_promotions: [{ seq: 12, promotion_id: "promo_001" }],
      recent_rollbacks: [{ seq: 13, promotion_id: "promo_001" }],
      budget_spent_micro_usd: 550_000,
      halted: false,
    });
  });

  test("phi reports the latest potential and its per-event history", () => {
    const dir = seedExtended();
    assert.deepEqual(getView(dir, "phi"), {
      phi_last: 93,
      history: [
        { seq: 4, phi: 95 },
        { seq: 7, phi: 93 },
      ],
    });
  });

  test("budget breaks spend down by warrant and by role in integer micro-USD", () => {
    const dir = seedExtended();
    assert.deepEqual(getView(dir, "budget"), {
      budget_spent_micro_usd: 550_000,
      by_warrant: nullObject({ warrant_001: 550_000 }),
      by_role: nullObject({ builder: 550_000 }),
    });
  });

  test("job_state over the extended ledger materializes warrants, jobs and flags", () => {
    const dir = seedExtended();
    const events = readLedgerFile(dir).events;
    assert.deepEqual(getView(dir, "job_state"), {
      version: 1,
      mode: "BUILD",
      epoch: 1,
      seq: 15,
      last_event_hash: events[14].hash,
      budget_spent_micro_usd: 550_000,
      warrants: nullObject({
        warrant_001: {
          id: "warrant_001",
          intent_id: "intent_001",
          role: "builder",
          tier: "mid",
          status: "completed",
          budget_micro_usd: 1_500_000,
        },
      }),
      jobs: nullObject({
        job_001: {
          id: "job_001",
          warrant_id: "warrant_001",
          worker_id: "worker_1",
          status: "completed",
          // The notary's verdict.accepted is the authoritative final verdict.
          outcome_verdict: "accepted",
        },
        job_002: {
          id: "job_002",
          warrant_id: "warrant_001",
          worker_id: "worker_2",
          // needs_human at seq 8, resolved to accepted by the verdict.
          status: "accepted",
          outcome_verdict: "accepted",
        },
        job_003: {
          id: "job_003",
          warrant_id: "warrant_001",
          worker_id: "worker_3",
          status: "leased",
          outcome_verdict: null,
        },
      }),
      phi_last: 93,
      halted: false,
      needs_human: true,
    });
  });

  test("the empty ledger folds to a clean initial state", () => {
    const dir = makeTmp();
    const state = getView(dir, "state"); // alias of job_state
    assert.deepEqual(state, {
      version: 1,
      mode: null,
      epoch: 0,
      seq: 0,
      last_event_hash: null,
      budget_spent_micro_usd: 0,
      warrants: nullObject(),
      jobs: nullObject(),
      phi_last: null,
      halted: false,
      needs_human: false,
    });
    const digest = getView(dir, "orchestrator_digest");
    assert.deepEqual(digest, {
      mode: null,
      epoch: 0,
      seq: 0,
      active_warrants: 0,
      queued_jobs: 0,
      leased_jobs: 0,
      phi_last: null,
      budget_spent_micro_usd: 0,
      halted: false,
    });
    assert.deepEqual(getView(dir, "phi"), { phi_last: null, history: [] });
    assert.deepEqual(getView(dir, "budget"), {
      budget_spent_micro_usd: 0,
      by_warrant: nullObject(),
      by_role: nullObject(),
    });
  });

  test("unknown projections are a usage error (exit 2)", () => {
    const dir = seedSpecFive();
    assert.throws(
      () => getView(dir, "bogus_projection"),
      (err) => err instanceof LedgerError && err.code === "USAGE_ERROR",
    );
    const res = runBin(BIN_LOG, ["view", "bogus_projection", "--dir", dir]);
    assert.equal(res.status, 2);
    assert.equal(JSON.parse(res.stderr).error, "USAGE_ERROR");
  });
});

// ---------------------------------------------------------------------------
// 7. Snapshots
// ---------------------------------------------------------------------------

describe("createSnapshot — fold snapshots", () => {
  test("writes ledger/snapshots/snapshot-<seq>.json with the folded state", () => {
    const dir = seedSpecFive();
    const result = createSnapshot(dir);
    assert.equal(result.seq, 5);
    assert.equal(
      result.snapshot_path,
      join(dir, "ledger", "snapshots", "snapshot-5.json"),
    );
    assert.equal(existsSync(result.snapshot_path), true);

    const doc = JSON.parse(readFileSync(result.snapshot_path, "utf8"));
    assert.equal(doc.v, 1);
    assert.equal(doc.seq, 5);
    assert.equal(doc.state_hash, result.state_hash);
    assert.equal(jcs(doc.state), jcs(getView(dir, "job_state")));
    assert.equal(doc.state_hash, jcsHash(doc.state));
  });

  test("snapshot state_hash matches the replayed cache state_hash", () => {
    const dir = seedExtended();
    const snap = createSnapshot(dir);
    const replay = replayCache(dir);
    assert.equal(snap.state_hash, replay.state_hash);
    assert.equal(snap.seq, replay.seq);
  });

  test("snapshot works through both CLI entrypoints", () => {
    const dir = seedSpecFive();
    for (const [bin, pre] of [
      [BIN_LOG, []],
      [BIN_MIRQL, ["l"]],
    ]) {
      const res = runBin(bin, [...pre, "snapshot", "--dir", dir]);
      assert.equal(res.status, 0, res.stderr);
      const out = JSON.parse(res.stdout);
      assert.equal(out.seq, 5);
      assert.equal(out.snapshot_path, join(dir, "ledger", "snapshots", "snapshot-5.json"));
      assert.match(out.state_hash, /^sha256:[0-9a-f]{64}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// 8. Pre-signed envelopes, keyring and integrity gates
// ---------------------------------------------------------------------------

describe("appendEvent — pre-signed envelopes and keyring verification", () => {
  /** Build a signed envelope for seq/prev by hand. */
  function makeEnvelope(kp, { seq, prevHash, type = "job.enqueued", payload = {}, idempotencyKey = "env-1" }) {
    return signEvent(
      {
        v: 1,
        id: ulid(BASE_MS),
        tenant_id: "mirql-core",
        seq,
        epoch: 1,
        hlc: { wall_ms: BASE_MS, logical: 0, node: "local" },
        ts: new Date(BASE_MS).toISOString(),
        type,
        writer: { ns: "tool:queue", key_id: kp.keyId },
        idempotency_key: idempotencyKey,
        prev_hash: prevHash,
        payload,
      },
      kp.privateKey,
      kp.keyId,
    );
  }

  test("verifies a caller-supplied envelope against ledger/keyring.json", () => {
    const dir = makeTmp();
    mkdirSync(join(dir, "ledger"), { recursive: true });
    mkdirSync(resolveTrustRoot(dir), { recursive: true });
    saveTestKeyring(dir, { [QUEUE_KP.keyId]: QUEUE_KP.publicKey });
    const envelope = makeEnvelope(QUEUE_KP, { seq: 1, prevHash: GENESIS_PREV_HASH });
    const result = appendEvent(dir, envelope);
    assert.deepEqual(
      { status: result.status, seq: result.seq, hash: result.hash },
      { status: "appended", seq: 1, hash: envelope.hash },
    );
  });

  test("rejects an envelope whose signature does not verify (integrity)", () => {
    const dir = makeTmp();
    const envelope = makeEnvelope(QUEUE_KP, { seq: 1, prevHash: GENESIS_PREV_HASH });
    const forged = {
      ...envelope,
      sig: (envelope.sig[0] === "A" ? "B" : "A") + envelope.sig.slice(1),
    };
    assert.throws(
      () => appendEvent(dir, forged),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
  });

  test("rejects an envelope with a tampered payload (hash mismatch)", () => {
    const dir = makeTmp();
    const envelope = makeEnvelope(QUEUE_KP, {
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      payload: { amount: 1 },
    });
    const tampered = { ...envelope, payload: { amount: 2 } };
    assert.throws(
      () => appendEvent(dir, tampered),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
  });

  test("rejects an envelope whose seq does not continue the chain", () => {
    const dir = seedSpecFive();
    const envelope = makeEnvelope(QUEUE_KP, {
      seq: 99,
      prevHash: readLedgerFile(dir).events[4].hash,
      idempotencyKey: "env-jump",
    });
    assert.throws(
      () => appendEvent(dir, envelope),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
  });

  test("rejects Law 17 floats in a caller-supplied envelope (usage error)", () => {
    const dir = makeTmp();
    trustTestKeys(dir);
    const bogus = {
      ...makeEnvelope(QUEUE_KP, { seq: 1, prevHash: GENESIS_PREV_HASH }),
      payload: { ratio: 0.5 },
      hash: sha256("forged"),
      sig: "A".repeat(86),
    };
    assert.throws(
      () => appendEvent(dir, bogus),
      (err) => err instanceof LedgerError && err.code === "USAGE_ERROR",
    );
  });

  test("appendEvent keeps the cache in sync after every append", () => {
    const dir = makeTmp();
    const opts = { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS };
    appendEvent(dir, { type: "mirql.genesis", writer: { ns: "tool:queue" }, payload: {} }, opts);
    const cache1 = JSON.parse(readFileSync(join(dir, "cache", "state.json"), "utf8"));
    assert.equal(cache1.seq, 1);
    appendEvent(dir, { type: "factory.resumed", writer: { ns: "tool:queue" }, payload: {} }, opts);
    const cache2 = JSON.parse(readFileSync(join(dir, "cache", "state.json"), "utf8"));
    assert.equal(cache2.seq, 2);
    assert.equal(jcs(cache2), jcs(getView(dir, "job_state")));
  });
});

// ---------------------------------------------------------------------------
// 9. CLI surface
// ---------------------------------------------------------------------------

describe("CLI — append/verify/view through bin/mirql.mjs and bin/mirql-log.mjs", () => {
  test("append via --event, then --file, then stdin, growing the chain 1..4", () => {
    const dir = makeTmp();
    trustTestKeys(dir);
    const signOpts = (kp) => [
      "--sign-key",
      kp.privateKey,
      "--key-id",
      kp.keyId,
      "--dir",
      dir,
    ];

    const genesis = {
      type: "mirql.genesis",
      writer: { ns: "tool:queue" },
      idempotency_key: "cli-1",
      payload: { macro_state: "BUILD" },
    };
    const res1 = runBin(BIN_LOG, ["append", "--event", JSON.stringify(genesis), ...signOpts(QUEUE_KP)]);
    assert.equal(res1.status, 0, res1.stderr);
    assert.deepEqual(JSON.parse(res1.stdout), {
      status: "appended",
      seq: 1,
      hash: readLedgerFile(dir).events[0].hash,
    });

    const warrantFile = join(dir, "warrant.event.json");
    writeFileSync(
      warrantFile,
      jcs({
        type: "warrant.created",
        writer: { ns: "tool:run_supervisor" },
        idempotency_key: "cli-2",
        payload: { warrant_id: "w_1", role: "builder" },
      }),
      "utf8",
    );
    const res2 = runBin(BIN_MIRQL, ["l", "append", "--file", warrantFile, ...signOpts(RUN_KP)]);
    assert.equal(res2.status, 0, res2.stderr);
    assert.equal(JSON.parse(res2.stdout).seq, 2);

    const lease = {
      type: "job.leased",
      writer: { ns: "tool:queue" },
      idempotency_key: "cli-3",
      payload: { job_id: "j_1", warrant_id: "w_1" },
    };
    const res3 = runBin(BIN_LOG, ["append", ...signOpts(QUEUE_KP)], { input: JSON.stringify(lease) });
    assert.equal(res3.status, 0, res3.stderr);
    assert.equal(JSON.parse(res3.stdout).seq, 3);

    const outcome = {
      type: "attempt.outcome",
      writer: { ns: "tool:run_supervisor" },
      idempotency_key: "cli-4",
      payload: { job_id: "j_1", warrant_id: "w_1", status: "completed", cost_micro_usd: 7_500 },
    };
    const res4 = runBin(BIN_MIRQL, ["l", "append", ...signOpts(RUN_KP)], { input: JSON.stringify(outcome) });
    assert.equal(res4.status, 0, res4.stderr);
    assert.equal(JSON.parse(res4.stdout).seq, 4);

    const verify = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(verify.status, 0);
    assert.deepEqual(JSON.parse(verify.stdout), {
      valid: true,
      event_count: 4,
      head_hash: readLedgerFile(dir).events[3].hash,
    });

    const view = runBin(BIN_MIRQL, ["l", "view", "job_state", "--dir", dir]);
    assert.equal(view.status, 0, view.stderr);
    const state = JSON.parse(view.stdout);
    assert.equal(state.seq, 4);
    assert.equal(state.budget_spent_micro_usd, 7_500);

    const digest = runBin(BIN_LOG, ["view", "orchestrator_digest", "--dir", dir]);
    assert.equal(digest.status, 0);
    const digestDoc = JSON.parse(digest.stdout);
    assert.equal(digestDoc.leased_jobs, 0); // the job completed at seq 4
    assert.equal(digestDoc.budget_spent_micro_usd, 7_500);
  });

  test("MIRQL_DIR env var selects the ledger directory", () => {
    const dir = seedSpecFive();
    const res = runBin(BIN_LOG, ["verify"], { env: { MIRQL_DIR: dir } });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(JSON.parse(res.stdout).event_count, 5);
  });

  test("without --dir or MIRQL_DIR the ledger lives at <cwd>/.mirql", () => {
    const cwd = makeTmp();
    const event = {
      type: "mirql.genesis",
      writer: { ns: "tool:queue" },
      idempotency_key: "cwd-1",
      payload: {},
    };
    const res = runBin(
      BIN_LOG,
      ["append", "--event", JSON.stringify(event), "--sign-key", QUEUE_KP.privateKey, "--key-id", QUEUE_KP.keyId],
      { cwd },
    );
    assert.equal(res.status, 0, res.stderr);
    assert.equal(existsSync(join(cwd, ".mirql", "ledger", "events.jsonl")), true);
  });

  test("usage errors exit 2 with JSON on stderr", () => {
    const dir = makeTmp();
    const cases = [
      [BIN_LOG, ["append", "--event", "{oops", "--dir", dir]],
      [BIN_LOG, ["append", "--dir", dir]], // no input at all
      [BIN_LOG, ["append", "--file", join(dir, "missing.json"), "--dir", dir]],
      [BIN_LOG, ["bogus", "--dir", dir]],
      [BIN_MIRQL, ["l", "bogus", "--dir", dir]],
      [BIN_MIRQL, ["l", "view", "--dir", dir]], // missing projection
    ];
    for (const [bin, args] of cases) {
      const res = runBin(bin, args);
      assert.equal(res.status, 2, `${bin} ${args.join(" ")} -> ${res.status}`);
      assert.equal(JSON.parse(res.stderr).error, "USAGE_ERROR");
    }
  });

  test("the help subcommand prints usage JSON and exits 0", () => {
    const res = runBin(BIN_LOG, ["help"]);
    assert.equal(res.status, 0);
    const doc = JSON.parse(res.stdout);
    assert.equal(doc.tool, "log");
    assert.match(doc.usage, /mirql-log/);
    assert.deepEqual(Object.keys(doc.subcommands).sort(), [
      "append",
      "replay",
      "snapshot",
      "verify",
      "view",
    ]);
  });

  test("runCli is the programmatic CLI entrypoint returning exit codes", () => {
    const dir = seedSpecFive();
    assert.equal(runCli(["verify", "--dir", dir]), 0);
    assert.equal(runCli(["view", "phi", "--dir", dir]), 0);
    assert.equal(runCli(["view", "bogus_projection", "--dir", dir]), 2);
    assert.equal(runCli(["not-a-subcommand", "--dir", dir]), 2);
    assert.equal(runCli([]), 0); // bare invocation keeps the stub contract
  });
});

// ---------------------------------------------------------------------------
// 10. W1 stub contract (pinned by tests/structure.test.mjs)
// ---------------------------------------------------------------------------

describe("CLI — the W1 stub contract stays pinned", () => {
  test("mirql-log answers bare, --help, -h and status with the stub contract", () => {
    for (const args of [[], ["--help"], ["-h"], ["status"]]) {
      const res = runBin(BIN_LOG, args);
      assert.equal(res.status, 0, `mirql-log ${args.join(" ")}`);
      assert.deepEqual(JSON.parse(res.stdout), { tool: "log", status: "stub" });
    }
  });

  test("the mirql router keeps mapping log/l to the stub contract", () => {
    for (const args of [["log"], ["l"]]) {
      const res = runBin(BIN_MIRQL, args);
      assert.equal(res.status, 0);
      assert.deepEqual(JSON.parse(res.stdout), { tool: "log", status: "stub" });
    }
  });
});

// ---------------------------------------------------------------------------
// 11. Claude Opus 5.5 High Review Findings — Regression Suite
// ---------------------------------------------------------------------------

describe("Claude Opus 5.5 High Review Findings — Regression Suite", () => {
  function makeSignedEnvelope(kp, { seq, prevHash, type = "job.enqueued", writerNs = "tool:queue", payload = {}, idempotencyKey = "env-1", keyId = kp.keyId }) {
    return signEvent(
      {
        v: 1,
        id: ulid(BASE_MS),
        tenant_id: "mirql-core",
        seq,
        epoch: 1,
        hlc: { wall_ms: BASE_MS, logical: 0, node: "local" },
        ts: new Date(BASE_MS).toISOString(),
        type,
        writer: { ns: writerNs, key_id: keyId },
        idempotency_key: idempotencyKey,
        prev_hash: prevHash,
        payload,
      },
      kp.privateKey,
      keyId,
    );
  }

  test("B1: unsigned event or unresolvable key rejected with exit 3", () => {
    const dir = makeTmp();
    const env = makeSignedEnvelope(QUEUE_KP, { seq: 1, prevHash: GENESIS_PREV_HASH });

    // 1. Missing signature on appendEvent
    const unsigned = { ...env };
    delete unsigned.sig;
    assert.throws(
      () => appendEvent(dir, unsigned),
      (err) =>
        err instanceof LedgerError &&
        err.code === "INTEGRITY_VIOLATION" &&
        err.exitCode === 3 &&
        err.message === "missing signature or unresolvable public key",
    );

    // 2. Missing signature through CLI append (exits 3)
    const cliResUnsigned = runBin(BIN_LOG, ["append", "--dir", dir, "--event", JSON.stringify(unsigned)]);
    assert.equal(cliResUnsigned.status, 3);
    assert.equal(JSON.parse(cliResUnsigned.stderr).error, "INTEGRITY_VIOLATION");
    assert.equal(JSON.parse(cliResUnsigned.stderr).reason, "missing signature or unresolvable public key");

    // 3. Unresolvable key on appendEvent (unknown key_id that is not in keyring and not ed25519:<b64>)
    const unresolvable = {
      ...env,
      writer: { ns: "tool:queue", key_id: "non-resolvable-key-id" },
    };
    assert.throws(
      () => appendEvent(dir, unresolvable),
      (err) =>
        err instanceof LedgerError &&
        err.code === "INTEGRITY_VIOLATION" &&
        err.exitCode === 3 &&
        err.message === "missing signature or unresolvable public key",
    );

    // 4. verifyLedger on unsigned line fails with exit 3
    mkdirSync(join(dir, "ledger"), { recursive: true });
    writeFileSync(join(dir, "ledger", "events.jsonl"), jcs(unsigned) + "\n", "utf8");
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "missing signature or unresolvable public key",
      seq: 1,
    });
    const cliResVerify = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(cliResVerify.status, 3);
    assert.equal(JSON.parse(cliResVerify.stdout).error, "missing signature or unresolvable public key");
  });

  test("B2: hashless lines rejected without --conformance", () => {
    const dir = seedGoldenFixture();

    // In normal verification, unhashed lines are hard-rejected
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "unhashed_line",
      seq: 1,
    });

    const cliVerify = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(cliVerify.status, 3);
    assert.equal(JSON.parse(cliVerify.stdout).error, "unhashed_line");

    // With --conformance, raw-line linkage is permitted
    assert.equal(verifyLedger(dir, { conformance: true }).valid, true);
    const cliVerifyConf = runBin(BIN_LOG, ["verify", "--conformance", "--dir", dir]);
    assert.equal(cliVerifyConf.status, 0);
    assert.equal(JSON.parse(cliVerifyConf.stdout).valid, true);
  });

  test("B3: key not in keyring.json rejected with exit 3", () => {
    const dir = makeTmp();
    mkdirSync(join(dir, "ledger"), { recursive: true });

    // Keyring contains ONLY QUEUE_KP (real key)
    mkdirSync(resolveTrustRoot(dir), { recursive: true });
    saveTestKeyring(dir, { [QUEUE_KP.keyId]: QUEUE_KP.publicKey });

    // Other / evil keypair whose key is NOT in keyring.json
    const EVIL_KP = generateEd25519Keypair();

    // P1b: calling appendEvent with signingKey=evil, publicKey=evil must return exit code 3 (INTEGRITY_VIOLATION), not seq 1
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "job.enqueued",
            writer: { ns: "tool:queue" },
            payload: {},
          },
          {
            signingKey: EVIL_KP.privateKey,
            publicKey: EVIL_KP.publicKey,
            nowMs: BASE_MS,
          },
        ),
      (err) =>
        err instanceof LedgerError &&
        err.code === "INTEGRITY_VIOLATION" &&
        err.exitCode === 3 &&
        err.message === "missing signature or unresolvable public key",
    );

    // P1c: running CLI mirql l append --sign-key evil --public-key evil fails with exit code 3 (INTEGRITY_VIOLATION)
    const cliResEvil = runBin(BIN_MIRQL, [
      "l",
      "append",
      "--dir",
      dir,
      "--event",
      JSON.stringify({
        type: "job.enqueued",
        writer: { ns: "tool:queue" },
        payload: {},
      }),
      "--sign-key",
      EVIL_KP.privateKey,
      "--public-key",
      EVIL_KP.publicKey,
    ]);
    assert.equal(cliResEvil.status, 3);
    assert.equal(JSON.parse(cliResEvil.stderr).error, "INTEGRITY_VIOLATION");
    assert.equal(JSON.parse(cliResEvil.stderr).reason, "missing signature or unresolvable public key");

    // Also running mirql-log append --sign-key evil --public-key evil fails with exit 3
    const cliResLog = runBin(BIN_LOG, [
      "append",
      "--dir",
      dir,
      "--event",
      JSON.stringify({
        type: "job.enqueued",
        writer: { ns: "tool:queue" },
        payload: {},
      }),
      "--sign-key",
      EVIL_KP.privateKey,
      "--public-key",
      EVIL_KP.publicKey,
    ]);
    assert.equal(cliResLog.status, 3);
    assert.equal(JSON.parse(cliResLog.stderr).error, "INTEGRITY_VIOLATION");

    const otherEnv = makeSignedEnvelope(EVIL_KP, {
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      writerNs: "tool:queue",
    });

    // Programmatic append fails because embedded ed25519:... is not trusted when keyring exists
    assert.throws(
      () => appendEvent(dir, otherEnv),
      (err) =>
        err instanceof LedgerError &&
        err.code === "INTEGRITY_VIOLATION" &&
        err.exitCode === 3 &&
        err.message === "missing signature or unresolvable public key",
    );

    // CLI append fails with exit 3
    const cliRes = runBin(BIN_LOG, [
      "append",
      "--dir",
      dir,
      "--event",
      JSON.stringify(otherEnv),
    ]);
    assert.equal(cliRes.status, 3);
    assert.equal(JSON.parse(cliRes.stderr).error, "INTEGRITY_VIOLATION");
    assert.equal(JSON.parse(cliRes.stderr).reason, "missing signature or unresolvable public key");

    // verifyLedger fails with exit 3 when such an event is in events.jsonl
    writeFileSync(join(dir, "ledger", "events.jsonl"), jcs(otherEnv) + "\n", "utf8");
    assert.deepEqual(verifyLedger(dir), {
      valid: false,
      error: "missing signature or unresolvable public key",
      seq: 1,
    });
    const cliVerify = runBin(BIN_LOG, ["verify", "--dir", dir]);
    assert.equal(cliVerify.status, 3);
    assert.equal(JSON.parse(cliVerify.stdout).error, "missing signature or unresolvable public key");
  });

  test("B4: unauthorized writer attempting idempotency dedup rejected with exit 4; dedup is scoped to (writer.ns, idempotency_key)", () => {
    const dir = makeTmp();
    const optsQueue = { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS };

    // 1. Initial event by tool:queue
    const first = appendEvent(
      dir,
      {
        type: "job.enqueued",
        writer: { ns: "tool:queue" },
        idempotency_key: "idem-shared",
        payload: {},
      },
      optsQueue,
    );
    assert.equal(first.status, "appended");

    // 2. Unauthorized writer tool:log tries to emit job.leased using existing idempotency_key
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "job.leased",
            writer: { ns: "tool:log" },
            idempotency_key: "idem-shared",
            payload: {},
          },
          { signingKey: QUEUE_KP.privateKey },
        ),
      (err) => err instanceof LedgerError && err.code === "POLICY_DENIAL" && err.exitCode === 4,
    );

    // CLI append denial exits 4
    const cliRes = runBin(BIN_LOG, [
      "append",
      "--dir",
      dir,
      "--event",
      JSON.stringify({
        type: "job.leased",
        writer: { ns: "tool:log" },
        idempotency_key: "idem-shared",
        payload: {},
      }),
      "--sign-key",
      QUEUE_KP.privateKey,
    ]);
    assert.equal(cliRes.status, 4);
    assert.equal(JSON.parse(cliRes.stderr).error, "POLICY_DENIAL");

    // 3. Different authorized writer (tool:run_supervisor) uses same idempotency_key -> NOT deduped, appended!
    const optsRun = { signingKey: RUN_KP.privateKey, keyId: RUN_KP.keyId, nowMs: BASE_MS + 1000 };
    const second = appendEvent(
      dir,
      {
        type: "attempt.outcome",
        writer: { ns: "tool:run_supervisor" },
        idempotency_key: "idem-shared",
        payload: {},
      },
      optsRun,
    );
    assert.equal(second.status, "appended");
    assert.equal(second.seq, 2);

    // 4. Same writer tool:queue retries with idempotency_key -> deduped!
    const retry = appendEvent(
      dir,
      {
        type: "job.enqueued",
        writer: { ns: "tool:queue" },
        idempotency_key: "idem-shared",
        payload: {},
      },
      optsQueue,
    );
    assert.equal(retry.status, "deduped");
    assert.equal(retry.event.seq, 1);
  });

  test("B5: job_id: \"__proto__\" does not pollute Object.prototype", () => {
    assert.equal(({}).status, undefined);
    assert.equal(({}).role, undefined);
    assert.equal(Object.prototype.status, undefined);
    assert.equal(Object.prototype.role, undefined);

    const dir = makeTmp();
    appendEvent(
      dir,
      {
        type: "job.leased",
        writer: { ns: "tool:queue" },
        payload: { job_id: "__proto__", status: "leased" },
      },
      { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS },
    );
    appendEvent(
      dir,
      {
        type: "warrant.created",
        writer: { ns: "tool:run_supervisor" },
        payload: { warrant_id: "constructor", role: "builder", budget_micro_usd: 1000 },
      },
      { signingKey: RUN_KP.privateKey, keyId: RUN_KP.keyId, nowMs: BASE_MS + 1000 },
    );
    appendEvent(
      dir,
      {
        type: "attempt.outcome",
        writer: { ns: "tool:run_supervisor" },
        payload: { warrant_id: "constructor", cost_micro_usd: 350, role: "builder" },
      },
      { signingKey: RUN_KP.privateKey, keyId: RUN_KP.keyId, nowMs: BASE_MS + 2000 },
    );

    // Check that Object.prototype was NOT polluted
    assert.equal(({}).status, undefined, "Object.prototype.status must remain undefined");
    assert.equal(({}).role, undefined, "Object.prototype.role must remain undefined");
    assert.equal(Object.prototype.status, undefined);
    assert.equal(Object.prototype.role, undefined);

    const state = getView(dir, "job_state");
    const budget = getView(dir, "budget");

    // Verify own properties on null-prototype objects
    assert.equal(state.jobs["__proto__"]?.status, "leased");
    assert.equal(state.warrants["constructor"]?.role, "builder");
    assert.equal(budget.budget_spent_micro_usd, 350);
    assert.equal(budget.by_warrant["constructor"], 350);
  });

  test("B6: negative cost and safe-integer overflow rejected", () => {
    const dir = makeTmp();
    const opts = { signingKey: RUN_KP.privateKey, keyId: RUN_KP.keyId, nowMs: BASE_MS };

    // 1. Negative cost_micro_usd in appendEvent rejected
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor" },
            payload: { cost_micro_usd: -500 },
          },
          opts,
        ),
      (err) => err instanceof LedgerError && err.code === "USAGE_ERROR" && err.message.includes("cost_micro_usd"),
    );

    // 2. Safe-integer overflow in appendEvent rejected
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor" },
            payload: { cost_micro_usd: Number.MAX_SAFE_INTEGER + 1 },
          },
          opts,
        ),
      (err) => err instanceof LedgerError && err.code === "USAGE_ERROR",
    );

    // Append valid outcome close to MAX_SAFE_INTEGER
    appendEvent(
      dir,
      {
        type: "attempt.outcome",
        writer: { ns: "tool:run_supervisor" },
        idempotency_key: "big-spend",
        payload: { cost_micro_usd: Number.MAX_SAFE_INTEGER - 100 },
      },
      opts,
    );

    // Next append exceeding MAX_SAFE_INTEGER cumulative spend rejected
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor" },
            idempotency_key: "overflow-spend",
            payload: { cost_micro_usd: 101 },
          },
          { ...opts, nowMs: BASE_MS + 1000 },
        ),
      (err) => err instanceof LedgerError && err.code === "USAGE_ERROR" && err.message.includes("MAX_SAFE_INTEGER"),
    );

    // 3. Negative phi_after rejected
    assert.throws(
      () =>
        appendEvent(
          dir,
          {
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor" },
            idempotency_key: "bad-phi",
            payload: { phi_after: -1 },
          },
          { ...opts, nowMs: BASE_MS + 2000 },
        ),
      (err) => err instanceof LedgerError && err.code === "USAGE_ERROR" && err.message.includes("phi_after"),
    );

    // 4. foldEvents also validates costs & overflow
    assert.throws(
      () => foldEvents([{ seq: 1, type: "attempt.outcome", payload: { cost_micro_usd: -10 } }]),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
    assert.throws(
      () => foldEvents([{ seq: 1, type: "attempt.outcome", payload: { phi_after: -10 } }]),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
    assert.throws(
      () =>
        foldEvents([
          { seq: 1, type: "attempt.outcome", payload: { cost_micro_usd: Number.MAX_SAFE_INTEGER } },
          { seq: 2, type: "attempt.outcome", payload: { cost_micro_usd: 1 } },
        ]),
      (err) => err instanceof LedgerError && err.code === "INTEGRITY_VIOLATION",
    );
  });

  test("B7: orchestrator_digest remains <= 2048 bytes even with large input strings", () => {
    const dir = makeTmp();
    const opts = { signingKey: QUEUE_KP.privateKey, keyId: QUEUE_KP.keyId, nowMs: BASE_MS };

    // Genesis event with a massive macro_state string (50KB)
    const hugeMode = "BUILD_MODE_" + "Z".repeat(50_000);
    appendEvent(
      dir,
      {
        type: "mirql.genesis",
        writer: { ns: "tool:queue" },
        payload: { macro_state: hugeMode },
      },
      opts,
    );

    const digest = getView(dir, "orchestrator_digest");
    const jsonStr = jcs(digest);
    const byteLen = Buffer.byteLength(jsonStr, "utf8");

    assert.equal(
      byteLen <= ORCHESTRATOR_DIGEST_MAX_BYTES,
      true,
      `orchestrator_digest size (${byteLen} bytes) must be <= ${ORCHESTRATOR_DIGEST_MAX_BYTES} bytes`,
    );
    assert.equal(digest.mode.startsWith("BUILD_MODE_"), true);
    assert.equal(digest.mode.length <= 256, true);

    // CLI view also strictly satisfies the bound
    const cliRes = runBin(BIN_LOG, ["view", "orchestrator_digest", "--dir", dir]);
    assert.equal(cliRes.status, 0);
    assert.equal(Buffer.byteLength(cliRes.stdout.trim(), "utf8") <= ORCHESTRATOR_DIGEST_MAX_BYTES, true);
  });
});
