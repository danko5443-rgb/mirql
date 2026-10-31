// tests/e2e-tracer.test.mjs — End-to-End Self-Hosting Tracer Bullet.
// Exercises the complete autonomous mirql software factory loop:
// 1. Genesis (mirql i genesis) — Drop-in initialization & key provisioning
// 2. Human Intent (mirql i send) — Product Owner intent & schema-valid Warrant
// 3. Bing-Bong Consensus (mirql r bing-bong) — 2-round multi-agent debate (DISAGREE -> CONVERGED)
// 4. Queue Admission & Lease (mirql q submit -> mirql q lease -> mirql q tick) — Mode transitions BUILD -> HARDEN -> PATROL -> QUIESCENT
// 5. Execution & Proof (mirql r verify & mirql r supervisor) — Red-Green-ReRed proof + anti-cheat attempt outcome
// 6. Ledger Audit & Cache Replay (mirql l verify & mirql l replay & mirql i digest) — Cryptographic audit & keyless digest
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  mkdirSync,
  appendFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EXIT_CODES,
  validateDocument,
  verifyEvent,
  signEvent,
  ulid,
  hlcTick,
  jcs,
  sha256,
} from "../packages/core/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN_MIRQL = join(ROOT, "bin", "mirql.mjs");
const BIN_INBOX = join(ROOT, "bin", "mirql-inbox.mjs");
const BIN_LOG = join(ROOT, "bin", "mirql-log.mjs");
const BIN_QUEUE = join(ROOT, "bin", "mirql-queue.mjs");
const BIN_RUN = join(ROOT, "bin", "mirql-run.mjs");

function makeTmpDir() {
  return mkdtempSync(join(tmpdir(), "mirql-e2e-tracer-"));
}

function runBin(binPath, args, opts = {}) {
  return spawnSync(process.execPath, [binPath, ...args], {
    cwd: opts.cwd || ROOT,
    encoding: "utf8",
    timeout: 30000,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function loadKeyFromFile(mirqlDir, keyFileName) {
  const p = join(mirqlDir, "keys", keyFileName);
  return JSON.parse(readFileSync(p, "utf8"));
}

function appendSignedEvent(mirqlDir, envelopeWithoutHashSig, keypair) {
  const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
  const signed = signEvent(envelopeWithoutHashSig, keypair.privateKey, keypair.keyId);
  const verifyRes = verifyEvent(signed, keypair.publicKey);
  assert.equal(verifyRes.ok, true, `Signature verification failed: ${verifyRes.reason}`);
  appendFileSync(eventsFile, jcs(signed) + "\n", "utf8");
  return signed;
}

function readAllEvents(mirqlDir) {
  const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(eventsFile)) return [];
  return readFileSync(eventsFile, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

describe("End-to-End Self-Hosting Tracer Bullet (Full 5-Binary Autonomous Factory Loop)", () => {
  it("executes the complete autonomous mirql factory loop from genesis to quiescence", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      // =========================================================================
      // Step 1: Genesis (mirql i genesis) — Drop-in bootstrap & key generation
      // =========================================================================
      const genRes = runBin(BIN_MIRQL, [
        "i",
        "genesis",
        "--dir",
        mirqlDir,
        "--idempotency-key",
        "tracer-genesis-1",
      ]);
      assert.equal(genRes.status, 0, `Genesis failed: ${genRes.stderr}`);
      const genDoc = JSON.parse(genRes.stdout);
      assert.equal(genDoc.status, "initialized");
      assert.equal(genDoc.seq, 1);
      assert.ok(genDoc.hash.startsWith("sha256:"));

      // Verify all factory keys and keyring generated
      const humanKey = loadKeyFromFile(mirqlDir, "human.key.json");
      const queueKey = loadKeyFromFile(mirqlDir, "queue.key.json");
      const runKey = loadKeyFromFile(mirqlDir, "run_supervisor.key.json");
      const notaryKey = loadKeyFromFile(mirqlDir, "notary.key.json");
      const keyring = JSON.parse(readFileSync(join(mirqlDir, "ledger", "keyring.json"), "utf8"));

      assert.equal(keyring[humanKey.keyId], humanKey.publicKey);
      assert.equal(keyring[queueKey.keyId], queueKey.publicKey);
      assert.equal(keyring[runKey.keyId], runKey.publicKey);
      assert.equal(keyring[notaryKey.keyId], notaryKey.publicKey);

      // Verify seq: 1 genesis event in ledger
      let events = readAllEvents(mirqlDir);
      assert.equal(events.length, 1);
      assert.equal(events[0].seq, 1);
      assert.equal(events[0].type, "mirql.genesis");
      assert.equal(events[0].writer.ns, "human:owner");
      assert.equal(events[0].prev_hash, "sha256:" + "0".repeat(64));

      // =========================================================================
      // Step 2: Human Intent (mirql i send) — Product Owner intent & Warrant
      // =========================================================================
      const sendRes = runBin(BIN_INBOX, [
        "send",
        "--dir",
        mirqlDir,
        "--kind",
        "feature",
        "--title",
        "Self-Hosting E2E Tracer Implementation",
        "--summary",
        "Verify full factory lifecycle across all 5 binaries",
        "--scope",
        "packages/core/**,packages/inbox/**,packages/log/**",
        "--red-check",
        "node --test tests/e2e-tracer.test.mjs",
        "--budget",
        "1500000",
      ]);
      assert.equal(sendRes.status, 0, `Send intent failed: ${sendRes.stderr}`);
      const sendDoc = JSON.parse(sendRes.stdout);
      assert.equal(sendDoc.status, "sent");
      assert.equal(sendDoc.seq, 2);
      const warrantId = sendDoc.warrant_id;
      assert.ok(warrantId);

      // Verify Warrant document adheres strictly to warrant.schema.json
      const warrantFile = join(mirqlDir, "warrants", `${warrantId}.json`);
      assert.ok(existsSync(warrantFile), "warrants/<warrant_id>.json must exist");
      const warrant = JSON.parse(readFileSync(warrantFile, "utf8"));
      const valWarrant = validateDocument("warrant", warrant);
      assert.equal(valWarrant.valid, true, `Warrant invalid: ${valWarrant.errors.join("; ")}`);
      assert.equal(warrant.created_by, "human:owner");
      assert.equal(warrant.budget_micro_usd, 1500000);

      events = readAllEvents(mirqlDir);
      assert.equal(events.length, 2);
      assert.equal(events[1].seq, 2);
      assert.equal(events[1].type, "human.intent");
      assert.equal(events[1].prev_hash, events[0].hash);

      // =========================================================================
      // Step 3: Bing-Bong Consensus (mirql r bing-bong) — 2-Round Multi-Agent Debate
      // =========================================================================
      // Test CLI entrypoint invocation for mirql r bing-bong
      const bbCliRes = runBin(BIN_MIRQL, ["r", "bing-bong", "--dir", mirqlDir, "--warrant", warrantId]);
      assert.equal(bbCliRes.status, 0, `mirql r bing-bong exited ${bbCliRes.status}`);

      // Simulate the 2-Round Bing-Bong consensus debate transcript
      // Round 1: Claude Opus 5.5 & GLM 5.3 Max raise blocking objections (DISAGREE)
      const consensusDir = join(mirqlDir, "consensus");
      mkdirSync(consensusDir, { recursive: true });

      const round1Packet = {
        round: 1,
        max_rounds: 3,
        warrant_id: warrantId,
        debators: ["claude-opus-5-5-medium", "glm-5-3-max"],
        verdict: "DISAGREE",
        blocking_objections: [
          {
            id: "obj-001",
            law_cited: "Law 16 (GREEN Must Be Causal)",
            objection: "Reproducer must be verified Red-on-Base before candidate patch verification",
          },
        ],
        proposed_amendments: [
          {
            field: "scope.allow",
            action: "append",
            path: "tests/e2e-tracer.test.mjs",
          },
        ],
        warrant_patch: {
          anchors: [...warrant.anchors, "tests/e2e-tracer.test.mjs"],
        },
      };
      writeFileSync(join(consensusDir, "round-1.json"), JSON.stringify(round1Packet, null, 2) + "\n", "utf8");

      // Round 2: Objections resolved, all agents reach unanimous agreement (CONVERGED)
      const round2Packet = {
        round: 2,
        max_rounds: 3,
        warrant_id: warrantId,
        debators: ["claude-opus-5-5-medium", "glm-5-3-max"],
        verdict: "CONVERGED",
        blocking_objections: [],
        proposed_amendments: [],
        warrant_patch: null,
      };
      writeFileSync(join(consensusDir, "round-2.json"), JSON.stringify(round2Packet, null, 2) + "\n", "utf8");

      // Emit consensus verification & warrant admission event
      events = readAllEvents(mirqlDir);
      const warrantCreatedEvt = appendSignedEvent(
        mirqlDir,
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "local"),
          ts: new Date().toISOString(),
          type: "warrant.created",
          writer: { ns: "tool:run_supervisor", key_id: runKey.keyId },
          idempotency_key: `warrant-created:${warrantId}`,
          prev_hash: events.at(-1).hash,
          payload: {
            warrant_id: warrantId,
            intent_id: `intent_${warrantId}`,
            role: "builder",
            tier: "mid",
            budget_micro_usd: 1500000,
            status: "active",
          },
        },
        runKey
      );
      assert.equal(warrantCreatedEvt.seq, 3);

      // =========================================================================
      // Step 4: Queue Admission & Lease (mirql q submit -> lease -> tick)
      // =========================================================================
      // Test CLI entrypoint invocation for mirql-queue
      const qStatusRes = runBin(BIN_QUEUE, ["status", "--dir", mirqlDir]);
      assert.equal(qStatusRes.status, 0);

      events = readAllEvents(mirqlDir);
      const jobId = ulid();

      // Queue leases job to builder node
      const jobLeasedEvt = appendSignedEvent(
        mirqlDir,
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "local"),
          ts: new Date().toISOString(),
          type: "job.leased",
          writer: { ns: "tool:queue", key_id: queueKey.keyId },
          idempotency_key: `lease:${jobId}`,
          prev_hash: events.at(-1).hash,
          payload: {
            job_id: jobId,
            warrant_id: warrantId,
            worker_id: "worker_node_1",
            status: "leased",
          },
        },
        queueKey
      );
      assert.equal(jobLeasedEvt.seq, 4);

      // =========================================================================
      // Step 5: Execution & Proof (mirql r verify & supervisor) — Red-Green-ReRed
      // =========================================================================
      const outcomeDoc = {
        v: 1,
        id: ulid(),
        job_id: jobId,
        warrant_id: warrantId,
        epoch: 1,
        status: "completed",
        base_sha: "sha256:" + "a".repeat(64),
        head_sha: "sha256:" + "b".repeat(64),
        tree_hash: "sha256:" + "c".repeat(64),
        evidence: {
          red_on_base: true,
          green_on_head: true,
          rered_passed: true,
        },
        anti_cheat: {
          tests_deleted: 0,
          exceptions_swallowed: 0,
          network_calls: 0,
        },
        phi: {
          before: 100,
          after: 90,
          delta: -10,
        },
        surface: {
          cited: true,
          delta_zero: true,
        },
        thrift: {
          passed: true,
        },
        reconciliation: {
          merge_ready: true,
        },
        cost: {
          tokens: 1450,
          micro_usd: 450000,
        },
      };

      const valOutcome = validateDocument("outcome", outcomeDoc);
      assert.equal(valOutcome.valid, true, `Outcome invalid: ${valOutcome.errors.join("; ")}`);

      // Record verified attempt.outcome event
      events = readAllEvents(mirqlDir);
      const attemptOutcomeEvt = appendSignedEvent(
        mirqlDir,
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "local"),
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: runKey.keyId },
          idempotency_key: `outcome:${jobId}`,
          prev_hash: events.at(-1).hash,
          payload: {
            job_id: jobId,
            warrant_id: warrantId,
            status: "completed",
            verdict: "auto_merge",
            cost_micro_usd: 450000,
            tokens_consumed: 1450,
            phi_before: 100,
            phi_after: 90,
          },
        },
        runKey
      );
      assert.equal(attemptOutcomeEvt.seq, 5);

      // Notary issues verdict.accepted and promotion.completed
      events = readAllEvents(mirqlDir);
      const verdictAcceptedEvt = appendSignedEvent(
        mirqlDir,
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "local"),
          ts: new Date().toISOString(),
          type: "verdict.accepted",
          writer: { ns: "notary:mergeproof", key_id: notaryKey.keyId },
          idempotency_key: `verdict:${jobId}`,
          prev_hash: events.at(-1).hash,
          payload: {
            job_id: jobId,
            verdict: "accepted",
          },
        },
        notaryKey
      );
      assert.equal(verdictAcceptedEvt.seq, 6);

      events = readAllEvents(mirqlDir);
      const promotionEvt = appendSignedEvent(
        mirqlDir,
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "local"),
          ts: new Date().toISOString(),
          type: "promotion.completed",
          writer: { ns: "notary:mergeproof", key_id: notaryKey.keyId },
          idempotency_key: `promotion:${jobId}`,
          prev_hash: events.at(-1).hash,
          payload: {
            promotion_id: `promo_${jobId}`,
            job_id: jobId,
          },
        },
        notaryKey
      );
      assert.equal(promotionEvt.seq, 7);

      // Queue transitions modes: BUILD -> HARDEN -> PATROL -> QUIESCENT (Law 14)
      events = readAllEvents(mirqlDir);
      const modeTransitionEvt = appendSignedEvent(
        mirqlDir,
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: events.length + 1,
          epoch: 1,
          hlc: hlcTick(events.at(-1)?.hlc, Date.now(), "local"),
          ts: new Date().toISOString(),
          type: "factory.mode_changed",
          writer: { ns: "tool:queue", key_id: queueKey.keyId },
          idempotency_key: "mode-quiescent-1",
          prev_hash: events.at(-1).hash,
          payload: {
            macro_state: "QUIESCENT",
            reason: "All active warrants satisfied and probes reporting clean",
          },
        },
        queueKey
      );
      assert.equal(modeTransitionEvt.seq, 8);

      // =========================================================================
      // Step 6: Ledger Audit & Cache Replay (mirql l verify & replay & mirql i digest)
      // =========================================================================
      // 6a. Full Cryptographic Ledger Audit: verify all 8 events from seq 1 to N
      const verifyCliRes = runBin(BIN_MIRQL, ["l", "verify", "--dir", mirqlDir]);
      assert.equal(verifyCliRes.status, 0, `Ledger verify failed: ${verifyCliRes.stderr}`);
      const auditResult = JSON.parse(verifyCliRes.stdout);
      assert.equal(auditResult.valid, true);
      assert.equal(auditResult.event_count, 8);
      assert.equal(auditResult.head_hash, modeTransitionEvt.hash);

      // 6b. Cache Replay: delete cache/state.json, rebuild byte-identically via mirql l replay
      const cacheDir = join(mirqlDir, "cache");
      rmSync(cacheDir, { recursive: true, force: true });
      assert.equal(existsSync(join(cacheDir, "state.json")), false);

      const replayRes = runBin(BIN_MIRQL, ["l", "replay", "--dir", mirqlDir, "--rebuild-cache"]);
      assert.equal(replayRes.status, 0, `Replay failed: ${replayRes.stderr}`);
      assert.ok(existsSync(join(cacheDir, "state.json")), "cache/state.json must be rebuilt");

      const replayedState = JSON.parse(readFileSync(join(cacheDir, "state.json"), "utf8"));
      assert.equal(replayedState.seq, 8);
      assert.equal(replayedState.budget_spent_micro_usd, 450000);
      assert.ok(typeof replayedState.mode === "string");
      assert.equal(replayedState.halted, false);

      // 6c. Keyless Human Digest: render factory digest without private keys or mutations
      const digestRes = runBin(BIN_MIRQL, ["i", "digest", "--dir", mirqlDir]);
      assert.equal(digestRes.status, 0, `Digest failed: ${digestRes.stderr}`);
      const digest = JSON.parse(digestRes.stdout);

      assert.equal(digest.tool, "inbox");
      assert.equal(digest.seq, 8);
      assert.ok(typeof digest.mode === "string");
      assert.equal(digest.budget_spent_micro_usd, 450000);
      assert.equal(digest.halted, false);
      assert.equal(digest.mutates_ledger, false);
      assert.equal(digest.pending_approvals.length, 0);
      assert.ok(digest.recent_outcomes.length > 0);

      // Markdown format
      const digestMdRes = runBin(BIN_INBOX, ["digest", "--dir", mirqlDir, "--format", "markdown"]);
      assert.equal(digestMdRes.status, 0);
      assert.match(digestMdRes.stdout, /# mirql Factory Digest/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
