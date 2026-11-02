import { trustFile } from "../packages/core/trust-root.mjs";
// tests/queue.test.mjs — Comprehensive test suite for Work Package W4: mirql-queue
import { test, describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  appendFileSync,
  existsSync,
  statSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  EXIT_CODES,
  sha256,
  ulid,
  jcs,
  generateEd25519Keypair,
  signEvent,
  hlcTick,
} from "../packages/core/index.mjs";
import { runSupervisor } from "../packages/run/index.mjs";
import {
  getQueueStatus,
  submitWarrant,
  tickQueue,
  leaseNextJob,
  verifyLeaseEpoch,
  promoteJob,
  haltQueue,
  resumeQueue,
  checkNotRoadmapGate,
  tick,
  DEFAULT_POLICY,
  foldLedger,
  foldQueueState,
  loadKeyring,
  saveKeyring,
  appendLedgerEvent,
  getOrCreateQueueKeypair,
} from "../packages/queue/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

/** Helper to spawn CLI */
function runBin(binRelPath, args) {
  return spawnSync(process.execPath, [join(ROOT, binRelPath), ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30_000,
  });
}

/** Build a valid canonical warrant */
function makeValidWarrant(overrides = {}) {
  return {
    v: 1,
    id: ulid(1_700_000_001_000),
    class: "surgical",
    semantic_fingerprint: sha256("intent: deterministic integer queue test"),
    anchors: [{ path: "packages/queue/index.mjs" }],
    evidence: { citations: 1 },
    red_check: { reviewed: 1 },
    scope: { allow_globs: ["packages/queue/**"] },
    budget_micro_usd: 500_000,
    created_by: "human:owner",
    ...overrides,
  };
}

/** Append an attempt outcome event to test failure/success */
function recordAttemptOutcome(mirqlDir, jobId, warrantId, status, verdict, cost = 10_000) {
  const supervisorKeypair = generateEd25519Keypair();
  saveKeyring(mirqlDir, { "tool:run_supervisor": supervisorKeypair.publicKey });
  const eventWithoutHashSig = {
    v: 1,
    id: ulid(),
    tenant_id: "mirql-core",
    seq: 999,
    epoch: 1,
    hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
    ts: new Date().toISOString(),
    type: "attempt.outcome",
    writer: { ns: "tool:run_supervisor", key_id: supervisorKeypair.keyId },
    idempotency_key: `outcome-${ulid()}`,
    prev_hash: sha256("prev"),
    payload: {
      job_id: jobId,
      warrant_id: warrantId,
      status,
      verdict,
      cost_micro_usd: cost,
      tokens_consumed: 100,
    },
  };

  const signed = signEvent(
    eventWithoutHashSig,
    supervisorKeypair.privateKey,
    supervisorKeypair.keyId,
  );
  const ledgerPath = join(mirqlDir, "ledger", "events.jsonl");
  appendFileSync(ledgerPath, jcs(signed) + "\n", "utf8");
}

describe("Work Package W4: mirql-queue Test Suite", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-queue-test-"));
  });

  afterEach(() => {
    if (tempDir) {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup error
      }
    }
  });

  // ---------------------------------------------------------------------------
  // 1. Warrant validation & Law 9 NOT-ROADMAP.md gate
  // ---------------------------------------------------------------------------
  describe("1. Warrant validation & Law 9 NOT-ROADMAP.md Gate", () => {
    it("submitting a valid canonical warrant succeeds", () => {
      const warrant = makeValidWarrant();
      const res = submitWarrant(tempDir, warrant, { repoRoot: ROOT });
      assert.equal(res.ok, true);
      assert.equal(res.status, "submitted");
      assert.equal(res.warrant_id, warrant.id);
      assert.equal(res.tier, "flash");
      assert.equal(res.attempt, 1);
      assert.ok(res.job_id);
    });

    it("rejects non-integer budget warrant under Law 17", () => {
      const badWarrant = makeValidWarrant({ budget_micro_usd: 12.34 });
      const res = submitWarrant(tempDir, badWarrant, { repoRoot: ROOT });
      assert.equal(res.ok, false);
      assert.equal(res.status, "rejected");
      assert.equal(res.exit_code, EXIT_CODES.USAGE_ERROR);
    });

    it("Law 9 Gate: rejects warrant proposing Autonomous Merge Without Proof with exit code 4 (POLICY_DENIAL)", () => {
      const antiWarrant = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("anti-goal 1"),
        evidence: { summary: "Autonomous Merge Without Proof" },
      });
      const res = submitWarrant(tempDir, antiWarrant, { repoRoot: ROOT });
      assert.equal(res.ok, false);
      assert.equal(res.status, "rejected");
      assert.equal(res.exit_code, EXIT_CODES.POLICY_DENIAL);
      assert.equal(res.id, "nr-0002");
    });

    it("Law 9 Gate: rejects warrant proposing Floating-Point Cost with exit code 4 (POLICY_DENIAL)", () => {
      const antiWarrant = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("anti-goal 2"),
        evidence: { description: "Introduces Floating-Point Cost calculation for billing" },
      });
      const res = submitWarrant(tempDir, antiWarrant, { repoRoot: ROOT });
      assert.equal(res.ok, false);
      assert.equal(res.status, "rejected");
      assert.equal(res.exit_code, EXIT_CODES.POLICY_DENIAL);
      assert.equal(res.id, "nr-0003");
    });

    it("Law 9 Gate: rejects other forbidden patterns (nr-0001, nr-0004, nr-0005)", () => {
      const nr1 = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("anti 1"),
        scope: { note: "Never auto-approve HUMAN verdicts on timeout" },
      });
      assert.equal(submitWarrant(tempDir, nr1, { repoRoot: ROOT }).exit_code, EXIT_CODES.POLICY_DENIAL);

      const nr4 = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("anti 4"),
        scope: { allow_egress: true },
      });
      assert.equal(submitWarrant(tempDir, nr4, { repoRoot: ROOT }).exit_code, EXIT_CODES.POLICY_DENIAL);

      const nr5 = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("anti 5"),
        evidence: { note: "Bypassing base-fail reproduction test" },
      });
      assert.equal(submitWarrant(tempDir, nr5, { repoRoot: ROOT }).exit_code, EXIT_CODES.POLICY_DENIAL);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Semantic fingerprint deduplication on submit
  // ---------------------------------------------------------------------------
  describe("2. Semantic Fingerprint Deduplication", () => {
    it("deduplicates warrant submission when open warrant has identical fingerprint", () => {
      const fingerprint = sha256("intent: deduplication test");
      const warrant1 = makeValidWarrant({ id: ulid(1_700_000_010_000), semantic_fingerprint: fingerprint });
      const res1 = submitWarrant(tempDir, warrant1, { repoRoot: ROOT });
      assert.equal(res1.status, "submitted");

      const warrant2 = makeValidWarrant({ id: ulid(1_700_000_020_000), semantic_fingerprint: fingerprint });
      const res2 = submitWarrant(tempDir, warrant2, { repoRoot: ROOT });

      assert.equal(res2.ok, true);
      assert.equal(res2.status, "deduplicated");
      assert.equal(res2.deduplicated, true);
      assert.equal(res2.warrant_id, warrant1.id);

      const status = getQueueStatus(tempDir);
      assert.equal(status.open_warrants.length, 1);
      assert.equal(status.open_warrants[0], warrant1.id);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Monotonic epoch leasing & Law 5 stale-epoch rejection
  // ---------------------------------------------------------------------------
  describe("3. Monotonic Epoch Leasing & Law 5 Stale-Epoch Fencing", () => {
    it("increments epoch monotonically on each lease", () => {
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const l1 = leaseNextJob(tempDir);
      assert.equal(l1.ok, true);
      assert.equal(l1.status, "leased");
      assert.equal(l1.epoch, 2); // Initial state is 1, lease increments to 2
      assert.equal(l1.attempt, 1);

      // Verify verifyLeaseEpoch works for valid epoch
      const validEpochCheck = verifyLeaseEpoch(tempDir, l1.job_id, 2);
      assert.equal(validEpochCheck, EXIT_CODES.OK);

      // Verify verifyLeaseEpoch rejects stale epoch with EXIT_CODES.STALE_EPOCH (5)
      const staleEpochCheck = verifyLeaseEpoch(tempDir, l1.job_id, 1);
      assert.equal(staleEpochCheck, EXIT_CODES.STALE_EPOCH);

      // Verify verifyLeaseEpoch rejects expired lease
      const expiredCheck = verifyLeaseEpoch(tempDir, l1.job_id, 2, { nowMs: Date.now() + 2_000_000 });
      assert.equal(expiredCheck, EXIT_CODES.STALE_EPOCH);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Law 8 Escalation Ladder
  // ---------------------------------------------------------------------------
  describe("4. Law 8 Escalation Ladder & NEEDS_HUMAN", () => {
    it("escalates attempt 1 (flash) -> attempt 2 (mid) -> attempt 3 (max/doctor) -> NEEDS_HUMAN (exit code 10)", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      // Attempt 1 -> tier flash
      const l1 = leaseNextJob(tempDir);
      assert.equal(l1.ok, true);
      assert.equal(l1.attempt, 1);
      assert.equal(l1.tier, "flash");

      // Record failure for attempt 1
      const keypair = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": keypair.publicKey });
      const failEvent1 = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 100,
          epoch: l1.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: keypair.keyId },
          idempotency_key: `fail-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: l1.job_id, warrant_id: warrant.id, status: "failed", verdict: "reject", cost_micro_usd: 1000 },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(failEvent1) + "\n", "utf8");

      // Attempt 2 -> tier mid
      const l2 = leaseNextJob(tempDir);
      assert.equal(l2.ok, true);
      assert.equal(l2.attempt, 2);
      assert.equal(l2.tier, "mid");

      // Record failure for attempt 2
      const failEvent2 = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 101,
          epoch: l2.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: keypair.keyId },
          idempotency_key: `fail-${ulid()}`,
          prev_hash: failEvent1.hash,
          payload: { job_id: l2.job_id, warrant_id: warrant.id, status: "failed", verdict: "reject", cost_micro_usd: 1000 },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(failEvent2) + "\n", "utf8");

      // Attempt 3 -> tier max / role doctor
      const l3 = leaseNextJob(tempDir);
      assert.equal(l3.ok, true);
      assert.equal(l3.attempt, 3);
      assert.equal(l3.tier, "max");
      assert.equal(l3.role, "doctor");

      // Record failure for attempt 3 (3rd failure reaches max_attempts_per_warrant)
      const failEvent3 = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 102,
          epoch: l3.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: keypair.keyId },
          idempotency_key: `fail-${ulid()}`,
          prev_hash: failEvent2.hash,
          payload: { job_id: l3.job_id, warrant_id: warrant.id, status: "failed", verdict: "reject", cost_micro_usd: 1000 },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(failEvent3) + "\n", "utf8");

      // Warrant transitions to NEEDS_HUMAN (exit code 10)
      const l4 = leaseNextJob(tempDir);
      assert.equal(l4.ok, false);
      assert.equal(l4.action, "NEEDS_HUMAN");
      assert.equal(l4.exit_code, EXIT_CODES.NEEDS_HUMAN);

      const t = tickQueue(tempDir, { repoRoot: ROOT });
      assert.equal(t.action, "NEEDS_HUMAN");
      assert.equal(t.exit_code, EXIT_CODES.NEEDS_HUMAN);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Law 12 Macro Mode FSM transitions
  // ---------------------------------------------------------------------------
  describe("5. Law 12 Macro Mode FSM Transitions", async () => {
    it("transitions BUILD -> HARDEN -> PATROL -> QUIESCENT, and wakes back to BUILD", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      let status = getQueueStatus(tempDir);
      assert.equal(status.mode, "BUILD");

      // Lease the job
      const l = leaseNextJob(tempDir);
      assert.equal(l.ok, true);

      // Complete the warrant successfully
      const keypair = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": keypair.publicKey });
      const successEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 50,
          epoch: l.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: keypair.keyId },
          idempotency_key: `succ-${ulid()}`,
          prev_hash: sha256("genesis"),
          payload: { job_id: l.job_id, warrant_id: warrant.id, status: "completed", verdict: "auto_merge", cost_micro_usd: 500 },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(successEvt) + "\n", "utf8");

      // 1. In BUILD with 0 open warrants -> transitions BUILD to HARDEN
      const t1 = tickQueue(tempDir, { repoRoot: ROOT });
      assert.equal(t1.action, "TRANSITION");
      assert.equal(t1.next_mode, "HARDEN");

      status = getQueueStatus(tempDir);
      assert.equal(status.mode, "HARDEN");

      // 2. In HARDEN: hardening passes -> transitions HARDEN to PATROL
      const t2 = tickQueue(tempDir, { repoRoot: ROOT, hardening_passed: true });
      assert.equal(t2.action, "TRANSITION");
      assert.equal(t2.next_mode, "PATROL");

      status = getQueueStatus(tempDir);
      assert.equal(status.mode, "PATROL");

      // 3. In PATROL: probes clean and head unchanged -> transitions PATROL to QUIESCENT
      const t3 = tickQueue(tempDir, { repoRoot: ROOT, probes_clean: true, head_unchanged: true });
      assert.equal(t3.action, "TRANSITION");
      assert.equal(t3.next_mode, "QUIESCENT");
      assert.equal(t3.tokens_per_hr, 0);

      status = getQueueStatus(tempDir);
      assert.equal(status.mode, "QUIESCENT");

      // 4. In QUIESCENT: stays in QUIESCENT at 0 tokens/hr
      const t4 = tickQueue(tempDir, { repoRoot: ROOT });
      assert.equal(t4.action, "QUIESCENT");
      assert.equal(t4.next_mode, "QUIESCENT");
      assert.equal(t4.tokens_per_hr, 0);

      // 5. Wake up from QUIESCENT -> BUILD on new warrant arrival
      const newWarrant = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("intent: fresh wake up warrant"),
      });
      submitWarrant(tempDir, newWarrant, { repoRoot: ROOT });

      status = getQueueStatus(tempDir);
      assert.equal(status.mode, "BUILD");
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Halt, resume, and budget exhaustion
  // ---------------------------------------------------------------------------
  describe("6. Halt, Resume, and Budget Exhaustion", async () => {
    it("halt blocks leasing and tick with exit code 6 (HALTED), resume restores", () => {
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      // Halt queue
      const haltRes = haltQueue(tempDir, "Safety emergency");
      assert.equal(haltRes.ok, true);
      assert.equal(haltRes.halted, true);

      let status = getQueueStatus(tempDir);
      assert.equal(status.halted, true);

      // Leasing must be blocked with exit code 6
      const leaseRes = leaseNextJob(tempDir);
      assert.equal(leaseRes.ok, false);
      assert.equal(leaseRes.action, "HALTED");
      assert.equal(leaseRes.exit_code, EXIT_CODES.HALTED);

      // Tick must return HALTED with exit code 6
      const tickRes = tickQueue(tempDir, { repoRoot: ROOT });
      assert.equal(tickRes.action, "HALTED");
      assert.equal(tickRes.exit_code, EXIT_CODES.HALTED);

      // Resume queue
      const resumeRes = resumeQueue(tempDir, "Clear to proceed");
      assert.equal(resumeRes.ok, true);
      assert.equal(resumeRes.halted, false);

      status = getQueueStatus(tempDir);
      assert.equal(status.halted, false);

      // Leasing proceeds now
      const leaseRes2 = leaseNextJob(tempDir);
      assert.equal(leaseRes2.ok, true);
      assert.equal(leaseRes2.status, "leased");
    });

    it("budget exhaustion returns exit code 7 (BUDGET_EXHAUSTED)", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      // Append an attempt consuming 30,000,000 micro-USD (daily budget is 25,000,000)
      const keypair = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": keypair.publicKey });
      const budgetEvent = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 1,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: keypair.keyId },
          idempotency_key: `budget-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: ulid(), warrant_id: warrant.id, status: "completed", cost_micro_usd: 30_000_000 },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(budgetEvent) + "\n", "utf8");

      const leaseRes = leaseNextJob(tempDir);
      assert.equal(leaseRes.ok, false);
      assert.equal(leaseRes.action, "BUDGET_EXHAUSTED");
      assert.equal(leaseRes.exit_code, EXIT_CODES.BUDGET_EXHAUSTED);

      const tickRes = tickQueue(tempDir, { repoRoot: ROOT });
      assert.equal(tickRes.action, "BUDGET_EXHAUSTED");
      assert.equal(tickRes.exit_code, EXIT_CODES.BUDGET_EXHAUSTED);
    });
  });

  // ---------------------------------------------------------------------------
  // 7. CLI Execution via bin/mirql.mjs q and bin/mirql-queue.mjs
  // ---------------------------------------------------------------------------
  describe("7. CLI Execution (bin/mirql.mjs q & bin/mirql-queue.mjs)", () => {
    it("mirql q status returns valid JSON on stdout with code 0", () => {
      const res = runBin("bin/mirql.mjs", ["q", "status", "--dir", tempDir]);
      assert.equal(res.status, 0, res.stderr);
      const parsed = JSON.parse(res.stdout);
      assert.equal(parsed.tool, "queue");
      assert.equal(parsed.mode, "BUILD");
      assert.equal(parsed.halted, false);
      assert.deepEqual(parsed.open_warrants, []);
    });

    it("mirql q submit accepts valid warrant JSON and returns code 0", () => {
      const warrant = makeValidWarrant();
      const res = runBin("bin/mirql.mjs", [
        "q",
        "submit",
        "--dir",
        tempDir,
        "--warrant",
        JSON.stringify(warrant),
      ]);
      assert.equal(res.status, 0, res.stderr);
      const parsed = JSON.parse(res.stdout);
      assert.equal(parsed.status, "submitted");
      assert.equal(parsed.warrant_id, warrant.id);
    });

    it("mirql q submit rejects Autonomous Merge Without Proof with exit code 4", () => {
      const antiWarrant = makeValidWarrant({
        id: ulid(),
        semantic_fingerprint: sha256("anti cli"),
        evidence: { description: "Autonomous Merge Without Proof" },
      });
      const res = runBin("bin/mirql.mjs", [
        "q",
        "submit",
        "--dir",
        tempDir,
        "--warrant",
        JSON.stringify(antiWarrant),
      ]);
      assert.equal(res.status, 4);
      const err = JSON.parse(res.stderr);
      assert.equal(err.exit_code, 4);
      assert.equal(err.id, "nr-0002");
    });

    it("mirql q lease assigns epoch and returns code 0", () => {
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const res = runBin("bin/mirql.mjs", ["q", "lease", "--dir", tempDir]);
      assert.equal(res.status, 0, res.stderr);
      const parsed = JSON.parse(res.stdout);
      assert.equal(parsed.status, "leased");
      assert.equal(parsed.epoch, 2);
    });

    it("mirql q halt and resume via CLI", () => {
      const haltRes = runBin("bin/mirql.mjs", ["q", "halt", "--dir", tempDir, "--reason", "Test halt"]);
      assert.equal(haltRes.status, 0);
      assert.equal(JSON.parse(haltRes.stdout).halted, true);

      // lease when halted exits with code 6
      const leaseRes = runBin("bin/mirql.mjs", ["q", "lease", "--dir", tempDir]);
      assert.equal(leaseRes.status, 6);

      const resumeRes = runBin("bin/mirql.mjs", ["q", "resume", "--dir", tempDir, "--reason", "Test resume"]);
      assert.equal(resumeRes.status, 0);
      assert.equal(JSON.parse(resumeRes.stdout).halted, false);
    });

    it("bin/mirql-queue.mjs status works standalone", () => {
      const res = runBin("bin/mirql-queue.mjs", ["status", "--dir", tempDir]);
      assert.equal(res.status, 0, res.stderr);
      const parsed = JSON.parse(res.stdout);
      assert.equal(parsed.tool, "queue");
    });

    it("bin/mirql-queue.mjs --help outputs stub contract", () => {
      const res = runBin("bin/mirql-queue.mjs", ["--help"]);
      assert.equal(res.status, 0);
      assert.deepEqual(JSON.parse(res.stdout), { tool: "queue", status: "stub" });
    });
  });

  // ---------------------------------------------------------------------------
  // 8. Law 1 (No execution without warrant) & Promote Verification
  // ---------------------------------------------------------------------------
  describe("8. Law 1 Enforcement & Job Promotion Verification", async () => {
    it("Law 1: refuses to lease builder job unbacked by open warrant", async () => {
      const { appendFileSync, mkdirSync } = await import("node:fs");
      mkdirSync(join(tempDir, "ledger"), { recursive: true });
      const keypair = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:queue": keypair.publicKey });
      const ghostJobEvent = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 1,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "queue" },
          ts: new Date().toISOString(),
          type: "job.enqueued",
          writer: { ns: "tool:queue", key_id: keypair.keyId },
          idempotency_key: `ghost-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: ulid(), warrant_id: "non-existent-warrant", role: "builder", tier: "flash", attempt: 1 },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(ghostJobEvent) + "\n", "utf8");

      const leaseRes = leaseNextJob(tempDir);
      assert.equal(leaseRes.ok, false);
      assert.equal(leaseRes.exit_code, EXIT_CODES.POLICY_DENIAL);
    });

    it("promoteJob verifies notary:mergeproof verdict and epoch", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });
      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);

      // Missing verdict rejects with POLICY_DENIAL (4)
      const missingVerdict = promoteJob(tempDir, { jobId: leased.job_id });
      assert.equal(missingVerdict.exit_code, EXIT_CODES.POLICY_DENIAL);

      // Append verdict from notary:mergeproof
      const notaryKp = generateEd25519Keypair();
      const baseSha = sha256("base commit 1");
      saveKeyring(tempDir, { "notary:mergeproof": notaryKp.publicKey });
      const verdictEvent = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 5,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "notary" },
          ts: new Date().toISOString(),
          type: "verdict.accepted",
          writer: { ns: "notary:mergeproof", key_id: notaryKp.keyId },
          idempotency_key: `verdict-${ulid()}`,
          prev_hash: sha256("prev"),
          payload: { job_id: leased.job_id, status: "accepted", base_sha: baseSha },
        },
        notaryKp.privateKey,
        notaryKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(verdictEvent) + "\n", "utf8");

      // Valid promotion succeeds
      const promoted = promoteJob(tempDir, { jobId: leased.job_id, baseSha });
      assert.equal(promoted.ok, true);
      assert.equal(promoted.status, "promoted");
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Regression Tests for Claude Opus 5.5 High Review Findings (B1–B7)
  // ---------------------------------------------------------------------------
  describe("9. Regression Tests: Blocking Fixes B1–B7", () => {
    it("B1: submitting one warrant and calling lease twice does not create a second concurrent lease", () => {
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const l1 = leaseNextJob(tempDir);
      assert.equal(l1.ok, true);
      assert.equal(l1.status, "leased");
      assert.equal(l1.warrant_id, warrant.id);

      // Calling lease again while warrant has an active unexpired lease must not lease it again
      const l2 = leaseNextJob(tempDir);
      assert.equal(l2.ok, true);
      assert.equal(l2.status, "empty");
      assert.equal(l2.job_id, undefined);

      const status = getQueueStatus(tempDir);
      assert.equal(status.active_leases.length, 1);
    });

    it("B2: lease expiry is detected and reaped by tick", () => {
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const t0 = 1_700_000_000_000;
      const ttl = 60_000;
      const l1 = leaseNextJob(tempDir, { nowMs: t0, ttl_ms: ttl });
      assert.equal(l1.ok, true);
      assert.equal(l1.status, "leased");

      // Verify active lease exists before expiry
      let status = getQueueStatus(tempDir, { nowMs: t0 + 10_000 });
      assert.equal(status.active_leases.length, 1);

      // Tick at t0 + 100_000 ms (lease has expired)
      tickQueue(tempDir, { nowMs: t0 + 100_000, repoRoot: ROOT });

      // Expired lease must be reaped
      status = getQueueStatus(tempDir, { nowMs: t0 + 100_000 });
      assert.equal(status.active_leases.length, 0);

      // Warrant should now be requeued / escalated to attempt 2
      assert.equal(status.warrants[warrant.id].failed_attempts, 1);
      assert.equal(status.warrants[warrant.id].status, "active");

      // Next lease is for attempt 2 (mid tier)
      const l2 = leaseNextJob(tempDir, { nowMs: t0 + 101_000 });
      assert.equal(l2.ok, true);
      assert.equal(l2.attempt, 2);
      assert.equal(l2.tier, "mid");
    });

    it("B3: verifyLeaseEpoch with undefined epoch or closed lease returns exit code 5 (STALE_EPOCH)", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });
      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);

      // undefined or null epoch -> STALE_EPOCH (5)
      assert.equal(verifyLeaseEpoch(tempDir, leased.job_id, undefined), EXIT_CODES.STALE_EPOCH);
      assert.equal(verifyLeaseEpoch(tempDir, leased.job_id, null), EXIT_CODES.STALE_EPOCH);

      // non-existent job -> STALE_EPOCH (5)
      assert.equal(verifyLeaseEpoch(tempDir, "non-existent-job", leased.epoch), EXIT_CODES.STALE_EPOCH);

      // Matching active epoch -> OK (0)
      assert.equal(verifyLeaseEpoch(tempDir, leased.job_id, leased.epoch), EXIT_CODES.OK);

      // Now close the lease by recording attempt outcome
      const keypair = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": keypair.publicKey });
      const outcomeEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 90,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: keypair.keyId },
          idempotency_key: `outcome-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: leased.job_id, warrant_id: warrant.id, status: "completed", verdict: "auto_merge" },
        },
        keypair.privateKey,
        keypair.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(outcomeEvt) + "\n", "utf8");

      // Closed lease (no live lease) must return STALE_EPOCH (5)
      assert.equal(verifyLeaseEpoch(tempDir, leased.job_id, leased.epoch), EXIT_CODES.STALE_EPOCH);
    });

    it("B4: promotion with expired lease or mismatched base SHA rejected; forged factory.resumed does not lift halt", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant();
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const t0 = 1_700_000_000_000;
      const ttl = 60_000;
      const leased = leaseNextJob(tempDir, { nowMs: t0, ttl_ms: ttl });
      assert.equal(leased.ok, true);

      const notaryKp = generateEd25519Keypair();
      const baseSha = sha256("canonical-base-commit");

      // Save keyring with notary:mergeproof and human:owner
      const ownerKp = generateEd25519Keypair();
      const keyring = {
        "notary:mergeproof": notaryKp.publicKey,
        "human:owner": ownerKp.publicKey,
      };
      saveKeyring(tempDir, keyring);

      const verdictEvent = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 10,
          epoch: leased.epoch,
          hlc: { wall_ms: t0 + 1000, logical: 0, node: "notary" },
          ts: new Date(t0 + 1000).toISOString(),
          type: "verdict.accepted",
          writer: { ns: "notary:mergeproof", key_id: notaryKp.keyId },
          idempotency_key: `verdict-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: leased.job_id, status: "accepted", base_sha: baseSha },
        },
        notaryKp.privateKey,
        notaryKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(verdictEvent) + "\n", "utf8");

      // 1. Mismatched base SHA -> POLICY_DENIAL (4)
      const mismatchRes = promoteJob(tempDir, { jobId: leased.job_id, baseSha: sha256("wrong-base") });
      assert.equal(mismatchRes.ok, false);
      assert.equal(mismatchRes.exit_code, EXIT_CODES.POLICY_DENIAL);

      // 2. Expired lease -> STALE_EPOCH (5)
      const expiredRes = promoteJob(tempDir, { jobId: leased.job_id, baseSha, nowMs: t0 + 100_000 });
      assert.equal(expiredRes.ok, false);
      assert.equal(expiredRes.exit_code, EXIT_CODES.STALE_EPOCH);

      // 3. Forged factory.resumed with untrusted key does not lift halt
      haltQueue(tempDir, "Safety halt");
      assert.equal(getQueueStatus(tempDir).halted, true);

      const evilKp = generateEd25519Keypair();
      const forgedResume = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 12,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "attacker" },
          ts: new Date().toISOString(),
          type: "factory.resumed",
          writer: { ns: "human:owner", key_id: evilKp.keyId },
          idempotency_key: `forged-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { reason: "Forged resume" },
        },
        evilKp.privateKey,
        evilKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedResume) + "\n", "utf8");

      // Halt must NOT be lifted because evilKp is not in keyring.json!
      const statusAfterForged = getQueueStatus(tempDir);
      assert.equal(statusAfterForged.halted, true);

      // Real owner with registered key CAN lift halt
      const genuineResume = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 13,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
          ts: new Date().toISOString(),
          type: "factory.resumed",
          writer: { ns: "human:owner", key_id: ownerKp.keyId },
          idempotency_key: `genuine-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { reason: "Genuine owner resume" },
        },
        ownerKp.privateKey,
        ownerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(genuineResume) + "\n", "utf8");

      assert.equal(getQueueStatus(tempDir).halted, false);
    });

    it("B5: one warrant in NEEDS_HUMAN does not stop unrelated active warrants from being leased", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant1 = makeValidWarrant({ id: ulid(1_700_000_100_000), semantic_fingerprint: sha256("w1") });
      const warrant2 = makeValidWarrant({ id: ulid(1_700_000_200_000), semantic_fingerprint: sha256("w2") });

      submitWarrant(tempDir, warrant1, { repoRoot: ROOT });

      // Lease warrant 1 and record 3 failures so warrant 1 enters NEEDS_HUMAN
      const supervisorKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": supervisorKp.publicKey });
      for (let attempt = 1; attempt <= 3; attempt++) {
        const l = leaseNextJob(tempDir);
        assert.equal(l.warrant_id, warrant1.id);
        const failEvt = signEvent(
          {
            v: 1,
            id: ulid(),
            tenant_id: "mirql-core",
            seq: 20 + attempt,
            epoch: l.epoch,
            hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
            ts: new Date().toISOString(),
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor", key_id: supervisorKp.keyId },
            idempotency_key: `fail-${attempt}-${ulid()}`,
            prev_hash: sha256("p"),
            payload: { job_id: l.job_id, warrant_id: warrant1.id, status: "failed", verdict: "reject" },
          },
          supervisorKp.privateKey,
          supervisorKp.keyId,
        );
        appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(failEvt) + "\n", "utf8");
      }

      // Check status: warrant 1 is needs_human
      const status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant1.id].status, "needs_human");

      // Submit warrant 2 and verify leasing selects warrant 2, NOT block with NEEDS_HUMAN
      submitWarrant(tempDir, warrant2, { repoRoot: ROOT });
      const l2 = leaseNextJob(tempDir);
      assert.equal(l2.ok, true);
      assert.equal(l2.warrant_id, warrant2.id);
      assert.equal(l2.status, "leased");

      // Resolving parked warrant 1 via human.approval unparks it
      const ownerKp = generateEd25519Keypair();
      const approvalEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 30,
          epoch: 2,
          hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
          ts: new Date().toISOString(),
          type: "human.approval",
          writer: { ns: "human:owner", key_id: ownerKp.keyId },
          idempotency_key: `approval-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { warrant_id: warrant1.id, status: "active" },
        },
        ownerKp.privateKey,
        ownerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(approvalEvt) + "\n", "utf8");

      // Before keyring registration, privileged human.approval fails closed
      assert.equal(getQueueStatus(tempDir).warrants[warrant1.id].status, "needs_human");

      // Register ownerKp in keyring
      saveKeyring(tempDir, { ...(loadKeyring(tempDir) || {}), "human:owner": ownerKp.publicKey });

      const statusAfterApproval = getQueueStatus(tempDir);
      assert.equal(statusAfterApproval.warrants[warrant1.id].status, "active");
    });

    it("B6: reused warrant id rejected with exit code 4 (POLICY_DENIAL)", () => {
      const fixedId = ulid(1_700_000_999_000);
      const warrant1 = makeValidWarrant({ id: fixedId, semantic_fingerprint: sha256("warrant-orig") });
      const res1 = submitWarrant(tempDir, warrant1, { repoRoot: ROOT });
      assert.equal(res1.ok, true);
      assert.equal(res1.status, "submitted");

      // Resubmitting a warrant with the exact same ID (even with different fingerprint)
      const warrant2 = makeValidWarrant({ id: fixedId, semantic_fingerprint: sha256("warrant-different-intent") });
      const res2 = submitWarrant(tempDir, warrant2, { repoRoot: ROOT });
      assert.equal(res2.ok, false);
      assert.equal(res2.status, "rejected");
      assert.equal(res2.exit_code, EXIT_CODES.POLICY_DENIAL);
    });

    it("B7: concurrent appends serialize cleanly with the lockfile", async () => {
      const { readFileSync } = await import("node:fs");
      const keypair = generateEd25519Keypair();

      // Launch 8 concurrent appendLedgerEvent calls
      const promises = [];
      for (let i = 0; i < 8; i++) {
        promises.push(
          Promise.resolve().then(() => {
            return appendLedgerEvent(
              tempDir,
              {
                type: "job.enqueued",
                payload: { job_id: ulid(), index: i },
              },
              keypair,
            );
          }),
        );
      }

      const results = await Promise.all(promises);
      assert.equal(results.length, 8);

      // Verify ledger has sequential seq 1..8 and valid hash chain
      const ledgerPath = join(tempDir, "ledger", "events.jsonl");
      const lines = readFileSync(ledgerPath, "utf8").trim().split(/\r?\n/);
      assert.equal(lines.length, 8);

      const events = lines.map((l) => JSON.parse(l));
      for (let i = 0; i < events.length; i++) {
        assert.equal(events[i].seq, i + 1, `seq at index ${i} should be ${i + 1}`);
        if (i === 0) {
          assert.equal(events[i].prev_hash, "sha256:0000000000000000000000000000000000000000000000000000000000000000");
        } else {
          assert.equal(events[i].prev_hash, events[i - 1].hash);
        }
      }
    });

    it("R1: concurrent child processes calling lease receive distinct epochs and unique jobs", async () => {
      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const execFileAsync = promisify(execFile);

      // Submit 4 distinct warrants
      for (let i = 1; i <= 4; i++) {
        const warrant = makeValidWarrant({
          id: ulid(1_700_000_300_000 + i * 1000),
          semantic_fingerprint: sha256(`concurrent-warrant-${i}`),
        });
        const sub = submitWarrant(tempDir, warrant, { repoRoot: ROOT });
        assert.equal(sub.ok, true);
      }

      // Concurrently invoke `mirql q lease --dir <tempDir> --concurrency 4` using 4 child processes
      const mirqlBin = join(ROOT, "bin", "mirql.mjs");
      const spawnLease = () =>
        execFileAsync(process.execPath, [
          mirqlBin,
          "q",
          "lease",
          "--dir",
          tempDir,
          "--concurrency",
          "4",
        ]);

      const runs = await Promise.all([
        spawnLease(),
        spawnLease(),
        spawnLease(),
        spawnLease(),
      ]);

      const parsedResults = runs.map((r) => {
        assert.equal(r.stderr, "");
        return JSON.parse(r.stdout.trim());
      });

      // Verify all 4 succeeded
      for (const res of parsedResults) {
        assert.equal(res.ok, true);
        assert.equal(res.status, "leased");
      }

      // Assert distinct epochs [2, 3, 4, 5]
      const epochs = parsedResults.map((r) => r.epoch).sort((a, b) => a - b);
      assert.deepEqual(epochs, [2, 3, 4, 5]);

      // Assert distinct jobs and warrants
      const jobIds = new Set(parsedResults.map((r) => r.job_id));
      assert.equal(jobIds.size, 4);

      const warrantIds = new Set(parsedResults.map((r) => r.warrant_id));
      assert.equal(warrantIds.size, 4);
    });

    it("R2: privileged events fail closed when no keyring exists or key not registered", async () => {
      const { appendFileSync, unlinkSync, existsSync } = await import("node:fs");

      // Halt queue
      haltQueue(tempDir, "Safety halt");
      assert.equal(getQueueStatus(tempDir).halted, true);

      // Ensure keyring does NOT exist
      const keyringPath = trustFile(tempDir, "keyring.json");
      if (existsSync(keyringPath)) {
        unlinkSync(keyringPath);
      }

      // An attacker signs a factory.resumed event
      const attackerKp = generateEd25519Keypair();
      const resumeEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 50,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "attacker" },
          ts: new Date().toISOString(),
          type: "factory.resumed",
          writer: { ns: "human:owner", key_id: attackerKp.keyId },
          idempotency_key: `resume-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { reason: "Attacker resume without keyring" },
        },
        attackerKp.privateKey,
        attackerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(resumeEvt) + "\n", "utf8");

      // When no keyring.json exists, privileged event MUST be rejected / ignored
      const statusNoKeyring = getQueueStatus(tempDir);
      assert.equal(statusNoKeyring.halted, true);

      // Now create a keyring with tool:queue and daemon:lifeguard, NOT human:owner
      const lifeguardKp = generateEd25519Keypair();
      const queueKp = getOrCreateQueueKeypair(tempDir);
      saveKeyring(tempDir, {
        "tool:queue": queueKp.publicKey,
        "daemon:lifeguard": lifeguardKp.publicKey,
      });

      // Append another resume event with unregistered key
      const resumeEvt2 = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 51,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "attacker" },
          ts: new Date().toISOString(),
          type: "factory.resumed",
          writer: { ns: "human:owner", key_id: attackerKp.keyId },
          idempotency_key: `resume2-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { reason: "Attacker resume not in keyring" },
        },
        attackerKp.privateKey,
        attackerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(resumeEvt2) + "\n", "utf8");

      // Key not registered in keyring -> still ignored!
      const statusKeyNotRegistered = getQueueStatus(tempDir);
      assert.equal(statusKeyNotRegistered.halted, true);

      // Now register human:owner with valid public key
      const validOwnerKp = generateEd25519Keypair();
      saveKeyring(tempDir, {
        "daemon:lifeguard": lifeguardKp.publicKey,
        "human:owner": validOwnerKp.publicKey,
      });

      const validResumeEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 52,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
          ts: new Date().toISOString(),
          type: "factory.resumed",
          writer: { ns: "human:owner", key_id: validOwnerKp.keyId },
          idempotency_key: `valid-resume-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { reason: "Authorized owner resume" },
        },
        validOwnerKp.privateKey,
        validOwnerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(validResumeEvt) + "\n", "utf8");

      // With registered key and valid signature, privileged event is accepted
      const statusAuthorized = getQueueStatus(tempDir);
      assert.equal(statusAuthorized.halted, false);
    });

    it("R3: promotion closes active lease and timeouts/outcomes for completed warrants are ignored", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant({ id: ulid(1_700_000_400_000), semantic_fingerprint: sha256("warrant-r3") });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);
      assert.equal(leased.status, "leased");

      // Verify active lease exists prior to promotion
      const statusBefore = getQueueStatus(tempDir);
      assert.ok(statusBefore.active_leases.some((l) => l.job_id === leased.job_id));

      // Issue valid verdict from registered notary:mergeproof
      const notaryKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "notary:mergeproof": notaryKp.publicKey });
      const baseSha = sha256("base commit r3");

      const verdictEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 60,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "notary" },
          ts: new Date().toISOString(),
          type: "verdict.accepted",
          writer: { ns: "notary:mergeproof", key_id: notaryKp.keyId },
          idempotency_key: `verdict-r3-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: leased.job_id, status: "accepted", base_sha: baseSha },
        },
        notaryKp.privateKey,
        notaryKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(verdictEvt) + "\n", "utf8");

      // Promote the job
      const promoteRes = promoteJob(tempDir, { jobId: leased.job_id, baseSha });
      assert.equal(promoteRes.ok, true);
      assert.equal(promoteRes.status, "promoted");

      // Verify active lease is deleted upon promotion
      const statusAfter = getQueueStatus(tempDir);
      assert.equal(statusAfter.active_leases.some((l) => l.job_id === leased.job_id), false);
      assert.equal(statusAfter.warrants[warrant.id].status, "completed");

      // Re-promoting the same job returns STALE_EPOCH (5) because lease is closed
      const secondPromote = promoteJob(tempDir, { jobId: leased.job_id, baseSha });
      assert.equal(secondPromote.ok, false);
      assert.equal(secondPromote.exit_code, EXIT_CODES.STALE_EPOCH);

      // Appending subsequent timeout for completed warrant MUST be ignored
      const supervisorKp = generateEd25519Keypair();
      const timeoutEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 62,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "job.timeout",
          writer: { ns: "tool:queue", key_id: supervisorKp.keyId },
          idempotency_key: `timeout-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: leased.job_id, warrant_id: warrant.id, epoch: leased.epoch, reason: "late_timeout" },
        },
        supervisorKp.privateKey,
        supervisorKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(timeoutEvt) + "\n", "utf8");

      // Status must remain completed, NOT reset to active!
      const statusAfterTimeout = getQueueStatus(tempDir);
      assert.equal(statusAfterTimeout.warrants[warrant.id].status, "completed");
      assert.equal(statusAfterTimeout.warrants[warrant.id].failed_attempts, 0);

      // Appending a late failed outcome must also be ignored
      const lateFailEvt = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 63,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: supervisorKp.keyId },
          idempotency_key: `fail-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: leased.job_id, warrant_id: warrant.id, status: "failed", verdict: "reject" },
        },
        supervisorKp.privateKey,
        supervisorKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(lateFailEvt) + "\n", "utf8");

      const statusAfterLateFail = getQueueStatus(tempDir);
      assert.equal(statusAfterLateFail.warrants[warrant.id].status, "completed");
      assert.equal(statusAfterLateFail.warrants[warrant.id].failed_attempts, 0);
    });

    it("N1: unsigned or forged job.promoted, human.approval, and human.intent fail closed", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant({ id: ulid(1_700_000_500_000), semantic_fingerprint: sha256("warrant-n1") });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);
      assert.equal(leased.status, "leased");

      // 1. Unsigned job.promoted MUST NOT complete warrant or close lease
      const unsignedPromote = {
        v: 1,
        id: ulid(),
        tenant_id: "mirql-core",
        seq: 70,
        epoch: leased.epoch,
        hlc: { wall_ms: Date.now(), logical: 0, node: "queue" },
        ts: new Date().toISOString(),
        type: "job.promoted",
        writer: { ns: "tool:queue", key_id: "fake-key" },
        idempotency_key: `forged-prom-${ulid()}`,
        prev_hash: sha256("p"),
        payload: { job_id: leased.job_id, warrant_id: warrant.id, epoch: leased.epoch, base_sha: sha256("base") },
      };
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), JSON.stringify(unsignedPromote) + "\n", "utf8");

      let status = getQueueStatus(tempDir);
      assert.notEqual(status.warrants[warrant.id].status, "completed");
      assert.equal(status.active_leases.some((l) => l.job_id === leased.job_id), true);

      // 2. Forged job.promoted with unregistered attacker key MUST NOT complete warrant
      const attackerKp = generateEd25519Keypair();
      const forgedPromote = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 71,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "queue" },
          ts: new Date().toISOString(),
          type: "job.promoted",
          writer: { ns: "tool:queue", key_id: attackerKp.keyId },
          idempotency_key: `forged-prom-2-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { job_id: leased.job_id, warrant_id: warrant.id, epoch: leased.epoch, base_sha: sha256("base") },
        },
        attackerKp.privateKey,
        attackerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedPromote) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      assert.notEqual(status.warrants[warrant.id].status, "completed");
      assert.equal(status.active_leases.some((l) => l.job_id === leased.job_id), true);

      // Now fail the job 3 times to put warrant into needs_human
      const supervisorKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": supervisorKp.publicKey });
      let currentLease = leased;
      for (let attempt = 1; attempt <= 3; attempt++) {
        if (attempt > 1) {
          currentLease = leaseNextJob(tempDir);
        }
        const failEvt = signEvent(
          {
            v: 1,
            id: ulid(),
            tenant_id: "mirql-core",
            seq: 72 + attempt,
            epoch: currentLease.epoch,
            hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
            ts: new Date().toISOString(),
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor", key_id: supervisorKp.keyId },
            idempotency_key: `fail-${attempt}-${ulid()}`,
            prev_hash: sha256("p"),
            payload: { job_id: currentLease.job_id, warrant_id: warrant.id, status: "failed", verdict: "reject" },
          },
          supervisorKp.privateKey,
          supervisorKp.keyId,
        );
        appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(failEvt) + "\n", "utf8");
      }

      status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant.id].status, "needs_human");

      // 3. Unsigned human.approval MUST NOT unpark warrant
      const unsignedApproval = {
        v: 1,
        id: ulid(),
        tenant_id: "mirql-core",
        seq: 80,
        epoch: leased.epoch,
        hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
        ts: new Date().toISOString(),
        type: "human.approval",
        writer: { ns: "human:owner", key_id: "fake-key" },
        idempotency_key: `unsigned-app-${ulid()}`,
        prev_hash: sha256("p"),
        payload: { warrant_id: warrant.id, status: "active" },
      };
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), JSON.stringify(unsignedApproval) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant.id].status, "needs_human");

      // 4. Forged human.approval with unregistered attacker key MUST NOT unpark warrant
      const forgedApproval = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 81,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
          ts: new Date().toISOString(),
          type: "human.approval",
          writer: { ns: "human:owner", key_id: attackerKp.keyId },
          idempotency_key: `forged-app-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { warrant_id: warrant.id, status: "active" },
        },
        attackerKp.privateKey,
        attackerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedApproval) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant.id].status, "needs_human");

      // 5. Forged human.intent with unregistered attacker key MUST NOT unpark warrant
      const forgedIntent = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 82,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
          ts: new Date().toISOString(),
          type: "human.intent",
          writer: { ns: "human:owner", key_id: attackerKp.keyId },
          idempotency_key: `forged-intent-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { warrant_id: warrant.id },
        },
        attackerKp.privateKey,
        attackerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedIntent) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant.id].status, "needs_human");

      // 6. Properly signed human.approval with registered key in keyring DOES work
      const genuineOwnerKp = generateEd25519Keypair();
      saveKeyring(tempDir, { ...(loadKeyring(tempDir) || {}), "human:owner": genuineOwnerKp.publicKey });

      const genuineApproval = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 83,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "owner" },
          ts: new Date().toISOString(),
          type: "human.approval",
          writer: { ns: "human:owner", key_id: genuineOwnerKp.keyId },
          idempotency_key: `genuine-app-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { warrant_id: warrant.id, status: "active" },
        },
        genuineOwnerKp.privateKey,
        genuineOwnerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(genuineApproval) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant.id].status, "active");
      assert.equal(status.warrants[warrant.id].failed_attempts, 0);
    });

    it("N1 (universal): unsigned job.leased or forged attempt.outcome cannot revive expired lease or complete warrant", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant({ id: ulid(1_700_000_600_000), semantic_fingerprint: sha256("warrant-n1-universal") });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);
      assert.equal(leased.status, "leased");

      // 1. Manually append an unsigned job.leased event with epoch 99
      const unsignedLease = {
        v: 1,
        id: ulid(),
        tenant_id: "mirql-core",
        seq: 10,
        epoch: 99,
        hlc: { wall_ms: Date.now(), logical: 0, node: "queue" },
        ts: new Date().toISOString(),
        type: "job.leased",
        writer: { ns: "tool:queue", key_id: "unsigned-key" },
        idempotency_key: `unsigned-lease-${ulid()}`,
        prev_hash: sha256("p"),
        payload: {
          job_id: leased.job_id,
          warrant_id: warrant.id,
          epoch: 99,
          leased_at_ms: Date.now(),
          ttl_ms: 600000,
        },
      };
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), JSON.stringify(unsignedLease) + "\n", "utf8");

      let status = getQueueStatus(tempDir);
      // Epoch must remain what genuine leasing gave, NOT 99 from unsigned event
      assert.equal(status.epoch, leased.epoch);

      // 2. Forged attempt.outcome with unregistered key claiming completed
      const attackerKp = generateEd25519Keypair();
      const forgedOutcome = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 11,
          epoch: leased.epoch,
          hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
          ts: new Date().toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: attackerKp.keyId },
          idempotency_key: `forged-outcome-${ulid()}`,
          prev_hash: sha256("p"),
          payload: {
            job_id: leased.job_id,
            warrant_id: warrant.id,
            status: "completed",
            verdict: "auto_merge",
          },
        },
        attackerKp.privateKey,
        attackerKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedOutcome) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      // Forged outcome must be ignored: warrant still in_progress under live lease, not completed
      assert.equal(status.warrants[warrant.id].status, "in_progress");
      assert.equal(status.active_leases.some((l) => l.job_id === leased.job_id), true);
    });

    it("N2 (namespace binding): key registered for tool:queue cannot sign factory.resumed as human:owner", async () => {
      const { appendFileSync } = await import("node:fs");

      // Halt queue and ensure tool:queue key is registered in keyring
      haltQueue(tempDir, "Safety halt");
      assert.equal(getQueueStatus(tempDir).halted, true);

      const queueKp = getOrCreateQueueKeypair(tempDir);

      // Attempt to sign factory.resumed using queueKp, but claiming writer namespace human:owner
      const forgedResume = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 30,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "queue" },
          ts: new Date().toISOString(),
          type: "factory.resumed",
          writer: { ns: "human:owner", key_id: queueKp.keyId },
          idempotency_key: `impersonated-resume-${ulid()}`,
          prev_hash: sha256("p"),
          payload: { reason: "Impersonating owner with queue key" },
        },
        queueKp.privateKey,
        queueKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedResume) + "\n", "utf8");

      // Event MUST be rejected: queue must remain halted!
      const status = getQueueStatus(tempDir);
      assert.equal(status.halted, true);

      // Also verify tool:queue key cannot sign verdict.accepted as notary:mergeproof
      const forgedVerdict = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 31,
          epoch: 1,
          hlc: { wall_ms: Date.now(), logical: 0, node: "queue" },
          ts: new Date().toISOString(),
          type: "verdict.accepted",
          writer: { ns: "notary:mergeproof", key_id: queueKp.keyId },
          idempotency_key: `impersonated-verdict-${ulid()}`,
          prev_hash: sha256("p"),
          payload: {
            job_id: "fake-job",
            warrant_id: "fake-warrant",
            verdict: "auto_merge",
            base_sha: sha256("base"),
          },
        },
        queueKp.privateKey,
        queueKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(forgedVerdict) + "\n", "utf8");

      const rawState = foldQueueState(tempDir);
      assert.equal(Boolean(rawState.verdicts["fake-job"]), false);
    });

    it("N3 (hash chain): after a skipped line in events.jsonl, the next appended event has continuous seq and unbroken prev_hash", async () => {
      const { appendFileSync, readFileSync } = await import("node:fs");
      const warrant = makeValidWarrant({ id: ulid(1_700_000_700_000), semantic_fingerprint: sha256("warrant-n3-chain") });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const ledgerPath = join(tempDir, "ledger", "events.jsonl");
      let lines = readFileSync(ledgerPath, "utf8").trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
      const lastValidEvent = JSON.parse(lines[lines.length - 1]);

      // Manually append an invalid line (unauthorized writer namespace) with valid sequence and hash
      const invalidSeq = lastValidEvent.seq + 1;
      const invalidPrevHash = lastValidEvent.hash;
      const invalidRaw = {
        v: 1,
        id: ulid(),
        tenant_id: "mirql-core",
        seq: invalidSeq,
        epoch: 1,
        hlc: { wall_ms: Date.now(), logical: 0, node: "attacker" },
        ts: new Date().toISOString(),
        type: "job.enqueued",
        writer: { ns: "attacker:rogue", key_id: "rogue-key" },
        idempotency_key: `rogue-${ulid()}`,
        prev_hash: invalidPrevHash,
        payload: { job_id: "rogue-job" },
      };
      const invalidHash = sha256(jcs(invalidRaw));
      invalidRaw.hash = invalidHash;

      appendFileSync(ledgerPath, JSON.stringify(invalidRaw) + "\n", "utf8");

      // Now invoke leaseNextJob. It reads ledger via foldLedger under withLedgerLock,
      // recognizes disk_seq and disk_last_hash from the invalid line, and appends job.leased.
      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);

      lines = readFileSync(ledgerPath, "utf8").trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
      const allEvents = lines.map((l) => JSON.parse(l));

      const skippedEvent = allEvents[allEvents.length - 2];
      const newlyAppendedEvent = allEvents[allEvents.length - 1];

      assert.equal(skippedEvent.seq, invalidSeq);
      assert.equal(newlyAppendedEvent.seq, invalidSeq + 1, "next sequence must be skipped line seq + 1");
      assert.equal(newlyAppendedEvent.prev_hash, skippedEvent.hash, "prev_hash must chain to skipped line hash");
    });

    it("stale success outcome for expired lease (epoch 2) is rejected while lease 2 (epoch 3) is running", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant({ id: ulid(1_700_000_800_000), semantic_fingerprint: sha256("warrant-stale-success") });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      // Lease 1 (epoch 2)
      const l1 = leaseNextJob(tempDir);
      assert.equal(l1.ok, true);
      assert.equal(l1.epoch, 2);

      // Advance time past lease 1 expiry and reap via tickQueue
      const reapTime = l1.leased_at_ms + l1.ttl_ms + 1000;
      tickQueue(tempDir, { repoRoot: ROOT, nowMs: reapTime });

      let status = getQueueStatus(tempDir, { nowMs: reapTime });
      assert.equal(status.active_leases.length, 0);
      assert.equal(status.warrants[warrant.id].failed_attempts, 1);

      // Lease 2 (epoch 3) is now running
      const l2 = leaseNextJob(tempDir, { nowMs: reapTime + 1000 });
      assert.equal(l2.ok, true);
      assert.equal(l2.epoch, 3);
      assert.equal(l2.attempt, 2);

      // Late outcome for lease 1 arrives reporting completed with epoch 2
      const supervisorKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": supervisorKp.publicKey });

      const lateOutcome = signEvent(
        {
          v: 1,
          id: ulid(),
          tenant_id: "mirql-core",
          seq: 90,
          epoch: 2,
          hlc: { wall_ms: reapTime + 2000, logical: 0, node: "supervisor" },
          ts: new Date(reapTime + 2000).toISOString(),
          type: "attempt.outcome",
          writer: { ns: "tool:run_supervisor", key_id: supervisorKp.keyId },
          idempotency_key: `late-success-${ulid()}`,
          prev_hash: sha256("p"),
          payload: {
            job_id: l1.job_id,
            warrant_id: warrant.id,
            epoch: 2,
            status: "completed",
            verdict: "auto_merge",
            cost_micro_usd: 15_000,
            tokens_consumed: 120,
          },
        },
        supervisorKp.privateKey,
        supervisorKp.keyId,
      );
      appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(lateOutcome) + "\n", "utf8");

      status = getQueueStatus(tempDir);
      // Stale outcome MUST NOT mark warrant as completed!
      assert.notEqual(status.warrants[warrant.id].status, "completed");
      assert.equal(status.warrants[warrant.id].status, "in_progress");
      // Active lease 2 (epoch 3) must still be active
      assert.equal(status.active_leases.some((l) => l.job_id === l2.job_id && l.epoch === 3), true);
      // Cumulative spend is recorded
      assert.equal(status.budget_spent_micro_usd, 15_000);
    });

    it("outcome for an unknown job id that was never leased does not increment failed attempts or push warrant to needs_human", async () => {
      const { appendFileSync } = await import("node:fs");
      const warrant = makeValidWarrant({ id: ulid(1_700_000_900_000), semantic_fingerprint: sha256("warrant-unknown-job") });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      let status = getQueueStatus(tempDir);
      assert.equal(status.warrants[warrant.id].status, "active");
      assert.equal(status.warrants[warrant.id].failed_attempts, 0);

      const supervisorKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": supervisorKp.publicKey });
      const unleasedJobId = ulid();

      // Emit 5 failed outcomes for the unleased job id
      for (let i = 1; i <= 5; i++) {
        const bogusOutcome = signEvent(
          {
            v: 1,
            id: ulid(),
            tenant_id: "mirql-core",
            seq: 100 + i,
            epoch: 1,
            hlc: { wall_ms: Date.now(), logical: 0, node: "supervisor" },
            ts: new Date().toISOString(),
            type: "attempt.outcome",
            writer: { ns: "tool:run_supervisor", key_id: supervisorKp.keyId },
            idempotency_key: `bogus-${i}-${ulid()}`,
            prev_hash: sha256("p"),
            payload: {
              job_id: unleasedJobId,
              warrant_id: warrant.id,
              epoch: 1,
              status: "failed",
              verdict: "reject",
              cost_micro_usd: 5_000,
            },
          },
          supervisorKp.privateKey,
          supervisorKp.keyId,
        );
        appendFileSync(join(tempDir, "ledger", "events.jsonl"), jcs(bogusOutcome) + "\n", "utf8");
      }

      status = getQueueStatus(tempDir);
      // Warrant must remain healthy and active, NOT in needs_human
      assert.equal(status.warrants[warrant.id].status, "active");
      assert.equal(status.warrants[warrant.id].failed_attempts, 0);
      // Cost was tracked (5 * 5000 = 25000)
      assert.equal(status.budget_spent_micro_usd, 25_000);
    });
  });

  // ---------------------------------------------------------------------------
  // P0 Remediation: H1 (supervisor epoch threading) and H4 (key permissions)
  // ---------------------------------------------------------------------------
  describe("P0 Remediation: H1 supervisor epoch threading & H4 key permissions", () => {
    it("H1: supervisor threads the leased epoch (2) so the fold accepts attempt.outcome and completes the job", () => {
      const warrant = makeValidWarrant({
        id: ulid(1_700_001_000_000),
        semantic_fingerprint: sha256("warrant-h1-epoch-threading"),
      });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      // Lease the job — the first lease bumps the epoch from 1 to 2.
      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);
      assert.equal(leased.epoch, 2);

      // Register the supervisor writer key so the fold verifies its signature.
      const supervisorKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": supervisorKp.publicKey });

      const res = runSupervisor({
        mirqlDir: tempDir,
        keypair: supervisorKp,
        jobId: leased.job_id,
        warrantId: warrant.id,
        epoch: leased.epoch,
        builderCommand: "node -v",
        runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
      });

      assert.equal(res.verified, true);
      assert.equal(res.outcome.epoch, 2);
      assert.equal(res.event.epoch, 2);
      assert.equal(res.event.payload.epoch, 2);
      assert.equal(res.event.payload.status, "completed");

      const status = getQueueStatus(tempDir);
      // The fold ACCEPTED the outcome: job and warrant reach "completed".
      assert.equal(status.jobs[leased.job_id].status, "completed");
      assert.equal(status.jobs[leased.job_id].outcome_verdict, "auto_merge");
      assert.equal(status.warrants[warrant.id].status, "completed");
      const folded = foldQueueState(tempDir);
      assert.equal(folded.metrics.warrants_completed, 1);
      assert.equal(folded.metrics.jobs_completed, 1);
      // The lease is closed.
      assert.equal(status.active_leases.length, 0);
    });

    it("H1: a supervisor outcome with the default epoch 1 is still fenced off an epoch-2 lease (stale discard preserved)", () => {
      const warrant = makeValidWarrant({
        id: ulid(1_700_001_100_000),
        semantic_fingerprint: sha256("warrant-h1-stale-fence-preserved"),
      });
      submitWarrant(tempDir, warrant, { repoRoot: ROOT });

      const leased = leaseNextJob(tempDir);
      assert.equal(leased.ok, true);
      assert.equal(leased.epoch, 2);

      const supervisorKp = generateEd25519Keypair();
      saveKeyring(tempDir, { "tool:run_supervisor": supervisorKp.publicKey });

      // NOTE: no `epoch` passed — the supervisor records the legacy default 1.
      runSupervisor({
        mirqlDir: tempDir,
        keypair: supervisorKp,
        jobId: leased.job_id,
        warrantId: warrant.id,
        builderCommand: "node -v",
        runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
      });

      const status = getQueueStatus(tempDir);
      // Law 5 fencing still discards the mismatched-epoch outcome: the job
      // stays leased and the warrant does NOT complete.
      assert.equal(status.jobs[leased.job_id].status, "leased");
      assert.notEqual(status.warrants[warrant.id].status, "completed");
      assert.equal(status.active_leases.length, 1);
    });

    it("H4: getOrCreateQueueKeypair writes the private key 0o600 inside a 0o700 keys directory", () => {
      const kp = getOrCreateQueueKeypair(tempDir);
      const keyPath = trustFile(tempDir, "keys", "queue.key.json");
      assert.ok(existsSync(keyPath), "queue key file must exist");
      assert.equal(typeof kp.privateKey, "string");

      if (process.platform !== "win32") {
        assert.equal(statSync(keyPath).mode & 0o777, 0o600);
        assert.equal(statSync(trustFile(tempDir, "keys")).mode & 0o777, 0o700);
      }
    });
  });
});
