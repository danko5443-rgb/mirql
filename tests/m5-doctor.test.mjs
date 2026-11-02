import { provisionTestTrust } from "./helpers/keyring.mjs";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  normalizeFailureSignature,
  diagnoseHealth,
  evaluateCircuitBreakers,
  evaluateMacroStateTransition,
  BreakerStore,
  runDoctor,
  isCircuitBreakerTripped,
  SUBSYSTEMS,
  CIRCUIT_ACTIONS,
  MACRO_STATES,
} from "../packages/run/doctor.mjs";
import { runSupervisor } from "../packages/run/supervisor.mjs";
import { main as runCliMain } from "../packages/run/index.mjs";
import { submitWarrant, leaseNextJob, tick as queueTick } from "../packages/queue/index.mjs";
import { appendLedgerEventRaw, getOrCreateQueueKeypair } from "../packages/queue/ledger.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "../packages/run/ledger.mjs";
import { EXIT_CODES, jcs, sha256 } from "../packages/core/index.mjs";

describe("Milestone M5: Doctor & Circuit Breakers", () => {
  describe("1. Failure Signature Normalization", () => {
    it("normalizes timeout events with ms integers", () => {
      const sig1 = normalizeFailureSignature({
        type: "job.timeout",
        payload: { timeout_ms: 30000 },
      });
      assert.equal(sig1, "SIG:TIMEOUT:30000ms");

      const sig2 = normalizeFailureSignature("Command timed out after 15000ms");
      assert.equal(sig2, "SIG:TIMEOUT:15000ms");
    });

    it("normalizes assertion and test verification failures", () => {
      const sig = normalizeFailureSignature("AssertionError: expected 'pass' to equal 'fail'");
      assert.equal(sig, "SIG:ASSERTION:test_verification_failure");
    });

    it("normalizes syntax and parse errors", () => {
      const sig = normalizeFailureSignature(new SyntaxError("Unexpected token '{' at line 42"));
      assert.equal(sig, "SIG:SYNTAX:parse_error");
    });

    it("normalizes drift and surface violations", () => {
      const sig = normalizeFailureSignature("architectural drift detected in surface.lock");
      assert.equal(sig, "SIG:DRIFT:architectural_boundary_breach");
    });

    it("normalizes mutant survivor floor gaps", () => {
      const sig = normalizeFailureSignature("mutant kill rate 7500 bp below 8000 bp floor");
      assert.equal(sig, "SIG:MUTANT_SURVIVOR:floor_unmet");
    });

    it("normalizes flakiness and non-deterministic outcomes", () => {
      const sig = normalizeFailureSignature("non-deterministic flake detected across iterations");
      assert.equal(sig, "SIG:FLAKE:non_deterministic_execution");
    });

    it("normalizes real probe.completed failure events cleanly without raw JSON dump", () => {
      const sig = normalizeFailureSignature({
        type: "probe.completed",
        payload: { probe: "ast_claim_check_drift", type: "drift", status: "fail", failures: 1 },
      });
      assert.equal(sig, "SIG:PROBE_FAIL:drift");
    });

    it("normalizes lifeguard.alert events cleanly", () => {
      const sig = normalizeFailureSignature({
        type: "lifeguard.alert",
        payload: { reason: "heartbeat_timeout_stale" },
      });
      assert.equal(sig, "SIG:LIFEGUARD_ALERT:heartbeat_timeout_stale");
    });

    it("strips volatile ULIDs, timestamps, and memory hex addresses", () => {
      const raw = "Crash at 0xDEADBEEF during job 01ARZ3NDEKTSV4RRFFQ69G5FAV at 2026-11-01T12:00:00.000Z";
      const sig = normalizeFailureSignature(raw);
      assert.ok(!sig.includes("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
      assert.ok(!sig.includes("DEADBEEF"));
      assert.ok(!sig.includes("2026-11-01"));
    });
  });

  describe("2. Triage Diagnostic Engine (diagnoseHealth)", () => {
    it("returns clean healthy report when no failures exist", () => {
      const report = diagnoseHealth([], [], {}, { nowMs: 1700000000000 });
      assert.equal(report.healthy, true);
      assert.equal(report.incidents_count, 0);
      assert.equal(report.failure_signature, "SIG:CLEAN:all_systems_operational");
      assert.ok(Number.isSafeInteger(report.timestamp_ms));
      assert.deepEqual(report.affected_jobs, []);
      assert.deepEqual(report.affected_probes, []);
    });

    it("recognizes real probe.completed shape: status 'pass' is NOT reported as failure (Blocker B1)", () => {
      const events = [
        {
          type: "probe.completed",
          payload: {
            probe: "unit_conformance_suite",
            type: "tests",
            status: "pass",
            failures: 0,
            duration_ms: 50,
          },
        },
      ];
      const report = diagnoseHealth(events, [], {}, { nowMs: 1700000000000 });
      assert.equal(report.healthy, true);
      assert.equal(report.incidents_count, 0);
      assert.equal(report.failure_signature, "SIG:CLEAN:all_systems_operational");
    });

    it("aggregates recurring ledger failure events and identifies dominant signature", () => {
      const events = [
        {
          id: "01ARZ3NDEKTSV4RRFFQ69G5FA1",
          type: "job.failed",
          payload: { job_id: "01ARZ3NDEKTSV4RRFFQ69G5FA1", reason: "AssertionError: expected 1 to equal 0" },
        },
        {
          id: "01ARZ3NDEKTSV4RRFFQ69G5FA2",
          type: "job.failed",
          payload: { job_id: "01ARZ3NDEKTSV4RRFFQ69G5FA2", reason: "AssertionError: expected 2 to equal 0" },
        },
        {
          id: "01ARZ3NDEKTSV4RRFFQ69G5FA3",
          type: "job.timeout",
          payload: { job_id: "01ARZ3NDEKTSV4RRFFQ69G5FA3", timeout_ms: 10000 },
        },
      ];

      const report = diagnoseHealth(events, [], {}, { nowMs: 1700000000000 });
      assert.equal(report.healthy, false);
      assert.equal(report.incidents_count, 3);
      assert.equal(report.failure_signature, "SIG:ASSERTION:test_verification_failure");
      assert.ok(report.root_cause_analysis.includes("Test assertion regression"));
      assert.ok(report.recommended_remediation.includes("Revert breaking patch"));
      assert.equal(report.affected_jobs.length, 3);
    });

    it("detects probe failure outputs", () => {
      const probes = [
        { name: "drift", ok: false, passed: false, status: "fail", error: "public surface drift" },
        { name: "tests", ok: true, passed: true, status: "pass" },
      ];

      const report = diagnoseHealth([], probes, {}, { nowMs: 1700000000000 });
      assert.equal(report.healthy, false);
      assert.equal(report.failure_signature, "SIG:PROBE_FAIL:drift");
      assert.deepEqual(report.affected_probes, ["drift"]);
      assert.ok(report.recommended_remediation.includes("surface.lock"));
    });

    it("detects hung leases and exhausted retry warrants in queue status", () => {
      const queueStatus = {
        active_leases: {
          lease_1: {
            lease_id: "lease_1",
            job_id: "job_hung_1",
            leased_at_ms: 1000,
            ttl_ms: 5000,
            expires_at_ms: 6000,
          },
        },
        warrants: {
          w_needs_human: {
            id: "w_needs_human",
            status: "needs_human",
            failed_attempts: 3,
          },
        },
      };

      const report = diagnoseHealth([], [], queueStatus, { nowMs: 10000 });
      assert.equal(report.healthy, false);
      assert.equal(report.incidents_count, 2);
      assert.ok(report.affected_jobs.includes("job_hung_1"));
    });
  });

  describe("3. Multi-Tier Circuit Breakers (evaluateCircuitBreakers)", () => {
    it("returns reset action when all subsystems are healthy and metrics within bounds", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 1000000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics);
      assert.equal(res.action, "reset");
      assert.equal(res.target_subsystem, "all");
      assert.equal(res.cooldown_ms, 0);
      assert.equal(res.reason, "all_subsystems_healthy");
      assert.ok(Number.isSafeInteger(res.metrics.budget_spent_micro_usd));
      assert.ok(Number.isSafeInteger(res.metrics.consecutive_failures.flash));
    });

    it("trips circuit breaker when daily budget ceiling is exhausted (Law 17)", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 25000000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics);
      assert.equal(res.action, "trip");
      assert.equal(res.target_subsystem, "budget");
      assert.equal(res.reason, "daily_budget_exhausted");
      assert.equal(res.cooldown_ms, 172800000);
    });

    it("throttles budget when reaching high watermark (>= 90%)", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 22500000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics);
      assert.equal(res.action, "throttle");
      assert.equal(res.target_subsystem, "budget");
      assert.equal(res.reason, "daily_budget_near_ceiling");
    });

    it("throttles worker:flash when flash tier failures reach threshold", () => {
      const metrics = {
        tier_failures: { flash: 2, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 500000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics, { retries_per_tier: 2 });
      assert.equal(res.action, "throttle");
      assert.equal(res.target_subsystem, "worker:flash");
      assert.equal(res.reason, "flash_tier_failures_escalate_to_mid");
    });

    it("throttles worker:mid when mid tier failures reach threshold", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 2, max: 0 },
        daily_budget_spent_micro_usd: 500000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics, { retries_per_tier: 2 });
      assert.equal(res.action, "throttle");
      assert.equal(res.target_subsystem, "worker:mid");
      assert.equal(res.reason, "mid_tier_failures_escalate_to_max");
    });

    it("forces hardening when max tier failures reach threshold", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 2 },
        daily_budget_spent_micro_usd: 500000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics, { retries_per_tier: 2 });
      assert.equal(res.action, "force_harden");
      assert.equal(res.target_subsystem, "worker:max");
      assert.equal(res.reason, "max_tier_retry_exhausted_force_harden");
    });

    it("throttles queue when hung leases exist", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 10000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 2,
      };

      const res = evaluateCircuitBreakers(metrics);
      assert.equal(res.action, "throttle");
      assert.equal(res.target_subsystem, "queue");
      assert.equal(res.reason, "hung_leases_require_reap");
    });

    it("rejects tripping lifeguard under Law 2 unblockable kill authority (Blocker B7)", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 0,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      assert.throws(() => {
        evaluateCircuitBreakers(metrics, { manual_trip: "lifeguard" });
      }, /Cannot trip lifeguard/);
    });

    it("supports manual operator trip overrides for worker tiers", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 0,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics, { manual_trip: "worker:flash", cooldown_ms: 600000 });
      assert.equal(res.action, "trip");
      assert.equal(res.target_subsystem, "worker:flash");
      assert.equal(res.cooldown_ms, 600000);
      assert.equal(res.reason, "manual_operator_trip");
    });
  });

  describe("4. Macro-State Transition Triggers (Law 14)", () => {
    it("transitions BUILD -> HARDEN on force_harden breaker action", () => {
      const breaker = { action: "force_harden", reason: "max_tier_failures" };
      const triage = { healthy: false };
      const trans = evaluateMacroStateTransition("BUILD", triage, breaker);
      assert.equal(trans.should_transition, true);
      assert.equal(trans.from_state, "BUILD");
      assert.equal(trans.to_state, "HARDEN");
      assert.equal(trans.reason, "max_tier_failures");
    });

    it("transitions BUILD -> HARDEN when all warrants are resolved", () => {
      const breaker = { action: "reset" };
      const triage = { healthy: true };
      const trans = evaluateMacroStateTransition("BUILD", triage, breaker, { all_warrants_resolved: true });
      assert.equal(trans.should_transition, true);
      assert.equal(trans.from_state, "BUILD");
      assert.equal(trans.to_state, "HARDEN");
      assert.equal(trans.reason, "all_warrants_resolved");
    });

    it("transitions HARDEN -> PATROL when hardening passes", () => {
      const breaker = { action: "reset" };
      const triage = { healthy: true };
      const trans = evaluateMacroStateTransition("HARDEN", triage, breaker, { hardening_passed: true });
      assert.equal(trans.should_transition, true);
      assert.equal(trans.from_state, "HARDEN");
      assert.equal(trans.to_state, "PATROL");
      assert.equal(trans.reason, "hardening_passed");
    });

    it("transitions PATROL -> QUIESCENT when probes clean, triage healthy, and breakers clear (Law 14)", () => {
      const breaker = { action: "reset" };
      const triage = { healthy: true };
      const trans = evaluateMacroStateTransition("PATROL", triage, breaker, { probes_clean: true });
      assert.equal(trans.should_transition, true);
      assert.equal(trans.from_state, "PATROL");
      assert.equal(trans.to_state, "QUIESCENT");
      assert.equal(trans.reason, "probes_clean_head_unchanged");
    });

    it("blocks transition to QUIESCENT if circuit breaker is tripped", () => {
      const breaker = { action: "trip", target_subsystem: "worker:flash" };
      const triage = { healthy: true };
      const trans = evaluateMacroStateTransition("PATROL", triage, breaker, { probes_clean: true });
      assert.equal(trans.should_transition, false);
      assert.equal(trans.to_state, "PATROL");
    });

    it("halts immediately on Lifeguard daemon intervention (Law 2)", () => {
      const breaker = { action: "reset" };
      const triage = { healthy: false, lifeguard_halt: true };
      const trans = evaluateMacroStateTransition("BUILD", triage, breaker);
      assert.equal(trans.should_transition, true);
      assert.equal(trans.to_state, "HALTED");
    });
  });

  describe("5. Durable Ledger Persistence & BreakerStore (Law 4)", () => {
    let tmpDir;

    it("persists trips directly to the durable signed ledger and reconstructs state (Blocker B6)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-ledger-test-"));
      provisionTestTrust(tmpDir);
      const store = new BreakerStore(tmpDir);

      const entry = store.trip("worker:flash", "test_trip", 50000, 1000);
      assert.equal(entry.state, "tripped");
      assert.equal(entry.expires_at_ms, 51000);

      // Verify that authoritative event exists in .mirql/ledger/events.jsonl (Law 4)
      const eventsFile = join(tmpDir, "ledger", "events.jsonl");
      assert.ok(existsSync(eventsFile));
      const content = readFileSync(eventsFile, "utf8");
      assert.ok(content.includes('"probe":"doctor"'));
      assert.ok(content.includes('"action":"trip"'));

      // Reconstruct state from ledger
      assert.equal(isCircuitBreakerTripped(tmpDir, "worker:flash", 20000), true);
      assert.equal(isCircuitBreakerTripped(tmpDir, "worker:flash", 60000), false);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("resets individual subsystems and all subsystems via signed ledger events", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-ledger-test-"));
      provisionTestTrust(tmpDir);
      const store = new BreakerStore(tmpDir);

      store.trip("queue", "trip_queue", 100000, 1000);
      store.trip("budget", "trip_budget", 100000, 1000);

      assert.equal(store.isTripped("queue", 2000), true);
      assert.equal(store.isTripped("budget", 2000), true);

      store.reset("queue", 3000);
      assert.equal(store.isTripped("queue", 4000), false);
      assert.equal(store.isTripped("budget", 4000), true);

      store.reset("all", 5000);
      assert.equal(store.isTripped("budget", 6000), false);

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  describe("6. Real End-to-End Ledger Integration Tests (Claude Review Cases A–F)", () => {
    let tmpDir;

    it("Case A: Real passing probe produces healthy=true without false positive failure (Blocker B1)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-real-case-a-"));
      provisionTestTrust(tmpDir);
      const keypair = getOrGenerateSupervisorKey(tmpDir);

      appendSupervisorEvent(
        tmpDir,
        {
          type: "probe.completed",
          payload: {
            probe: "unit_conformance_suite",
            type: "tests",
            status: "pass",
            failures: 0,
            duration_ms: 120,
          },
          nowMs: 1000,
        },
        keypair,
      );

      const res = runDoctor({ mirqlDir: tmpDir, nowMs: 2000 });
      assert.equal(res.healthy, true);
      assert.equal(res.triage.healthy, true);
      assert.equal(res.triage.failure_signature, "SIG:CLEAN:all_systems_operational");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("Case B: Real leased and completed job does not show up as hung lease (Blocker B2)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-real-case-b-"));
      provisionTestTrust(tmpDir);
      const queueKeypair = getOrCreateQueueKeypair(tmpDir);
      const supervisorKeypair = getOrGenerateSupervisorKey(tmpDir);

      // Submit valid canonical warrant
      const wRes = submitWarrant(
        tmpDir,
        {
          v: 1,
          id: "01ARZ3NDEKTSV4RRFFQ69G5W01",
          class: "surgical",
          semantic_fingerprint: sha256("test-intent-1"),
          anchors: ["packages/core/**"],
          evidence: { test: 1 },
          red_check: { test: 1 },
          scope: { allow: 1 },
          budget_micro_usd: 1000000,
          created_by: "human:owner",
        },
        { nowMs: 1000 },
      );
      assert.equal(wRes.status, "submitted");

      // Lease job
      const lRes = leaseNextJob(tmpDir, { nowMs: 2000 });
      assert.equal(lRes.status, "leased");

      // Supervisor records passing attempt.outcome
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: lRes.epoch,
          payload: {
            job_id: lRes.job_id,
            warrant_id: lRes.warrant_id,
            status: "completed",
            verdict: "auto_merge",
            cost_micro_usd: 5000,
          },
          nowMs: 3000,
        },
        supervisorKeypair,
      );

      // Now 1 hour has passed (3,600,000 ms)
      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: 3600000 });
      assert.equal(docRes.breaker.metrics.hung_leases_count, 0);
      assert.notEqual(docRes.triage.failure_signature, "SIG:LEASE_HUNG:lease_timeout");
      assert.equal(docRes.healthy, true);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("Case C: Real worker failures correctly increment tier failure counts and throttle/harden (Blocker B3)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-real-case-c-"));
      provisionTestTrust(tmpDir);
      const queueKeypair = getOrCreateQueueKeypair(tmpDir);
      const supervisorKeypair = getOrGenerateSupervisorKey(tmpDir);

      // Submit warrant 1
      submitWarrant(
        tmpDir,
        {
          v: 1,
          id: "01ARZ3NDEKTSV4RRFFQ69G5W02",
          class: "surgical",
          semantic_fingerprint: sha256("test-intent-max"),
          anchors: ["packages/core/**"],
          evidence: { test: 1 },
          red_check: { test: 1 },
          scope: { allow: 1 },
          budget_micro_usd: 2000000,
          created_by: "human:owner",
        },
        { nowMs: 1000 },
      );

      // Warrant 1 Attempt 1 (flash): fail
      const l1 = leaseNextJob(tmpDir, { nowMs: 2000 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l1.epoch,
          payload: {
            job_id: l1.job_id,
            warrant_id: l1.warrant_id,
            status: "failed",
            verdict: "reject",
            cost_micro_usd: 10000,
          },
          nowMs: 3000,
        },
        supervisorKeypair,
      );

      // Warrant 1 Attempt 2 (mid): fail
      const l2 = leaseNextJob(tmpDir, { nowMs: 4000 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l2.epoch,
          payload: {
            job_id: l2.job_id,
            warrant_id: l2.warrant_id,
            status: "failed",
            verdict: "reject",
            cost_micro_usd: 10000,
          },
          nowMs: 5000,
        },
        supervisorKeypair,
      );

      // Submit warrant 2
      submitWarrant(
        tmpDir,
        {
          v: 1,
          id: "01ARZ3NDEKTSV4RRFFQ69G5W03",
          class: "surgical",
          semantic_fingerprint: sha256("test-intent-mid-2"),
          anchors: ["packages/core/**"],
          evidence: { test: 1 },
          red_check: { test: 1 },
          scope: { allow: 1 },
          budget_micro_usd: 2000000,
          created_by: "human:owner",
        },
        { nowMs: 5100 },
      );

      // Warrant 2 Attempt 1 (flash): fail
      const l3 = leaseNextJob(tmpDir, { nowMs: 5200 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l3.epoch,
          payload: {
            job_id: l3.job_id,
            warrant_id: l3.warrant_id,
            status: "failed",
            verdict: "reject",
            cost_micro_usd: 10000,
          },
          nowMs: 5300,
        },
        supervisorKeypair,
      );

      // Warrant 1 Attempt 3 (max): fail
      const l4 = leaseNextJob(tmpDir, { nowMs: 5400 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l4.epoch,
          payload: {
            job_id: l4.job_id,
            warrant_id: l4.warrant_id,
            status: "failed",
            verdict: "reject",
            cost_micro_usd: 10000,
          },
          nowMs: 5500,
        },
        supervisorKeypair,
      );

      // Warrant 2 Attempt 2 (mid): fail
      const l5 = leaseNextJob(tmpDir, { nowMs: 6000 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l5.epoch,
          payload: {
            job_id: l5.job_id,
            warrant_id: l5.warrant_id,
            status: "failed",
            verdict: "reject",
            cost_micro_usd: 10000,
          },
          nowMs: 6500,
        },
        supervisorKeypair,
      );

      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: 7000 });
      assert.equal(docRes.breaker.metrics.consecutive_failures.mid, 2);
      assert.equal(docRes.breaker.action, "throttle");
      assert.equal(docRes.breaker.target_subsystem, "worker:mid");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("Case D: Real macro-state changes are accurately recognized by Doctor (Blocker B4)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-real-case-d-"));
      provisionTestTrust(tmpDir);
      const keypair = getOrCreateQueueKeypair(tmpDir);

      appendLedgerEventRaw(
        tmpDir,
        {
          type: "factory.mode_changed",
          payload: { from_mode: "BUILD", to_mode: "PATROL" },
          nowMs: 1000,
        },
        keypair,
        {},
      );

      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: 2000 });
      assert.equal(docRes.transition.from_state, "PATROL");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("Case E: Daily budget window measures spend within last 24h, not lifetime (Blocker B5)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-real-case-e-"));
      provisionTestTrust(tmpDir);
      const queueKeypair = getOrCreateQueueKeypair(tmpDir);
      const supervisorKeypair = getOrGenerateSupervisorKey(tmpDir);

      const now = Date.now();
      const threeDaysAgo = now - (3 * 86400000);

      // Record 20 USD spent 3 days ago
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: 1,
          payload: {
            job_id: "01ARZ3NDEKTSV4RRFFQ69G5OLD",
            warrant_id: "01ARZ3NDEKTSV4RRFFQ69G5WOLD",
            cost_micro_usd: 20000000,
            status: "completed",
          },
          nowMs: threeDaysAgo,
        },
        supervisorKeypair,
      );

      // Record 1 USD spent today
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: 2,
          payload: {
            job_id: "01ARZ3NDEKTSV4RRFFQ69G5NEW",
            warrant_id: "01ARZ3NDEKTSV4RRFFQ69G5WNEW",
            cost_micro_usd: 1000000,
            status: "completed",
          },
          nowMs: now,
        },
        supervisorKeypair,
      );

      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: now });
      assert.equal(docRes.breaker.metrics.budget_spent_micro_usd, 1000000);
      assert.equal(docRes.breaker.action, "reset");
      assert.equal(docRes.healthy, true);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("Case F: Supervisor refuses execution when worker tier circuit breaker is tripped", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-supervisor-trip-"));
      provisionTestTrust(tmpDir);
      const store = new BreakerStore(tmpDir);
      store.trip("worker:flash", "test_worker_trip", 60000, Date.now());

      const warrant = {
        v: 1,
        id: "01ARZ3NDEKTSV4RRFFQ69G5W03",
        class: "surgical",
        semantic_fingerprint: sha256("test-intent-trip"),
        anchors: ["packages/core/**"],
        evidence: { test: 1 },
        red_check: { test: 1 },
        scope: { allow: 1 },
        budget_micro_usd: 1000000,
        created_by: "human:owner",
      };

      assert.throws(() => {
        runSupervisor({
          mirqlDir: tmpDir,
          warrant,
          skipPidFile: true,
          noHeartbeatTicker: true,
        });
      }, /Circuit breaker tripped for worker tier "flash"/);

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  describe("7. CLI Execution (mirql r doctor)", () => {
    let tmpDir;

    it("returns EXIT_CODES.OK when workspace and ledger are healthy", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      provisionTestTrust(tmpDir);
      mkdirSync(join(tmpDir, "ledger"), { recursive: true });
      writeFileSync(join(tmpDir, "ledger", "events.jsonl"), "", "utf8");

      const exitCode = runCliMain(["doctor", "--ledger", tmpDir]);
      assert.equal(exitCode, EXIT_CODES.OK);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("returns EXIT_CODES.OK on successful operator trip and reset actions (Major Issue M1)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      provisionTestTrust(tmpDir);
      mkdirSync(join(tmpDir, "ledger"), { recursive: true });

      const tripCode = runCliMain(["doctor", "--ledger", tmpDir, "--trip", "worker:flash"]);
      assert.equal(tripCode, EXIT_CODES.OK);

      // Verify that doctor status now reports DOMAIN_NEGATIVE (unhealthy due to tripped breaker)
      const checkCode = runCliMain(["doctor", "--ledger", tmpDir]);
      assert.equal(checkCode, EXIT_CODES.DOMAIN_NEGATIVE);

      // Reset and verify recovery
      const resetCode = runCliMain(["doctor", "--ledger", tmpDir, "--reset", "worker:flash"]);
      assert.equal(resetCode, EXIT_CODES.OK);

      const checkAfterReset = runCliMain(["doctor", "--ledger", tmpDir]);
      assert.equal(checkAfterReset, EXIT_CODES.OK);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("rejects --trip with no value or empty string with USAGE_ERROR (Major Issue M1)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      provisionTestTrust(tmpDir);
      const exitCode = runCliMain(["doctor", "--ledger", tmpDir, "--trip"]);
      assert.equal(exitCode, EXIT_CODES.USAGE_ERROR);
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("rejects --reset with no value or empty string with USAGE_ERROR (Major Issue M1)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      provisionTestTrust(tmpDir);
      const exitCode = runCliMain(["doctor", "--ledger", tmpDir, "--reset"]);
      assert.equal(exitCode, EXIT_CODES.USAGE_ERROR);
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("rejects non-integer --cooldown 1.9 under Law 17 safe integer rule (Major Issue M1)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      provisionTestTrust(tmpDir);
      const exitCode = runCliMain(["doctor", "--ledger", tmpDir, "--cooldown", "1.9"]);
      assert.equal(exitCode, EXIT_CODES.USAGE_ERROR);
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("rejects tripping lifeguard under Law 2 (Blocker B7)", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      provisionTestTrust(tmpDir);
      const exitCode = runCliMain(["doctor", "--ledger", tmpDir, "--trip", "lifeguard"]);
      assert.equal(exitCode, EXIT_CODES.USAGE_ERROR);
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("NEW-B8 regression: manual operator trip survives subsequent plain doctor run", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-b8-"));
      provisionTestTrust(tmpDir);
      mkdirSync(join(tmpDir, "ledger"), { recursive: true });

      const store = new BreakerStore(tmpDir);
      store.trip("worker:flash", "manual_operator_trip", 3600000, 1000);

      // Verify tripped
      assert.equal(isCircuitBreakerTripped(tmpDir, "worker:flash", 2000), true);

      // Run plain doctor inspection (read-only audit, all subsystems healthy)
      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: 2000 });
      assert.equal(docRes.ok, true);

      // Verify trip SURVIVED the plain doctor run (NOT erased by recommendation!)
      assert.equal(isCircuitBreakerTripped(tmpDir, "worker:flash", 3000), true);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("NEW-B9 regression: forged unsigned events in ledger are ignored by breaker fold and triage", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-b9-"));
      provisionTestTrust(tmpDir);
      const keypair = getOrCreateQueueKeypair(tmpDir);

      // Legitimate warmup event
      appendLedgerEventRaw(
        tmpDir,
        {
          type: "factory.resumed",
          payload: { mode: "BUILD" },
          nowMs: 1000,
        },
        keypair,
        {},
      );

      // Inject forged unsigned trip line directly into events.jsonl
      const forgedTripLine = JSON.stringify({
        v: 1,
        type: "probe.completed",
        writer: "supervisor",
        payload: {
          probe: "doctor",
          type: "doctor_breaker",
          breaker: { target_subsystem: "worker:flash", action: "trip", cooldown_ms: 3600000 },
          expires_at_ms: 10000000,
        },
      });
      const forgedHaltLine = JSON.stringify({
        v: 1,
        type: "lifeguard.alert",
        writer: "lifeguard",
        payload: { reason: "forged_halt" },
      });

      appendFileSync(join(tmpDir, "ledger", "events.jsonl"), forgedTripLine + "\n" + forgedHaltLine + "\n", "utf8");

      // Verify isCircuitBreakerTripped ignores the forged line
      assert.equal(isCircuitBreakerTripped(tmpDir, "worker:flash", 2000), false);

      // Verify runDoctor triage ignores the forged lifeguard alert
      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: 2000 });
      assert.equal(docRes.triage.lifeguard_halt, false);
      assert.notEqual(docRes.triage.failure_signature, "SIG:LIFEGUARD_ALERT:forged_halt");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("Law 17 regression: evaluates integer watermark exactness without float operations", () => {
      const limit = 30;
      const metricsNotThrottled = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 26,
        budget_limit_micro_usd: limit,
        hung_leases_count: 0,
      };
      const res1 = evaluateCircuitBreakers(metricsNotThrottled, { budget_limit_micro_usd: limit });
      assert.equal(res1.action, "reset");

      const metricsThrottled = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        daily_budget_spent_micro_usd: 27,
        budget_limit_micro_usd: limit,
        hung_leases_count: 0,
      };
      const res2 = evaluateCircuitBreakers(metricsThrottled, { budget_limit_micro_usd: limit });
      assert.equal(res2.action, "throttle");
      assert.equal(res2.target_subsystem, "budget");
    });

    it("Attribution accuracy regression: multiple uncompleted warrants count per-tier failures accurately", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-attrib-"));
      provisionTestTrust(tmpDir);
      const queueKeypair = getOrCreateQueueKeypair(tmpDir);
      const supervisorKeypair = getOrGenerateSupervisorKey(tmpDir);

      // Warrant 1: fails attempt 1 (flash)
      submitWarrant(
        tmpDir,
        {
          v: 1,
          id: "01ARZ3NDEKTSV4RRFFQ69G5W11",
          class: "surgical",
          semantic_fingerprint: sha256("test-attrib-1"),
          anchors: ["packages/core/**"],
          evidence: { test: 1 },
          red_check: { test: 1 },
          scope: { allow: 1 },
          budget_micro_usd: 1000000,
          created_by: "human:owner",
        },
        { nowMs: 1000 },
      );
      const l1 = leaseNextJob(tmpDir, { nowMs: 2000 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l1.epoch,
          payload: { job_id: l1.job_id, warrant_id: l1.warrant_id, status: "failed", verdict: "reject", cost_micro_usd: 1000 },
          nowMs: 3000,
        },
        supervisorKeypair,
      );

      // Warrant 2: fails attempt 1 (flash)
      submitWarrant(
        tmpDir,
        {
          v: 1,
          id: "01ARZ3NDEKTSV4RRFFQ69G5W12",
          class: "surgical",
          semantic_fingerprint: sha256("test-attrib-2"),
          anchors: ["packages/core/**"],
          evidence: { test: 1 },
          red_check: { test: 1 },
          scope: { allow: 1 },
          budget_micro_usd: 1000000,
          created_by: "human:owner",
        },
        { nowMs: 3500 },
      );
      const l2 = leaseNextJob(tmpDir, { nowMs: 4000 });
      appendSupervisorEvent(
        tmpDir,
        {
          type: "attempt.outcome",
          epoch: l2.epoch,
          payload: { job_id: l2.job_id, warrant_id: l2.warrant_id, status: "failed", verdict: "reject", cost_micro_usd: 1000 },
          nowMs: 5000,
        },
        supervisorKeypair,
      );

      const docRes = runDoctor({ mirqlDir: tmpDir, nowMs: 6000 });
      assert.equal(docRes.breaker.metrics.consecutive_failures.flash, 2);
      assert.equal(docRes.breaker.metrics.consecutive_failures.mid, 0);
      assert.equal(docRes.breaker.action, "throttle");
      assert.equal(docRes.breaker.target_subsystem, "worker:flash");

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});
