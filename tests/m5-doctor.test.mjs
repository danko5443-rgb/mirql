import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  normalizeFailureSignature,
  diagnoseHealth,
  evaluateCircuitBreakers,
  evaluateMacroStateTransition,
  BreakerStore,
  runDoctor,
  SUBSYSTEMS,
  CIRCUIT_ACTIONS,
  MACRO_STATES,
} from "../packages/run/doctor.mjs";
import { main as runCliMain } from "../packages/run/index.mjs";
import { EXIT_CODES, jcs } from "../packages/core/index.mjs";

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
      assert.equal(report.failure_signature, "SIG:DRIFT:architectural_boundary_breach");
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

      // Current time is 10000 ms, which exceeds lease expiry of 6000 ms
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
        budget_spent_micro_usd: 1000000,
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
        budget_spent_micro_usd: 25000000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 0,
      };

      const res = evaluateCircuitBreakers(metrics);
      assert.equal(res.action, "trip");
      assert.equal(res.target_subsystem, "budget");
      assert.equal(res.reason, "daily_budget_exhausted");
      assert.equal(res.cooldown_ms, 172800000); // 48h
    });

    it("throttles budget when reaching high watermark (>= 90%)", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        budget_spent_micro_usd: 22500000, // 90% of 25m
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
        budget_spent_micro_usd: 500000,
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
        budget_spent_micro_usd: 500000,
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
        budget_spent_micro_usd: 500000,
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
        budget_spent_micro_usd: 10000,
        budget_limit_micro_usd: 25000000,
        hung_leases_count: 2,
      };

      const res = evaluateCircuitBreakers(metrics);
      assert.equal(res.action, "throttle");
      assert.equal(res.target_subsystem, "queue");
      assert.equal(res.reason, "hung_leases_require_reap");
    });

    it("supports manual operator trip overrides", () => {
      const metrics = {
        tier_failures: { flash: 0, mid: 0, max: 0 },
        budget_spent_micro_usd: 0,
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

    it("transitions PATROL -> QUIESCENT when probes are clean", () => {
      const breaker = { action: "reset" };
      const triage = { healthy: true };
      const trans = evaluateMacroStateTransition("PATROL", triage, breaker, { probes_clean: true });
      assert.equal(trans.should_transition, true);
      assert.equal(trans.from_state, "PATROL");
      assert.equal(trans.to_state, "QUIESCENT");
      assert.equal(trans.reason, "probes_clean_head_unchanged");
    });

    it("halts immediately on Lifeguard daemon intervention (Law 2)", () => {
      const breaker = { action: "reset" };
      const triage = { healthy: false };
      const trans = evaluateMacroStateTransition("BUILD", triage, breaker, { lifeguard_halt: true });
      assert.equal(trans.should_transition, true);
      assert.equal(trans.to_state, "HALTED");
    });
  });

  describe("5. BreakerStore Persistence", () => {
    let tmpDir;

    it("trips and persists breaker state to disk", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-test-"));
      const store = new BreakerStore(tmpDir);

      const entry = store.trip("worker:flash", "test_trip", 50000, 1000);
      assert.equal(entry.state, "tripped");
      assert.equal(entry.expires_at_ms, 51000);

      // Verify file created
      const stateFile = join(tmpDir, "state", "doctor_breakers.json");
      assert.ok(existsSync(stateFile));

      // Check isTripped within cooldown
      assert.equal(store.isTripped("worker:flash", 20000), true);

      // Check isTripped after cooldown expires
      assert.equal(store.isTripped("worker:flash", 60000), false);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("resets individual subsystems and all subsystems", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-test-"));
      const store = new BreakerStore(tmpDir);

      store.trip("queue", "trip_queue", 100000, 1000);
      store.trip("budget", "trip_budget", 100000, 1000);

      assert.equal(store.isTripped("queue", 2000), true);
      assert.equal(store.isTripped("budget", 2000), true);

      store.reset("queue");
      assert.equal(store.isTripped("queue", 2000), false);
      assert.equal(store.isTripped("budget", 2000), true);

      store.reset("all");
      assert.equal(store.isTripped("budget", 2000), false);

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  describe("6. CLI Execution (mirql r doctor)", () => {
    let tmpDir;

    it("returns EXIT_CODES.OK when workspace and ledger are healthy", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      mkdirSync(join(tmpDir, "ledger"), { recursive: true });
      writeFileSync(join(tmpDir, "ledger", "events.jsonl"), "", "utf8");

      const exitCode = runCliMain(["doctor", "--ledger", tmpDir]);
      assert.equal(exitCode, EXIT_CODES.OK);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("returns EXIT_CODES.DOMAIN_NEGATIVE when breaker is manually tripped via CLI", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      mkdirSync(join(tmpDir, "ledger"), { recursive: true });

      const exitCode = runCliMain(["doctor", "--ledger", tmpDir, "--trip", "worker:flash"]);
      assert.equal(exitCode, EXIT_CODES.DOMAIN_NEGATIVE);

      // Reset and verify recovery
      const resetCode = runCliMain(["doctor", "--ledger", tmpDir, "--reset", "worker:flash"]);
      assert.equal(resetCode, EXIT_CODES.OK);

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("validates trip subsystem and returns USAGE_ERROR on unknown subsystem", () => {
      tmpDir = mkdtempSync(join(tmpdir(), "mirql-doctor-cli-"));
      const exitCode = runCliMain(["doctor", "--ledger", tmpDir, "--trip", "nonexistent_subsystem"]);
      assert.equal(exitCode, EXIT_CODES.USAGE_ERROR);
      rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});
