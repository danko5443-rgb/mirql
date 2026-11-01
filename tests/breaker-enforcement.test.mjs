// tests/breaker-enforcement.test.mjs — circuit breakers are binding (issue #15).
// Pins the enforcement chain end to end: a tripped breaker (folded from
// verified ledger events, Law 4) makes the queue REFUSE new leases until the
// cooldown expires or a human resets it. Throttle slows work; only a trip
// stops it. Doctor recommendation events (the exact payload runDoctor writes)
// are binding, not advisory.

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { EXIT_CODES, ulid, sha256, getActiveTrippedBreakers } from "../packages/core/index.mjs";
import { submitWarrant, tickQueue, leaseNextJob } from "../packages/queue/index.mjs";
import { BreakerStore } from "../packages/run/doctor.mjs";
import { appendSupervisorEvent } from "../packages/run/ledger.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

function makeValidWarrant(overrides = {}) {
  return {
    v: 1,
    id: ulid(1_700_000_001_000),
    class: "surgical",
    semantic_fingerprint: sha256("intent: breaker enforcement test"),
    anchors: [{ path: "packages/queue/index.mjs" }],
    evidence: { citations: 1 },
    red_check: { reviewed: 1 },
    scope: { allow_globs: ["packages/queue/**"] },
    budget_micro_usd: 500_000,
    created_by: "human:owner",
    ...overrides,
  };
}

describe("circuit breakers are binding, not advisory (issue #15)", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-breaker-enf-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("EXIT_CODES reserves 8 for an open breaker", () => {
    assert.equal(EXIT_CODES.BREAKER_OPEN, 8);
  });

  it("clean ledger: no active breakers, leasing proceeds", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    assert.deepEqual(getActiveTrippedBreakers(tempDir), []);
    const res = leaseNextJob(tempDir);
    assert.equal(res.ok, true, res.error);
  });

  it("a tripped breaker refuses new leases (fail-closed, exit 8)", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    const store = new BreakerStore(tempDir);
    store.trip("worker", "consecutive_tier_failures", 3_600_000);

    const active = getActiveTrippedBreakers(tempDir);
    assert.equal(active.length, 1);
    assert.equal(active[0].subsystem, "worker");
    assert.equal(active[0].reason, "consecutive_tier_failures");

    const res = leaseNextJob(tempDir);
    assert.equal(res.ok, false);
    assert.equal(res.status, "breaker_tripped");
    assert.equal(res.exit_code, EXIT_CODES.BREAKER_OPEN);
    assert.equal(res.breakers.length, 1);
    assert.match(res.error, /worker/);
  });

  it("human reset reopens the queue", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    const store = new BreakerStore(tempDir);
    store.trip("worker", "test_trip", 3_600_000);
    assert.equal(leaseNextJob(tempDir).status, "breaker_tripped");

    store.reset("worker");
    const res = leaseNextJob(tempDir);
    assert.equal(res.ok, true, res.error);
  });

  it("cooldown expiry auto-heals the breaker", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    const t0 = Date.now();
    const store = new BreakerStore(tempDir);
    store.trip("worker", "short_fuse", 100, t0);
    assert.equal(leaseNextJob(tempDir, { nowMs: t0 }).status, "breaker_tripped");

    // Past expiry the fold drops it and leasing resumes
    assert.deepEqual(getActiveTrippedBreakers(tempDir, t0 + 5_000), []);
    const res = leaseNextJob(tempDir, { nowMs: t0 + 5_000 });
    assert.equal(res.ok, true, res.error);
  });

  it("throttle does NOT block leasing — only a trip stops work", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    // Append the same event shape runDoctor writes for a throttle recommendation
    appendSupervisorEvent(tempDir, {
      type: "probe.completed",
      payload: {
        probe: "doctor",
        type: "doctor",
        status: "fail",
        breaker: {
          action: "throttle",
          target_subsystem: "worker",
          cooldown_ms: 3_600_000,
          reason: "elevated_failure_rate",
        },
        expires_at_ms: Date.now() + 3_600_000,
      },
    });
    const res = leaseNextJob(tempDir);
    assert.equal(res.ok, true, "throttled subsystem must still lease (trip-only blocking)");
  });

  it("doctor recommendation events are binding on the queue (exact runDoctor payload shape)", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    // Byte-for-byte the payload runDoctor appends when evaluateCircuitBreakers
    // recommends a trip — this is the producer whose events must bind.
    const nowMs = Date.now();
    appendSupervisorEvent(tempDir, {
      type: "probe.completed",
      payload: {
        probe: "doctor",
        type: "doctor",
        status: "fail",
        breaker: {
          target_subsystem: "budget",
          action: "trip",
          cooldown_ms: 3_600_000,
          reason: "daily_budget_exhausted",
        },
        expires_at_ms: nowMs + 3_600_000,
      },
      nowMs,
    });

    const active = getActiveTrippedBreakers(tempDir);
    assert.equal(active.length, 1);
    assert.equal(active[0].subsystem, "budget");

    const res = leaseNextJob(tempDir);
    assert.equal(res.ok, false);
    assert.equal(res.status, "breaker_tripped");
    assert.equal(res.exit_code, EXIT_CODES.BREAKER_OPEN);
  });

  it("forged (unauthenticated) breaker events never bind", () => {
    submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
    tickQueue(tempDir);
    // Raw append with no valid signature — readVerifiedLedgerEvents must drop it
    const ledgerDir = join(tempDir, "ledger");
    mkdirSync(ledgerDir, { recursive: true });
    appendFileSync(
      join(ledgerDir, "events.jsonl"),
      JSON.stringify({
        v: 1,
        type: "probe.completed",
        writer: { ns: "tool:run_supervisor", key_id: "forged" },
        payload: {
          probe: "doctor",
          type: "doctor",
          breaker: { action: "trip", target_subsystem: "worker", cooldown_ms: 999999, reason: "forged" },
          expires_at_ms: Date.now() + 999999,
        },
      }) + "\n",
      "utf8",
    );
    assert.deepEqual(getActiveTrippedBreakers(tempDir), []);
    const res = leaseNextJob(tempDir);
    assert.equal(res.ok, true, "unauthenticated trip must not block work");
  });
});
