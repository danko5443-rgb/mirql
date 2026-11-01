// tests/m1-wake.test.mjs — Milestone M1: Event-Driven Wake Rules & Concurrency 1 Gates.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ulid,
  sha256,
  jcs,
  EXIT_CODES,
  createLedgerWatcher,
  waitForLedgerEvent,
} from "../packages/core/index.mjs";
import {
  submitWarrant,
  leaseNextJob,
  tickQueue,
  getQueueStatus,
  foldQueueState,
} from "../packages/queue/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

function makeValidWarrant(overrides = {}) {
  const nowMs = Date.now();
  return {
    v: 1,
    id: ulid(nowMs),
    class: "bugfix",
    semantic_fingerprint: sha256(`test intent ${Math.random()}`),
    anchors: ["ROADMAP.md"],
    evidence: {
      issue_id: "ISSUE-M1-001",
      reproducer_test: "tests/m1-repro.test.mjs",
    },
    red_check: {
      exit_code: 1,
      stdout: "",
      stderr: "Expected failure on base",
    },
    scope: {
      paths: ["packages/core/watcher.mjs"],
      max_files: 5,
      max_loc_delta: 200,
    },
    budget_micro_usd: 1_500_000,
    created_by: "human:owner",
    ...overrides,
  };
}

describe("Milestone M1: Event-Driven Wake Rules & Concurrency 1", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-m1-test-"));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // ---------------------------------------------------------------------------
  // 1. Concurrency 1 Invariant (Law 14)
  // ---------------------------------------------------------------------------
  describe("1. Concurrency 1 Enforcement in BUILD Mode", () => {
    it("strictly prevents a second concurrent BUILD lease while one is active", () => {
      const w1 = makeValidWarrant();
      const w2 = makeValidWarrant();

      submitWarrant(tempDir, w1, { repoRoot: ROOT });
      submitWarrant(tempDir, w2, { repoRoot: ROOT });

      const statusBefore = getQueueStatus(tempDir);
      assert.equal(statusBefore.open_warrants.length, 2);

      // Lease 1 should succeed
      const l1 = leaseNextJob(tempDir, { concurrency: 1 });
      assert.equal(l1.ok, true);
      assert.equal(l1.status, "leased");
      assert.equal(l1.warrant_id, w1.id);

      // Lease 2 immediately after MUST NOT grant a second lease (Concurrency 1)
      const l2 = leaseNextJob(tempDir, { concurrency: 1 });
      assert.equal(l2.ok, true);
      assert.equal(l2.status, "concurrency_limit");
      assert.equal(l2.job_id, undefined);
      assert.ok(l2.active_lease);
      assert.equal(l2.active_lease.warrant_id, w1.id);

      // Check status: active leases count is strictly 1
      const statusDuring = getQueueStatus(tempDir);
      assert.equal(statusDuring.active_leases.length, 1);
    });

    it("tickQueue returns WAIT_IN_PROGRESS while a BUILD lease is active", () => {
      const w1 = makeValidWarrant();
      const w2 = makeValidWarrant();

      submitWarrant(tempDir, w1, { repoRoot: ROOT });
      submitWarrant(tempDir, w2, { repoRoot: ROOT });

      const l1 = leaseNextJob(tempDir, { concurrency: 1 });
      assert.equal(l1.status, "leased");

      // While lease is running, tickQueue must wait rather than transitioning mode
      const t = tickQueue(tempDir, { repoRoot: ROOT, concurrency: 1 });
      assert.equal(t.action, "WAIT_IN_PROGRESS");
      assert.equal(t.next_mode, "BUILD");

      const status = getQueueStatus(tempDir);
      assert.equal(status.mode, "BUILD");
    });

    it("grants the second lease once the first active lease expires or finishes", () => {
      const t0 = 1_700_000_000_000;
      const ttl = 30_000;
      const w1 = makeValidWarrant();
      const w2 = makeValidWarrant();

      submitWarrant(tempDir, w1, { repoRoot: ROOT, nowMs: t0 });
      submitWarrant(tempDir, w2, { repoRoot: ROOT, nowMs: t0 });

      // Lease 1
      const l1 = leaseNextJob(tempDir, { nowMs: t0, ttl_ms: ttl, concurrency: 1 });
      assert.equal(l1.status, "leased");
      assert.equal(l1.warrant_id, w1.id);

      // Reap expired lease at t0 + 40_000ms
      tickQueue(tempDir, { nowMs: t0 + 40_000, repoRoot: ROOT, concurrency: 1 });

      // Now lease can be granted for the next job
      const l2 = leaseNextJob(tempDir, { nowMs: t0 + 41_000, ttl_ms: ttl, concurrency: 1 });
      assert.equal(l2.ok, true);
      assert.equal(l2.status, "leased");
      assert.ok(l2.job_id);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Zero-Polling Reactive Event Watcher (Law 14)
  // ---------------------------------------------------------------------------
  describe("2. Zero-Polling Reactive Ledger Event Watcher", () => {
    it("dispatches new appended events reactively without polling", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const received = [];
      const watcher = createLedgerWatcher(ledgerPath, { debounceMs: 15 });

      watcher.on("event", (evt) => {
        received.push(evt);
      });

      try {
        const dummyEvent1 = {
          v: 1,
          id: ulid(),
          type: "human.intent",
          seq: 1,
          payload: { text: "hello reactive wake" },
        };
        appendFileSync(ledgerPath, jcs(dummyEvent1) + "\n", "utf8");

        // Wait for reactive dispatch
        await new Promise((r) => setTimeout(r, 80));

        assert.equal(received.length, 1);
        assert.equal(received[0].type, "human.intent");
        assert.equal(received[0].payload.text, "hello reactive wake");

        const dummyEvent2 = {
          v: 1,
          id: ulid(),
          type: "job.enqueued",
          seq: 2,
          payload: { job_id: "JOB-123" },
        };
        appendFileSync(ledgerPath, jcs(dummyEvent2) + "\n", "utf8");

        await new Promise((r) => setTimeout(r, 80));

        assert.equal(received.length, 2);
        assert.equal(received[1].type, "job.enqueued");
      } finally {
        watcher.close();
      }
    });

    it("coalesces burst writes cleanly through debouncing", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const received = [];
      const watcher = createLedgerWatcher(ledgerPath, { debounceMs: 25 });
      watcher.on("event", (evt) => received.push(evt));

      try {
        // Rapid append of 5 events in immediate sequence
        for (let i = 1; i <= 5; i++) {
          const evt = {
            v: 1,
            id: ulid(),
            type: "burst.test",
            seq: i,
            payload: { index: i },
          };
          appendFileSync(ledgerPath, jcs(evt) + "\n", "utf8");
        }

        // Wait for debounce flush
        await new Promise((r) => setTimeout(r, 120));

        assert.equal(received.length, 5);
        for (let i = 1; i <= 5; i++) {
          assert.equal(received[i - 1].seq, i);
          assert.equal(received[i - 1].payload.index, i);
        }
      } finally {
        watcher.close();
      }
    });

    it("waitForLedgerEvent resolves when matching event appears and rejects on timeout", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      // 1. Successful wait
      const waitPromise = waitForLedgerEvent(
        ledgerPath,
        (e) => e.type === "warrant.minted" && e.payload?.role === "doctor",
        { timeoutMs: 1500, debounceMs: 10 },
      );

      // Append irrelevant event first
      appendFileSync(
        ledgerPath,
        jcs({ v: 1, id: ulid(), type: "irrelevant.event", seq: 1 }) + "\n",
        "utf8",
      );

      // Append target event
      setTimeout(() => {
        appendFileSync(
          ledgerPath,
          jcs({
            v: 1,
            id: ulid(),
            type: "warrant.minted",
            seq: 2,
            payload: { role: "doctor", warrant_id: "W-DOC-1" },
          }) + "\n",
          "utf8",
        );
      }, 50);

      const matched = await waitPromise;
      assert.equal(matched.type, "warrant.minted");
      assert.equal(matched.payload.warrant_id, "W-DOC-1");

      // 2. Timeout case
      await assert.rejects(
        waitForLedgerEvent(
          ledgerPath,
          (e) => e.type === "never.happening",
          { timeoutMs: 100, debounceMs: 10 },
        ),
        /Timeout waiting for event/,
      );
    });

    it("attaches cleanly before events.jsonl exists and starts tracking upon file creation", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");

      // File does not exist yet!
      const watcher = createLedgerWatcher(ledgerPath, { debounceMs: 15 });
      const received = [];
      watcher.on("event", (evt) => received.push(evt));

      try {
        await new Promise((r) => setTimeout(r, 40));

        // Create file and append
        const evt = {
          v: 1,
          id: ulid(),
          type: "first.birth",
          seq: 1,
          payload: { born: true },
        };
        writeFileSync(ledgerPath, jcs(evt) + "\n", "utf8");

        await new Promise((r) => setTimeout(r, 120));

        assert.equal(received.length, 1);
        assert.equal(received[0].type, "first.birth");
      } finally {
        watcher.close();
      }
    });
  });
});
