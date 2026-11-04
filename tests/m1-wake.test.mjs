import { initEmptyRepo } from "./helpers/git.mjs";
import { authorizeTestWarrant } from "./helpers/warrant.mjs";
import { provisionTestTrust } from "./helpers/keyring.mjs";
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
  DEFAULT_POLICY,
  isLeaseLive,
  validateConcurrencyLimit,
} from "../packages/queue/index.mjs";
import { runSupervisorReactive } from "../packages/run/index.mjs";

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
    provisionTestTrust(tempDir);
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
    it("DEFAULT_POLICY specifies max_build_concurrency: 1 by default", () => {
      assert.equal(DEFAULT_POLICY.max_build_concurrency, 1);
    });

    it("strictly prevents a second concurrent BUILD lease by DEFAULT with NO options passed", () => {
      const w1 = makeValidWarrant();
      const w2 = makeValidWarrant();

      submitWarrant(tempDir, w1, { repoRoot: ROOT });
      submitWarrant(tempDir, w2, { repoRoot: ROOT });

      const statusBefore = getQueueStatus(tempDir);
      assert.equal(statusBefore.open_warrants.length, 2);

      // Lease 1 should succeed with no options passed
      const l1 = leaseNextJob(tempDir);
      assert.equal(l1.ok, true);
      assert.equal(l1.status, "leased");
      assert.equal(l1.warrant_id, w1.id);

      // Lease 2 immediately after MUST NOT grant a second lease (Concurrency 1 by default)
      const l2 = leaseNextJob(tempDir);
      assert.equal(l2.ok, true);
      assert.equal(l2.status, "concurrency_limit");
      assert.equal(l2.job_id, undefined);
      assert.ok(l2.active_lease);
      assert.equal(l2.active_lease.warrant_id, w1.id);

      // Check status: active leases count is strictly 1
      const statusDuring = getQueueStatus(tempDir);
      assert.equal(statusDuring.active_leases.length, 1);
    });

    it("tickQueue returns WAIT_IN_PROGRESS while a BUILD lease is active by default", () => {
      const w1 = makeValidWarrant();
      const w2 = makeValidWarrant();

      submitWarrant(tempDir, w1, { repoRoot: ROOT });
      submitWarrant(tempDir, w2, { repoRoot: ROOT });

      const l1 = leaseNextJob(tempDir);
      assert.equal(l1.status, "leased");

      // While lease is running, tickQueue must wait rather than transitioning mode
      const t = tickQueue(tempDir, { repoRoot: ROOT });
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
      const l1 = leaseNextJob(tempDir, { nowMs: t0, ttl_ms: ttl });
      assert.equal(l1.status, "leased");
      assert.equal(l1.warrant_id, w1.id);

      // Reap expired lease at t0 + 40_000ms
      tickQueue(tempDir, { nowMs: t0 + 40_000, repoRoot: ROOT });

      // Now lease can be granted for the next job
      const l2 = leaseNextJob(tempDir, { nowMs: t0 + 41_000, ttl_ms: ttl });
      assert.equal(l2.ok, true);
      assert.equal(l2.status, "leased");
      assert.ok(l2.job_id);
    });

    it("Law 17: validateConcurrencyLimit rejects invalid limit values (0, negative, NaN, string)", () => {
      assert.equal(validateConcurrencyLimit(undefined).valid, true);
      assert.equal(validateConcurrencyLimit(null).valid, true);
      assert.equal(validateConcurrencyLimit(1).valid, true);
      assert.equal(validateConcurrencyLimit(5).valid, true);

      assert.equal(validateConcurrencyLimit(0).valid, false);
      assert.equal(validateConcurrencyLimit(-1).valid, false);
      assert.equal(validateConcurrencyLimit(NaN).valid, false);
      assert.equal(validateConcurrencyLimit("1").valid, false);
      assert.equal(validateConcurrencyLimit(1.5).valid, false);

      // Fails closed in leaseNextJob
      const res = leaseNextJob(tempDir, { concurrency: 0 });
      assert.equal(res.ok, false);
      assert.equal(res.status, "rejected");
      assert.equal(res.exit_code, EXIT_CODES.USAGE_ERROR);
    });

    it("isLeaseLive helper accurately tests unexpired vs expired leases", () => {
      const liveLease = { leased_at_ms: 1000, ttl_ms: 5000 };
      assert.equal(isLeaseLive(liveLease, 2000), true);
      assert.equal(isLeaseLive(liveLease, 6000), true);
      assert.equal(isLeaseLive(liveLease, 6001), false);
      assert.equal(isLeaseLive(null), false);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Zero-Polling Reactive Event Watcher (Law 14)
  // ---------------------------------------------------------------------------
  describe("2. Zero-Polling Reactive Ledger Event Watcher", () => {
    it("dispatches new appended events reactively without fixed polling sleeps", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const watcher = createLedgerWatcher(ledgerPath, { debounceMs: 15 });

      try {
        const dummyEvent1 = {
          v: 1,
          id: ulid(),
          type: "human.intent",
          seq: 1,
          payload: { text: "hello reactive wake" },
        };

        const eventPromise1 = watcher.waitFor((e) => e.type === "human.intent", {
          timeoutMs: 2000,
        });
        appendFileSync(ledgerPath, jcs(dummyEvent1) + "\n", "utf8");
        const received1 = await eventPromise1;
        assert.equal(received1.type, "human.intent");
        assert.equal(received1.payload.text, "hello reactive wake");

        const dummyEvent2 = {
          v: 1,
          id: ulid(),
          type: "job.enqueued",
          seq: 2,
          payload: { job_id: "JOB-123" },
        };
        const eventPromise2 = watcher.waitFor((e) => e.type === "job.enqueued", {
          timeoutMs: 2000,
        });
        appendFileSync(ledgerPath, jcs(dummyEvent2) + "\n", "utf8");
        const received2 = await eventPromise2;
        assert.equal(received2.type, "job.enqueued");
      } finally {
        watcher.close();
      }
    });

    it("coalesces burst writes cleanly through debouncing and maxWaitMs", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const watcher = createLedgerWatcher(ledgerPath, { debounceMs: 25, maxWaitMs: 100 });

      try {
        const lastPromise = watcher.waitFor((e) => e.seq === 5, { timeoutMs: 2000 });

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

        const finalEvt = await lastPromise;
        assert.equal(finalEvt.seq, 5);
        assert.equal(finalEvt.payload.index, 5);
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
        { timeoutMs: 2000, debounceMs: 10 },
      );

      // Append irrelevant event first
      appendFileSync(
        ledgerPath,
        jcs({ v: 1, id: ulid(), type: "irrelevant.event", seq: 1 }) + "\n",
        "utf8",
      );

      // Append target event after small tick
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
      }, 30);

      const matched = await waitPromise;
      assert.equal(matched.type, "warrant.minted");
      assert.equal(matched.payload.warrant_id, "W-DOC-1");

      // 2. Timeout case
      await assert.rejects(
        waitForLedgerEvent(
          ledgerPath,
          (e) => e.type === "never.happening",
          { timeoutMs: 50, debounceMs: 10 },
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

      try {
        const birthPromise = watcher.waitFor((e) => e.type === "first.birth", {
          timeoutMs: 2000,
        });

        // Create file and append
        const evt = {
          v: 1,
          id: ulid(),
          type: "first.birth",
          seq: 1,
          payload: { born: true },
        };
        writeFileSync(ledgerPath, jcs(evt) + "\n", "utf8");

        const received = await birthPromise;
        assert.equal(received.type, "first.birth");
      } finally {
        watcher.close();
      }
    });

    it("handles multi-byte UTF-8 characters split across chunk boundaries", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const watcher = createLedgerWatcher(ledgerPath, { debounceMs: 10 });

      try {
        // Multi-byte character: 🎉 (4 bytes in UTF-8: 0xF0 0x9F 0x8E 0x89)
        const eventText = jcs({
          v: 1,
          id: ulid(),
          type: "emoji.party",
          seq: 1,
          payload: { celebration: "🎉" },
        }) + "\n";

        const utf8Bytes = Buffer.from(eventText, "utf8");
        // Split right in the middle of the 4-byte emoji
        const splitIndex = eventText.indexOf("🎉") + 2;

        const part1 = utf8Bytes.subarray(0, splitIndex);
        const part2 = utf8Bytes.subarray(splitIndex);

        const partyPromise = watcher.waitFor((e) => e.type === "emoji.party", {
          timeoutMs: 2000,
        });

        appendFileSync(ledgerPath, part1);
        setTimeout(() => {
          appendFileSync(ledgerPath, part2);
        }, 20);

        const received = await partyPromise;
        assert.equal(received.type, "emoji.party");
        assert.equal(received.payload.celebration, "🎉");
      } finally {
        watcher.close();
      }
    });

    it("error handling does not crash the process when no error listener is attached", () => {
      const watcher = createLedgerWatcher(join(tempDir, "nonexistent", "events.jsonl"), {
        debounceMs: 10,
      });
      // Should not throw an uncaught exception
      watcher._handleError(new Error("simulated watcher error"));
      assert.ok(watcher.lastError);
      watcher.close();
    });
  });

  // ---------------------------------------------------------------------------
  // 3. End-to-End Reactive Supervisor Loop (M1)
  // ---------------------------------------------------------------------------
  describe("3. End-to-End Reactive Supervisor Wake Loop", () => {
    beforeEach(() => initEmptyRepo(tempDir));
    it("runSupervisorReactive wakes, leases job, executes supervisor, and writes attempt.outcome to ledger", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const warrant = makeValidWarrant();
      authorizeTestWarrant(tempDir, warrant);

      // Start reactive supervisor wired to queue lease
      const reactive = await runSupervisorReactive({
        mirqlDir: tempDir,
        workspaceDir: tempDir,
        debounceMs: 10,
        skipPidFile: true,
        noHeartbeatTicker: true,
        leaseJob: () => leaseNextJob(tempDir),
        getWarrant: (wId) => (wId === warrant.id ? warrant : null),
        builderCommand: "exit 0",
      });

      try {
        assert.equal(reactive.getStepsExecuted(), 0);

        // Prepare outcome promise on ledger
        const outcomePromise = waitForLedgerEvent(
          ledgerPath,
          (e) => e.type === "attempt.outcome" && e.payload?.warrant_id === warrant.id,
          { timeoutMs: 3000, debounceMs: 10 },
        );

        // Client submits warrant to queue
        const sub = submitWarrant(tempDir, warrant, { repoRoot: ROOT });
        assert.equal(sub.ok, true);

        // Reactive supervisor wakes, leases the job, executes supervisor step, and writes attempt.outcome!
        const outcomeEvent = await outcomePromise;
        assert.equal(outcomeEvent.type, "attempt.outcome");
        assert.equal(outcomeEvent.payload.warrant_id, warrant.id);
        assert.ok(reactive.getStepsExecuted() >= 1, "Completed steps count must be >= 1");
      } finally {
        reactive.close();
      }
    });

    it("handles a burst of warrant submissions sequentially without stranding any jobs", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const w1 = makeValidWarrant();
      const w2 = makeValidWarrant();
      const w3 = makeValidWarrant();
      for (const warrant of [w1, w2, w3]) authorizeTestWarrant(tempDir, warrant);
      const warrantMap = new Map([
        [w1.id, w1],
        [w2.id, w2],
        [w3.id, w3],
      ]);

      const reactive = await runSupervisorReactive({
        mirqlDir: tempDir,
        workspaceDir: tempDir,
        debounceMs: 10,
        skipPidFile: true,
        noHeartbeatTicker: true,
        leaseJob: () => leaseNextJob(tempDir),
        getWarrant: (wId) => warrantMap.get(wId) || null,
        builderCommand: "exit 0",
      });

      try {
        const outcomesReceived = [];
        let startOutcomeDeadline;
        const outcomePromise = new Promise((resolve, reject) => {
          // Adaptive deadline: each received outcome re-arms the step timer, so
          // CPU contention from parallel test files cannot flake the
          // no-stranding invariant this test pins. The absolute cap keeps the
          // test bounded even under pathological stall.
          const STEP_TIMEOUT_MS = 15000;
          const ABSOLUTE_CAP_MS = 300000;
          let startedAt = Date.now();
          let settled = false;
          let timeout = null;
          const armStepTimeout = () => {
            if (timeout) clearTimeout(timeout);
            timeout = setTimeout(() => {
              settled = true;
              reject(
                new Error(
                  `Timeout: received ${outcomesReceived.length} of 9 outcomes after ${Date.now() - startedAt}ms`,
                ),
              );
            }, STEP_TIMEOUT_MS);
          };
          startOutcomeDeadline = () => { startedAt = Date.now(); armStepTimeout(); };
          // Dispatch progress can precede the watcher reading its appended outcomes.
          reactive.watcher.on("step", () => {
            if (!settled && Date.now() - startedAt < ABSOLUTE_CAP_MS) armStepTimeout();
          });
          reactive.watcher.on("event", (evt) => {
            if (evt.type === "attempt.outcome") {
              outcomesReceived.push(evt);
              if (outcomesReceived.length === 9) {
                settled = true;
                if (timeout) clearTimeout(timeout);
                resolve(outcomesReceived);
              } else if (!settled && Date.now() - startedAt < ABSOLUTE_CAP_MS) {
                armStepTimeout();
              }
            }
          });
        });

        // Submit 3 warrants in rapid burst
        submitWarrant(tempDir, w1, { repoRoot: ROOT });
        submitWarrant(tempDir, w2, { repoRoot: ROOT });
        submitWarrant(tempDir, w3, { repoRoot: ROOT });
        // Synchronous ingestion is setup, before asynchronous dispatch can progress.
        startOutcomeDeadline();

        const outcomes = await outcomePromise;
        // Their worker ("exit 0") changes nothing, so each warrant is refused up to
        // its attempt limit. Every job still gets its turn.
        assert.equal(outcomes.length, 9);
        assert.equal(reactive.getStepsExecuted(), 9);

        const outcomeWarrantIds = outcomes.map((o) => o.payload.warrant_id);
        assert.ok(outcomeWarrantIds.includes(w1.id));
        assert.ok(outcomeWarrantIds.includes(w2.id));
        assert.ok(outcomeWarrantIds.includes(w3.id));

        // Epochs must be strictly monotonic safe integers
        const epochs = outcomes.map((o) => o.epoch);
        for (let i = 1; i < epochs.length; i++) {
          assert.ok(epochs[i] > epochs[i - 1], "Epochs must strictly increase");
        }
      } finally {
        reactive.close();
      }
    });

    it("releases lease on unresolvable warrant so subsequent jobs in the queue are not blocked", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      const wBad = makeValidWarrant();
      const wGood = makeValidWarrant();
      authorizeTestWarrant(tempDir, wGood);

      // Only wGood is registered in warrant lookup: wBad returns null
      const reactive = await runSupervisorReactive({
        mirqlDir: tempDir,
        workspaceDir: tempDir,
        debounceMs: 10,
        skipPidFile: true,
        noHeartbeatTicker: true,
        leaseJob: () => leaseNextJob(tempDir),
        getWarrant: (wId) => (wId === wGood.id ? wGood : null),
        builderCommand: "exit 0",
      });

      try {
        const outcomesReceived = [];
        const outcomePromise = new Promise((resolve, reject) => {
          const STEP_TIMEOUT_MS = 15000;
          const ABSOLUTE_CAP_MS = 300000;
          const startedAt = Date.now();
          let timeout = null;
          const armStepTimeout = () => {
            if (timeout) clearTimeout(timeout);
            timeout = setTimeout(() => {
              reject(
                new Error(
                  `Timeout: received ${outcomesReceived.length} of 6 outcomes after ${Date.now() - startedAt}ms`,
                ),
              );
            }, STEP_TIMEOUT_MS);
          };
          armStepTimeout();
          reactive.watcher.on("step", () => {
            if (Date.now() - startedAt < ABSOLUTE_CAP_MS) armStepTimeout();
          });
          reactive.watcher.on("event", (evt) => {
            if (evt.type === "attempt.outcome") {
              outcomesReceived.push(evt);
              if (outcomesReceived.length === 6) {
                if (timeout) clearTimeout(timeout);
                resolve(outcomesReceived);
              } else if (Date.now() - startedAt < ABSOLUTE_CAP_MS) {
                armStepTimeout();
              }
            }
          });
        });

        // Submit bad warrant, then good warrant
        submitWarrant(tempDir, wBad, { repoRoot: ROOT });
        submitWarrant(tempDir, wGood, { repoRoot: ROOT });

        const outcomes = await outcomePromise;
        assert.equal(outcomes.length, 6);

        // First 3 outcomes must be failed attempts for wBad (capped at max_attempts)
        const badOutcomes = outcomes.filter((o) => o.payload.warrant_id === wBad.id);
        assert.equal(badOutcomes.length, 3);
        for (const bo of badOutcomes) {
          assert.equal(bo.payload.status, "failed");
          assert.equal(bo.payload.verdict, "reject");
        }

        // wGood was still leased and dispatched, not blocked by the bad warrant's
        // lease. Its worker ("exit 0") changes nothing, so the supervisor refuses it on its merits.
        const goodOutcomes = outcomes.filter((o) => o.payload.warrant_id === wGood.id);
        assert.equal(goodOutcomes.length, 3);
        for (const good of goodOutcomes) assert.equal(good.payload.rule, "NO_WORKER_CHANGES");
      } finally {
        reactive.close();
      }
    });

    it("handles leaseJob exception without crashing the watcher or throwing unhandled rejection", async () => {
      const ledgerDir = join(tempDir, "ledger");
      mkdirSync(ledgerDir, { recursive: true });
      const ledgerPath = join(ledgerDir, "events.jsonl");
      writeFileSync(ledgerPath, "", "utf8");

      let leaseCallCount = 0;
      const wGood = makeValidWarrant();
      authorizeTestWarrant(tempDir, wGood);

      const reactive = await runSupervisorReactive({
        mirqlDir: tempDir,
        workspaceDir: tempDir,
        debounceMs: 10,
        skipPidFile: true,
        noHeartbeatTicker: true,
        leaseJob: async (dir) => {
          leaseCallCount++;
          if (leaseCallCount === 1) {
            throw new Error("Simulated transient filesystem or lock error");
          }
          return leaseNextJob(dir);
        },
        getWarrant: (wId) => (wId === wGood.id ? wGood : null),
        builderCommand: "exit 0",
        verifyOptions: {
          runCheck: ({ stage }) => ({
            exitCode: stage === "red_on_base" || stage === "re_red_on_revert" ? 1 : 0,
          }),
        },
      });

      try {
        const outcomePromise = waitForLedgerEvent(
          ledgerPath,
          (e) => e.type === "attempt.outcome" && e.payload?.warrant_id === wGood.id,
          { timeoutMs: 4000, debounceMs: 10 },
        );

        submitWarrant(tempDir, wGood, { repoRoot: ROOT });

        // Submit another trigger to recover from transient lease error
        setTimeout(() => {
          submitWarrant(tempDir, makeValidWarrant(), { repoRoot: ROOT });
        }, 50);

        const outcome = await outcomePromise;
        assert.equal(outcome.type, "attempt.outcome");
        assert.equal(outcome.payload.warrant_id, wGood.id);
      } finally {
        reactive.close();
      }
    });
  });
});
