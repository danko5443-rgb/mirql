// tests/law9-multinode.test.mjs — Law 9 multi-node exercises: several N-1 supervisor
// nodes (real child processes) share one ledger and must drain work exactly once,
// survive mixed concurrent operations, and fence off a dead node's late outcome.
// Tests are Φ-exempt (tests/**) and exercise only public package/CLI surfaces.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { sha256, ulid, generateEd25519Keypair } from "../packages/core/index.mjs";
import { provisionTestTrust, authorizeTestKey } from "./helpers/keyring.mjs";
import {
  getQueueStatus,
  submitWarrant,
  tickQueue,
  leaseNextJob,
  appendLedgerEvent,
} from "../packages/queue/index.mjs";

const execFileAsync = promisify(execFile);
const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const MIRQL_BIN = join(ROOT, "bin", "mirql.mjs");

function makeValidWarrant(overrides = {}) {
  return {
    v: 1,
    id: ulid(1_700_100_000_000 + Math.floor(Math.random() * 1_000_000)),
    class: "surgical",
    semantic_fingerprint: sha256(`law9-multinode-${ulid()}`),
    anchors: [{ path: "packages/queue/index.mjs" }],
    evidence: { citations: 1 },
    red_check: { reviewed: 1 },
    scope: { allow_globs: ["packages/queue/**"] },
    budget_micro_usd: 500_000,
    created_by: "human:owner",
    ...overrides,
  };
}

/** A real N-1 supervisor node: a child process leasing through the CLI against the shared ledger. */
function spawnLeaseNode(dir) {
  return execFileAsync(process.execPath, [MIRQL_BIN, "q", "lease", "--dir", dir, "--concurrency", "8"], { timeout: 60_000 });
}

function spawnTickNode(dir) {
  return execFileAsync(process.execPath, [MIRQL_BIN, "q", "tick", "--dir", dir], { timeout: 60_000 });
}

function spawnSubmitNode(dir, warrant) {
  return execFileAsync(process.execPath, [MIRQL_BIN, "q", "submit", "--dir", dir, "--warrant", JSON.stringify(warrant)], { timeout: 60_000 });
}

/** The ledger must stay a single ordered chain no matter how many nodes appended. */
function assertChainContiguous(dir) {
  const lines = readFileSync(join(dir, "ledger", "events.jsonl"), "utf8").trim().split(/\r?\n/).filter(Boolean);
  const events = lines.map((line) => JSON.parse(line));
  for (const [index, event] of events.entries()) {
    assert.equal(event.seq, index + 1, `seq ${event.seq} at index ${index} breaks the chain`);
    const expectedPrev = index === 0 ? "sha256:0000000000000000000000000000000000000000000000000000000000000000" : events[index - 1].hash;
    assert.equal(event.prev_hash, expectedPrev, `prev_hash at seq ${event.seq} breaks the chain`);
  }
  return events;
}

/** A supervisor node records its outcome through the locked append path, under its own enrolled key. */
function recordOutcome(dir, keypair, { jobId, warrantId, epoch, status = "completed", verdict = "auto_merge", nowMs }) {
  appendLedgerEvent(dir, {
    type: "attempt.outcome",
    nowMs,
    epoch,
    payload: { job_id: jobId, warrant_id: warrantId, epoch, status, verdict, cost_micro_usd: 1_000, tokens_consumed: 10 },
  }, keypair);
}

describe("Law 9: several N-1 nodes against one ledger", () => {
  let tempDir;
  let supervisorKeypair;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-law9-"));
    provisionTestTrust(tempDir);
    supervisorKeypair = generateEd25519Keypair();
    supervisorKeypair.writer = { ns: "tool:run_supervisor" };
    authorizeTestKey(tempDir, "tool:run_supervisor", supervisorKeypair);
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("three nodes drain eight jobs across rounds: each job leased once, epochs monotonic, chain intact", async () => {
    const warrants = [];
    for (let i = 0; i < 8; i += 1) {
      const warrant = makeValidWarrant();
      const submission = submitWarrant(tempDir, warrant, { repoRoot: ROOT });
      assert.equal(submission.ok, true, `warrant ${i} must submit`);
      warrants.push(warrant);
    }

    const seenLeases = [];
    let round = 0;
    while (seenLeases.length < 8 && round < 8) {
      round += 1;
      const runs = await Promise.all([spawnLeaseNode(tempDir), spawnLeaseNode(tempDir), spawnLeaseNode(tempDir)]);
      const leases = runs.map((run) => {
        assert.equal(run.stderr, "", `lease node stderr: ${run.stderr}`);
        return JSON.parse(run.stdout.trim());
      });
      for (const lease of leases) {
        assert.equal(lease.ok, true, lease.message ?? "lease must succeed");
        if (lease.status === "leased") seenLeases.push(lease);
      }
      // Each node reports its outcome before the next round of leases.
      for (const lease of leases.filter((l) => l.status === "leased")) {
        recordOutcome(tempDir, supervisorKeypair, { jobId: lease.job_id, warrantId: lease.warrant_id, epoch: lease.epoch, nowMs: lease.leased_at_ms + 1000 });
      }
    }

    assert.equal(seenLeases.length, 8, `expected 8 leases, saw ${seenLeases.length}`);
    assert.equal(new Set(seenLeases.map((l) => l.job_id)).size, 8, "no job may be leased twice");
    assert.equal(new Set(seenLeases.map((l) => l.warrant_id)).size, 8, "every warrant is drained exactly once");
    const epochs = seenLeases.map((l) => l.epoch).sort((a, b) => a - b);
    assert.deepEqual(epochs, epochs.map((_, i) => i + 2), "lease epochs are globally monotonic from the shared counter");
    assertChainContiguous(tempDir);

    const status = getQueueStatus(tempDir);
    assert.equal(status.queued_jobs.length, 0);
    assert.equal(status.active_leases.length, 0);
    for (const warrant of warrants) {
      assert.equal(status.warrants[warrant.id].status, "completed", `warrant ${warrant.id} must complete`);
    }
  });

  it("mixed concurrent nodes (submit, lease, tick) all land on one chain", async () => {
    const first = makeValidWarrant();
    submitWarrant(tempDir, first, { repoRoot: ROOT });
    const second = makeValidWarrant();

    const [submitRun, leaseRun, tickRun] = await Promise.all([
      spawnSubmitNode(tempDir, second),
      spawnLeaseNode(tempDir),
      spawnTickNode(tempDir),
    ]);
    assert.equal(submitRun.stderr, "");
    assert.equal(leaseRun.stderr, "");
    assert.equal(tickRun.stderr, "");
    assert.equal(JSON.parse(submitRun.stdout.trim()).ok, true);
    assert.equal(JSON.parse(leaseRun.stdout.trim()).ok, true);
    assert.equal(typeof JSON.parse(tickRun.stdout.trim()).action, "string", "the tick node reports its deterministic action");

    const events = assertChainContiguous(tempDir);
    const leased = events.filter((event) => event.type === "job.leased");
    assert.equal(leased.length, 1, "exactly one lease wins the race");
    const status = getQueueStatus(tempDir);
    assert.equal(Object.keys(status.warrants).length, 2, "both submissions survived the race");
    assert.equal(status.queued_jobs.length, 1, "one job remains queued behind the live lease");
  });

  it("a dead node's late outcome is fenced off after another node re-leased the job", async () => {
    const warrant = makeValidWarrant();
    submitWarrant(tempDir, warrant, { repoRoot: ROOT });

    // Node A leases (a real child process), then dies without an outcome.
    const nodeA = JSON.parse((await spawnLeaseNode(tempDir)).stdout.trim());
    assert.equal(nodeA.status, "leased");

    // Its lease expires; another node's tick reaps it and re-leases at a higher epoch.
    const reapAt = nodeA.leased_at_ms + nodeA.ttl_ms + 1000;
    tickQueue(tempDir, { repoRoot: ROOT, nowMs: reapAt });
    assert.equal(getQueueStatus(tempDir, { nowMs: reapAt }).active_leases.length, 0, "the dead lease is reaped");
    const nodeB = leaseNextJob(tempDir, { nowMs: reapAt + 1000, repoRoot: ROOT });
    assert.equal(nodeB.ok, true);
    assert.ok(nodeB.epoch > nodeA.epoch, "the re-lease must fence the dead node's epoch");
    assert.equal(nodeB.attempt, nodeA.attempt + 1, "the reaped attempt counts");

    // Node A resurrects and reports success at its stale epoch — through the locked append path.
    recordOutcome(tempDir, supervisorKeypair, { jobId: nodeA.job_id, warrantId: warrant.id, epoch: nodeA.epoch, nowMs: nodeB.leased_at_ms + 1000 });
    let status = getQueueStatus(tempDir, { nowMs: nodeB.leased_at_ms + 1000 });
    assert.notEqual(status.warrants[warrant.id].status, "completed", "a stale epoch must not complete the warrant");
    assert.equal(status.active_leases.some((l) => l.job_id === nodeB.job_id), true, "the live re-lease must survive the stale outcome");

    // Node B's own outcome at the current epoch completes the job exactly once.
    recordOutcome(tempDir, supervisorKeypair, { jobId: nodeB.job_id, warrantId: warrant.id, epoch: nodeB.epoch, nowMs: nodeB.leased_at_ms + 2000 });
    status = getQueueStatus(tempDir, { nowMs: nodeB.leased_at_ms + 2000 });
    assert.equal(status.warrants[warrant.id].status, "completed");
    assert.equal(status.active_leases.length, 0);
    assertChainContiguous(tempDir);
  });
});
