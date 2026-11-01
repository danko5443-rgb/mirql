// tests/e2e-tracer.test.mjs — End-to-End Self-Hosting Tracer Bullet (W5b hardened).
//
// Drives the REAL CLIs across the full autonomous mirql factory loop:
//   1. mirql i genesis --human-key-out <tmpHumanKey>  (Law 6: key outside .mirql)
//   2. mirql i send --key <tmpHumanKey> ...           (anchored warrant, B7)
//   3. mirql q submit -> mirql q lease                (real W4 queue)
//   4. mirql l verify                                  (append-only chain + signatures)
//   5. mirql i digest                                  (keyless read-only digest)
//   6. mirql i act --decision approve --key ...        (human sovereignty)
// plus the B5 halt/resume drill: mirql q halt -> mirql i act --decision resume
// emits mirql.resume, which BOTH the queue and log folds honor.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  readFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EXIT_CODES,
  validateDocument,
  sha256,
  jcs,
} from "../packages/core/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN_MIRQL = join(ROOT, "bin", "mirql.mjs");
const BIN_INBOX = join(ROOT, "bin", "mirql-inbox.mjs");
const BIN_LOG = join(ROOT, "bin", "mirql-log.mjs");
const BIN_QUEUE = join(ROOT, "bin", "mirql-queue.mjs");

const CROCKFORD_ULID = /^[0-9A-HJKMNPQRSTVWXYZ]{26}$/;

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

function readAllEvents(mirqlDir) {
  const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(eventsFile)) return [];
  return readFileSync(eventsFile, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

describe("End-to-End Self-Hosting Tracer Bullet (W5b hardened: full 5-binary autonomous loop)", () => {
  it("executes the complete autonomous loop: genesis -> send -> lease -> verify -> digest -> act -> halt/resume", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");
    const operatorDir = join(tmp, "operator");
    const humanKeyPath = join(operatorDir, "human_owner.key.private.json");
    mkdirSync(operatorDir, { recursive: true });

    try {
      // =====================================================================
      // Step 1: Genesis — drop-in bootstrap, externalized human key (Law 6)
      // =====================================================================
      const genRes = runBin(BIN_MIRQL, [
        "i", "genesis",
        "--dir", mirqlDir,
        "--human-key-out", humanKeyPath,
        "--idempotency-key", "tracer-genesis-1",
      ]);
      assert.equal(genRes.status, 0, `Genesis failed: ${genRes.stderr}`);
      const genDoc = JSON.parse(genRes.stdout);
      assert.equal(genDoc.status, "initialized");
      assert.equal(genDoc.seq, 1);
      assert.ok(genDoc.hash.startsWith("sha256:"));
      assert.equal(resolve(genDoc.human_key_path), resolve(humanKeyPath));

      // The human private key lives OUTSIDE .mirql, factory keys inside.
      assert.ok(existsSync(humanKeyPath), "human key file must exist");
      assert.equal(
        existsSync(join(mirqlDir, "keys", "human.key.json")), false,
        "no human private key may remain inside .mirql/keys/",
      );
      assert.ok(existsSync(join(mirqlDir, "keys", "queue.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "run_supervisor.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "notary.key.json")));

      const humanKeyDoc = JSON.parse(readFileSync(humanKeyPath, "utf8"));
      assert.equal(humanKeyDoc.writer.ns, "human:owner");

      // Keyring entries are namespace-bound objects { ns, publicKey } (B3).
      const keyring = JSON.parse(
        readFileSync(join(mirqlDir, "ledger", "keyring.json"), "utf8"),
      );
      assert.equal(keyring["human:owner"].ns, "human:owner");
      assert.equal(keyring["human:owner"].publicKey, humanKeyDoc.publicKey);
      assert.equal(keyring["tool:queue"].ns, "tool:queue");
      assert.equal(keyring[humanKeyDoc.keyId].ns, "human:owner");

      let events = readAllEvents(mirqlDir);
      assert.equal(events.length, 1);
      assert.equal(events[0].seq, 1);
      assert.equal(events[0].type, "mirql.genesis");
      assert.equal(events[0].writer.ns, "human:owner");
      assert.equal(events[0].writer.key_id, humanKeyDoc.keyId);
      assert.equal(events[0].prev_hash, "sha256:" + "0".repeat(64));

      // Genesis is idempotent through the CLI as well.
      const genAgain = runBin(BIN_MIRQL, [
        "i", "genesis", "--dir", mirqlDir, "--human-key-out", humanKeyPath,
      ]);
      assert.equal(genAgain.status, 0);
      assert.equal(JSON.parse(genAgain.stdout).status, "already_initialized");
      assert.equal(readAllEvents(mirqlDir).length, 1);

      // =====================================================================
      // Step 2: Human Intent — explicit credentials, anchored warrant (B7)
      // =====================================================================
      const sendRes = runBin(BIN_MIRQL, [
        "i", "send",
        "--dir", mirqlDir,
        "--key", humanKeyPath,
        "--kind", "feature",
        "--title", "Self-Hosting E2E Tracer Implementation",
        "--summary", "Verify full factory lifecycle across all 5 binaries",
        "--scope", "packages/core/**,packages/inbox/**,packages/log/**",
        "--red-check", "node scripts/run-tests.mjs",
        "--budget", "1500000",
      ]);
      assert.equal(sendRes.status, 0, `Send intent failed: ${sendRes.stderr}`);
      const sendDoc = JSON.parse(sendRes.stdout);
      assert.equal(sendDoc.status, "sent");
      assert.equal(sendDoc.seq, 2);
      const warrantId = sendDoc.warrant_id;
      assert.match(warrantId, CROCKFORD_ULID);

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
      assert.equal(events[1].writer.ns, "human:owner");
      assert.equal(events[1].prev_hash, events[0].hash);
      // B7: the event anchors the warrant document cryptographically.
      assert.equal(events[1].payload.warrant_hash, sha256(jcs(warrant)));
      assert.equal(events[1].payload.semantic_fingerprint, warrant.semantic_fingerprint);

      // =====================================================================
      // Step 3: Queue admission & lease with the real W4 queue
      // =====================================================================
      const submitRes = runBin(BIN_QUEUE, [
        "submit", "--dir", mirqlDir, "--file", warrantFile,
      ]);
      assert.equal(submitRes.status, 0, `Queue submit failed: ${submitRes.stderr}`);
      const submitDoc = JSON.parse(submitRes.stdout);
      assert.equal(submitDoc.status, "submitted");
      const jobId = submitDoc.job_id;
      assert.match(jobId, CROCKFORD_ULID);

      const leaseRes = runBin(BIN_QUEUE, ["lease", "--dir", mirqlDir]);
      assert.equal(leaseRes.status, 0, `Queue lease failed: ${leaseRes.stderr}`);
      const leaseDoc = JSON.parse(leaseRes.stdout);
      assert.equal(leaseDoc.status, "leased");
      assert.equal(leaseDoc.job_id, jobId);
      assert.equal(leaseDoc.warrant_id, warrantId);
      assert.ok(typeof leaseDoc.epoch === "number" && leaseDoc.epoch >= 2);

      const qStatusRes = runBin(BIN_QUEUE, ["status", "--dir", mirqlDir]);
      assert.equal(qStatusRes.status, 0, `Queue status failed: ${qStatusRes.stderr}`);
      const qStatus = JSON.parse(qStatusRes.stdout);
      assert.equal(qStatus.halted, false);
      assert.equal(qStatus.jobs[jobId].status, "leased");
      assert.ok(qStatus.open_warrants.includes(warrantId));

      events = readAllEvents(mirqlDir);
      assert.equal(events.length, 4);
      assert.equal(events[2].type, "job.enqueued");
      assert.equal(events[2].writer.ns, "tool:queue");
      assert.equal(events[3].type, "job.leased");
      assert.equal(events[3].writer.ns, "tool:queue");

      // =====================================================================
      // Step 4: Cryptographic ledger audit (chain + signatures + bindings)
      // =====================================================================
      const verifyRes = runBin(BIN_MIRQL, ["l", "verify", "--dir", mirqlDir]);
      assert.equal(verifyRes.status, 0, `Ledger verify failed: ${verifyRes.stderr}`);
      const audit = JSON.parse(verifyRes.stdout);
      assert.equal(audit.valid, true);
      assert.equal(audit.event_count, 4);
      assert.equal(audit.head_hash, events[3].hash);

      // The standalone mirql-log binary verifies identically.
      const verifyLogBin = runBin(BIN_LOG, ["verify", "--dir", mirqlDir]);
      assert.equal(verifyLogBin.status, 0);
      assert.deepEqual(JSON.parse(verifyLogBin.stdout), audit);

      // =====================================================================
      // Step 5: Keyless read-only digest
      // =====================================================================
      const digestRes = runBin(BIN_MIRQL, ["i", "digest", "--dir", mirqlDir]);
      assert.equal(digestRes.status, 0, `Digest failed: ${digestRes.stderr}`);
      const digest = JSON.parse(digestRes.stdout);
      assert.equal(digest.tool, "inbox");
      assert.equal(digest.seq, 4);
      assert.equal(digest.halted, false);
      assert.equal(digest.budget_spent_micro_usd, 0);
      assert.equal(digest.mutates_ledger, false);
      assert.equal(digest.pending_approvals.length, 0);

      const digestMdRes = runBin(BIN_INBOX, [
        "digest", "--dir", mirqlDir, "--format", "markdown",
      ]);
      assert.equal(digestMdRes.status, 0);
      assert.match(digestMdRes.stdout, /# mirql Factory Digest/);
      assert.match(digestMdRes.stdout, /\$0\.00/); // Law 17 integer-only format

      // =====================================================================
      // Step 6: Human sovereignty — propose, then signed approval
      // =====================================================================
      const proposeRes = runBin(BIN_MIRQL, [
        "i", "propose",
        "--dir", mirqlDir,
        "--roadmap-ref", "M1",
        "--title", "Approve tracer warrant execution",
        "--description", "Human sign-off on the E2E tracer bullet run",
      ]);
      assert.equal(proposeRes.status, 0, `Propose failed: ${proposeRes.stderr}`);
      const propDoc = JSON.parse(proposeRes.stdout);
      assert.equal(propDoc.status, "proposed");
      const proposalId = propDoc.proposal_id;
      assert.match(proposalId, CROCKFORD_ULID);

      // Without the key the action fails closed (Law 6).
      const actNoKey = runBin(BIN_MIRQL, [
        "i", "act", "--dir", mirqlDir, "--decision", "approve", "--target-id", proposalId,
      ]);
      assert.equal(actNoKey.status, EXIT_CODES.POLICY_DENIAL);
      assert.equal(JSON.parse(actNoKey.stderr).error, "credentials_required");

      const actRes = runBin(BIN_MIRQL, [
        "i", "act",
        "--dir", mirqlDir,
        "--decision", "approve",
        "--key", humanKeyPath,
        "--target-id", proposalId,
        "--reason", "Human approves the tracer run",
      ]);
      assert.equal(actRes.status, 0, `Act failed: ${actRes.stderr}`);
      const actDoc = JSON.parse(actRes.stdout);
      assert.equal(actDoc.status, "acted");
      assert.equal(actDoc.decision, "approve");
      assert.equal(actDoc.seq, 5);
      assert.equal(actDoc.event.type, "human.approval");
      assert.equal(actDoc.event.writer.ns, "human:owner");

      const proposalDoc = JSON.parse(
        readFileSync(join(mirqlDir, "proposals", `${proposalId}.json`), "utf8"),
      );
      assert.equal(proposalDoc.status, "approved");

      // =====================================================================
      // Step 7: Halt / resume deadlock drill (B5)
      // =====================================================================
      const haltRes = runBin(BIN_QUEUE, ["halt", "--dir", mirqlDir, "--reason", "tracer halt drill"]);
      assert.equal(haltRes.status, 0, `Halt failed: ${haltRes.stderr}`);
      assert.equal(JSON.parse(haltRes.stdout).status, "halted");

      const statusHalted = JSON.parse(runBin(BIN_QUEUE, ["status", "--dir", mirqlDir]).stdout);
      assert.equal(statusHalted.halted, true);

      // Resume is a human-sovereign action emitting mirql.resume (NOT
      // human.approval) so both the queue and log folds lift the halt.
      const resumeRes = runBin(BIN_MIRQL, [
        "i", "act",
        "--dir", mirqlDir,
        "--decision", "resume",
        "--key", humanKeyPath,
        "--target-id", proposalId,
        "--reason", "Human resumes the factory",
      ]);
      assert.equal(resumeRes.status, 0, `Resume failed: ${resumeRes.stderr}`);
      const resumeDoc = JSON.parse(resumeRes.stdout);
      assert.equal(resumeDoc.status, "acted");
      assert.equal(resumeDoc.decision, "resume");
      assert.equal(resumeDoc.seq, 7);
      assert.equal(resumeDoc.event.type, "mirql.resume");
      assert.equal(resumeDoc.event.writer.ns, "human:owner");

      // The QUEUE fold lifts the halt on mirql.resume.
      const statusResumed = JSON.parse(runBin(BIN_QUEUE, ["status", "--dir", mirqlDir]).stdout);
      assert.equal(statusResumed.halted, false);

      // The LOG fold lifts the halt on mirql.resume.
      const viewRes = runBin(BIN_MIRQL, ["l", "view", "state", "--dir", mirqlDir]);
      assert.equal(viewRes.status, 0, `View failed: ${viewRes.stderr}`);
      const stateDoc = JSON.parse(viewRes.stdout);
      assert.equal(stateDoc.seq, 7);
      assert.equal(stateDoc.halted, false);

      // The INBOX digest fold lifts the halt on mirql.resume.
      const digestResumed = JSON.parse(runBin(BIN_MIRQL, ["i", "digest", "--dir", mirqlDir]).stdout);
      assert.equal(digestResumed.halted, false);
      assert.equal(digestResumed.seq, 7);

      // =====================================================================
      // Step 8: Final full-ledger audit
      // =====================================================================
      events = readAllEvents(mirqlDir);
      assert.equal(events.length, 7);
      const finalVerify = runBin(BIN_MIRQL, ["l", "verify", "--dir", mirqlDir]);
      assert.equal(finalVerify.status, 0, `Final verify failed: ${finalVerify.stderr}`);
      const finalAudit = JSON.parse(finalVerify.stdout);
      assert.equal(finalAudit.valid, true);
      assert.equal(finalAudit.event_count, 7);
      assert.equal(finalAudit.head_hash, events[6].hash);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
