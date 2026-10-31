// tests/inbox.test.mjs — Comprehensive test suite for packages/inbox.
// Covers drop-in genesis, human intent ingestion, Law 6 cryptographic sovereignty,
// read-only keyless digest, and the bounded proposer intake gate.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  readFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EXIT_CODES,
  validateDocument,
  verifyEvent,
  sha256,
  generateEd25519Keypair,
} from "../packages/core/index.mjs";
import {
  runGenesis,
  sendIntent,
  renderDigest,
  actOnItem,
  createProposal,
  loadKeyring,
  loadWriterKey,
  runCli,
} from "../packages/inbox/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN_MIRQL = join(ROOT, "bin", "mirql.mjs");
const BIN_INBOX = join(ROOT, "bin", "mirql-inbox.mjs");

function makeTmpDir() {
  return mkdtempSync(join(tmpdir(), "mirql-inbox-test-"));
}

function runBin(binPath, args, opts = {}) {
  return spawnSync(process.execPath, [binPath, ...args], {
    cwd: opts.cwd || ROOT,
    encoding: "utf8",
    timeout: 30000,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

describe("Work Package W5b: mirql-inbox test suite", () => {
  it("genesis initializes the .mirql layout, keyring, and seq: 1 mirql.genesis event", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      const res = runGenesis(mirqlDir, { idempotencyKey: "test-genesis-1" });
      assert.equal(res.status, "initialized");
      assert.equal(res.seq, 1);
      assert.ok(res.hash.startsWith("sha256:"));

      // Check directory layout
      assert.ok(existsSync(join(mirqlDir, "ledger", "events.jsonl")));
      assert.ok(existsSync(join(mirqlDir, "ledger", "keyring.json")));
      assert.ok(existsSync(join(mirqlDir, "ledger", "snapshots")));
      assert.ok(existsSync(join(mirqlDir, "cache", "state.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "human.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "queue.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "run_supervisor.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "log.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "inbox.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "notary.key.json")));
      assert.ok(existsSync(join(mirqlDir, "keys", "lifeguard.key.json")));
      assert.ok(existsSync(join(mirqlDir, "consensus")));
      assert.ok(existsSync(join(mirqlDir, "proposals")));
      assert.ok(existsSync(join(mirqlDir, "warrants")));

      // Verify genesis event envelope
      const lines = readFileSync(join(mirqlDir, "ledger", "events.jsonl"), "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0);
      assert.equal(lines.length, 1);

      const evt = JSON.parse(lines[0]);
      assert.equal(evt.seq, 1);
      assert.equal(evt.type, "mirql.genesis");
      assert.equal(evt.writer.ns, "human:owner");
      assert.equal(evt.prev_hash, "sha256:" + "0".repeat(64));

      const keyring = loadKeyring(mirqlDir);
      assert.ok(keyring[evt.writer.key_id]);
      const humanPub = keyring[evt.writer.key_id];
      const verifyRes = verifyEvent(evt, humanPub);
      assert.equal(verifyRes.ok, true);

      // Verify genesis idempotency
      const again = runGenesis(mirqlDir, { idempotencyKey: "test-genesis-1" });
      assert.equal(again.status, "already_initialized");
      assert.equal(again.seq, 1);
      assert.equal(again.hash, res.hash);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("send creates schema-valid warrant.schema.json and signed human.intent event", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);

      const sendRes = sendIntent(mirqlDir, {
        kind: "bug",
        title: "Fix off-by-one in sequence counter",
        summary: "Ensure seq starts strictly at 1",
        scope: ["packages/core/**", "packages/inbox/**"],
        red_check: "node --test tests/inbox.test.mjs",
        budget_micro_usd: 1200000,
      });

      assert.equal(sendRes.status, "sent");
      assert.equal(sendRes.seq, 2);
      assert.ok(sendRes.warrant_id);
      assert.ok(sendRes.intent_id.startsWith("intent_"));

      // Verify warrant document
      const warrantPath = join(mirqlDir, "warrants", `${sendRes.warrant_id}.json`);
      assert.ok(existsSync(warrantPath));
      const warrant = JSON.parse(readFileSync(warrantPath, "utf8"));

      const val = validateDocument("warrant", warrant);
      assert.equal(val.valid, true, `Warrant invalid: ${val.errors.join("; ")}`);
      assert.equal(warrant.created_by, "human:owner");
      assert.equal(warrant.budget_micro_usd, 1200000);
      assert.equal(warrant.class, "surgical");

      // Verify event in ledger
      const lines = readFileSync(join(mirqlDir, "ledger", "events.jsonl"), "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0);
      assert.equal(lines.length, 2);

      const evt2 = JSON.parse(lines[1]);
      assert.equal(evt2.seq, 2);
      assert.equal(evt2.type, "human.intent");
      assert.equal(evt2.writer.ns, "human:owner");
      assert.equal(evt2.payload.warrant_id, sendRes.warrant_id);

      const keyring = loadKeyring(mirqlDir);
      assert.equal(verifyEvent(evt2, keyring[evt2.writer.key_id]).ok, true);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("enforces Law 6: rejects act with non-human writer key or forged key", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);

      // Attempting to act with a queue key or unauthorized foreign key
      const queueKey = loadWriterKey(mirqlDir, "tool:queue");
      assert.ok(queueKey);

      assert.throws(
        () =>
          actOnItem(
            mirqlDir,
            { decision: "approve", target_id: "warrant_001", reason: "looks good" },
            { signingKey: queueKey.privateKey, writer: "tool:queue" }
          ),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL
      );

      // Attempting to act with a forged foreign key not in keyring
      const forgedKp = generateEd25519Keypair();
      assert.throws(
        () =>
          actOnItem(
            mirqlDir,
            { decision: "approve", target_id: "warrant_001" },
            { signingKey: forgedKp.privateKey, publicKey: forgedKp.publicKey }
          ),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL || err.exitCode === EXIT_CODES.INTEGRITY_VIOLATION
      );

      // Legitimate human act succeeds
      const actRes = actOnItem(mirqlDir, {
        decision: "approve",
        target_id: "warrant_001",
        reason: "Affirmative human approval verified",
      });
      assert.equal(actRes.status, "acted");
      assert.equal(actRes.decision, "approve");
      assert.equal(actRes.event.type, "human.approval");
      assert.equal(actRes.event.writer.ns, "human:owner");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("digest is strictly keyless and does not mutate events.jsonl", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);
      sendIntent(mirqlDir, {
        title: "Test intent for digest",
        summary: "Inspect digest stability",
      });

      const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
      const contentBefore = readFileSync(eventsFile, "utf8");
      const hashBefore = sha256(contentBefore);

      // Render JSON digest
      const digest = renderDigest(mirqlDir);
      assert.equal(digest.tool, "inbox");
      assert.equal(digest.mode, "BUILD");
      assert.equal(digest.seq, 2);
      assert.equal(digest.mutates_ledger, false);
      assert.ok(Array.isArray(digest.pending_approvals));
      assert.ok(Array.isArray(digest.pending_proposals));
      assert.ok(Array.isArray(digest.recent_outcomes));

      // Render Markdown digest
      const md = renderDigest(mirqlDir, { format: "markdown" });
      assert.match(md, /# mirql Factory Digest/);
      assert.match(md, /Macro Mode/);

      // Verify zero mutation
      const contentAfter = readFileSync(eventsFile, "utf8");
      assert.equal(sha256(contentAfter), hashBefore);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("propose enforces ROADMAP.md citation, NOT-ROADMAP filter, and max 3 quota", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      runGenesis(mirqlDir);

      // 1. Missing or invalid roadmap citation rejected
      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M99",
            title: "Invalid milestone ref",
            description: "Should fail roadmap citation gate",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL
      );

      // 2. NOT-ROADMAP nr-0001 (auto-approve on timeout) rejected
      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M1",
            title: "Add auto-approve timeout to inbox",
            description: "Configure auto_approve_timeout_s when human is offline",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL
      );

      // 3. NOT-ROADMAP nr-0002 (direct git push) rejected
      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M1",
            title: "Allow builder direct agent git push",
            description: "Execute git_push to origin without notary proof",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL
      );

      // 4. NOT-ROADMAP nr-0003 (float numbers) rejected
      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M2",
            title: "Support floating-point budgets",
            description: "Allow float_numbers and fractional_cents in ledger math",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL
      );

      // 5. Valid proposal succeeds
      const p1 = createProposal(mirqlDir, {
        roadmap_ref: "M1",
        title: "Deterministic wake trigger harness",
        description: "Zero unprompted polling with pure reactive supervisor wake",
      });
      assert.equal(p1.status, "proposed");
      assert.ok(existsSync(join(mirqlDir, "proposals", `${p1.proposal_id}.json`)));

      // Add two more proposals to reach the 3-proposal limit
      const p2 = createProposal(mirqlDir, {
        roadmap_ref: "M2",
        title: "Potential Phi collection ratchet",
        description: "Enforce monotone potential non-increasing invariant",
      });
      assert.equal(p2.status, "proposed");

      const p3 = createProposal(mirqlDir, {
        roadmap_ref: "M3",
        title: "Claim-check drift detection harness",
        description: "Verify public surface claims mechanically",
      });
      assert.equal(p3.status, "proposed");

      // 6. Fourth proposal exceeds quota ceiling (max 3 active) -> rejected
      assert.throws(
        () =>
          createProposal(mirqlDir, {
            roadmap_ref: "M4",
            title: "Incremental mutation tester",
            description: "Generate AST mutants on changed lines",
          }),
        (err) => err.exitCode === EXIT_CODES.POLICY_DENIAL
      );

      // Verify digest reflects the 3 pending proposals
      const digest = renderDigest(mirqlDir);
      assert.equal(digest.pending_proposals.length, 3);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("CLI subcommands work cleanly through bin/mirql.mjs and bin/mirql-inbox.mjs", () => {
    const tmp = makeTmpDir();
    const mirqlDir = join(tmp, ".mirql");

    try {
      // 1. Genesis via mirql i genesis
      const resGen = runBin(BIN_MIRQL, ["i", "genesis", "--dir", mirqlDir]);
      assert.equal(resGen.status, 0, `Genesis failed: ${resGen.stderr}`);
      const genDoc = JSON.parse(resGen.stdout);
      assert.equal(genDoc.status, "initialized");
      assert.equal(genDoc.seq, 1);

      // 2. Send intent via mirql-inbox send
      const resSend = runBin(BIN_INBOX, [
        "send",
        "--dir",
        mirqlDir,
        "--title",
        "CLI submission test",
        "--summary",
        "Testing CLI flags",
        "--kind",
        "feature",
        "--budget",
        "2000000",
      ]);
      assert.equal(resSend.status, 0, `Send failed: ${resSend.stderr}`);
      const sendDoc = JSON.parse(resSend.stdout);
      assert.equal(sendDoc.status, "sent");
      assert.equal(sendDoc.seq, 2);

      // 3. Propose via mirql i propose
      const resProp = runBin(BIN_MIRQL, [
        "i",
        "propose",
        "--dir",
        mirqlDir,
        "--roadmap-ref",
        "M1",
        "--title",
        "Proposer CLI test",
        "--description",
        "Testing proposal submission via CLI router",
      ]);
      assert.equal(resProp.status, 0, `Propose failed: ${resProp.stderr}`);
      const propDoc = JSON.parse(resProp.stdout);
      assert.equal(propDoc.status, "proposed");

      // 4. Digest via mirql i digest
      const resDigest = runBin(BIN_MIRQL, ["i", "digest", "--dir", mirqlDir]);
      assert.equal(resDigest.status, 0, `Digest failed: ${resDigest.stderr}`);
      const digDoc = JSON.parse(resDigest.stdout);
      assert.equal(digDoc.seq, 2);
      assert.equal(digDoc.pending_proposals.length, 1);

      // 5. Act via mirql-inbox act
      const resAct = runBin(BIN_INBOX, [
        "act",
        "--dir",
        mirqlDir,
        "--decision",
        "approve",
        "--target-id",
        propDoc.proposal_id,
        "--reason",
        "CLI human approval test",
      ]);
      assert.equal(resAct.status, 0, `Act failed: ${resAct.stderr}`);
      const actDoc = JSON.parse(resAct.stdout);
      assert.equal(actDoc.status, "acted");
      assert.equal(actDoc.seq, 3);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
