// tests/m7-canary.test.mjs — Milestone M7: Keyless Canary Promotion Gauntlet & Ouroboros Self-Hosting Test Suite.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateSLSAProvenance,
  verifySLSAProvenance,
  stageCanary,
  sampleCanaryHealth,
  evaluateAndPromoteCanary,
  rollbackCanary,
  submitWarrant,
  leaseNextJob,
  CANARY_DEFAULTS,
  main as queueMain,
} from "../packages/queue/index.mjs";
import {
  foldQueueState,
  readLedgerEvents,
  EXIT_CODES,
  sha256,
  ulid,
} from "../packages/core/index.mjs";
import {
  getOrCreateQueueKeypair,
} from "../packages/queue/ledger.mjs";

describe("Milestone M7: Keyless Canary Promotion Gauntlet & Ouroboros Self-Hosting", () => {
  let tmpDir;
  let mirqlDir;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "mirql-m7-test-"));
    mirqlDir = join(tmpDir, ".mirql");
    mkdirSync(mirqlDir, { recursive: true });
    getOrCreateQueueKeypair(mirqlDir);
  });

  afterEach(() => {
    if (tmpDir && existsSync(tmpDir)) {
      try {
        rmSync(tmpDir, { recursive: true, force: true });
      } catch {}
    }
  });

  function setupReadyJob(warrantId = null) {
    const wid = warrantId || ulid();
    const warrant = {
      v: 1,
      id: wid,
      class: "surgical",
      semantic_fingerprint: sha256(`intent: canary test ${wid}`),
      anchors: [{ path: "packages/queue/index.mjs" }],
      evidence: { citations: 1 },
      red_check: { reviewed: 1 },
      scope: { allow_globs: ["packages/queue/**"] },
      budget_micro_usd: 500_000,
      created_by: "human:owner",
    };
    const res = submitWarrant(mirqlDir, warrant);
    assert.equal(res.ok, true, `submitWarrant must succeed: ${res.error}`);
    leaseNextJob(mirqlDir, { workerId: "worker-canary-test" });
    return res.job_id;
  }

  describe("1. Keyless SLSA v1.0 Provenance Generation & Cryptographic Verification", () => {
    it("generates a compliant in-toto statement and SLSA v1.0 provenance attestation", () => {
      const prov = generateSLSAProvenance({
        subjectName: "mirql",
        subjectDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        baseSha: "0000000000000000000000000000000000000000",
        warrantId: ulid(),
        supervisorVersion: "0.1.0",
        candidateVersion: "0.2.0",
        nowMs: 1700000000000,
      });

      assert.ok(prov.statement, "Provenance must contain statement");
      assert.equal(prov.statement._type, "https://in-toto.io/Statement/v1");
      assert.equal(prov.statement.predicateType, "https://slsa.dev/provenance/v1");
      assert.equal(prov.statement.subject[0].name, "mirql");
      assert.equal(prov.statement.predicate.runDetails.builder.version, "0.1.0");

      assert.ok(prov.envelope, "Provenance must contain DSSE/in-toto envelope");
      assert.equal(prov.envelope.payloadType, "application/vnd.in-toto+json");
      assert.ok(prov.envelope.signatures.length > 0, "Envelope must have signatures");
      assert.ok(prov.ephemeral_public_key, "Ephemeral public key must be exported");

      const verifyRes = verifySLSAProvenance(prov.envelope);
      assert.equal(verifyRes.valid, true, "SLSA provenance must cryptographically verify");
      assert.equal(verifyRes.errors.length, 0);
    });

    it("detects cryptographic tampering of provenance envelope payload or digest", () => {
      const prov = generateSLSAProvenance({
        subjectName: "mirql",
        subjectDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      });

      // Digest mismatch check
      const wrongDigestRes = verifySLSAProvenance(
        prov.envelope,
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      );
      assert.equal(wrongDigestRes.valid, false);
      assert.ok(wrongDigestRes.errors.some((e) => e.includes("digest mismatch")));

      // Tampered payload
      const tamperedEnvelope = {
        ...prov.envelope,
        payload: Buffer.from(JSON.stringify({ _type: "https://tampered.io" })).toString("base64"),
      };
      const tamperedRes = verifySLSAProvenance(tamperedEnvelope);
      assert.equal(tamperedRes.valid, false);
      assert.ok(tamperedRes.errors.length > 0);
    });
  });

  describe("2. Law 9 Invariant Enforcement (N-1 Supervisor Evaluates N)", () => {
    it("strictly rejects candidate from staging/evaluating itself (supervisor === candidate)", () => {
      const jobId = setupReadyJob();

      assert.throws(
        () => {
          stageCanary(mirqlDir, {
            jobId,
            baseSha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            supervisorVersion: "0.2.0",
            candidateVersion: "0.2.0", // Self-evaluation violation!
          });
        },
        (err) => {
          assert.equal(err.errorCode, "LAW_9_VIOLATION");
          assert.equal(err.exitCode, EXIT_CODES.POLICY_DENIAL);
          return true;
        },
      );
    });

    it("successfully stages canary under prior N-1 supervisor", () => {
      const jobId = setupReadyJob();

      const res = stageCanary(mirqlDir, {
        jobId,
        baseSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        supervisorVersion: "0.1.0",
        candidateVersion: "0.2.0",
        probationWindowMs: 5000,
        nowMs: 1700000000000,
      });

      assert.equal(res.ok, true);
      assert.equal(res.status, "staged");
      assert.ok(res.canary_id);
      assert.equal(res.candidate_version, "0.2.0");
      assert.equal(res.supervisor_version, "0.1.0");

      const state = foldQueueState(mirqlDir);
      assert.ok(state.canaries[res.canary_id]);
      assert.equal(state.canaries[res.canary_id].status, "probation");
      assert.equal(state.jobs[jobId].status, "canary_probation");
    });
  });

  describe("3. Real-Time Traffic Sampling & Law 17 Integer Basis Points Math", () => {
    it("computes error rates in exact basis points with safe integers (zero floats)", () => {
      const jobId = setupReadyJob();
      const staged = stageCanary(mirqlDir, {
        jobId,
        baseSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        probationWindowMs: 5000,
        nowMs: 1700000000000,
      });

      // 1 error out of 10,000 requests = 1 basis point (0.01%)
      const sample1 = sampleCanaryHealth(mirqlDir, staged.canary_id, {
        totalRequests: 10000,
        errorCount: 1,
        latencyP50Ms: 15,
        latencyP90Ms: 45,
        latencyP99Ms: 150,
      }, { nowMs: 1700000001000 });

      assert.equal(sample1.ok, true);
      assert.equal(sample1.error_rate_bp, 1);
      assert.equal(sample1.healthy, true);
      assert.equal(sample1.anomaly_detected, false);

      // Verify safe integer guarantee (Law 17)
      assert.ok(Number.isSafeInteger(sample1.error_rate_bp));
      assert.ok(Number.isSafeInteger(sample1.latency_p99_ms));
    });

    it("rejects non-integer metric inputs under Law 17", () => {
      assert.throws(
        () => {
          sampleCanaryHealth(mirqlDir, "dummy-id", {
            totalRequests: 1000.5, // Float violation!
            errorCount: 0,
          });
        },
        (err) => {
          assert.equal(err.errorCode, "INVALID_INTEGER");
          assert.equal(err.exitCode, EXIT_CODES.USAGE_ERROR);
          return true;
        },
      );
    });

    it("triggers instant automated rollback upon statistical anomaly (error spike or latency spike)", () => {
      const jobId = setupReadyJob();
      const staged = stageCanary(mirqlDir, {
        jobId,
        baseSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        probationWindowMs: 5000,
        nowMs: 1700000000000,
      });

      // 5 errors out of 10,000 = 5 bp (exceeds default 1 bp threshold)
      const anomalySample = sampleCanaryHealth(mirqlDir, staged.canary_id, {
        totalRequests: 10000,
        errorCount: 5,
        latencyP99Ms: 250,
      }, { nowMs: 1700000001000 });

      assert.equal(anomalySample.healthy, false);
      assert.equal(anomalySample.anomaly_detected, true);
      assert.equal(anomalySample.reason, "error_rate_spike");
      assert.ok(anomalySample.rollback, "Automatic rollback must be triggered");
      assert.equal(anomalySample.rollback.status, "rolled_back");

      const state = foldQueueState(mirqlDir);
      assert.equal(state.canaries[staged.canary_id].status, "rolled_back");
    });
  });

  describe("4. Autonomous Canary Promotion & Probation Window Gating", () => {
    it("holds promotion while probation window is active, then atomically promotes upon clean completion", () => {
      const jobId = setupReadyJob();
      const startTime = 1700000000000;
      const probationMs = 10000;

      const staged = stageCanary(mirqlDir, {
        jobId,
        baseSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        candidateVersion: "0.2.0",
        supervisorVersion: "0.1.0",
        probationWindowMs: probationMs,
        nowMs: startTime,
      });

      // Record healthy sample
      sampleCanaryHealth(mirqlDir, staged.canary_id, {
        totalRequests: 50000,
        errorCount: 0,
        latencyP99Ms: 80,
      }, { nowMs: startTime + 2000 });

      // Attempt premature promotion at t + 3000ms
      const prematureRes = evaluateAndPromoteCanary(mirqlDir, staged.canary_id, {
        nowMs: startTime + 3000,
      });
      assert.equal(prematureRes.ok, false);
      assert.equal(prematureRes.status, "probation_active");
      assert.equal(prematureRes.remaining_ms, 7000);

      // Attempt promotion after probation window elapsed (t + 11000ms)
      const promotedRes = evaluateAndPromoteCanary(mirqlDir, staged.canary_id, {
        nowMs: startTime + 11000,
      });
      assert.equal(promotedRes.ok, true);
      assert.equal(promotedRes.status, "promoted");
      assert.equal(promotedRes.version, "0.2.0");

      const state = foldQueueState(mirqlDir);
      assert.equal(state.canaries[staged.canary_id].status, "promoted");
      assert.equal(state.jobs[jobId].status, "promoted");
    });

    it("prevents promoting an already rolled-back canary", () => {
      const jobId = setupReadyJob();
      const staged = stageCanary(mirqlDir, {
        jobId,
        baseSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        probationWindowMs: 1000,
        nowMs: 1700000000000,
      });

      rollbackCanary(mirqlDir, staged.canary_id, { reason: "manual_abort", nowMs: 1700000001000 });

      const evalRes = evaluateAndPromoteCanary(mirqlDir, staged.canary_id, {
        nowMs: 1700000005000,
        force: true,
      });
      assert.equal(evalRes.ok, false);
      assert.equal(evalRes.status, "rolled_back");
    });
  });

  describe("5. CLI Interface Integration (`mirql q promote` & `mirql q canary`)", () => {
    it("supports staging canary via CLI router", () => {
      const jobId = setupReadyJob();

      const oldStdout = process.stdout.write;
      let stdoutData = "";
      process.stdout.write = (chunk) => { stdoutData += chunk; return true; };

      try {
        const exitCode = queueMain([
          "canary",
          "stage",
          jobId,
          "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
          "--dir",
          mirqlDir,
        ]);
        assert.equal(exitCode, EXIT_CODES.OK);
        const parsed = JSON.parse(stdoutData.trim());
        assert.equal(parsed.ok, true);
        assert.equal(parsed.status, "staged");
      } finally {
        process.stdout.write = oldStdout;
      }
    });

    it("supports sampling health and promoting via CLI router flags", () => {
      const jobId = setupReadyJob();

      const staged = stageCanary(mirqlDir, {
        jobId,
        baseSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        probationWindowMs: 500,
      });

      const oldStdout = process.stdout.write;
      let stdoutData = "";
      process.stdout.write = (chunk) => { stdoutData += chunk; return true; };

      try {
        // Sample via CLI
        stdoutData = "";
        const sampleExit = queueMain([
          "promote",
          "--sample-health",
          staged.canary_id,
          "--total-requests",
          "10000",
          "--error-count",
          "0",
          "--latency-p99",
          "50",
          "--dir",
          mirqlDir,
        ]);
        assert.equal(sampleExit, EXIT_CODES.OK);
        const sampleParsed = JSON.parse(stdoutData.trim());
        assert.equal(sampleParsed.healthy, true);

        // Evaluate via CLI with force
        stdoutData = "";
        const evalExit = queueMain([
          "promote",
          "--evaluate-canary",
          staged.canary_id,
          "--force",
          "--dir",
          mirqlDir,
        ]);
        assert.equal(evalExit, EXIT_CODES.OK);
        const evalParsed = JSON.parse(stdoutData.trim());
        assert.equal(evalParsed.status, "promoted");
      } finally {
        process.stdout.write = oldStdout;
      }
    });
  });

  describe("6. Complete Ouroboros Self-Hosting Gauntlet", () => {
    it("completes full self-hosting loop: warrant -> job -> canary stage -> health verification -> promotion", () => {
      const jobId = setupReadyJob();

      // Stage candidate N (version 0.2.0) under supervisor N-1 (version 0.1.0)
      const stageRes = stageCanary(mirqlDir, {
        jobId,
        baseSha: "commit-ouroboros-release-candidate-hash-001",
        supervisorVersion: "0.1.0",
        candidateVersion: "0.2.0",
        probationWindowMs: 1000,
      });
      assert.equal(stageRes.status, "staged");

      // Record multiple production traffic telemetry samples
      sampleCanaryHealth(mirqlDir, stageRes.canary_id, {
        totalRequests: 20000,
        errorCount: 1, // 0 bp
        latencyP99Ms: 45,
      });
      sampleCanaryHealth(mirqlDir, stageRes.canary_id, {
        totalRequests: 40000,
        errorCount: 2, // 0 bp
        latencyP99Ms: 52,
      });

      // Complete probation and evaluate
      const promoRes = evaluateAndPromoteCanary(mirqlDir, stageRes.canary_id, { force: true });
      assert.equal(promoRes.status, "promoted");
      assert.equal(promoRes.version, "0.2.0");

      // Verify all events in durable ledger (Law 4)
      const events = readLedgerEvents(mirqlDir).map((e) => e.event);
      const stagedEvt = events.find((e) => e.type === "job.canary_staged");
      const healthEvts = events.filter((e) => e.type === "job.canary_health");
      const promotedEvt = events.find((e) => e.type === "job.promoted");

      assert.ok(stagedEvt, "Durable ledger must contain job.canary_staged");
      assert.equal(healthEvts.length, 2, "Durable ledger must contain all health samples");
      assert.ok(promotedEvt, "Durable ledger must contain job.promoted");

      // Final folded state reflects promoted release
      const finalState = foldQueueState(mirqlDir);
      assert.equal(finalState.canaries[stageRes.canary_id].status, "promoted");
      assert.equal(finalState.jobs[jobId].status, "promoted");
    });
  });
});
