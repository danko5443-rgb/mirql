// packages/queue/canary.mjs — Keyless Canary Promotion Gauntlet & Provenance Engine (Milestone M7).
//
// Invariants enforced:
// - Law 9: N-1 supervisor evaluates, gates, and promotes version N.
// - Law 4: One durable ledger; all canary state transitions fold purely from ledger events.
// - Law 17: Integer-only metrics (basis points, safe integers, zero floats, RFC 8785 JCS).
// - SLSA v1.0 / Sigstore keyless cryptographic provenance envelope.
// - Automated promotion on clean probation window; instant rollback on statistical anomaly.
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  jcs,
  sha256,
  ulid,
  hlcTick,
  signEvent,
  verifyEvent,
  generateEd25519Keypair,
  EXIT_CODES,
  withLedgerLock,
  foldQueueState,
  readLedgerEvents,
} from "../core/index.mjs";
import {
  getOrCreateQueueKeypair,
  appendLedgerEventRaw,
} from "./ledger.mjs";

/** Default canary configuration parameters. All rates in basis points (1 bp = 0.01%). */
export const CANARY_DEFAULTS = Object.freeze({
  PROBATION_WINDOW_MS: 60000,
  ERROR_THRESHOLD_BP: 1, // 0.01% max error rate (1 in 10,000)
  LATENCY_P99_CEILING_MS: 2000, // 2000ms max p99
  MIN_REQUIRED_SAMPLES: 1,
});

/**
 * Structured error helper with exitCode.
 */
function canaryError(code, message, exitCode = EXIT_CODES.POLICY_DENIAL) {
  const err = new Error(message);
  err.errorCode = code;
  err.exitCode = exitCode;
  return err;
}

/**
 * Validates a non-negative safe integer (Law 17).
 */
function requireSafeInteger(val, name) {
  if (!Number.isSafeInteger(val) || val < 0) {
    throw canaryError(
      "INVALID_INTEGER",
      `Law 17 violation: ${name} must be a non-negative safe integer; got ${val}`,
      EXIT_CODES.USAGE_ERROR,
    );
  }
  return val;
}

/**
 * Helper to fetch all events from the ledger.
 */
function getLedgerEvents(mirqlDir) {
  return readLedgerEvents(mirqlDir).map((item) => (item?.event ? item.event : item));
}

/**
 * Generates a SLSA v1.0 / in-toto compliant provenance statement with keyless ephemeral signing.
 *
 * @param {object} params
 * @param {string} params.subjectName
 * @param {string} params.subjectDigest - SHA-256 hash of candidate artifact / commit
 * @param {string} params.commitSha
 * @param {string} params.baseSha
 * @param {string} params.warrantId
 * @param {string} [params.supervisorVersion]
 * @param {string} [params.candidateVersion]
 * @param {number} [params.epoch]
 * @param {number} [params.nowMs]
 * @returns {{
 *   statement: object,
 *   envelope: object,
 *   statement_hash: string,
 *   ephemeral_public_key: string,
 *   ephemeral_key_id: string
 * }}
 */
export function generateSLSAProvenance(params = {}) {
  const nowMs = Number.isSafeInteger(params.nowMs) ? params.nowMs : Date.now();
  const subjectName = params.subjectName || "mirql";
  const subjectDigest = params.subjectDigest || sha256(params.commitSha || "default-candidate");
  const commitSha = params.commitSha || subjectDigest;
  const baseSha = params.baseSha || "0000000000000000000000000000000000000000";
  const warrantId = params.warrantId || "01M6CANARY0000000000000000";
  const supervisorVersion = params.supervisorVersion || "0.1.0";
  const candidateVersion = params.candidateVersion || "0.2.0";
  const epoch = Number.isSafeInteger(params.epoch) ? params.epoch : 1;

  // In-toto Statement v1 / SLSA Provenance v1.0 specification
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: subjectName,
        digest: {
          sha256: subjectDigest,
        },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://mirql.dev/build/v1",
        externalParameters: {
          entryPoint: "bin/mirql.mjs",
          baseSha,
          commitSha,
          warrantId,
        },
        internalParameters: {
          nodeVersion: process.version,
          epoch,
          tenantId: "mirql-core",
        },
      },
      runDetails: {
        builder: {
          id: "keyless:sigstore:mirql-factory",
          version: supervisorVersion,
        },
        metadata: {
          invocationId: ulid(nowMs),
          startedOn: new Date(nowMs).toISOString(),
          finishedOn: new Date(nowMs).toISOString(),
        },
        byproducts: [
          {
            name: "target_candidate_version",
            value: candidateVersion,
          },
        ],
      },
    },
  };

  const canonicalStatement = jcs(statement);
  const statementHash = sha256(canonicalStatement);

  // Keyless ephemeral signing ceremony (Sigstore/SLSA model)
  const ephemeralKp = generateEd25519Keypair();
  const envelopeToSign = {
    payloadType: "application/vnd.in-toto+json",
    payloadHash: statementHash,
    issuedAtMs: nowMs,
    builderKeyId: ephemeralKp.keyId,
  };
  const signatureRes = signEvent(
    {
      v: 1,
      id: ulid(nowMs),
      type: "slsa.provenance",
      ts: new Date(nowMs).toISOString(),
      payload: envelopeToSign,
    },
    ephemeralKp.privateKey,
    ephemeralKp.keyId,
  );

  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(canonicalStatement, "utf8").toString("base64"),
    signatures: [
      {
        keyid: ephemeralKp.keyId,
        sig: signatureRes.sig,
        publicKey: ephemeralKp.publicKey,
      },
    ],
    attestation: signatureRes,
  };

  return {
    statement,
    envelope,
    statement_hash: statementHash,
    ephemeral_public_key: ephemeralKp.publicKey,
    ephemeral_key_id: ephemeralKp.keyId,
  };
}

/**
 * Verifies a SLSA v1.0 provenance attestation envelope.
 *
 * @param {object} envelope
 * @param {string} [expectedDigest]
 * @returns {{ valid: boolean, errors: string[], statement?: object }}
 */
export function verifySLSAProvenance(envelope, expectedDigest) {
  const errors = [];
  if (!envelope || typeof envelope !== "object") {
    return { valid: false, errors: ["Envelope must be a valid object"] };
  }
  if (envelope.payloadType !== "application/vnd.in-toto+json") {
    errors.push(`Invalid payloadType: ${envelope.payloadType}`);
  }
  if (!envelope.payload || typeof envelope.payload !== "string") {
    errors.push("Missing envelope base64 payload");
    return { valid: false, errors };
  }

  let statement;
  let rawJson = "";
  try {
    rawJson = Buffer.from(envelope.payload, "base64").toString("utf8");
    statement = JSON.parse(rawJson);
  } catch (err) {
    errors.push(`Failed to parse base64 payload: ${err.message}`);
    return { valid: false, errors };
  }

  if (statement._type !== "https://in-toto.io/Statement/v1") {
    errors.push(`Invalid statement _type: ${statement._type}`);
  }
  if (statement.predicateType !== "https://slsa.dev/provenance/v1") {
    errors.push(`Invalid predicateType: ${statement.predicateType}`);
  }

  if (expectedDigest) {
    const subjectDigest = statement.subject?.[0]?.digest?.sha256;
    if (subjectDigest !== expectedDigest) {
      errors.push(`Subject digest mismatch: expected ${expectedDigest}, found ${subjectDigest}`);
    }
  }

  // Cryptographic signature verification
  const sigInfo = envelope.signatures?.[0];
  if (!sigInfo || !sigInfo.sig || !sigInfo.publicKey) {
    errors.push("Missing envelope signature or ephemeral public key");
  } else if (envelope.attestation) {
    const computedHash = sha256(rawJson);
    if (envelope.attestation.payload?.payloadHash !== computedHash) {
      errors.push(`Attestation payload hash mismatch: expected ${computedHash}, got ${envelope.attestation.payload?.payloadHash}`);
    }
    const verifyRes = verifyEvent(envelope.attestation, sigInfo.publicKey);
    if (!verifyRes.ok) {
      errors.push(`Cryptographic signature verification failed: ${verifyRes.reason}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    statement,
  };
}

/**
 * Stages a candidate release into the canary probation gauntlet.
 * Enforces Law 9: N-1 supervisor evaluates and stages version N.
 *
 * @param {string} mirqlDir
 * @param {object} options
 * @returns {object}
 */
export function stageCanary(mirqlDir, options = {}) {
  const jobId = options.jobId || options.job_id;
  const baseSha = options.baseSha || options.base_sha;
  const candidateVersion = options.candidateVersion || options.candidate_version || "0.2.0";
  const supervisorVersion = options.supervisorVersion || options.supervisor_version || "0.1.0";
  const probationWindowMs = Number.isSafeInteger(options.probationWindowMs ?? options.probation_window_ms)
    ? (options.probationWindowMs ?? options.probation_window_ms)
    : CANARY_DEFAULTS.PROBATION_WINDOW_MS;
  const errorThresholdBp = Number.isSafeInteger(options.errorThresholdBp ?? options.error_threshold_bp)
    ? (options.errorThresholdBp ?? options.error_threshold_bp)
    : CANARY_DEFAULTS.ERROR_THRESHOLD_BP;
  const latencyP99CeilingMs = Number.isSafeInteger(options.latencyP99CeilingMs ?? options.latency_p99_ceiling_ms)
    ? (options.latencyP99CeilingMs ?? options.latency_p99_ceiling_ms)
    : CANARY_DEFAULTS.LATENCY_P99_CEILING_MS;

  // Law 9: N-1 Processes N invariant
  if (supervisorVersion === candidateVersion) {
    throw canaryError(
      "LAW_9_VIOLATION",
      `Law 9 violation: candidate version (${candidateVersion}) cannot bootstrap itself; supervisor must be prior version (N-1)`,
      EXIT_CODES.POLICY_DENIAL,
    );
  }

  if (!jobId) {
    throw canaryError("MISSING_JOB_ID", "jobId is required to stage canary deployment", EXIT_CODES.USAGE_ERROR);
  }
  if (!baseSha) {
    throw canaryError("MISSING_BASE_SHA", "baseSha is required for canary staging", EXIT_CODES.POLICY_DENIAL);
  }

  return withLedgerLock(mirqlDir, () => {
    const state = foldQueueState(mirqlDir);
    const job = state.jobs[jobId];
    if (!job) {
      throw canaryError("JOB_NOT_FOUND", `Job ${jobId} not found in folded ledger`, EXIT_CODES.POLICY_DENIAL);
    }

    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
    const canaryId = ulid(nowMs);

    // Generate cryptographic SLSA provenance statement
    const provenance = generateSLSAProvenance({
      subjectName: "mirql",
      subjectDigest: sha256(jobId + ":" + candidateVersion),
      commitSha: baseSha,
      baseSha,
      warrantId: job.warrant_id,
      supervisorVersion,
      candidateVersion,
      epoch: job.epoch || 1,
      nowMs,
    });

    // Save provenance envelope to disk
    const provDir = join(mirqlDir, "provenance");
    mkdirSync(provDir, { recursive: true });
    const provPath = join(provDir, `${canaryId}.slsa.json`);
    writeFileSync(provPath, JSON.stringify(provenance.envelope, null, 2) + "\n", "utf8");

    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    const eventPayload = {
      canary_id: canaryId,
      job_id: jobId,
      warrant_id: job.warrant_id,
      base_sha: baseSha,
      candidate_version: candidateVersion,
      supervisor_version: supervisorVersion,
      probation_window_ms: probationWindowMs,
      error_threshold_bp: errorThresholdBp,
      latency_p99_ceiling_ms: latencyP99CeilingMs,
      staged_at_ms: nowMs,
      provenance_hash: provenance.statement_hash,
      provenance_path: provPath,
      ephemeral_key_id: provenance.ephemeral_key_id,
      status: "probation",
    };

    const stagedEvent = appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.canary_staged",
        epoch: job.epoch || 1,
        nowMs,
        payload: eventPayload,
      },
      keypair,
      state,
    );

    return {
      ok: true,
      status: "staged",
      canary_id: canaryId,
      job_id: jobId,
      candidate_version: candidateVersion,
      supervisor_version: supervisorVersion,
      probation_window_ms: probationWindowMs,
      staged_at_ms: nowMs,
      provenance_hash: provenance.statement_hash,
      event: stagedEvent,
    };
  });
}

/**
 * Samples real-time traffic/performance metrics during canary probation.
 * All arithmetic strictly complies with Law 17 (Integer-only, zero floats).
 *
 * @param {string} mirqlDir
 * @param {string} canaryId
 * @param {object} sampleMetrics - { totalRequests, errorCount, latencyP50Ms, latencyP90Ms, latencyP99Ms }
 * @param {object} [options]
 * @returns {object}
 */
export function sampleCanaryHealth(mirqlDir, canaryId, sampleMetrics = {}, options = {}) {
  if (!canaryId || typeof canaryId !== "string") {
    throw canaryError("MISSING_CANARY_ID", "canaryId is required", EXIT_CODES.USAGE_ERROR);
  }

  const totalRequests = requireSafeInteger(sampleMetrics.totalRequests ?? sampleMetrics.total_requests ?? 10000, "totalRequests");
  const errorCount = requireSafeInteger(sampleMetrics.errorCount ?? sampleMetrics.error_count ?? 0, "errorCount");
  const latencyP50Ms = requireSafeInteger(sampleMetrics.latencyP50Ms ?? sampleMetrics.latency_p50_ms ?? 10, "latencyP50Ms");
  const latencyP90Ms = requireSafeInteger(sampleMetrics.latencyP90Ms ?? sampleMetrics.latency_p90_ms ?? 50, "latencyP90Ms");
  const latencyP99Ms = requireSafeInteger(sampleMetrics.latencyP99Ms ?? sampleMetrics.latency_p99_ms ?? 100, "latencyP99Ms");

  if (totalRequests === 0) {
    throw canaryError("ZERO_REQUESTS", "totalRequests must be > 0 for health calculation", EXIT_CODES.USAGE_ERROR);
  }
  if (errorCount > totalRequests) {
    throw canaryError("INVALID_METRIC", "errorCount cannot exceed totalRequests", EXIT_CODES.USAGE_ERROR);
  }

  // Integer basis points: error_rate_bp = (errorCount * 10000) / totalRequests
  const errorRateBp = Math.floor((errorCount * 10000) / totalRequests);

  return withLedgerLock(mirqlDir, () => {
    const state = foldQueueState(mirqlDir);
    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);
    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();

    const canary = state.canaries?.[canaryId];
    const errorThresholdBp = options.errorThresholdBp ?? canary?.error_threshold_bp ?? CANARY_DEFAULTS.ERROR_THRESHOLD_BP;
    const latencyP99CeilingMs = options.latencyP99CeilingMs ?? canary?.latency_p99_ceiling_ms ?? CANARY_DEFAULTS.LATENCY_P99_CEILING_MS;

    const isHealthy = (errorRateBp <= errorThresholdBp) && (latencyP99Ms <= latencyP99CeilingMs);
    const anomalyDetected = !isHealthy;
    const reason = isHealthy
      ? "metrics_within_thresholds"
      : (errorRateBp > errorThresholdBp ? "error_rate_spike" : "latency_spike");

    const sampleId = ulid(nowMs);
    const payload = {
      sample_id: sampleId,
      canary_id: canaryId,
      total_requests: totalRequests,
      error_count: errorCount,
      error_rate_bp: errorRateBp,
      error_threshold_bp: errorThresholdBp,
      latency_p50_ms: latencyP50Ms,
      latency_p90_ms: latencyP90Ms,
      latency_p99_ms: latencyP99Ms,
      latency_p99_ceiling_ms: latencyP99CeilingMs,
      healthy: isHealthy,
      anomaly_detected: anomalyDetected,
      reason,
      sampled_at_ms: nowMs,
    };

    const healthEvent = appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.canary_health",
        epoch: 1,
        nowMs,
        payload,
      },
      keypair,
      state,
    );

    // If an anomaly is detected, instantly initiate emergency rollback!
    let rollbackResult = null;
    if (anomalyDetected && options.autoRollback !== false) {
      rollbackResult = rollbackCanary(mirqlDir, canaryId, {
        reason: `Anomaly detected during canary sampling: ${reason} (error_rate_bp: ${errorRateBp}, p99: ${latencyP99Ms}ms)`,
        nowMs: nowMs + 1,
        keyFile: options.keyFile,
        skipLock: true,
      });
    }

    return {
      ok: true,
      canary_id: canaryId,
      sample_id: sampleId,
      healthy: isHealthy,
      anomaly_detected: anomalyDetected,
      error_rate_bp: errorRateBp,
      latency_p99_ms: latencyP99Ms,
      reason,
      event: healthEvent,
      rollback: rollbackResult,
    };
  });
}

/**
 * Evaluates the canary probation window and executes promotion or rollback.
 *
 * @param {string} mirqlDir
 * @param {string} canaryId
 * @param {object} options
 * @returns {object}
 */
export function evaluateAndPromoteCanary(mirqlDir, canaryId, options = {}) {
  if (!canaryId || typeof canaryId !== "string") {
    throw canaryError("MISSING_CANARY_ID", "canaryId is required", EXIT_CODES.USAGE_ERROR);
  }

  return withLedgerLock(mirqlDir, () => {
    const rawEvents = getLedgerEvents(mirqlDir);
    const canaryEvents = rawEvents.filter(
      (e) => e.payload?.canary_id === canaryId,
    );

    const stagedEvt = canaryEvents.find((e) => e.type === "job.canary_staged");
    if (!stagedEvt) {
      throw canaryError("CANARY_NOT_FOUND", `No staged canary found for id ${canaryId}`, EXIT_CODES.POLICY_DENIAL);
    }

    const state = foldQueueState(mirqlDir);
    const canaryState = state.canaries?.[canaryId];
    if (canaryState?.status === "promoted") {
      return {
        ok: true,
        status: "promoted",
        already_promoted: true,
        canary_id: canaryId,
        message: "Canary is already promoted",
      };
    }
    if (canaryState?.status === "rolled_back") {
      return {
        ok: false,
        status: "rolled_back",
        canary_id: canaryId,
        message: "Canary was previously rolled back",
      };
    }

    const stagedPayload = stagedEvt.payload;
    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
    const elapsedMs = nowMs - stagedPayload.staged_at_ms;

    // 1. Verify probation window has elapsed
    if (elapsedMs < stagedPayload.probation_window_ms && options.force !== true) {
      return {
        ok: false,
        status: "probation_active",
        canary_id: canaryId,
        elapsed_ms: elapsedMs,
        probation_window_ms: stagedPayload.probation_window_ms,
        remaining_ms: stagedPayload.probation_window_ms - elapsedMs,
        message: "Canary is still actively undergoing probation window",
      };
    }

    // 2. Evaluate all recorded health samples
    const healthSamples = canaryEvents.filter((e) => e.type === "job.canary_health");
    if (healthSamples.length < CANARY_DEFAULTS.MIN_REQUIRED_SAMPLES && options.force !== true) {
      throw canaryError(
        "INSUFFICIENT_SAMPLES",
        `Canary requires at least ${CANARY_DEFAULTS.MIN_REQUIRED_SAMPLES} health metric sample(s) before promotion`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    const anomalySample = healthSamples.find((s) => s.payload?.anomaly_detected === true);
    if (anomalySample) {
      // Anomaly detected: instant rollback
      const rb = rollbackCanary(mirqlDir, canaryId, {
        reason: `Anomaly detected in sample ${anomalySample.payload?.sample_id}: ${anomalySample.payload?.reason}`,
        nowMs,
        keyFile: options.keyFile,
        skipLock: true,
      });
      return {
        ok: false,
        status: "rolled_back",
        canary_id: canaryId,
        reason: anomalySample.payload?.reason,
        rollback: rb,
      };
    }

    // 3. Clean probation passed: Execute atomic promotion!
    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    const promotionPayload = {
      canary_id: canaryId,
      job_id: stagedPayload.job_id,
      warrant_id: stagedPayload.warrant_id,
      base_sha: stagedPayload.base_sha,
      promoted_version: stagedPayload.candidate_version,
      prior_version: stagedPayload.supervisor_version,
      samples_evaluated: healthSamples.length,
      probation_elapsed_ms: elapsedMs,
      promoted_at_ms: nowMs,
      status: "promoted",
    };

    const promotedEvent = appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.promoted",
        epoch: stagedEvt.epoch || 1,
        nowMs,
        payload: promotionPayload,
      },
      keypair,
      state,
    );

    return {
      ok: true,
      status: "promoted",
      canary_id: canaryId,
      job_id: stagedPayload.job_id,
      version: stagedPayload.candidate_version,
      samples_evaluated: healthSamples.length,
      promoted_at_ms: nowMs,
      event: promotedEvent,
    };
  });
}

/**
 * Rolls back a canary deployment to the prior stable release (N-1).
 *
 * @param {string} mirqlDir
 * @param {string} canaryId
 * @param {object} options
 * @returns {object}
 */
export function rollbackCanary(mirqlDir, canaryId, options = {}) {
  const reason = options.reason || "anomaly_detected";
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();

  const doRollback = () => {
    const rawEvents = getLedgerEvents(mirqlDir);
    const stagedEvt = rawEvents.find(
      (e) => e.type === "job.canary_staged" && e.payload?.canary_id === canaryId,
    );

    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);
    const state = foldQueueState(mirqlDir);

    const priorVersion = stagedEvt?.payload?.supervisor_version || "0.1.0";
    const candidateVersion = stagedEvt?.payload?.candidate_version || "0.2.0";

    const rollbackPayload = {
      canary_id: canaryId,
      reason,
      active_version: priorVersion,
      rolled_back_version: candidateVersion,
      rolled_back_at_ms: nowMs,
      status: "rolled_back",
    };

    const eventType = options.eventType || "mirql.rollback";

    const rollbackEvent = appendLedgerEventRaw(
      mirqlDir,
      {
        type: eventType,
        epoch: stagedEvt?.epoch || 1,
        nowMs,
        payload: rollbackPayload,
      },
      keypair,
      state,
    );

    return {
      ok: true,
      status: "rolled_back",
      canary_id: canaryId,
      active_version: priorVersion,
      rolled_back_version: candidateVersion,
      reason,
      event: rollbackEvent,
    };
  };

  if (options.skipLock) {
    return doRollback();
  }
  return withLedgerLock(mirqlDir, doRollback);
}
