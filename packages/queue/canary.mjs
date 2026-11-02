// packages/queue/canary.mjs — Keyless Canary Promotion Gauntlet & Provenance Engine (Milestone M7).
//
// Invariants enforced:
// - Law 9: Strict unidirectional N-1 supervisor evaluates, gates, and promotes version N (SemVer candidate > supervisor).
// - Law 4: One durable ledger; all canary state transitions fold purely from cryptographically verified ledger events.
// - Law 6: Silence is never consent; absent metrics/signatures fail closed; no synthetic telemetry.
// - Law 17: Integer-only metrics (basis points, safe non-negative integers, zero floats, RFC 8785 JCS).
// - SLSA v1.0 / Sigstore keyless cryptographic provenance envelope with artifact binding and active verification.
// - Automated promotion on clean probation window; instant rollback on statistical anomaly.
// - Idempotent fail-closed rollback with single-writer constant event types (mirql.rollback).
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  jcs,
  sha256,
  ulid,
  signEvent,
  verifyEvent,
  generateEd25519Keypair,
  EXIT_CODES,
  withLedgerLock,
  foldQueueState,
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
 * Structured error helper with exitCode and errorCode.
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
 * Parses and validates semver string (e.g. "1.2.3", "0.2.0-rc1").
 *
 * @param {string} v
 * @returns {{ major: number, minor: number, patch: number, prerelease: string | null } | null}
 */
export function parseSemver(v) {
  if (typeof v !== "string") return null;
  const match = v.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4] || null,
  };
}

/**
 * Compares two semver strings:
 *  1 if a > b
 * -1 if a < b
 *  0 if a === b
 *
 * @param {string} aStr
 * @param {string} bStr
 * @returns {number}
 */
export function compareSemver(aStr, bStr) {
  const a = parseSemver(aStr);
  const b = parseSemver(bStr);
  if (!a || !b) {
    throw canaryError("INVALID_SEMVER", `Invalid semver format for comparison: "${aStr}" vs "${bStr}"`, EXIT_CODES.USAGE_ERROR);
  }
  if (a.major !== b.major) return a.major > b.major ? 1 : -1;
  if (a.minor !== b.minor) return a.minor > b.minor ? 1 : -1;
  if (a.patch !== b.patch) return a.patch > b.patch ? 1 : -1;
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && !b.prerelease) return -1;
  if (a.prerelease && b.prerelease) {
    if (a.prerelease > b.prerelease) return 1;
    if (a.prerelease < b.prerelease) return -1;
  }
  return 0;
}

/**
 * Generates a SLSA v1.0 / in-toto compliant provenance statement with keyless ephemeral signing.
 *
 * @param {object} params
 * @param {string} [params.subjectName]
 * @param {string} [params.subjectDigest] - SHA-256 hash of candidate artifact / commit
 * @param {string} [params.commitSha]
 * @param {string} [params.baseSha]
 * @param {string} [params.warrantId]
 * @param {string} [params.supervisorVersion]
 * @param {string} [params.candidateVersion]
 * @param {number} [params.epoch]
 * @param {number} [params.nowMs]
 * @returns {{
 *   statement: object,
 *   envelope: object,
 *   statement_hash: string,
 *   subject_digest: string,
 *   ephemeral_public_key: string,
 *   ephemeral_key_id: string
 * }}
 */
export function generateSLSAProvenance(params = {}) {
  const nowMs = Number.isSafeInteger(params.nowMs) ? params.nowMs : Date.now();
  const subjectName = params.subjectName || "mirql";
  const commitSha = params.commitSha || params.candidateSha || "0000000000000000000000000000000000000000";
  const baseSha = params.baseSha || "0000000000000000000000000000000000000000";
  const subjectDigest = params.subjectDigest || sha256(commitSha !== "0000000000000000000000000000000000000000" ? commitSha : (params.jobId ? `${params.jobId}:${params.candidateVersion}` : "mirql-candidate-artifact"));
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
    subject_digest: subjectDigest,
    ephemeral_public_key: ephemeralKp.publicKey,
    ephemeral_key_id: ephemeralKp.keyId,
  };
}

/**
 * Verifies a SLSA v1.0 provenance attestation envelope.
 * Strictly fails closed on missing signatures, invalid public keys, or missing attestation (B1 hardening).
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

  // Cryptographic signature and attestation verification (Fail-closed B1)
  if (!envelope.attestation || typeof envelope.attestation !== "object") {
    errors.push("Missing envelope attestation");
  }

  if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    errors.push("Missing envelope signatures array");
  } else {
    const sigInfo = envelope.signatures[0];
    if (!sigInfo || !sigInfo.sig || !sigInfo.publicKey) {
      errors.push("Missing envelope signature or ephemeral public key");
    } else if (envelope.attestation) {
      if (sigInfo.sig !== envelope.attestation.sig) {
        errors.push("Envelope signature does not match attestation event signature");
      }
      const computedHash = sha256(rawJson);
      if (envelope.attestation.payload?.payloadHash !== computedHash) {
        errors.push(`Attestation payload hash mismatch: expected ${computedHash}, got ${envelope.attestation.payload?.payloadHash}`);
      }
      const verifyRes = verifyEvent(envelope.attestation, sigInfo.publicKey);
      if (!verifyRes.ok) {
        errors.push(`Cryptographic signature verification failed: ${verifyRes.reason}`);
      }
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
 * Enforces Law 9: Strict unidirectional N-1 supervisor evaluates and stages version N.
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

  const rawProbation = options.probationWindowMs ?? options.probation_window_ms;
  const probationWindowMs = rawProbation !== undefined
    ? requireSafeInteger(rawProbation, "probationWindowMs")
    : CANARY_DEFAULTS.PROBATION_WINDOW_MS;

  const rawThreshold = options.errorThresholdBp ?? options.error_threshold_bp;
  const errorThresholdBp = rawThreshold !== undefined
    ? requireSafeInteger(rawThreshold, "errorThresholdBp")
    : CANARY_DEFAULTS.ERROR_THRESHOLD_BP;
  if (errorThresholdBp > 10000) {
    throw canaryError("INVALID_INTEGER", "errorThresholdBp cannot exceed 10000 (100%)", EXIT_CODES.USAGE_ERROR);
  }

  const rawCeiling = options.latencyP99CeilingMs ?? options.latency_p99_ceiling_ms;
  const latencyP99CeilingMs = rawCeiling !== undefined
    ? requireSafeInteger(rawCeiling, "latencyP99CeilingMs")
    : CANARY_DEFAULTS.LATENCY_P99_CEILING_MS;
  if (latencyP99CeilingMs === 0) {
    throw canaryError("INVALID_INTEGER", "latencyP99CeilingMs must be > 0", EXIT_CODES.USAGE_ERROR);
  }

  // Law 9: Strict unidirectional ordering: Candidate (N) must be strictly greater than supervisor (N-1)
  const cmp = compareSemver(candidateVersion, supervisorVersion);
  if (cmp <= 0) {
    throw canaryError(
      "LAW_9_VIOLATION",
      `Law 9 violation: candidate version (${candidateVersion}) must strictly exceed supervisor version (${supervisorVersion}); downgrades and self-evaluations are forbidden`,
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

    // Bind supervisor version to ledger history if active_version exists
    if (state.active_version && compareSemver(supervisorVersion, state.active_version) < 0) {
      throw canaryError(
        "STALE_SUPERVISOR",
        `Supervisor version (${supervisorVersion}) is older than active ledger version (${state.active_version})`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    // Fail closed: a job may only be staged once the notary has accepted it.
    assertNotaryVerdict(state, jobId);

    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
    const canaryId = ulid(nowMs);
    const subjectDigest = sha256(baseSha + ":" + candidateVersion);

    // Generate cryptographic SLSA provenance statement
    const provenance = generateSLSAProvenance({
      subjectName: "mirql",
      subjectDigest,
      commitSha: baseSha,
      baseSha,
      jobId,
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

    // Law 15: Identity derives from content hash (provenance_hash), not mechanical local paths
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
      subject_digest: subjectDigest,
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
      subject_digest: subjectDigest,
      event: stagedEvent,
    };
  });
}

/**
 * Samples real-time traffic/performance metrics during canary probation.
 * All arithmetic strictly complies with Law 17 (Integer-only, zero floats).
 * Rejects missing metrics (Law 6: no synthetic default data).
 *
 * @param {string} mirqlDir
 * @param {string} canaryId
 * @param {object} sampleMetrics - { total_requests, error_count, latency_p50_ms, latency_p90_ms, latency_p99_ms }
 * @param {object} [options]
 * @returns {object}
 */
export function sampleCanaryHealth(mirqlDir, canaryId, sampleMetrics, options = {}) {
  if (!canaryId || typeof canaryId !== "string") {
    throw canaryError("MISSING_CANARY_ID", "canaryId is required", EXIT_CODES.USAGE_ERROR);
  }

  // Law 6: Silence is never consent — metrics must be explicitly supplied, no synthetic defaults
  if (!sampleMetrics || typeof sampleMetrics !== "object" || Object.keys(sampleMetrics).length === 0) {
    throw canaryError("MISSING_METRICS", "sampleMetrics object is required; fabricating healthy metrics is prohibited (Law 6)", EXIT_CODES.USAGE_ERROR);
  }

  const rawTotal = sampleMetrics.totalRequests ?? sampleMetrics.total_requests;
  const rawErrors = sampleMetrics.errorCount ?? sampleMetrics.error_count;
  const rawP50 = sampleMetrics.latencyP50Ms ?? sampleMetrics.latency_p50_ms;
  const rawP90 = sampleMetrics.latencyP90Ms ?? sampleMetrics.latency_p90_ms;
  const rawP99 = sampleMetrics.latencyP99Ms ?? sampleMetrics.latency_p99_ms;

  if (rawTotal !== undefined) {
    requireSafeInteger(rawTotal, "totalRequests");
  }
  if (rawErrors !== undefined) {
    requireSafeInteger(rawErrors, "errorCount");
  }
  if (rawP50 !== undefined) {
    requireSafeInteger(rawP50, "latencyP50Ms");
  }
  if (rawP90 !== undefined) {
    requireSafeInteger(rawP90, "latencyP90Ms");
  }
  if (rawP99 !== undefined) {
    requireSafeInteger(rawP99, "latencyP99Ms");
  }

  if (rawTotal === undefined || rawErrors === undefined || rawP99 === undefined) {
    throw canaryError(
      "MISSING_METRICS",
      "sampleMetrics must explicitly supply total_requests, error_count, and latency_p99_ms",
      EXIT_CODES.USAGE_ERROR,
    );
  }

  const totalRequests = rawTotal;
  const errorCount = rawErrors;
  const latencyP99Ms = rawP99;

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
    const canary = state.canaries?.[canaryId];
    if (!canary) {
      throw canaryError("CANARY_NOT_FOUND", `Canary ${canaryId} not found in folded ledger`, EXIT_CODES.POLICY_DENIAL);
    }
    if (canary.status === "rolled_back" || canary.status === "promoted") {
      throw canaryError("CANARY_TERMINAL_STATE", `Cannot sample canary ${canaryId} in terminal state '${canary.status}'`, EXIT_CODES.POLICY_DENIAL);
    }

    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);
    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();

    // Staged thresholds are IMMUTABLE once staged (M1 hardening)
    const errorThresholdBp = canary.error_threshold_bp;
    const latencyP99CeilingMs = canary.latency_p99_ceiling_ms;

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
      latency_p50_ms: rawP50 ?? null,
      latency_p90_ms: rawP90 ?? null,
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
        epoch: canary.epoch || 1,
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
 * Throws INVALID_VERDICT unless the job has an accepted verdict written by
 * notary:mergeproof. A missing verdict is a denial, not a pass.
 * @param {object} state
 * @param {string} jobId
 */
function assertNotaryVerdict(state, jobId) {
  const verdict = jobId ? state.verdicts?.[jobId] : undefined;
  if (!verdict) {
    throw canaryError("INVALID_VERDICT", `Job ${jobId} has no notary verdict`, EXIT_CODES.POLICY_DENIAL);
  }
  if (verdict.status !== "accepted" || verdict.writer !== "notary:mergeproof") {
    throw canaryError(
      "INVALID_VERDICT",
      `Job ${jobId} has unaccepted or unauthorized verdict: ${verdict.status} by ${verdict.writer}`,
      EXIT_CODES.POLICY_DENIAL,
    );
  }
}

/**
 * Evaluates the canary probation window and executes promotion or rollback.
 * Decisions are strictly made from the cryptographically verified fold (B3 hardening).
 * Requires verified SLSA provenance envelope (M4 hardening).
 * `--force` cannot waive minimum required samples (B2 hardening).
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
    // Rely EXCLUSIVELY on the verified fold state (B3 hardening)
    const state = foldQueueState(mirqlDir);
    const canary = state.canaries?.[canaryId];
    if (!canary) {
      throw canaryError("CANARY_NOT_FOUND", `Canary ${canaryId} not found in verified ledger state`, EXIT_CODES.POLICY_DENIAL);
    }

    if (canary.status === "promoted") {
      return {
        ok: true,
        status: "promoted",
        already_promoted: true,
        canary_id: canaryId,
        message: "Canary is already promoted",
      };
    }
    if (canary.status === "rolled_back") {
      return {
        ok: false,
        status: "rolled_back",
        canary_id: canaryId,
        message: "Canary was previously rolled back",
      };
    }

    // Re-verify the notary verdict before promotion (fail closed).
    assertNotaryVerdict(state, canary.job_id);

    // Re-verify Law 9 invariant: candidate must strictly exceed supervisor (B4 hardening)
    const cmp = compareSemver(canary.candidate_version, canary.supervisor_version);
    if (cmp <= 0) {
      throw canaryError(
        "LAW_9_VIOLATION",
        `Law 9 violation: candidate version (${canary.candidate_version}) must strictly exceed supervisor (${canary.supervisor_version})`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    // Cryptographic provenance verification (M4 hardening)
    const provPath = join(mirqlDir, "provenance", `${canaryId}.slsa.json`);
    let provEnvelope = options.provenanceEnvelope;
    if (!provEnvelope && existsSync(provPath)) {
      try {
        provEnvelope = JSON.parse(readFileSync(provPath, "utf8"));
      } catch (err) {
        throw canaryError("PROVENANCE_CORRUPT", `Failed to parse provenance envelope: ${err.message}`, EXIT_CODES.POLICY_DENIAL);
      }
    }
    if (provEnvelope) {
      const verifyRes = verifySLSAProvenance(provEnvelope, canary.subject_digest);
      if (!verifyRes.valid) {
        throw canaryError(
          "PROVENANCE_VERIFICATION_FAILED",
          `Cryptographic provenance verification failed: ${verifyRes.errors.join("; ")}`,
          EXIT_CODES.POLICY_DENIAL,
        );
      }
      const canonicalStatement = jcs(verifyRes.statement);
      const computedHash = sha256(canonicalStatement);
      if (computedHash !== canary.provenance_hash) {
        throw canaryError(
          "PROVENANCE_HASH_MISMATCH",
          `Provenance statement hash mismatch: staged=${canary.provenance_hash}, actual=${computedHash}`,
          EXIT_CODES.POLICY_DENIAL,
        );
      }
    } else if (options.requireProvenance !== false) {
      throw canaryError(
        "PROVENANCE_MISSING",
        `Keyless provenance envelope missing from disk at ${provPath}`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
    const elapsedMs = nowMs - canary.staged_at_ms;

    // 1. Require the full probation window for every promotion.
    if (elapsedMs < canary.probation_window_ms) {
      return {
        ok: false,
        status: "probation_active",
        canary_id: canaryId,
        elapsed_ms: elapsedMs,
        probation_window_ms: canary.probation_window_ms,
        remaining_ms: canary.probation_window_ms - elapsedMs,
        message: "Canary is still actively undergoing probation window",
      };
    }

    // 2. Evaluate all recorded health samples from verified fold
    const healthSamples = canary.samples || [];
    const minSamples = options.minSamples ?? CANARY_DEFAULTS.MIN_REQUIRED_SAMPLES;

    // B2 hardening: MIN_REQUIRED_SAMPLES can NEVER be bypassed by a bare boolean --force flag!
    if (healthSamples.length < minSamples) {
      throw canaryError(
        "INSUFFICIENT_SAMPLES",
        `Canary requires at least ${minSamples} verified health metric sample(s) before promotion (found: ${healthSamples.length})`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    // Check for anomalies across samples or folded anomaly flag
    const anomalySample = healthSamples.find((s) => s.anomaly_detected === true) || (canary.anomaly ? { reason: "folded_anomaly_detected" } : null);
    if (anomalySample) {
      const rb = rollbackCanary(mirqlDir, canaryId, {
        reason: `Anomaly detected during evaluation: ${anomalySample.reason}`,
        nowMs,
        keyFile: options.keyFile,
        skipLock: true,
      });
      return {
        ok: false,
        status: "rolled_back",
        canary_id: canaryId,
        reason: anomalySample.reason,
        rollback: rb,
      };
    }

    // 3. Clean probation passed: Execute atomic promotion!
    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    const promotionPayload = {
      canary_id: canaryId,
      job_id: canary.job_id,
      warrant_id: canary.warrant_id,
      base_sha: canary.base_sha,
      promoted_version: canary.candidate_version,
      prior_version: canary.supervisor_version,
      samples_evaluated: healthSamples.length,
      probation_elapsed_ms: elapsedMs,
      forced_waiver: false,
      promoted_at_ms: nowMs,
      status: "promoted",
    };

    const promotedEvent = appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.promoted",
        epoch: canary.epoch || 1,
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
      job_id: canary.job_id,
      version: canary.candidate_version,
      samples_evaluated: healthSamples.length,
      promoted_at_ms: nowMs,
      event: promotedEvent,
    };
  });
}

/**
 * Rolls back a canary deployment to the prior stable release (N-1).
 * Decisions are strictly made from the cryptographically verified fold (B3 hardening).
 * Idempotent, fail-closed, rejects unauthenticated event types (B6 & M2 hardening).
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
    // Rely EXCLUSIVELY on verified fold state (B3 hardening)
    const state = foldQueueState(mirqlDir);
    const canary = state.canaries?.[canaryId];

    if (!canary) {
      throw canaryError(
        "CANARY_NOT_FOUND",
        `Canary ${canaryId} not found in verified ledger state`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    // Prevent split-brain: cannot rollback already promoted canary (H10 & M2 hardening)
    if (canary.status === "promoted") {
      throw canaryError(
        "CANARY_ALREADY_PROMOTED",
        `Cannot rollback canary ${canaryId} that has already achieved promoted status`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }

    // Idempotent: if already rolled back, return without appending duplicate events
    if (canary.status === "rolled_back") {
      return {
        ok: true,
        status: "rolled_back",
        already_rolled_back: true,
        canary_id: canaryId,
        active_version: canary.supervisor_version,
        rolled_back_version: canary.candidate_version,
        reason: canary.rollback_reason || reason,
      };
    }

    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    const rollbackPayload = {
      canary_id: canaryId,
      job_id: canary.job_id,
      reason,
      active_version: canary.supervisor_version,
      rolled_back_version: canary.candidate_version,
      rolled_back_at_ms: nowMs,
      status: "rolled_back",
    };

    // B6 hardening: eventType is STRICTLY constant 'mirql.rollback' (caller cannot inject event types)
    const rollbackEvent = appendLedgerEventRaw(
      mirqlDir,
      {
        type: "mirql.rollback",
        epoch: canary.epoch || 1,
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
      active_version: canary.supervisor_version,
      rolled_back_version: canary.candidate_version,
      reason,
      event: rollbackEvent,
    };
  };

  if (options.skipLock) {
    return doRollback();
  }
  return withLedgerLock(mirqlDir, doRollback);
}
