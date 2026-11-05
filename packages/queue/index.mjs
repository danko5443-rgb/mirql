import { requireAuthorizedWarrant } from "../core/warrant.mjs";
// packages/queue/index.mjs — Deterministic State Machine, Warrant Admission & Lease Scheduler.
import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  EXIT_CODES,
  validateDocument,
  ulid,
  LedgerWatcher,
  createLedgerWatcher,
  waitForLedgerEvent,
  getActiveTrippedBreakers,
} from "../core/index.mjs";
import {
  getOrCreateQueueKeypair,
  foldQueueState,
  foldLedger,
  appendLedgerEvent,
  appendLedgerEventRaw,
  loadKeyring,
  saveKeyring,
  withLedgerLock,
} from "./ledger.mjs";
import { checkNotRoadmapGate, findNotRoadmapPath } from "./gate.mjs";
import {
  tick,
  DEFAULT_POLICY,
  isLeaseLive,
  validateConcurrencyLimit,
  selectAvailableWork,
} from "./fsm.mjs";
import {
  CANARY_DEFAULTS,
  generateSLSAProvenance,
  verifySLSAProvenance,
  stageCanary,
  sampleCanaryHealth,
  evaluateAndPromoteCanary,
  rollbackCanary,
} from "./canary.mjs";

export {
  foldLedger,
  foldQueueState,
  loadKeyring,
  saveKeyring,
  withLedgerLock,
  appendLedgerEvent,
  appendLedgerEventRaw,
  getOrCreateQueueKeypair,
} from "./ledger.mjs";
export { checkNotRoadmapGate } from "./gate.mjs";
export {
  tick,
  DEFAULT_POLICY,
  isLeaseLive,
  validateConcurrencyLimit,
} from "./fsm.mjs";
export {
  LedgerWatcher,
  createLedgerWatcher,
  waitForLedgerEvent,
} from "../core/index.mjs";
export {
  CANARY_DEFAULTS,
  generateSLSAProvenance,
  verifySLSAProvenance,
  stageCanary,
  sampleCanaryHealth,
  evaluateAndPromoteCanary,
  rollbackCanary,
} from "./canary.mjs";

/** Tool name reported by this package. */
export const TOOL = "queue";

function rejected(exit_code, error, extra = {}) {
  return { ok: false, status: "rejected", exit_code, error, ...extra };
}

function rejectOrThrow(options, exit_code, error, extra) {
  if (options.throwOnError) {
    const err = new Error(error);
    err.exitCode = exit_code;
    throw err;
  }
  return rejected(exit_code, error, extra);
}

function emitOk(res) {
  process.stdout.write(JSON.stringify(res) + "\n");
  return EXIT_CODES.OK;
}

function emitResult(res, fallback) {
  if (!res.ok) {
    process.stderr.write(JSON.stringify(res) + "\n");
    return res.exit_code ?? fallback;
  }
  return emitOk(res);
}

/**
 * Load policy configuration from policy/mirql.json if present.
 * @param {string} mirqlDir
 * @param {string} [repoRoot]
 * @returns {object}
 */
export function loadPolicy(mirqlDir, repoRoot) {
  const root = repoRoot || resolve(mirqlDir, "..");
  const candidate = join(root, "policy", "mirql.json");
  if (existsSync(candidate)) {
    try {
      const parsed = JSON.parse(readFileSync(candidate, "utf8"));
      return { ...DEFAULT_POLICY, ...parsed };
    } catch {
      // Fall through to default
    }
  }
  return { ...DEFAULT_POLICY };
}

/**
 * Resolve root repository directory from mirqlDir or options.
 * @param {string} mirqlDir
 * @param {string} [repoRoot]
 * @returns {string}
 */
function resolveRepoRoot(mirqlDir, repoRoot) {
  if (repoRoot) return resolve(repoRoot);
  return resolve(mirqlDir, "..");
}

/**
 * Get current queue status folded from the durable ledger.
 *
 * @param {string} mirqlDir - path to .mirql directory
 * @param {object} [options]
 * @returns {object} { tool, mode, epoch, seq, halted, budget_spent_micro_usd, open_warrants, queued_jobs, active_leases }
 */
export function getQueueStatus(mirqlDir, options = {}) {
  const state = foldQueueState(mirqlDir);
  const nowMs = options.nowMs ?? Date.now();

  const openWarrants = Object.values(state.warrants || {})
    .filter((w) => w.status === "active" || w.status === "open" || w.status === "in_progress")
    .map((w) => w.id);

  const queuedJobs = Object.values(state.jobs || {})
    .filter((j) => j.status === "queued" || j.status === "enqueued")
    .map((j) => j.id);

  const activeLeases = Object.values(state.active_leases || {}).filter(
    (l) => isLeaseLive(l, nowMs),
  );

  return {
    tool: TOOL,
    mode: state.mode || "BUILD",
    epoch: state.epoch || 1,
    seq: state.seq || 0,
    halted: Boolean(state.halted),
    budget_spent_micro_usd: state.budget_spent_micro_usd || 0,
    open_warrants: openWarrants,
    queued_jobs: queuedJobs,
    active_leases: activeLeases,
    warrants: state.warrants,
    jobs: state.jobs,
  };
}

/**
 * Submit a warrant document to the queue with negative-space and deduplication gates.
 *
 * @param {string} mirqlDir
 * @param {object} warrantInput
 * @param {object} [options]
 * @returns {{ ok: boolean, status: string, warrant_id?: string, job_id?: string, tier?: string, attempt?: number, exit_code?: number, error?: string }}
 */
export function submitWarrant(mirqlDir, warrantInput, options = {}) {
  const repoRoot = resolveRepoRoot(mirqlDir, options.repoRoot);

  // 1. Law 9 NOT-ROADMAP.md negative-space gate check
  let notRoadmapContent = "";
  const notRoadmapFile = options.notRoadmapFile || findNotRoadmapPath(repoRoot);
  if (notRoadmapFile && existsSync(notRoadmapFile)) {
    try {
      notRoadmapContent = readFileSync(notRoadmapFile, "utf8");
    } catch {
      // ignore
    }
  }

  const gateResult = checkNotRoadmapGate(warrantInput, notRoadmapContent);
  if (!gateResult.allowed) {
    const errorMsg = `Policy denial: warrant proposes forbidden pattern (${gateResult.id}: ${gateResult.reason})`;
    return rejectOrThrow(options, EXIT_CODES.POLICY_DENIAL, errorMsg, { id: gateResult.id, reason: gateResult.reason });
  }

  // 2. Validate warrant document against canonical schema
  const validation = validateDocument("warrant", warrantInput);
  if (!validation.valid) {
    const errorMsg = `Invalid warrant: ${validation.errors.join("; ")}`;
    return rejectOrThrow(options, EXIT_CODES.USAGE_ERROR, errorMsg, { errors: validation.errors });
  }

  return withLedgerLock(mirqlDir, () => {
    // 3. Fix B6: Enforce Warrant ID Uniqueness across entire ledger history
    const state = foldQueueState(mirqlDir);
    const existingWarrant = state.warrants?.[warrantInput.id];
    const alreadyAdmitted = Object.values(state.jobs || {}).some(job => job.warrant_id === warrantInput.id);
    let authorizedOnly = false;
    if (existingWarrant && !alreadyAdmitted) {
      try {
        requireAuthorizedWarrant(mirqlDir, { warrant: warrantInput, nowMs: options.nowMs });
        authorizedOnly = true;
      } catch (error) {
        if (error.code !== "WARRANT_UNAUTHORIZED") throw error;
      }
    }
    if (existingWarrant && !authorizedOnly) {
      const errorMsg = `Policy denial: warrant ID ${warrantInput.id} already exists in ledger`;
      return rejectOrThrow(options, EXIT_CODES.POLICY_DENIAL, errorMsg);
    }

    // 4. Semantic fingerprint deduplication check
    const openWarrants = Object.values(state.warrants || {}).filter(
      (w) => w.id !== warrantInput.id &&
        (w.status === "active" || w.status === "open" || w.status === "in_progress") &&
        Object.values(state.jobs || {}).some(job => job.warrant_id === w.id),
    );

    const existing = openWarrants.find(
      (w) => w.semantic_fingerprint === warrantInput.semantic_fingerprint,
    );

    if (existing) {
      const existingJob = Object.values(state.jobs || {}).find(
        (j) => j.warrant_id === existing.id,
      );
      return {
        ok: true,
        status: "deduplicated",
        deduplicated: true,
        warrant_id: existing.id,
        job_id: existingJob?.id ?? null,
        tier: existing.tier ?? "flash",
        attempt: existingJob?.attempt ?? 1,
      };
    }

    // 5. Warrant admission: enqueue corresponding job
    const nowMs = options.nowMs ?? Date.now();
    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);
    const jobId = ulid(nowMs);
    const warrantId = warrantInput.id;
    const role = warrantInput.role || "builder";
    const tier = "flash";
    const attempt = 1;

    appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.enqueued",
        nowMs,
        payload: {
          job_id: jobId,
          warrant_id: warrantId,
          role,
          tier,
          attempt,
          warrant: warrantInput,
        },
      },
      keypair,
      state,
    );

    // If currently QUIESCENT, wake up back to BUILD
    if (state.mode === "QUIESCENT") {
      appendLedgerEventRaw(
        mirqlDir,
        {
          type: "factory.mode_changed",
          nowMs: nowMs + 1,
          payload: {
            from_mode: "QUIESCENT",
            to_mode: "BUILD",
            reason: "new_warrant_submitted",
          },
        },
        keypair,
        state,
      );
    }

    return {
      ok: true,
      status: "submitted",
      warrant_id: warrantId,
      job_id: jobId,
      tier,
      attempt,
    };
  });
}

/**
 * Advance the queue state machine through deterministic tick reduction.
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {object} tick result
 */
export function tickQueue(mirqlDir, options = {}) {
  const policy = loadPolicy(mirqlDir, options.repoRoot);
  const nowMs = options.nowMs ?? Date.now();

  return withLedgerLock(mirqlDir, () => {
    let state = foldQueueState(mirqlDir, policy);

    // Fix B2: Reap expired leases
    const expiredLeases = Object.values(state.active_leases || {}).filter(
      (l) => !isLeaseLive(l, nowMs),
    );

    if (expiredLeases.length > 0) {
      const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);
      for (const lease of expiredLeases) {
        appendLedgerEventRaw(
          mirqlDir,
          {
            type: "job.timeout",
            nowMs,
            payload: {
              job_id: lease.job_id,
              warrant_id: lease.warrant_id,
              epoch: lease.epoch,
              reason: "lease_expired",
              attempt: lease.attempt,
              expired_at_ms: nowMs,
            },
          },
          keypair,
          state,
        );
      }
      // Re-fold state after reaping
      state = foldQueueState(mirqlDir, policy);
    }

    const result = tick(state, policy, nowMs, options);

    // If tick resulted in mode change, append factory.mode_changed event
    if (result.next_mode && result.next_mode !== state.mode && result.next_mode !== "HALTED") {
      const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);
      appendLedgerEventRaw(
        mirqlDir,
        {
          type: "factory.mode_changed",
          nowMs,
          payload: {
            from_mode: state.mode || "BUILD",
            to_mode: result.next_mode,
            reason: result.reason || result.action,
          },
        },
        keypair,
        state,
      );
    }

    return result;
  });
}

/**
 * Lease the next eligible queued or warrant job, assigning monotonic epoch & lease ttl.
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {object}
 */
export function leaseNextJob(mirqlDir, options = {}) {
  const policy = loadPolicy(mirqlDir, options.repoRoot);

  return withLedgerLock(mirqlDir, () => {
    const state = foldQueueState(mirqlDir, policy);
    const nowMs = options.nowMs ?? Date.now();

    // 1. Check halted
    if (state.halted === true) {
      return {
        ok: false,
        status: "halted",
        action: "HALTED",
        exit_code: EXIT_CODES.HALTED,
        error: "Queue is halted",
      };
    }

    // 1b. Circuit breakers are binding (issue #15): while any subsystem's
    // breaker is actively TRIPPED, no new work may start. The queue refuses
    // to lease (fail-closed, Law 14) until the cooldown expires or a human
    // resets the breaker via the doctor. Throttle does NOT block — only trips.
    const trippedBreakers = getActiveTrippedBreakers(mirqlDir, nowMs, options);
    if (trippedBreakers.length > 0) {
      return {
        ok: false,
        status: "breaker_tripped",
        action: "BREAKER_TRIPPED",
        exit_code: EXIT_CODES.BREAKER_OPEN,
        error: `Circuit breaker(s) tripped: ${trippedBreakers
          .map((b) => `${b.subsystem} (${b.reason}, expires in ${Math.max(0, b.expires_at_ms - nowMs)}ms)`)
          .join("; ")}`,
        breakers: trippedBreakers,
      };
    }

    // 2. Check budget exhaustion
    const budgetSpent = state.budget_spent_micro_usd || 0;
    if (budgetSpent >= policy.daily_budget_micro_usd) {
      return {
        ok: false,
        status: "budget_exhausted",
        action: "BUDGET_EXHAUSTED",
        exit_code: EXIT_CODES.BUDGET_EXHAUSTED,
        error: "Daily budget exhausted",
      };
    }

    const maxAttempts = policy.max_attempts_per_warrant ?? 3;
    const maxAwaitingHuman = policy.max_awaiting_human ?? 5;
    const allWarrants = Object.values(state.warrants || {});

    // Fix B5: Count warrants awaiting human review
    const needsHumanWarrants = allWarrants.filter(
      (w) => w.status === "needs_human" || (w.failed_attempts || 0) >= maxAttempts,
    );

    // If count of warrants awaiting human reaches policy ceiling, stop entire queue
    if (needsHumanWarrants.length >= maxAwaitingHuman) {
      return {
        ok: false,
        status: "needs_human",
        action: "NEEDS_HUMAN",
        exit_code: EXIT_CODES.NEEDS_HUMAN,
        error: "Too many warrants awaiting human intervention",
      };
    }

    const { availableOpenWarrants, availableQueuedJobs } = selectAvailableWork(state, allWarrants, maxAttempts, nowMs);

    // Law 14 & Milestone M1: Concurrency enforcement for BUILD mode
    const rawLimit =
      options.concurrency ??
      options.max_build_concurrency ??
      policy.max_build_concurrency ??
      policy.concurrency;
    const limitValidation = validateConcurrencyLimit(rawLimit);
    if (!limitValidation.valid) {
      return rejected(EXIT_CODES.USAGE_ERROR, limitValidation.error);
    }

    if (state.mode === "BUILD") {
      const activeUnexpiredLeases = Object.values(state.active_leases || {}).filter(
        (l) => isLeaseLive(l, nowMs),
      );
      if (activeUnexpiredLeases.length >= limitValidation.limit) {
        if (availableQueuedJobs.length === 0 && availableOpenWarrants.length === 0) {
          return {
            ok: true,
            status: "empty",
            message: "No jobs available to lease",
          };
        }
        return {
          ok: true,
          status: "concurrency_limit",
          message: `Concurrency limit (${limitValidation.limit}) reached for BUILD mode; lease already in progress`,
          active_lease: activeUnexpiredLeases[0],
        };
      }
    }

    let targetJobId = null;
    let targetWarrantId = null;
    let targetRole = "builder";
    let targetTier = "flash";
    let targetAttempt = 1;

    if (availableQueuedJobs.length > 0) {
      const job = availableQueuedJobs[0];
      targetJobId = job.id;
      targetWarrantId = job.warrant_id;
      targetRole = job.role || "builder";
      targetTier = job.tier || "flash";
      targetAttempt = job.attempt || 1;

      // Law 1 check: execution must be backed by an open warrant
      if (
        ["builder", "doctor", "consolidator"].includes(targetRole) &&
        (!targetWarrantId || !state.warrants[targetWarrantId])
      ) {
        return rejected(EXIT_CODES.POLICY_DENIAL, `Law 1 violation: role ${targetRole} must be backed by an open warrant`);
      }
    } else if (availableOpenWarrants.length > 0) {
      const warrant = availableOpenWarrants[0];
      const failed = warrant.failed_attempts || 0;
      targetAttempt = failed + 1;

      if (targetAttempt > maxAttempts) {
        return {
          ok: false,
          status: "needs_human",
          action: "NEEDS_HUMAN",
          exit_code: EXIT_CODES.NEEDS_HUMAN,
          warrant_id: warrant.id,
          error: "Warrant exceeded max retry attempts and requires human intervention",
        };
      }

      // Law 8 Escalation ladder: 1 -> flash, 2 -> mid, 3 -> max/doctor
      if (targetAttempt === 1) {
        targetTier = "flash";
        targetRole = warrant.role || "builder";
      } else if (targetAttempt === 2) {
        targetTier = "mid";
        targetRole = warrant.role || "builder";
      } else {
        targetTier = "max";
        targetRole = "doctor";
      }

      targetJobId = ulid(nowMs);
      targetWarrantId = warrant.id;
    } else {
      // No available jobs and no available warrants
      if (needsHumanWarrants.length > 0) {
        return {
          ok: false,
          status: "needs_human",
          action: "NEEDS_HUMAN",
          exit_code: EXIT_CODES.NEEDS_HUMAN,
          warrant_id: needsHumanWarrants[0].id,
          error: "Warrant exceeded max retry attempts and requires human intervention",
        };
      }
      return {
        ok: true,
        status: "empty",
        message: "No jobs available to lease",
      };
    }

    // 4. Monotonic epoch increment
    const nextEpoch = (state.epoch || 0) + 1;
    const ttlMs = options.ttl_ms ?? policy.lease_ttl_ms ?? 900000;
    const expiresAtMs = nowMs + ttlMs;

    const lease = {
      job_id: targetJobId,
      warrant_id: targetWarrantId,
      role: targetRole,
      tier: targetTier,
      epoch: nextEpoch,
      attempt: targetAttempt,
      ttl_ms: ttlMs,
      leased_at_ms: nowMs,
      expires_at_ms: expiresAtMs,
    };

    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.leased",
        epoch: nextEpoch,
        nowMs,
        payload: { ...lease, status: "leased" },
      },
      keypair,
      state,
    );

    return { ok: true, status: "leased", ...lease };
  });
}

/**
 * Verify that a lease for a job is valid and matches the current epoch (Law 5 single-lease fencing).
 *
 * @param {string} mirqlDir
 * @param {string} jobId
 * @param {number} epoch
 * @param {object} [options]
 * @returns {number} EXIT_CODES.OK (0) or EXIT_CODES.STALE_EPOCH (5)
 */
export function verifyLeaseEpoch(mirqlDir, jobId, epoch, options = {}) {
  // Fix B3: If epoch is undefined, null, or not a number -> STALE_EPOCH
  if (epoch === undefined || epoch === null || typeof epoch !== "number") {
    return EXIT_CODES.STALE_EPOCH;
  }

  const state = foldQueueState(mirqlDir);
  const nowMs = options.nowMs ?? Date.now();

  // Fix B3: Must have an active live lease; no live lease must always mean stale epoch
  const lease = state.active_leases[jobId];
  if (!lease) {
    return EXIT_CODES.STALE_EPOCH;
  }

  if (lease.epoch !== epoch) {
    return EXIT_CODES.STALE_EPOCH;
  }

  const expiresAt = lease.expires_at_ms ?? (lease.leased_at_ms + lease.ttl_ms);
  if (nowMs > expiresAt) {
    return EXIT_CODES.STALE_EPOCH;
  }

  return EXIT_CODES.OK;
}

/**
 * Promote a job following verified mergeproof verdict.
 *
 * @param {string} mirqlDir
 * @param {object} options - { jobId, baseSha, keyFile }
 * @returns {{ ok: boolean, status?: string, exit_code?: number, error?: string }}
 */
export function promoteJob(mirqlDir, options = {}) {
  const jobId = options.jobId || options.job_id;

  if (!jobId) {
    return rejected(EXIT_CODES.USAGE_ERROR, "Missing required jobId parameter");
  }

  // Fix B4: baseSha is strictly required
  const baseSha = options.baseSha || options.base_sha;
  if (!baseSha) {
    return rejected(EXIT_CODES.POLICY_DENIAL, "Missing required baseSha parameter");
  }

  return withLedgerLock(mirqlDir, () => {
    const state = foldQueueState(mirqlDir);

    const job = state.jobs[jobId];
    if (!job) {
      return rejected(EXIT_CODES.POLICY_DENIAL, `Job ${jobId} not found in ledger`);
    }

    const verdict = state.verdicts[jobId];
    if (!verdict) {
      return rejected(EXIT_CODES.POLICY_DENIAL, `No verdict found for job ${jobId}`);
    }

    if (verdict.writer !== "notary:mergeproof") {
      return rejected(EXIT_CODES.POLICY_DENIAL, `Verdict not authored by notary:mergeproof (found: ${verdict.writer})`);
    }

    if (verdict.epoch !== job.epoch) {
      return rejected(EXIT_CODES.STALE_EPOCH, `Stale epoch: verdict was issued under epoch ${verdict.epoch}, job lease is epoch ${job.epoch}`);
    }

    // Fix B4: Exact match with verdict base_sha
    if (verdict.base_sha !== baseSha) {
      return rejected(EXIT_CODES.POLICY_DENIAL, `Base commit SHA mismatch: expected ${baseSha}, found ${verdict.base_sha}`);
    }

    if (verdict.status !== "accepted") {
      return rejected(EXIT_CODES.POLICY_DENIAL, `Verdict status is ${verdict.status}, not accepted`);
    }

    const nowMs = options.nowMs ?? Date.now();

    // Fix B4 / Fix R3: Verify that the job has an active live lease
    const lease = state.active_leases[jobId];
    if (!lease) {
      return rejected(EXIT_CODES.STALE_EPOCH, `Job ${jobId} does not have an active live lease`);
    }

    const expiresAt = lease.expires_at_ms ?? (lease.leased_at_ms + lease.ttl_ms);
    if (nowMs > expiresAt) {
      return rejected(EXIT_CODES.STALE_EPOCH, `Lease for job ${jobId} has expired`);
    }

    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    appendLedgerEventRaw(
      mirqlDir,
      {
        type: "job.promoted",
        epoch: job.epoch,
        nowMs,
        payload: {
          job_id: jobId,
          warrant_id: job.warrant_id,
          epoch: job.epoch,
          base_sha: verdict.base_sha,
          promoted_at_ms: nowMs,
        },
      },
      keypair,
      state,
    );

    return {
      ok: true,
      status: "promoted",
      job_id: jobId,
      warrant_id: job.warrant_id,
      epoch: job.epoch,
    };
  });
}

/**
 * Halt the queue and factory.
 *
 * @param {string} mirqlDir
 * @param {string} [reason]
 * @param {object} [options]
 * @returns {object}
 */
export function haltQueue(mirqlDir, reason = "Manual halt", options = {}) {
  return withLedgerLock(mirqlDir, () => {
    const state = foldQueueState(mirqlDir);
    const nowMs = options.nowMs ?? Date.now();
    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    appendLedgerEventRaw(
      mirqlDir,
      {
        type: "factory.halted",
        nowMs,
        payload: {
          reason,
          halted_at_ms: nowMs,
        },
      },
      keypair,
      state,
    );

    return {
      ok: true,
      status: "halted",
      halted: true,
      reason,
    };
  });
}

/**
 * Resume the queue and factory from halted state.
 *
 * @param {string} mirqlDir
 * @param {string} [reason]
 * @param {object} [options]
 * @returns {object}
 */
export function resumeQueue(mirqlDir, reason = "Manual resume", options = {}) {
  return withLedgerLock(mirqlDir, () => {
    const state = foldQueueState(mirqlDir);
    const nowMs = options.nowMs ?? Date.now();
    const keypair = getOrCreateQueueKeypair(mirqlDir, options.keyFile);

    appendLedgerEventRaw(
      mirqlDir,
      {
        type: "factory.resumed",
        nowMs,
        payload: {
          reason,
          resumed_at_ms: nowMs,
        },
      },
      keypair,
      state,
    );

    return {
      ok: true,
      status: "resumed",
      halted: false,
      reason,
    };
  });
}

function runCanaryAction(action, args, flags, mirqlDir, options) {
  const canaryId = flags.canaryId ?? args[0];
  const metric = (value) => value === undefined ? undefined : Number(value);
  let result;
  try {
    switch (action) {
      case "stage":
        result = stageCanary(mirqlDir, {
          ...options,
          jobId: flags.jobId ?? args[0],
          baseSha: flags.baseSha ?? args[flags.jobId ? 0 : 1],
          candidateVersion: flags.candidateVersion,
          supervisorVersion: flags.supervisorVersion,
        });
        break;
      case "sample":
      case "health":
        result = sampleCanaryHealth(mirqlDir, canaryId, {
          totalRequests: metric(flags.totalRequests),
          errorCount: metric(flags.errorCount),
          latencyP99Ms: metric(flags.latencyP99),
        }, options);
        break;
      case "evaluate":
      case "promote":
        result = evaluateAndPromoteCanary(mirqlDir, canaryId, { ...options, force: Boolean(flags.force) });
        break;
      case "rollback": {
        const reason = flags.reason ?? args.slice(flags.canaryId ? 0 : 1).join(" ");
        result = rollbackCanary(mirqlDir, canaryId, { ...options, reason });
        break;
      }
      default:
        process.stderr.write(JSON.stringify({ tool: TOOL, error: "unknown_canary_action", canaryAction: action }) + "\n");
        return EXIT_CODES.USAGE_ERROR;
    }
  } catch (err) {
    process.stderr.write(JSON.stringify({ ok: false, error: err.errorCode || err.name, message: err.message }) + "\n");
    return err.exitCode ?? EXIT_CODES.POLICY_DENIAL;
  }
  process.stdout.write(JSON.stringify(result) + "\n");
  if (action === "evaluate" || action === "promote") {
    return result.ok ? EXIT_CODES.OK : (result.exit_code ?? EXIT_CODES.POLICY_DENIAL);
  }
  return EXIT_CODES.OK;
}

/**
 * Parse CLI argv into options and subcommand.
 * @param {string[]} argv
 * @returns {{ subcommand: string | null, flags: Record<string, string | boolean>, positionals: string[] }}
 */
function parseArgv(argv) {
  const flags = {};
  const positionals = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (typeof arg !== "string") continue;
    if (arg === "--dir" && i + 1 < argv.length) {
      flags.dir = argv[++i];
    } else if (arg.startsWith("--dir=")) {
      flags.dir = arg.slice("--dir=".length);
    } else if (arg === "--key-file" && i + 1 < argv.length) {
      flags.keyFile = argv[++i];
    } else if (arg.startsWith("--key-file=")) {
      flags.keyFile = arg.slice("--key-file=".length);
    } else if (arg === "--repo-root" && i + 1 < argv.length) {
      flags.repoRoot = argv[++i];
    } else if (arg.startsWith("--repo-root=")) {
      flags.repoRoot = arg.slice("--repo-root=".length);
    } else if (arg === "--file" && i + 1 < argv.length) {
      flags.file = argv[++i];
    } else if (arg.startsWith("--file=")) {
      flags.file = arg.slice("--file=".length);
    } else if (arg === "--warrant" && i + 1 < argv.length) {
      flags.warrant = argv[++i];
    } else if (arg.startsWith("--warrant=")) {
      flags.warrant = arg.slice("--warrant=".length);
    } else if (arg === "--job-id" && i + 1 < argv.length) {
      flags.jobId = argv[++i];
    } else if (arg.startsWith("--job-id=")) {
      flags.jobId = arg.slice("--job-id=".length);
    } else if (arg === "--base-sha" && i + 1 < argv.length) {
      flags.baseSha = argv[++i];
    } else if (arg.startsWith("--base-sha=")) {
      flags.baseSha = arg.slice("--base-sha=".length);
    } else if (arg === "--reason" && i + 1 < argv.length) {
      flags.reason = argv[++i];
    } else if (arg.startsWith("--reason=")) {
      flags.reason = arg.slice("--reason=".length);
    } else if (arg === "--concurrency" && i + 1 < argv.length) {
      flags.concurrency = argv[++i];
    } else if (arg.startsWith("--concurrency=")) {
      flags.concurrency = arg.slice("--concurrency=".length);
    } else if (arg === "--help" || arg === "-h") {
      flags.help = true;
    } else if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      if (eqIdx !== -1) {
        const rawKey = arg.slice(2, eqIdx);
        const val = arg.slice(eqIdx + 1);
        flags[rawKey] = val;
        const camel = rawKey.replace(/-([a-z])/g, (_, g) => g.toUpperCase());
        flags[camel] = val;
      } else {
        const rawKey = arg.slice(2);
        const camel = rawKey.replace(/-([a-z])/g, (_, g) => g.toUpperCase());
        const isBool = ["force", "canary", "sample-health", "evaluate-canary", "evaluate", "sample", "stage", "rollback"].includes(rawKey);
        if (!isBool && i + 1 < argv.length && !argv[i + 1].startsWith("-")) {
          flags[rawKey] = argv[++i];
          flags[camel] = flags[rawKey];
        } else {
          flags[rawKey] = true;
          flags[camel] = true;
        }
      }
    } else if (!arg.startsWith("-")) {
      positionals.push(arg);
    }
  }

  const subcommand = positionals[0] || null;
  return { subcommand, flags, positionals: positionals.slice(1) };
}

/**
 * CLI entrypoint.
 * @param {string[]} argv - arguments after the program name
 * @returns {number} process exit code (see EXIT_CODES)
 */
export function main(argv = []) {
  // Conformance gate requirement: empty argv or --help outputs stub contract
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
    return EXIT_CODES.OK;
  }

  const { subcommand, flags, positionals } = parseArgv(argv);

  if (!subcommand || flags.help) {
    process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
    return EXIT_CODES.OK;
  }

  const mirqlDir = flags.dir || join(process.cwd(), ".mirql");
  const options = {
    keyFile: flags.keyFile,
    repoRoot: flags.repoRoot,
    concurrency: flags.concurrency !== undefined ? Number(flags.concurrency) : undefined,
  };

  switch (subcommand) {
    case "status": {
      const status = getQueueStatus(mirqlDir, options);
      process.stdout.write(JSON.stringify(status) + "\n");
      return EXIT_CODES.OK;
    }

    case "submit": {
      let warrantInput = null;
      if (flags.warrant) {
        try {
          warrantInput = JSON.parse(flags.warrant);
        } catch {
          process.stderr.write(
            JSON.stringify({ tool: TOOL, error: "invalid_json_warrant" }) + "\n",
          );
          return EXIT_CODES.USAGE_ERROR;
        }
      } else if (flags.file) {
        try {
          warrantInput = JSON.parse(readFileSync(flags.file, "utf8"));
        } catch (err) {
          process.stderr.write(
            JSON.stringify({ tool: TOOL, error: "cannot_read_warrant_file", detail: String(err) }) +
              "\n",
          );
          return EXIT_CODES.USAGE_ERROR;
        }
      } else if (positionals.length > 0) {
        const arg = positionals[0];
        if (arg.trim().startsWith("{")) {
          try {
            warrantInput = JSON.parse(arg);
          } catch {
            process.stderr.write(
              JSON.stringify({ tool: TOOL, error: "invalid_json_warrant" }) + "\n",
            );
            return EXIT_CODES.USAGE_ERROR;
          }
        } else if (existsSync(arg)) {
          try {
            warrantInput = JSON.parse(readFileSync(arg, "utf8"));
          } catch (err) {
            process.stderr.write(
              JSON.stringify({ tool: TOOL, error: "cannot_read_warrant_file", detail: String(err) }) +
                "\n",
            );
            return EXIT_CODES.USAGE_ERROR;
          }
        }
      }

      if (!warrantInput) {
        process.stderr.write(
          JSON.stringify({ tool: TOOL, error: "missing_warrant_input" }) + "\n",
        );
        return EXIT_CODES.USAGE_ERROR;
      }

      const res = submitWarrant(mirqlDir, warrantInput, options);
      return emitResult(res, EXIT_CODES.USAGE_ERROR);
    }

    case "tick": {
      const res = tickQueue(mirqlDir, options);
      if (res.exit_code) {
        process.stderr.write(JSON.stringify(res) + "\n");
        return res.exit_code;
      }
      return emitOk(res);
    }

    case "lease": {
      const res = leaseNextJob(mirqlDir, options);
      return emitResult(res, EXIT_CODES.USAGE_ERROR);
    }

    case "canary": {
      const action = flags.action || positionals[0];
      const args = flags.action ? positionals : positionals.slice(1);
      return runCanaryAction(action, args, flags, mirqlDir, options);
    }

    case "promote": {
      if (flags.canary || flags.stage) return runCanaryAction("stage", positionals, flags, mirqlDir, options);
      if (flags.sampleHealth || flags.sample) return runCanaryAction("sample", positionals, flags, mirqlDir, options);
      if (flags.evaluateCanary || flags.evaluate) return runCanaryAction("evaluate", positionals, flags, mirqlDir, options);
      if (flags.rollback) return runCanaryAction("rollback", positionals, flags, mirqlDir, options);

      const jobId = flags.jobId || positionals[0];
      const baseSha = flags.baseSha || positionals[1];
      const res = promoteJob(mirqlDir, { ...options, jobId, baseSha });
      return emitResult(res, EXIT_CODES.POLICY_DENIAL);
    }

    case "halt": {
      const reason = flags.reason || positionals.join(" ") || "Manual halt";
      const res = haltQueue(mirqlDir, reason, options);
      return emitOk(res);
    }

    case "resume": {
      const reason = flags.reason || positionals.join(" ") || "Manual resume";
      const res = resumeQueue(mirqlDir, reason, options);
      return emitOk(res);
    }

    default: {
      process.stderr.write(
        JSON.stringify({
          tool: TOOL,
          error: "unknown_subcommand",
          subcommand,
        }) + "\n",
      );
      return EXIT_CODES.USAGE_ERROR;
    }
  }
}

export default main;
