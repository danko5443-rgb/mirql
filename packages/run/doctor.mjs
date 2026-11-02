// packages/run/doctor.mjs — Autonomous Diagnostic Role & Multi-Tier Circuit Breakers.
// Roles: roles/doctor.md (tier: max, emits: triage.report, circuit_breaker.recommendation)
// Laws: Law 2 (Lifeguard Kill Authority), Law 4 (Durable Ledger), Law 14 (Quiescence), Law 17 (Integer-Only JCS)

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  EXIT_CODES,
  jcs,
  foldLedger,
  readLedgerEvents,
  readVerifiedLedgerEvents,
  foldQueueState,
  foldBreakerStateFromLedger,
} from "../core/index.mjs";
// Breaker folds live in @mirql/core (pure Law-4 ledger folds) so every layer
// reads the same truth; re-exported here for existing consumers.
export {
  foldBreakerStateFromLedger,
  isCircuitBreakerTripped,
  getActiveTrippedBreakers,
} from "../core/index.mjs";
import { runProbe, KNOWN_PROBES } from "./probe.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";

/**
 * Valid subsystems that can be evaluated, throttled, tripped, or reset.
 * Note: Law 2 strictly forbids intercepting, masking, or tripping the Lifeguard daemon.
 * Lifeguard retains unblockable kill authority and is never a trip target.
 */
export const SUBSYSTEMS = Object.freeze([
  "worker",
  "worker:flash",
  "worker:mid",
  "worker:max",
  "probe",
  "budget",
  "queue",
  "all",
]);

export const CIRCUIT_ACTIONS = Object.freeze([
  "trip",
  "throttle",
  "reset",
  "force_harden",
]);

export const MACRO_STATES = Object.freeze([
  "BUILD",
  "HARDEN",
  "PATROL",
  "QUIESCENT",
  "HALTED",
]);

/**
 * Loads policy configuration from policy/mirql.json.
 *
 * @param {string} mirqlDir
 * @param {string} [workspaceDir]
 * @returns {object}
 */
export function loadDoctorPolicy(mirqlDir, workspaceDir) {
  const root = workspaceDir || resolve(mirqlDir, "..");
  const candidate = join(root, "policy", "mirql.json");
  if (existsSync(candidate)) {
    try {
      return JSON.parse(readFileSync(candidate, "utf8"));
    } catch {}
  }
  return {
    daily_budget_micro_usd: 25000000,
    per_job_budget_micro_usd: 1500000,
    retries_per_tier: 2,
    ladder: ["flash", "mid", "max", "human"],
    macro_states: ["BUILD", "HARDEN", "PATROL", "QUIESCENT", "HALTED"],
  };
}

/**
 * Normalizes an error string, error object, or event trace into a canonical,
 * low-noise failure signature stripped of volatile timestamps and random IDs.
 *
 * @param {any} input
 * @returns {string} canonical normalized failure signature
 */
export function normalizeFailureSignature(input) {
  if (!input) return "SIG:UNKNOWN:unspecified_failure";

  // If input is a ledger event, inspect domain payload cleanly
  if (typeof input === "object" && !(input instanceof Error)) {
    if (input.type === "probe.completed") {
      const pName = input.payload?.type || input.payload?.probe || "unknown";
      const cleanName = String(pName).toLowerCase().replace(/[^a-z0-9_]+/g, "_");
      return `SIG:PROBE_FAIL:${cleanName}`;
    }

    if (input.type === "lifeguard.alert") {
      const reason = input.payload?.reason || input.payload?.alert || "alert";
      const cleanReason = String(reason).toLowerCase().replace(/[^a-z0-9_]+/g, "_");
      return `SIG:LIFEGUARD_ALERT:${cleanReason}`;
    }

    if (input.type === "job.timeout" || input.type === "job.lease_expired") {
      const ms = input.payload?.timeout_ms ?? input.payload?.ttl_ms ?? 0;
      return `SIG:TIMEOUT:${Number.isSafeInteger(ms) && ms > 0 ? ms : "generic"}ms`;
    }

    if (input.type === "job.failed" || input.type === "attempt.failed") {
      const reason = input.payload?.reason ?? input.payload?.error ?? input.payload?.status ?? "";
      return normalizeFailureSignature(String(reason));
    }

    if (input.type === "attempt.outcome") {
      const reason = input.payload?.error || input.payload?.verdict || input.payload?.status || "failed";
      return normalizeFailureSignature(String(reason));
    }

    if (input.failure_signature) {
      return String(input.failure_signature).replace(/[^a-zA-Z0-9_:-]+/g, "_");
    }

    if (input.name && input.error) {
      const pName = String(input.name).toLowerCase().replace(/[^a-z0-9_]+/g, "_");
      return `SIG:PROBE_FAIL:${pName}`;
    }
  }

  let raw = "";
  if (typeof input === "string") {
    raw = input;
  } else if (input instanceof Error) {
    raw = `${input.name}: ${input.message}`;
  } else if (typeof input === "object") {
    raw = input.message || input.reason || input.error || "";
  }

  // Strip volatile memory addresses, timestamps, and ULIDs
  const sanitized = raw
    .replace(/[0-9A-HJKMNPQRSTVWXYZ]{26}/g, "<ULID>")
    .replace(/\b0x[0-9a-fA-F]+\b/g, "<HEX>")
    .replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/g, "<TS>")
    .replace(/\\/g, "/")
    .replace(/\r?\n.*/s, "")
    .trim();

  if (/timed?\s*out|timeout/i.test(sanitized)) {
    const match = sanitized.match(/(\d+)\s*ms/i);
    const ms = match ? parseInt(match[1], 10) : 0;
    return `SIG:TIMEOUT:${Number.isSafeInteger(ms) && ms > 0 ? ms : "generic"}ms`;
  }
  if (/assertion|expected.*to.*equal|assert/i.test(sanitized)) {
    return "SIG:ASSERTION:test_verification_failure";
  }
  if (/syntaxerror|unexpected token|invalid module syntax/i.test(sanitized)) {
    return "SIG:SYNTAX:parse_error";
  }
  if (/drift|public surface|surface\.lock/i.test(sanitized)) {
    return "SIG:DRIFT:architectural_boundary_breach";
  }
  if (/mutant|kill rate|survivor/i.test(sanitized)) {
    return "SIG:MUTANT_SURVIVOR:floor_unmet";
  }
  if (/flake|flakiness|non-deterministic/i.test(sanitized)) {
    return "SIG:FLAKE:non_deterministic_execution";
  }
  if (/\b(budget_exceeded|daily_budget|budget_exhausted|budget_ceiling)\b/i.test(sanitized)) {
    return "SIG:BUDGET_EXCEEDED:ceiling_exhaustion";
  }
  if (/\b(lease_expired|lease_timeout|hung_lease|lease_hung)\b/i.test(sanitized)) {
    return "SIG:LEASE_HUNG:lease_timeout";
  }
  if (/\b(retry_exhausted|tier_exhausted|retries_per_tier|max_retries)\b/i.test(sanitized)) {
    return "SIG:TIER_EXHAUSTED:warrant_needs_human";
  }
  if (/concurrency/i.test(sanitized)) {
    return "SIG:CONCURRENCY:limit_exceeded";
  }

  const slug = sanitized
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 48);

  return `SIG:${slug || "unknown_failure"}`;
}

/**
 * Evaluates ledger error events, probe failure outputs, and queue status to
 * diagnose system health and formulate a canonical triage report (roles/doctor.md).
 *
 * @param {object[]} [ledgerEvents=[]]
 * @param {object[]} [probeResults=[]]
 * @param {object} [queueStatus={}]
 * @param {object} [options={}]
 * @returns {object} canonical triage.report document
 */
export function diagnoseHealth(ledgerEvents = [], probeResults = [], queueStatus = {}, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const incidents = [];
  const affectedJobs = new Set();
  const affectedProbes = new Set();
  let lifeguardHalted = false;

  // 1. Scan ledger events for failure events using exact production event shapes
  for (const item of ledgerEvents) {
    const evt = item && item.event ? item.event : item;
    if (!evt || typeof evt !== "object") continue;
    const type = evt.type ?? "";

    // Lifeguard alerts (Law 2: Lifeguard unblockable kill authority)
    if (type === "lifeguard.alert") {
      lifeguardHalted = true;
      const sig = normalizeFailureSignature(evt);
      incidents.push({ source: "lifeguard", type, sig, raw: evt });
      continue;
    }

    // Job timeouts
    if (type === "job.timeout" || type === "job.lease_expired") {
      const jId = evt.payload?.job_id;
      if (jId) affectedJobs.add(jId);
      const sig = normalizeFailureSignature(evt);
      incidents.push({ source: "ledger", type, sig, raw: evt });
      continue;
    }

    // Worker attempt outcomes that failed
    if (type === "attempt.outcome") {
      const p = evt.payload || {};
      const isSuccess =
        p.status === "completed" &&
        (p.verdict === "auto_merge" || p.verdict === "pass" || !p.verdict);

      if (!isSuccess) {
        if (p.job_id) affectedJobs.add(p.job_id);
        const sig = normalizeFailureSignature(p.error || p.verdict || "attempt_failed");
        incidents.push({ source: "ledger", type, sig, raw: evt });
      }
      continue;
    }

    // Explicit job failures
    if (type === "job.failed" || type === "attempt.failed") {
      const jId = evt.payload?.job_id ?? evt.payload?.id ?? evt.id;
      if (jId) affectedJobs.add(jId);
      const sig = normalizeFailureSignature(evt);
      incidents.push({ source: "ledger", type, sig, raw: evt });
      continue;
    }

    // Completed probes: check real probe.completed shape (status !== "pass" or failures > 0)
    if (type === "probe.completed") {
      const p = evt.payload || {};
      // Skip doctor's own diagnostic audit records
      if (p.probe === "doctor" || p.type === "doctor") continue;
      const isPass = p.status === "pass" && (p.failures === undefined || p.failures === 0);
      if (!isPass) {
        const pName = p.type || p.probe || "unknown";
        affectedProbes.add(pName);
        const sig = normalizeFailureSignature(evt);
        incidents.push({ source: "probe_ledger", name: pName, sig, raw: evt });
      }
      continue;
    }
  }

  // 2. Scan active probeResults array passed directly from runner
  const pList = Array.isArray(probeResults)
    ? probeResults
    : probeResults && typeof probeResults === "object"
      ? Object.values(probeResults)
      : [];

  for (const p of pList) {
    if (!p || typeof p !== "object") continue;
    if (p.name === "doctor" || p.probe === "doctor") continue;
    const isPass = (p.ok === true || p.passed === true || p.status === "pass") && (p.failures === undefined || p.failures === 0);
    if (!isPass) {
      const pName = p.name ?? p.probe ?? p.type ?? "unknown";
      affectedProbes.add(pName);
      const sig = normalizeFailureSignature(p);
      incidents.push({
        source: "probe",
        name: pName,
        sig,
        raw: p,
      });
    }
  }

  // 3. Scan queue status for live hung leases and retry-exhausted warrants
  const activeLeases = Object.values(queueStatus.active_leases || {});
  for (const lease of activeLeases) {
    const expiry = lease.expires_at_ms ?? (lease.leased_at_ms + (lease.ttl_ms ?? 0));
    if (nowMs > expiry) {
      const sig = "SIG:LEASE_HUNG:lease_timeout";
      if (lease.job_id) affectedJobs.add(lease.job_id);
      incidents.push({
        source: "queue",
        type: "lease.hung",
        sig,
        raw: lease,
      });
    }
  }

  const maxAttempts = Number.isSafeInteger(options.max_attempts) ? options.max_attempts : 3;
  const warrants = Object.values(queueStatus.warrants || {});
  for (const w of warrants) {
    if (w.status === "needs_human" || (w.failed_attempts || 0) >= maxAttempts) {
      const sig = "SIG:TIER_EXHAUSTED:warrant_needs_human";
      incidents.push({
        source: "queue",
        type: "warrant.exhausted",
        sig,
        raw: w,
      });
    }
  }

  // If no incidents detected, return clean triage report
  if (incidents.length === 0) {
    return {
      v: 1,
      type: "triage.report",
      failure_signature: "SIG:CLEAN:all_systems_operational",
      root_cause_analysis: "No recurring failures, hanging leases, or probe degradations detected across inspected subsystems.",
      recommended_remediation: "Continue scheduled operations under active macro-state.",
      timestamp_ms: nowMs,
      incidents_count: 0,
      affected_jobs: [],
      affected_probes: [],
      healthy: true,
      lifeguard_halt: false,
    };
  }

  // Count incidents by signature
  const sigCounts = new Map();
  for (const inc of incidents) {
    sigCounts.set(inc.sig, (sigCounts.get(inc.sig) || 0) + 1);
  }

  // Identify dominant signature (prioritizing Lifeguard alerts)
  let primarySig = "";
  let maxCount = -1;
  for (const [sig, count] of sigCounts.entries()) {
    if (sig.startsWith("SIG:LIFEGUARD_ALERT")) {
      primarySig = sig;
      break;
    }
    if (count > maxCount) {
      maxCount = count;
      primarySig = sig;
    }
  }

  // Formulate root cause analysis and remediation based on dominant signature
  let rootCause = "Unclassified recurring defect detected across ledger and execution boundaries.";
  let remediation = "Inspect job logs and isolate failing module.";

  if (primarySig.startsWith("SIG:LIFEGUARD_ALERT")) {
    rootCause = "Lifeguard daemon issued an out-of-band health alert; system integrity breached or heartbeat stale (Law 2).";
    remediation = "System must immediately halt and undergo operator inspection. Do not resume without human affirmative clearance.";
  } else if (primarySig.startsWith("SIG:TIMEOUT")) {
    rootCause = "Worker execution exceeded configured lease TTL; potential deadlock, heavy computation, or unbounded external wait.";
    remediation = "Reap hung leases via queue tick, scale worker timeout, or decompose task anchors into smaller warrants.";
  } else if (primarySig.startsWith("SIG:ASSERTION")) {
    rootCause = "Test assertion regression; code modifications under attempt failed to meet behavioral contracts.";
    remediation = "Revert breaking patch or verify test expectations; escalate to mid/max tier builder.";
  } else if (primarySig.startsWith("SIG:SYNTAX")) {
    rootCause = "Unparseable syntax generated by unprivileged worker code mutation.";
    remediation = "Enforce pre-verification node check (node --check) and discard malformed candidate patches.";
  } else if (primarySig.startsWith("SIG:DRIFT") || primarySig === "SIG:PROBE_FAIL:drift") {
    rootCause = "Attempt modified files outside declared warrant anchors or introduced public API delta without citation.";
    remediation = "Re-anchor warrant or update surface.lock with explicit human citation.";
  } else if (primarySig.startsWith("SIG:MUTANT_SURVIVOR") || primarySig === "SIG:PROBE_FAIL:mutants") {
    rootCause = "Mutation kill rate dropped below the 8000 basis points (80.00%) floor.";
    remediation = "Augment test suite with targeted edge-case unit tests to kill surviving AST mutants.";
  } else if (primarySig.startsWith("SIG:FLAKE")) {
    rootCause = "Non-deterministic test execution producing intermittent failures under identical source states.";
    remediation = "Quarantine flaky test suite using 'mirql r flake --test <path> --quarantine <dir>' and investigate concurrency/timing assumptions.";
  } else if (primarySig.startsWith("SIG:BUDGET_EXCEEDED")) {
    rootCause = "Daily budget ceiling exceeded; micro-USD consumption reached configured threshold.";
    remediation = "Halt automated worker dispatch until human operator grants budget expansion or resets daily epoch.";
  } else if (primarySig.startsWith("SIG:LEASE_HUNG")) {
    rootCause = "Worker process terminated abnormally or lost heartbeat, leaving active lease in pending state.";
    remediation = "Trigger queue lease reaper (mirql q tick) to expire zombie leases and re-enqueue jobs.";
  } else if (primarySig.startsWith("SIG:TIER_EXHAUSTED")) {
    rootCause = "Job exhausted retry limits across worker tiers without passing verification.";
    remediation = "Escalate warrant to 'needs_human' inbox for human operator intervention or warrant refinement.";
  } else if (primarySig.startsWith("SIG:PROBE_FAIL:tests")) {
    rootCause = "Regression in core test suite or conformance verification.";
    remediation = "Fix failing tests or quarantine flaky tests.";
  } else if (primarySig.startsWith("SIG:PROBE_FAIL")) {
    rootCause = `Declarative probe regression detected: ${primarySig}.`;
    remediation = "Inspect probe logs and remediate detected invariant failure.";
  }

  return {
    v: 1,
    type: "triage.report",
    failure_signature: primarySig,
    root_cause_analysis: rootCause,
    recommended_remediation: remediation,
    timestamp_ms: nowMs,
    incidents_count: incidents.length,
    affected_jobs: Array.from(affectedJobs).sort(),
    affected_probes: Array.from(affectedProbes).sort(),
    healthy: false,
    lifeguard_halt: lifeguardHalted,
  };
}

/**
 * Multi-Tier Circuit Breaker Evaluator (roles/doctor.md).
 *
 * Tracks failure metrics across worker tiers (flash, mid, max), daily budget consumption,
 * and hung leases to prescribe autonomous circuit breaking directives.
 *
 * @param {object} systemMetrics
 * @param {object} [options={}]
 * @returns {object} canonical circuit_breaker.recommendation document
 */
export function evaluateCircuitBreakers(systemMetrics = {}, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();

  const tierFailures = {
    flash: Number.isSafeInteger(systemMetrics.tier_failures?.flash) ? systemMetrics.tier_failures.flash : 0,
    mid: Number.isSafeInteger(systemMetrics.tier_failures?.mid) ? systemMetrics.tier_failures.mid : 0,
    max: Number.isSafeInteger(systemMetrics.tier_failures?.max) ? systemMetrics.tier_failures.max : 0,
  };

  const retriesPerTier = Number.isSafeInteger(options.retries_per_tier)
    ? options.retries_per_tier
    : 2;

  const budgetSpent = Number.isSafeInteger(systemMetrics.daily_budget_spent_micro_usd)
    ? systemMetrics.daily_budget_spent_micro_usd
    : (Number.isSafeInteger(systemMetrics.budget_spent_micro_usd) ? systemMetrics.budget_spent_micro_usd : 0);

  const budgetLimit = Number.isSafeInteger(systemMetrics.budget_limit_micro_usd)
    ? systemMetrics.budget_limit_micro_usd
    : 25000000; // 25 USD default

  const hungLeases = Number.isSafeInteger(systemMetrics.hung_leases_count)
    ? systemMetrics.hung_leases_count
    : 0;

  const totalFailures = tierFailures.flash + tierFailures.mid + tierFailures.max;

  // Safe cooldown helper ensuring non-negative safe integers
  const resolveCooldown = (userMs, defaultMs) => {
    return Number.isSafeInteger(userMs) && userMs >= 0 ? userMs : defaultMs;
  };

  // Rule 0: Operator manual trip override
  if (options.manual_trip) {
    const rawTarget = options.manual_trip;
    if (rawTarget === "lifeguard") {
      throw new Error("Cannot trip lifeguard: Law 2 unblockable kill authority");
    }
    const target = SUBSYSTEMS.includes(rawTarget) && rawTarget !== "all" ? rawTarget : "worker";
    const cooldownMs = resolveCooldown(options.cooldown_ms, 3600000);
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: target,
      action: "trip",
      cooldown_ms: cooldownMs,
      reason: "manual_operator_trip",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 1: Daily budget ceiling exhausted (Law 17 micro-USD safe integer check)
  if (budgetLimit > 0 && budgetSpent >= budgetLimit) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "budget",
      action: "trip",
      cooldown_ms: resolveCooldown(options.cooldown_ms, 172800000), // 48h cooldown
      reason: "daily_budget_exhausted",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 2: Budget high watermark warning (>= 90%)
  // Law 17 integer-only math: 9000 basis points (90%) without floating point operations
  const watermark = Math.floor((budgetLimit * 90) / 100);
  if (budgetLimit > 0 && budgetSpent >= watermark) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "budget",
      action: "throttle",
      cooldown_ms: resolveCooldown(options.cooldown_ms, 3600000),
      reason: "daily_budget_near_ceiling",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 3: Max tier (critic/highest model) retry exhaustion -> force macro-state to HARDEN
  if (tierFailures.max >= retriesPerTier) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "worker:max",
      action: "force_harden",
      cooldown_ms: resolveCooldown(options.cooldown_ms, 1800000),
      reason: "max_tier_retry_exhausted_force_harden",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 4: Mid tier failure escalation
  if (tierFailures.mid >= retriesPerTier) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "worker:mid",
      action: "throttle",
      cooldown_ms: resolveCooldown(options.cooldown_ms, 900000),
      reason: "mid_tier_failures_escalate_to_max",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 5: Flash tier failure escalation
  if (tierFailures.flash >= retriesPerTier) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "worker:flash",
      action: "throttle",
      cooldown_ms: resolveCooldown(options.cooldown_ms, 300000),
      reason: "flash_tier_failures_escalate_to_mid",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 6: Hung leases detected
  if (hungLeases > 0) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "queue",
      action: "throttle",
      cooldown_ms: resolveCooldown(options.cooldown_ms, 60000),
      reason: "hung_leases_require_reap",
      metrics: {
        budget_spent_micro_usd: budgetSpent,
        budget_limit_micro_usd: budgetLimit,
        hung_leases_count: hungLeases,
        consecutive_failures: tierFailures,
        total_failures: totalFailures,
      },
    };
  }

  // Rule 7: Reset / Healthy
  return {
    v: 1,
    type: "circuit_breaker.recommendation",
    target_subsystem: "all",
    action: "reset",
    cooldown_ms: 0,
    reason: "all_subsystems_healthy",
    metrics: {
      budget_spent_micro_usd: budgetSpent,
      budget_limit_micro_usd: budgetLimit,
      hung_leases_count: hungLeases,
      consecutive_failures: tierFailures,
      total_failures: totalFailures,
    },
  };
}

/**
 * Evaluates whether the system macro-state should transition under circuit
 * breaker signals or diagnostic health triggers (Law 14: Convergence to Quiescence).
 *
 * Sequence: BUILD -> HARDEN -> PATROL -> QUIESCENT.
 *
 * @param {string} currentState
 * @param {object} triageReport
 * @param {object} breakerRecommendation
 * @param {object} [options={}]
 * @returns {{ should_transition: boolean, from_state: string, to_state: string, reason: string }}
 */
export function evaluateMacroStateTransition(currentState, triageReport, breakerRecommendation, options = {}) {
  const current = currentState || "BUILD";

  // Lifeguard or fatal budget trip -> HALTED (Law 2 unblockable kill authority)
  if (options.lifeguard_halt === true || triageReport?.lifeguard_halt === true || (breakerRecommendation?.action === "trip" && breakerRecommendation.target_subsystem === "budget")) {
    if (current !== "HALTED") {
      return {
        should_transition: true,
        from_state: current,
        to_state: "HALTED",
        reason: "circuit_breaker_or_lifeguard_trip",
      };
    }
  }

  // Force harden trigger from breaker
  if (breakerRecommendation?.action === "force_harden") {
    if (current === "BUILD") {
      return {
        should_transition: true,
        from_state: current,
        to_state: "HARDEN",
        reason: breakerRecommendation.reason || "circuit_breaker_force_harden",
      };
    }
  }

  // Quiescence convergence when work is complete or non-recoverable
  if (options.all_warrants_resolved === true && current === "BUILD") {
    return {
      should_transition: true,
      from_state: current,
      to_state: "HARDEN",
      reason: "all_warrants_resolved",
    };
  }

  if (current === "HARDEN" && options.hardening_passed === true) {
    return {
      should_transition: true,
      from_state: current,
      to_state: "PATROL",
      reason: "hardening_passed",
    };
  }

  // PATROL -> QUIESCENT requires clean probes, healthy triage, AND non-tripped breakers
  const isBreakerBlocking = breakerRecommendation?.action === "trip" || breakerRecommendation?.action === "force_harden";
  if (current === "PATROL" && options.probes_clean === true && triageReport?.healthy === true && !isBreakerBlocking) {
    return {
      should_transition: true,
      from_state: current,
      to_state: "QUIESCENT",
      reason: "probes_clean_head_unchanged",
    };
  }

  return {
    should_transition: false,
    from_state: current,
    to_state: current,
    reason: "no_state_transition_required",
  };
}

/**
 * Breaker state manager: authoritative state lives in the durable ledger (Law 4),
 * with an optional local cache file for fast out-of-band inspection.
 */
export class BreakerStore {
  /**
   * @param {string} mirqlDir
   * @param {object} [keypair]
   */
  constructor(mirqlDir, keypair = null) {
    this.mirqlDir = mirqlDir;
    this.keypair = keypair;
    this.stateFile = join(mirqlDir, "state", "doctor_breakers.json");
  }

  load(nowMs = Date.now()) {
    const events = readVerifiedLedgerEvents(this.mirqlDir);
    const folded = foldBreakerStateFromLedger(events, nowMs);
    // Sync cache file
    try {
      const stateDir = join(this.mirqlDir, "state");
      mkdirSync(stateDir, { recursive: true });
      writeFileSync(this.stateFile, jcs(folded) + "\n", "utf8");
    } catch {}
    return folded;
  }

  trip(subsystem, reason = "manual_trip", cooldownMs = 3600000, nowMs = Date.now()) {
    if (subsystem === "lifeguard" || subsystem === "all") {
      throw new Error(`Invalid subsystem to trip: "${subsystem}". Lifeguard has unblockable authority.`);
    }

    const safeCd = Number.isSafeInteger(cooldownMs) && cooldownMs >= 0 ? cooldownMs : 3600000;
    const expiresAt = Math.min(Number.MAX_SAFE_INTEGER, nowMs + safeCd);

    const keypair = this.keypair || getOrGenerateSupervisorKey(this.mirqlDir);
    appendSupervisorEvent(
      this.mirqlDir,
      {
        type: "probe.completed",
        payload: {
          probe: "doctor",
          type: "doctor",
          status: "fail",
          breaker: {
            action: "trip",
            target_subsystem: subsystem,
            cooldown_ms: safeCd,
            reason,
          },
          expires_at_ms: expiresAt,
        },
        nowMs,
      },
      keypair,
    );

    return this.load(nowMs).subsystems[subsystem];
  }

  throttle(subsystem, cooldownMs = 3600000, nowMs = Date.now()) {
    if (subsystem === "lifeguard" || subsystem === "all") {
      throw new Error(`Invalid subsystem to throttle: "${subsystem}". Lifeguard has unblockable authority.`);
    }

    const safeCd = Number.isSafeInteger(cooldownMs) && cooldownMs >= 0 ? cooldownMs : 3600000;
    const expiresAt = Math.min(Number.MAX_SAFE_INTEGER, nowMs + safeCd);

    const keypair = this.keypair || getOrGenerateSupervisorKey(this.mirqlDir);
    appendSupervisorEvent(
      this.mirqlDir,
      {
        type: "probe.completed",
        payload: {
          probe: "doctor",
          type: "doctor",
          status: "pass",
          breaker: {
            action: "throttle",
            target_subsystem: subsystem,
            cooldown_ms: safeCd,
            reason: "throttle_rate_limit",
          },
          expires_at_ms: expiresAt,
        },
        nowMs,
      },
      keypair,
    );

    return this.load(nowMs).subsystems[subsystem];
  }

  reset(subsystem, nowMs = Date.now()) {
    if (subsystem === "lifeguard") {
      throw new Error("Lifeguard is not managed by circuit breakers");
    }

    const keypair = this.keypair || getOrGenerateSupervisorKey(this.mirqlDir);
    appendSupervisorEvent(
      this.mirqlDir,
      {
        type: "probe.completed",
        payload: {
          probe: "doctor",
          type: "doctor",
          status: "pass",
          breaker: {
            action: "reset",
            target_subsystem: subsystem,
            cooldown_ms: 0,
            reason: "manual_reset",
          },
          expires_at_ms: 0,
        },
        nowMs,
      },
      keypair,
    );

    return this.load(nowMs);
  }

  isTripped(subsystem, nowMs = Date.now()) {
    const data = this.load(nowMs);
    return Boolean(data.subsystems?.[subsystem]?.state === "tripped");
  }
}

/**
 * Comprehensive doctor diagnostic execution function.
 *
 * @param {object} options
 * @returns {object}
 */
export function runDoctor(options = {}) {
  const mirqlDir = options.mirqlDir ?? options.dir ?? join(process.cwd(), ".mirql");
  const workspaceDir = options.workspaceDir ?? process.cwd();
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();

  const store = new BreakerStore(mirqlDir, options.keypair);

  // Handle explicit reset flag
  if (options.reset) {
    if (options.reset === "lifeguard") {
      throw new Error("Lifeguard is not managed by circuit breakers (Law 2)");
    }
    store.reset(options.reset, nowMs);
    return {
      ok: true,
      healthy: true,
      action: "reset",
      target: options.reset,
      timestamp_ms: nowMs,
    };
  }

  // Handle explicit trip flag
  if (options.trip) {
    if (options.trip === "lifeguard" || options.trip === "all") {
      throw new Error(`Invalid subsystem to trip: "${options.trip}" (Law 2)`);
    }
    const cooldownMs = Number.isSafeInteger(options.cooldown_ms) ? options.cooldown_ms : 3600000;
    const entry = store.trip(options.trip, options.reason || "operator_flag", cooldownMs, nowMs);
    return {
      ok: true,
      healthy: false,
      action: "trip",
      target: options.trip,
      entry,
      timestamp_ms: nowMs,
    };
  }

  // Read durable verified ledger events (Law 4 & Law 3)
  let ledgerEvents = [];
  try {
    ledgerEvents = options.ledgerEvents ?? readVerifiedLedgerEvents(mirqlDir, options);
  } catch {
    ledgerEvents = [];
  }

  // Load policy
  const policy = loadDoctorPolicy(mirqlDir, workspaceDir);

  // Fold real queue state using the canonical fold from @mirql/core
  let queueState = {};
  try {
    queueState = foldQueueState(mirqlDir, policy);
  } catch {
    queueState = foldLedger(ledgerEvents, policy);
  }

  // Probe outputs
  const probeResults = options.probeResults ? [...options.probeResults] : [];
  if (options.runProbes) {
    for (const p of KNOWN_PROBES) {
      try {
        const res = runProbe({ probe: p, mirqlDir, workspaceDir });
        probeResults.push({ name: p, ...res });
      } catch (err) {
        probeResults.push({ name: p, ok: false, passed: false, error: err.message });
      }
    }
  }

  // Run health triage
  const triage = diagnoseHealth(ledgerEvents, probeResults, queueState, {
    nowMs,
    max_attempts: policy.retries_per_tier ?? 2,
  });

  // Calculate daily budget spend within the last 24 hours (86,400,000 ms)
  const oneDayAgo = nowMs - 86400000;
  let dailyBudgetSpent = 0;
  for (const item of ledgerEvents) {
    const evt = item && item.event ? item.event : item;
    if (evt && evt.type === "attempt.outcome") {
      const evtTime = evt.hlc?.wall_ms || (evt.ts ? Date.parse(evt.ts) : 0);
      if (evtTime >= oneDayAgo) {
        const cost = evt.payload?.cost_micro_usd || 0;
        if (Number.isSafeInteger(cost) && cost > 0) {
          dailyBudgetSpent += cost;
        }
      }
    }
  }

  // Count consecutive failures on active/unresolved warrants per tier using policy ladder
  const ladder = policy.ladder || ["flash", "mid", "max", "human"];
  const tierFailures = { flash: 0, mid: 0, max: 0 };
  const warrants = Object.values(queueState.warrants || {});

  for (const w of warrants) {
    // Only uncompleted warrants count towards live tier failures (completed warrants are cleared)
    if (w.status !== "completed") {
      const fails = w.failed_attempts || 0;
      for (let i = 1; i <= fails; i++) {
        const tier = ladder[i - 1] || "flash";
        if (tier in tierFailures) {
          tierFailures[tier] += 1;
        }
      }
    }
  }

  // Check active hung leases from live queue state
  let hungLeasesCount = 0;
  for (const l of Object.values(queueState.active_leases || {})) {
    const exp = l.expires_at_ms ?? (l.leased_at_ms + (l.ttl_ms ?? 0));
    if (nowMs > exp) hungLeasesCount++;
  }

  const budgetLimit = policy.daily_budget_micro_usd ?? 25000000;
  const breakerMetrics = {
    tier_failures: tierFailures,
    daily_budget_spent_micro_usd: dailyBudgetSpent,
    budget_limit_micro_usd: budgetLimit,
    hung_leases_count: hungLeasesCount,
  };

  const breaker = evaluateCircuitBreakers(breakerMetrics, {
    retries_per_tier: policy.retries_per_tier ?? 2,
    nowMs,
    cooldown_ms: options.cooldown_ms,
  });

  const transition = evaluateMacroStateTransition(
    queueState.mode || "BUILD",
    triage,
    breaker,
    {
      nowMs,
      lifeguard_halt: triage.lifeguard_halt || queueState.halted === true,
      all_warrants_resolved: warrants.length > 0 && warrants.every((w) => w.status === "completed"),
      hardening_passed: Boolean(options.hardening_passed || queueState.hardening_passed),
      probes_clean: options.probes_clean !== undefined ? Boolean(options.probes_clean) : queueState.probes_clean,
    },
  );

  const breakerState = store.load(nowMs);
  const hasActiveTrippedBreakers = Object.values(breakerState.subsystems || {}).some(
    (s) => s.state === "tripped" && nowMs < (s.expires_at_ms || 0)
  );
  const isHealthy =
    triage.healthy &&
    breaker.action !== "trip" &&
    breaker.action !== "force_harden" &&
    !triage.lifeguard_halt &&
    !hasActiveTrippedBreakers;

  // Persist doctor evaluation to durable ledger (Law 4 & Law 3)
  try {
    const keypair = options.keypair || getOrGenerateSupervisorKey(mirqlDir);
    const payload = {
      probe: "doctor",
      type: "doctor",
      status: isHealthy ? "pass" : "fail",
      triage,
      recommendation: breaker,
      transition,
    };
    if (breaker.action === "trip" || breaker.action === "throttle") {
      payload.breaker = {
        target_subsystem: breaker.target_subsystem,
        action: breaker.action,
        cooldown_ms: breaker.cooldown_ms,
        reason: breaker.reason,
      };
      payload.expires_at_ms = Math.min(Number.MAX_SAFE_INTEGER, nowMs + breaker.cooldown_ms);
    }
    appendSupervisorEvent(
      mirqlDir,
      {
        type: "probe.completed",
        payload,
        nowMs,
      },
      keypair,
    );
  } catch (err) {
    if (options.strictLedgerWrite) throw err;
  }

  return {
    ok: true,
    healthy: isHealthy,
    triage,
    breaker,
    transition,
    breaker_state: breakerState,
  };
}
