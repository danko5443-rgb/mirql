// packages/run/doctor.mjs — Autonomous Diagnostic Role & Multi-Tier Circuit Breakers.
// Roles: roles/doctor.md (tier: max, emits: triage.report, circuit_breaker.recommendation)
// Laws: Law 2 (Lifeguard Kill Authority), Law 14 (Convergence to Quiescence), Law 17 (Integer-Only JCS)

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { EXIT_CODES, jcs } from "../core/index.mjs";
import { runProbe, KNOWN_PROBES } from "./probe.mjs";
import { quarantineTest } from "./mutant.mjs";

export const SUBSYSTEMS = Object.freeze([
  "worker",
  "worker:flash",
  "worker:mid",
  "worker:max",
  "probe",
  "budget",
  "queue",
  "lifeguard",
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
 * Reads events from the append-only ledger without cross-package imports.
 *
 * @param {string} mirqlDir
 * @returns {object[]}
 */
export function readLedgerEvents(mirqlDir) {
  const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(eventsFile)) return [];
  const raw = readFileSync(eventsFile, "utf8").trim();
  if (!raw) return [];
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const events = [];
  for (const line of lines) {
    try {
      events.push(JSON.parse(line));
    } catch {}
  }
  return events;
}

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
    macro_states: ["BUILD", "HARDEN", "PATROL", "QUIESCENT"],
  };
}

/**
 * Folds ledger events into state projection without cross-package imports.
 *
 * @param {object[]} events
 * @returns {object}
 */
export function reduceQueueState(events = []) {
  const state = {
    mode: "BUILD",
    warrants: {},
    jobs: {},
    active_leases: {},
    budget_spent_micro_usd: 0,
    metrics: { total_cost_micro_usd: 0 },
  };

  for (const evt of events) {
    if (!evt || !evt.type) continue;
    switch (evt.type) {
      case "mirql.genesis":
      case "factory.transition":
        if (evt.payload?.macro_state) state.mode = evt.payload.macro_state;
        if (evt.payload?.next_mode) state.mode = evt.payload.next_mode;
        break;
      case "warrant.created":
      case "warrant.issued": {
        const wId = evt.payload?.warrant?.id || evt.payload?.id || evt.id;
        if (wId) {
          state.warrants[wId] = {
            id: wId,
            status: "open",
            tier: evt.payload?.warrant?.tier || "flash",
            failed_attempts: 0,
            ...(evt.payload?.warrant || evt.payload || {}),
          };
        }
        break;
      }
      case "warrant.converged": {
        const wId = evt.payload?.warrant_id;
        if (wId && state.warrants[wId]) {
          state.warrants[wId].status = "completed";
        }
        break;
      }
      case "job.enqueued": {
        const jId = evt.payload?.job_id || evt.payload?.id || evt.id;
        if (jId) {
          state.jobs[jId] = {
            id: jId,
            status: "queued",
            warrant_id: evt.payload?.warrant_id,
          };
        }
        break;
      }
      case "job.leased": {
        const jId = evt.payload?.job_id;
        const lId = evt.payload?.lease_id || jId;
        if (lId) {
          const leasedAt = evt.payload?.leased_at_ms || evt.hlc?.wall_ms || Date.now();
          const ttl = evt.payload?.ttl_ms || 900000;
          state.active_leases[lId] = {
            lease_id: lId,
            job_id: jId,
            warrant_id: evt.payload?.warrant_id,
            leased_at_ms: leasedAt,
            ttl_ms: ttl,
            expires_at_ms: evt.payload?.expires_at_ms || (leasedAt + ttl),
          };
        }
        break;
      }
      case "job.completed": {
        const jId = evt.payload?.job_id;
        if (jId && state.jobs[jId]) state.jobs[jId].status = "completed";
        for (const [k, v] of Object.entries(state.active_leases)) {
          if (v.job_id === jId) delete state.active_leases[k];
        }
        break;
      }
      case "job.failed": {
        const jId = evt.payload?.job_id;
        const wId = evt.payload?.warrant_id;
        if (jId && state.jobs[jId]) state.jobs[jId].status = "failed";
        if (wId && state.warrants[wId]) {
          state.warrants[wId].failed_attempts = (state.warrants[wId].failed_attempts || 0) + 1;
        }
        for (const [k, v] of Object.entries(state.active_leases)) {
          if (v.job_id === jId) delete state.active_leases[k];
        }
        break;
      }
      case "attempt.outcome": {
        const cost = evt.payload?.cost_micro_usd || 0;
        if (Number.isSafeInteger(cost) && cost > 0) {
          state.budget_spent_micro_usd += cost;
          state.metrics.total_cost_micro_usd += cost;
        }
        break;
      }
    }
  }
  return state;
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

  let raw = "";
  if (typeof input === "string") {
    raw = input;
  } else if (input instanceof Error) {
    raw = `${input.name}: ${input.message}`;
  } else if (typeof input === "object") {
    if (input.failure_signature) {
      return String(input.failure_signature);
    }
    if (input.type === "job.timeout") {
      const timeoutMs = input.payload?.timeout_ms ?? 0;
      return `SIG:TIMEOUT:${Number.isSafeInteger(timeoutMs) ? timeoutMs : 0}ms`;
    }
    if (input.type === "job.failed" || input.type === "attempt.failed") {
      const reason = input.payload?.reason ?? input.payload?.error ?? input.payload?.status ?? "";
      raw = `job_failed: ${reason}`;
    } else if (input.probe) {
      const pName = input.probe.probe ?? input.probe.name ?? "unknown";
      const status = input.probe.status ?? "failed";
      raw = `probe_${pName}_${status}`;
    } else if (input.error || input.message || input.reason) {
      raw = String(input.error || input.message || input.reason);
    } else {
      raw = JSON.stringify(input);
    }
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
  if (/budget|ceiling|exhaust/i.test(sanitized)) {
    return "SIG:BUDGET_EXCEEDED:ceiling_exhaustion";
  }
  if (/lease|expired|hung/i.test(sanitized)) {
    return "SIG:LEASE_HUNG:lease_timeout";
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

  // 1. Scan ledger events for failure events
  for (const evt of ledgerEvents) {
    if (!evt || typeof evt !== "object") continue;
    const type = evt.type ?? "";
    const isFailureEvent =
      type === "job.failed" ||
      type === "job.timeout" ||
      type === "attempt.failed" ||
      type === "lifeguard.alert" ||
      (type === "probe.completed" && evt.payload?.probe?.status !== "pass");

    if (isFailureEvent) {
      const sig = normalizeFailureSignature(evt);
      const jobId = evt.payload?.job_id ?? evt.payload?.id ?? evt.id;
      if (jobId) affectedJobs.add(jobId);
      if (type === "probe.completed") {
        const pName = evt.payload?.probe?.probe ?? evt.payload?.probe?.name;
        if (pName) affectedProbes.add(pName);
      }
      incidents.push({
        source: "ledger",
        type,
        sig,
        raw: evt,
      });
    }
  }

  // 2. Scan probe results
  const pList = Array.isArray(probeResults)
    ? probeResults
    : probeResults && typeof probeResults === "object"
      ? Object.values(probeResults)
      : [];

  for (const p of pList) {
    if (!p || typeof p !== "object") continue;
    const isFail = p.ok === false || p.passed === false || (p.status && p.status !== "pass");
    if (isFail) {
      const pName = p.name ?? p.probe ?? "unknown";
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

  // 3. Scan queue status for hung leases and retry exhaustion
  const warrants = Object.values(queueStatus.warrants || {});
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

  for (const w of warrants) {
    if (w.status === "needs_human" || (w.failed_attempts || 0) >= 3) {
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
    };
  }

  // Count incidents by signature
  const sigCounts = new Map();
  for (const inc of incidents) {
    sigCounts.set(inc.sig, (sigCounts.get(inc.sig) || 0) + 1);
  }

  // Identify dominant signature
  let primarySig = "";
  let maxCount = -1;
  for (const [sig, count] of sigCounts.entries()) {
    if (count > maxCount) {
      maxCount = count;
      primarySig = sig;
    }
  }

  // Formulate root cause analysis and remediation based on dominant signature
  let rootCause = "Unclassified recurring defect detected across ledger and execution boundaries.";
  let remediation = "Inspect job logs and isolate failing module.";

  if (primarySig.startsWith("SIG:TIMEOUT")) {
    rootCause = "Worker execution exceeded configured lease TTL; potential deadlock, heavy computation, or unbounded external wait.";
    remediation = "Reap hung leases via queue tick, scale worker timeout, or decompose task anchors into smaller warrants.";
  } else if (primarySig.startsWith("SIG:ASSERTION")) {
    rootCause = "Test assertion regression; code modifications under attempt failed to meet behavioral contracts.";
    remediation = "Revert breaking patch or verify test expectations; escalate to mid/max tier builder.";
  } else if (primarySig.startsWith("SIG:SYNTAX")) {
    rootCause = "Unparseable syntax generated by unprivileged worker code mutation.";
    remediation = "Enforce pre-verification node check (node --check) and discard malformed candidate patches.";
  } else if (primarySig.startsWith("SIG:DRIFT")) {
    rootCause = "Attempt modified files outside declared warrant anchors or introduced public API delta without citation.";
    remediation = "Re-anchor warrant or update surface.lock with explicit human citation.";
  } else if (primarySig.startsWith("SIG:MUTANT_SURVIVOR")) {
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
  };
}

/**
 * Multi-Tier Circuit Breaker Evaluator (roles/doctor.md).
 *
 * Tracks failure metrics across worker tiers (flash, mid, max), budget consumption,
 * and hung leases to prescribe autonomous circuit breaking directives.
 *
 * @param {object} systemMetrics
 * @param {object} [options={}]
 * @returns {object} canonical circuit_breaker.recommendation document
 */
export function evaluateCircuitBreakers(systemMetrics = {}, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const tierFailures = {
    flash: systemMetrics.tier_failures?.flash ?? 0,
    mid: systemMetrics.tier_failures?.mid ?? 0,
    max: systemMetrics.tier_failures?.max ?? 0,
  };

  const retriesPerTier = Number.isSafeInteger(options.retries_per_tier)
    ? options.retries_per_tier
    : 2;

  const budgetSpent = Number.isSafeInteger(systemMetrics.budget_spent_micro_usd)
    ? systemMetrics.budget_spent_micro_usd
    : 0;

  const budgetLimit = Number.isSafeInteger(systemMetrics.budget_limit_micro_usd)
    ? systemMetrics.budget_limit_micro_usd
    : 25000000; // 25 USD default

  const hungLeases = Number.isSafeInteger(systemMetrics.hung_leases_count)
    ? systemMetrics.hung_leases_count
    : 0;

  const totalFailures = tierFailures.flash + tierFailures.mid + tierFailures.max;

  // Rule 0: Operator manual trip override
  if (options.manual_trip) {
    const target = SUBSYSTEMS.includes(options.manual_trip) ? options.manual_trip : "worker";
    const cooldownMs = Number.isSafeInteger(options.cooldown_ms) && options.cooldown_ms > 0
      ? options.cooldown_ms
      : 3600000;
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
      cooldown_ms: options.cooldown_ms ?? 172800000, // 48h cooldown
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
  if (budgetLimit > 0 && budgetSpent >= Math.floor((budgetLimit * 90) / 100)) {
    return {
      v: 1,
      type: "circuit_breaker.recommendation",
      target_subsystem: "budget",
      action: "throttle",
      cooldown_ms: options.cooldown_ms ?? 3600000,
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
      cooldown_ms: options.cooldown_ms ?? 1800000,
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
      cooldown_ms: options.cooldown_ms ?? 900000,
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
      cooldown_ms: options.cooldown_ms ?? 300000,
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
      cooldown_ms: options.cooldown_ms ?? 60000,
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

  // Lifeguard or fatal budget trip -> HALTED
  if (options.lifeguard_halt === true || (breakerRecommendation?.action === "trip" && breakerRecommendation.target_subsystem === "budget")) {
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

  if (current === "PATROL" && (options.probes_clean === true || triageReport?.healthy === true)) {
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
 * Breaker state persistence manager for tracking active circuit trips and cooldowns.
 */
export class BreakerStore {
  /**
   * @param {string} mirqlDir
   */
  constructor(mirqlDir) {
    this.mirqlDir = mirqlDir;
    this.stateFile = join(mirqlDir, "state", "doctor_breakers.json");
  }

  load() {
    if (!existsSync(this.stateFile)) {
      return {
        v: 1,
        subsystems: {},
      };
    }
    try {
      const parsed = JSON.parse(readFileSync(this.stateFile, "utf8"));
      return parsed && typeof parsed === "object" ? parsed : { v: 1, subsystems: {} };
    } catch {
      return { v: 1, subsystems: {} };
    }
  }

  save(data) {
    const stateDir = join(this.mirqlDir, "state");
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(this.stateFile, jcs(data) + "\n", "utf8");
  }

  trip(subsystem, reason = "manual_trip", cooldownMs = 3600000, nowMs = Date.now()) {
    const data = this.load();
    data.subsystems = data.subsystems || {};
    data.subsystems[subsystem] = {
      state: "tripped",
      reason,
      tripped_at_ms: nowMs,
      expires_at_ms: nowMs + cooldownMs,
      cooldown_ms: cooldownMs,
    };
    this.save(data);
    return data.subsystems[subsystem];
  }

  reset(subsystem) {
    const data = this.load();
    data.subsystems = data.subsystems || {};
    if (subsystem === "all") {
      data.subsystems = {};
    } else {
      delete data.subsystems[subsystem];
    }
    this.save(data);
  }

  isTripped(subsystem, nowMs = Date.now()) {
    const data = this.load();
    const entry = data.subsystems?.[subsystem];
    if (!entry) return false;
    if (entry.state === "tripped") {
      if (nowMs < (entry.expires_at_ms || 0)) {
        return true;
      }
      // Cooldown expired
      delete data.subsystems[subsystem];
      this.save(data);
    }
    return false;
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

  const store = new BreakerStore(mirqlDir);

  // Handle explicit reset flag
  if (options.reset) {
    store.reset(options.reset);
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

  // Read durable ledger events
  let ledgerEvents = [];
  try {
    ledgerEvents = readLedgerEvents(mirqlDir);
  } catch {
    ledgerEvents = [];
  }

  // Reduce queue state directly from ledger events
  let queueState = {};
  try {
    queueState = reduceQueueState(ledgerEvents);
  } catch {
    queueState = {};
  }

  // Load policy
  const policy = loadDoctorPolicy(mirqlDir, workspaceDir);

  // Probe outputs
  const probeResults = options.probeResults || [];
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
  const triage = diagnoseHealth(ledgerEvents, probeResults, queueState, { nowMs });

  // Auto-quarantine flaky test if requested
  if (options.autoQuarantine && triage.failure_signature.startsWith("SIG:FLAKE")) {
    const qDir = join(mirqlDir, "quarantine");
    for (const p of probeResults) {
      if (p.name === "tests" && p.testFile) {
        try {
          quarantineTest(p.testFile, qDir);
          triage.quarantine_applied = p.testFile;
        } catch {}
      }
    }
  }

  // Compute tier metrics
  const tierFailures = { flash: 0, mid: 0, max: 0 };
  const warrants = Object.values(queueState.warrants || {});
  for (const w of warrants) {
    const tier = w.tier || (w.class === "architectural" ? "max" : "flash");
    const fails = w.failed_attempts || 0;
    if (fails > 0 && tier in tierFailures) {
      tierFailures[tier] = Math.max(tierFailures[tier], fails);
    }
  }

  // Check active hung leases
  let hungLeasesCount = 0;
  for (const l of Object.values(queueState.active_leases || {})) {
    const exp = l.expires_at_ms ?? (l.leased_at_ms + (l.ttl_ms ?? 0));
    if (nowMs > exp) hungLeasesCount++;
  }

  const budgetSpent = queueState.budget_spent_micro_usd ?? queueState.metrics?.total_cost_micro_usd ?? 0;
  const budgetLimit = policy.daily_budget_micro_usd ?? 25000000;

  const breakerMetrics = {
    tier_failures: tierFailures,
    budget_spent_micro_usd: budgetSpent,
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
      all_warrants_resolved: warrants.length > 0 && warrants.every((w) => w.status === "completed"),
    },
  );

  const breakerState = store.load();
  const isHealthy = triage.healthy && breaker.action !== "trip" && breaker.action !== "force_harden";

  return {
    ok: true,
    healthy: isHealthy,
    triage,
    breaker,
    transition,
    breaker_state: breakerState,
  };
}
