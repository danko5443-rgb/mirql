// packages/queue/fsm.mjs — Law 12 Macro Mode FSM and Deterministic tick Reducer.
import { EXIT_CODES } from "../core/index.mjs";

export const DEFAULT_POLICY = Object.freeze({
  version: 1,
  daily_budget_micro_usd: 25000000,
  per_job_budget_micro_usd: 1500000,
  ladder: ["flash", "mid", "max", "human"],
  critic: "claude-opus-5-5-medium",
  retries_per_tier: 2,
  max_awaiting_human: 5,
  max_attempts_per_warrant: 3,
  lease_ttl_ms: 900000,
  refactor_cooldown_ms: 172800000,
  macro_states: ["BUILD", "HARDEN", "PATROL", "QUIESCENT"],
  quiescent_max_budget_bp: 500,
});

/**
 * Pure deterministic tick reducer for the mirql macro state machine.
 *
 * @param {object} state - folded ledger state
 * @param {object} [policy] - policy rules from policy/mirql.json
 * @param {number} [nowMs] - current wall-clock timestamp in ms
 * @param {object} [options] - additional evaluation inputs
 * @returns {{
 *   action: string,
 *   next_mode: string,
 *   reason?: string,
 *   exit_code?: number,
 *   warrant_id?: string,
 *   scouts?: string[],
 *   tokens_per_hr?: number,
 *   expired_leases?: object[]
 * }}
 */
export function tick(state, policy = DEFAULT_POLICY, nowMs = Date.now(), options = {}) {
  const mergedPolicy = { ...DEFAULT_POLICY, ...policy };

  // 1. Lifeguard check: system halted
  if (state.halted === true) {
    return {
      action: "HALTED",
      next_mode: "HALTED",
      exit_code: EXIT_CODES.HALTED,
      reason: "lifeguard_halted",
    };
  }

  // 2. Budget ceiling check
  const budgetSpent = state.budget_spent_micro_usd ?? state.metrics?.total_cost_micro_usd ?? 0;
  if (budgetSpent >= mergedPolicy.daily_budget_micro_usd) {
    return {
      action: "BUDGET_EXHAUSTED",
      next_mode: state.mode || "BUILD",
      exit_code: EXIT_CODES.BUDGET_EXHAUSTED,
      reason: "daily_budget_exhausted",
    };
  }

  // 3. Fix B2: Reap expired leases
  const expiredLeases = Object.values(state.active_leases || {}).filter(
    (l) => nowMs > (l.expires_at_ms ?? (l.leased_at_ms + l.ttl_ms)),
  );
  if (expiredLeases.length > 0) {
    return {
      action: "REAP_EXPIRED_LEASES",
      next_mode: state.mode || "BUILD",
      expired_leases: expiredLeases,
    };
  }

  // 4. Fix B5: Bounded retry / Parked NEEDS_HUMAN warrants
  const maxAttempts = mergedPolicy.max_attempts_per_warrant ?? 3;
  const maxAwaitingHuman = mergedPolicy.max_awaiting_human ?? 5;
  const warrants = Object.values(state.warrants || {});

  const needsHumanWarrants = warrants.filter(
    (w) =>
      w.status === "needs_human" ||
      (w.failed_attempts !== undefined && w.failed_attempts >= maxAttempts),
  );

  // If count of warrants awaiting human reaches policy ceiling, stop entire queue
  if (needsHumanWarrants.length >= maxAwaitingHuman) {
    return {
      action: "NEEDS_HUMAN",
      next_mode: state.mode || "BUILD",
      exit_code: EXIT_CODES.NEEDS_HUMAN,
      reason: "max_awaiting_human_reached",
    };
  }

  const currentMode = state.mode || "BUILD";

  // Fix B1: Helper to check if a warrant is currently leased
  function isWarrantActiveLeased(wId) {
    return Object.values(state.active_leases || {}).some(
      (l) => l.warrant_id === wId && nowMs <= (l.expires_at_ms ?? (l.leased_at_ms + l.ttl_ms)),
    );
  }

  // Filter available warrants that are active, not in needs_human, and not double-leased
  const availableOpenWarrants = warrants.filter(
    (w) =>
      (w.status === "active" || w.status === "open") &&
      w.status !== "needs_human" &&
      (w.failed_attempts || 0) < maxAttempts &&
      !isWarrantActiveLeased(w.id),
  );

  const availableQueuedJobs = Object.values(state.jobs || {}).filter(
    (j) =>
      (j.status === "queued" || j.status === "enqueued") &&
      state.warrants[j.warrant_id]?.status !== "needs_human" &&
      !isWarrantActiveLeased(j.warrant_id),
  );

  switch (currentMode) {
    case "BUILD": {
      if (availableOpenWarrants.length > 0 || availableQueuedJobs.length > 0) {
        return {
          action: "LEASE_JOB",
          next_mode: "BUILD",
          eligible_jobs: availableQueuedJobs,
          eligible_warrants: availableOpenWarrants,
        };
      }

      // Check if all non-completed warrants are parked in needs_human
      const unfinishedWarrants = warrants.filter(
        (w) => w.status !== "completed" && w.status !== "canceled" && w.status !== "revoked",
      );

      if (unfinishedWarrants.length > 0) {
        const allParked = unfinishedWarrants.every(
          (w) =>
            w.status === "needs_human" ||
            (w.failed_attempts !== undefined && w.failed_attempts >= maxAttempts),
        );
        if (allParked) {
          return {
            action: "NEEDS_HUMAN",
            next_mode: "BUILD",
            warrant_id: needsHumanWarrants[0]?.id,
            exit_code: EXIT_CODES.NEEDS_HUMAN,
            reason: `warrant_${needsHumanWarrants[0]?.id}_requires_human_review`,
          };
        }
        // Work is in-progress under active lease
        return {
          action: "WAIT_IN_PROGRESS",
          next_mode: "BUILD",
        };
      }

      // All active warrants and queued jobs are resolved -> transition BUILD to HARDEN
      return {
        action: "TRANSITION",
        next_mode: "HARDEN",
        reason: "all_warrants_resolved",
      };
    }

    case "HARDEN": {
      const hardeningPassed =
        options.hardening_passed === true || state.hardening_passed === true;

      if (hardeningPassed) {
        return {
          action: "TRANSITION",
          next_mode: "PATROL",
          reason: "hardening_passed",
        };
      }

      return {
        action: "SCHEDULE_SCOUTS",
        next_mode: "HARDEN",
        scouts: ["scout-bugs", "scout-mutants", "scout-drift", "consolidator"],
      };
    }

    case "PATROL": {
      const probesClean = options.probes_clean !== false && state.probes_clean !== false;
      const headUnchanged = options.head_unchanged !== false;

      if (probesClean && headUnchanged) {
        return {
          action: "TRANSITION",
          next_mode: "QUIESCENT",
          reason: "probes_clean_head_unchanged",
          tokens_per_hr: 0,
        };
      }

      return {
        action: "PROBE_FAILURE",
        next_mode: "BUILD",
        reason: "probes_failed_or_head_changed",
      };
    }

    case "QUIESCENT": {
      // Wake up back to BUILD if new open warrants arrived or head commit changed
      if (
        availableOpenWarrants.length > 0 ||
        availableQueuedJobs.length > 0 ||
        options.new_work === true
      ) {
        return {
          action: "TRANSITION",
          next_mode: "BUILD",
          reason: "new_work_arrived",
        };
      }

      return {
        action: "QUIESCENT",
        next_mode: "QUIESCENT",
        tokens_per_hr: 0,
      };
    }

    case "HALTED": {
      return {
        action: "HALTED",
        next_mode: "HALTED",
        exit_code: EXIT_CODES.HALTED,
        reason: "queue_is_halted",
      };
    }

    default: {
      return {
        action: "UNKNOWN",
        next_mode: "BUILD",
      };
    }
  }
}
