/**
 * Canonical process exit codes for every mirql tool and CLI.
 *
 * These are part of the public contract: scripts, supervisors and CI gates
 * branch on these numbers, and mergeproof verdicts cite them. Never reuse a
 * number for a new meaning — add a new one instead.
 */
export const EXIT_CODES = Object.freeze({
  /** Success. */
  OK: 0,
  /** The request was rejected by a domain rule (not a bug, not usage error). */
  DOMAIN_NEGATIVE: 1,
  /** Bad CLI arguments or malformed input document. */
  USAGE_ERROR: 2,
  /** Hash-chain break, bad signature, or any other integrity violation. */
  INTEGRITY_VIOLATION: 3,
  /** A warrant/scope/policy check refused the action. */
  POLICY_DENIAL: 4,
  /** The caller's epoch is stale; re-read state and retry with a fresh epoch. */
  STALE_EPOCH: 5,
  /** The system is halted (lifeguard). No work may proceed. */
  HALTED: 6,
  /** Budget exhausted; the action would exceed its micro-USD ceiling. */
  BUDGET_EXHAUSTED: 7,
  /** A circuit breaker is tripped; new work is refused until cooldown or reset. */
  BREAKER_OPEN: 8,
  /** The situation requires a human decision. */
  NEEDS_HUMAN: 10,
  /** Temporary failure; safe to retry with backoff (EX_TEMPFAIL). */
  TRANSIENT: 75,
  /** Wall-clock limit hit (GNU timeout convention). */
  TIMEOUT: 124,
});
