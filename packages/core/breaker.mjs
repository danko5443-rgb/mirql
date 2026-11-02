// packages/core/breaker.mjs — circuit breaker state folds (Law 4).
// Pure ledger folds: authoritative breaker state is reconstructed from
// verified ledger events, so every layer (queue admission, doctor, supervisor)
// reads the same truth without cross-package imports.

import { readVerifiedLedgerEvents } from "./fold.mjs";

/**
 * Reconstructs authoritative circuit breaker state by folding doctor events from the durable ledger (Law 4).
 *
 * @param {object[]} ledgerEvents
 * @param {number} [nowMs=Date.now()]
 * @returns {{ v: 1, subsystems: Record<string, object> }}
 */
export function foldBreakerStateFromLedger(ledgerEvents = [], nowMs = Date.now()) {
  const subsystems = {};

  for (const item of ledgerEvents) {
    const evt = item && item.event ? item.event : item;
    if (!evt || evt.type !== "probe.completed") continue;

    // Law 3 single-writer ACL: only supervisor or human:owner may emit breaker events
    const writerNs = typeof evt.writer === "object" ? evt.writer.ns : evt.writer;
    if (writerNs && writerNs !== "tool:run_supervisor" && writerNs !== "human:owner") continue;

    const p = evt.payload || {};
    if (p.probe !== "doctor" && p.type !== "doctor" && p.type !== "doctor_breaker") continue;

    const breaker = p.breaker;
    if (!breaker || !breaker.target_subsystem || typeof breaker.target_subsystem !== "string") continue;

    const target = breaker.target_subsystem;
    const action = breaker.action;

    // Reset action: ONLY resets if explicitly directed by an operator/breaker action
    if (action === "reset") {
      if (target === "all") {
        for (const k of Object.keys(subsystems)) delete subsystems[k];
      } else {
        delete subsystems[target];
      }
    } else if (action === "trip" || action === "throttle") {
      const cooldownMs =
        Number.isSafeInteger(breaker.cooldown_ms) && breaker.cooldown_ms > 0
          ? breaker.cooldown_ms
          : 3600000;
      const trippedAt = Number.isSafeInteger(evt.hlc?.wall_ms) ? evt.hlc.wall_ms : nowMs;
      const expiresAt =
        Number.isSafeInteger(p.expires_at_ms) && p.expires_at_ms > 0
          ? p.expires_at_ms
          : Math.min(Number.MAX_SAFE_INTEGER, trippedAt + cooldownMs);

      // Chronological fold (Law 4): update subsystem state to latest event
      subsystems[target] = {
        state: action === "trip" ? "tripped" : "throttled",
        reason: breaker.reason || "doctor_directive",
        tripped_at_ms: trippedAt,
        expires_at_ms: expiresAt,
        cooldown_ms: cooldownMs,
      };
    }
  }

  // Filter out expired breakers as of nowMs
  for (const [target, entry] of Object.entries(subsystems)) {
    if (nowMs >= (entry.expires_at_ms || 0)) {
      delete subsystems[target];
    }
  }

  return { v: 1, subsystems };
}

/**
 * Checks whether a circuit breaker is currently active and tripped in the durable ledger.
 * Uses readVerifiedLedgerEvents to prevent forged or unauthenticated entries from tripping breakers (Law 4).
 * Fails closed if the ledger cannot be read (Law 6).
 *
 * @param {string} mirqlDir
 * @param {string} subsystem
 * @param {number} [nowMs=Date.now()]
 * @param {object} [options={}]
 * @returns {boolean}
 */
export function isCircuitBreakerTripped(mirqlDir, subsystem, nowMs = Date.now(), options = {}) {
  let events = [];
  try {
    events = readVerifiedLedgerEvents(mirqlDir, options);
  } catch {
    return true; // Fail closed (Law 6)
  }
  const state = foldBreakerStateFromLedger(events, nowMs);
  if (state.subsystems["all"]?.state === "tripped") return true;
  if (state.subsystems[subsystem]?.state === "tripped") return true;
  if (
    subsystem &&
    typeof subsystem === "string" &&
    subsystem.includes(":") &&
    state.subsystems[subsystem.split(":")[0]]?.state === "tripped"
  ) {
    return true;
  }
  return false;
}

/**
 * Lists every subsystem whose circuit breaker is actively TRIPPED right now
 * (unexpired, folded from verified ledger events — Law 4). This is the
 * binding enforcement query for work admission (issue #15): while any
 * subsystem is tripped, new work must not start.
 *
 * Throttled subsystems are reported by the fold as "throttled" and are
 * deliberately NOT included — throttle slows work down, only a trip stops it.
 * Fails closed if the ledger cannot be read (Law 6).
 *
 * @param {string} mirqlDir
 * @param {number} [nowMs=Date.now()]
 * @param {object} [options={}]
 * @returns {Array<{ subsystem: string, reason: string, tripped_at_ms: number, expires_at_ms: number }>}
 */
export function getActiveTrippedBreakers(mirqlDir, nowMs = Date.now(), options = {}) {
  let events = [];
  try {
    events = readVerifiedLedgerEvents(mirqlDir, options);
  } catch (err) {
    // Law 6: Fail-closed on ledger read error
    return [
      {
        subsystem: "all",
        reason: `ledger_read_error: ${err.message}`,
        tripped_at_ms: nowMs,
        expires_at_ms: Number.MAX_SAFE_INTEGER,
      },
    ];
  }
  const state = foldBreakerStateFromLedger(events, nowMs);
  const active = [];
  for (const [subsystem, entry] of Object.entries(state.subsystems || {})) {
    if (entry?.state === "tripped" && nowMs < (entry.expires_at_ms || 0)) {
      active.push({
        subsystem,
        reason: entry.reason ?? "unknown",
        tripped_at_ms: entry.tripped_at_ms ?? 0,
        expires_at_ms: entry.expires_at_ms ?? 0,
      });
    }
  }
  return active;
}
