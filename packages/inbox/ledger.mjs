// packages/inbox/ledger.mjs — Ledger I/O, hash chaining, and state cache management.
import {
  readFileSync,
  appendFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  renameSync,
} from "node:fs";
import { join } from "node:path";
import { jcs, sha256, EXIT_CODES } from "../core/index.mjs";

export const GENESIS_PREV_HASH = `sha256:${"0".repeat(64)}`;

/**
 * Read all events from <mirqlDir>/ledger/events.jsonl.
 * @param {string} mirqlDir
 * @returns {{ events: object[], rawLines: string[] }}
 */
export function readEvents(mirqlDir) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(file)) return { events: [], rawLines: [] };

  const rawLines = [];
  const lines = readFileSync(file, "utf8").split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length > 0) rawLines.push(trimmed);
  }

  const events = [];
  for (const line of rawLines) {
    try {
      events.push(JSON.parse(line));
    } catch {}
  }

  return { events, rawLines };
}

/**
 * Get the last event and log summary.
 * @param {string} mirqlDir
 * @returns {{ lastEvent: object | null, count: number, lastHash: string }}
 */
export function getLastEvent(mirqlDir) {
  const { events, rawLines } = readEvents(mirqlDir);
  if (events.length === 0) {
    return { lastEvent: null, count: 0, lastHash: GENESIS_PREV_HASH };
  }
  const last = events[events.length - 1];
  const lastHash =
    typeof last.hash === "string" && last.hash.length > 0
      ? last.hash
      : sha256(rawLines[rawLines.length - 1]);
  return { lastEvent: last, count: events.length, lastHash };
}

/**
 * Atomically append a signed event line to <mirqlDir>/ledger/events.jsonl
 * and update <mirqlDir>/cache/state.json.
 *
 * @param {string} mirqlDir
 * @param {object} signedEvent
 */
export function appendEvent(mirqlDir, signedEvent) {
  const ledgerDir = join(mirqlDir, "ledger");
  const cacheDir = join(mirqlDir, "cache");
  mkdirSync(ledgerDir, { recursive: true });
  mkdirSync(cacheDir, { recursive: true });

  const eventsPath = join(ledgerDir, "events.jsonl");

  // Law 4 deduplication: if identical (writer.ns, idempotency_key) already exists, skip duplicate write
  if (signedEvent.idempotency_key && signedEvent.writer?.ns && existsSync(eventsPath)) {
    const { events: existing } = readEvents(mirqlDir);
    const dup = existing.find(
      (e) =>
        e.idempotency_key === signedEvent.idempotency_key &&
        e.writer?.ns === signedEvent.writer?.ns
    );
    if (dup) {
      return dup;
    }
  }

  const line = jcs(signedEvent) + "\n";
  appendFileSync(eventsPath, line, "utf8");

  // Update materialized state cache
  updateStateCache(mirqlDir);
}

/**
 * Pure deterministic state fold over events.
 *
 * @param {object[]} events
 * @returns {object}
 */
export function foldState(events) {
  const state = {
    version: 1,
    mode: "BUILD",
    epoch: 1,
    seq: 0,
    last_event_hash: GENESIS_PREV_HASH,
    budget_spent_micro_usd: 0,
    warrants: {},
    jobs: {},
    phi_last: 0,
    halted: false,
    needs_human: false,
    pending_human_items: 0,
    recent_outcomes: [],
  };

  for (const evt of events) {
    if (!evt || typeof evt !== "object") continue;
    state.seq = typeof evt.seq === "number" ? evt.seq : state.seq + 1;
    if (typeof evt.epoch === "number") state.epoch = evt.epoch;
    if (typeof evt.hash === "string") { state.last_event_hash = evt.hash; state.last_hash = evt.hash; }

    const payload = evt.payload && typeof evt.payload === "object" ? evt.payload : {};
    const type = evt.type || "";

    if (type === "mirql.genesis") {
      if (typeof payload.macro_state === "string") state.mode = payload.macro_state;
    } else if (type === "factory.mode_changed" || type === "queue.macro_transition") {
      if (typeof payload.macro_state === "string") state.mode = payload.macro_state;
      if (typeof payload.mode === "string") state.mode = payload.mode;
    } else if (type === "factory.halted" || type === "mirql.halted" || type === "mirql.halt" || type === "human.kill") {
      state.halted = true;
    } else if (type === "factory.resumed" || type === "mirql.resumed" || type === "mirql.resume" || type === "human.resume") {
      state.halted = false;
    } else if (type === "warrant.created") {
      const wid = payload.warrant_id;
      if (wid) {
        state.warrants[wid] = {
          id: wid,
          intent_id: payload.intent_id || null,
          role: payload.role || null,
          tier: payload.tier || null,
          status: payload.status || "active",
          budget_micro_usd: payload.budget_micro_usd || 0,
        };
      }
    } else if (type === "job.leased" || type === "job.enqueued") {
      const jid = payload.job_id;
      if (jid) {
        state.jobs[jid] = {
          id: jid,
          warrant_id: payload.warrant_id || null,
          worker_id: payload.worker_id || null,
          status: type === "job.leased" ? "leased" : "enqueued",
          outcome_verdict: null,
        };
      }
    } else if (type === "attempt.outcome") {
      const cost = Number.isSafeInteger(payload.cost_micro_usd) ? payload.cost_micro_usd : 0;
      state.budget_spent_micro_usd += cost;
      const jid = payload.job_id;
      if (jid && state.jobs[jid]) {
        if (payload.status) state.jobs[jid].status = payload.status;
        if (payload.verdict) state.jobs[jid].outcome_verdict = payload.verdict;
      }
      if (typeof payload.phi_after === "number") {
        state.phi_last = payload.phi_after;
      }
      state.recent_outcomes.push({
        seq: state.seq,
        job_id: jid || null,
        verdict: payload.verdict || payload.status || "completed",
        cost_micro_usd: cost,
      });
      if (state.recent_outcomes.length > 10) state.recent_outcomes.shift();
    } else if (type === "verdict.needs_human" || type === "human.approval_requested") {
      state.needs_human = true;
      state.pending_human_items += 1;
      const jid = payload.job_id;
      if (jid && state.jobs[jid]) state.jobs[jid].status = "needs_human";
    } else if (type === "human.approval" || type === "human.rejection" || type === "human.decision") {
      if (state.pending_human_items > 0) state.pending_human_items -= 1;
      if (state.pending_human_items === 0) state.needs_human = false;
      const tid = payload.target_id;
      if (tid && state.jobs[tid]) {
        state.jobs[tid].status = type === "human.approval" ? "approved" : "rejected";
      }
    } else if (type === "promotion.completed") {
      state.recent_outcomes.push({
        seq: state.seq,
        promotion_id: payload.promotion_id || null,
        verdict: "promoted",
      });
      if (state.recent_outcomes.length > 10) state.recent_outcomes.shift();
    }
  }

  return state;
}

/**
 * Re-folds the ledger and atomically updates <mirqlDir>/cache/state.json.
 * @param {string} mirqlDir
 * @returns {object} folded state
 */
export function updateStateCache(mirqlDir) {
  const { events } = readEvents(mirqlDir);
  const state = foldState(events);
  const cacheDir = join(mirqlDir, "cache");
  mkdirSync(cacheDir, { recursive: true });

  const cacheFile = join(cacheDir, "state.json");
  const tmpFile = `${cacheFile}.tmp`;
  writeFileSync(tmpFile, jcs(state) + "\n", "utf8");
  renameSync(tmpFile, cacheFile);
  return state;
}

/**
 * Fail closed unless the ledger is initialized: non-empty and anchored by a
 * valid `mirql.genesis` first event. Human actions (send/act) must never
 * operate on a foreign or uninitialized ledger.
 *
 * @param {string} mirqlDir
 * @returns {void}
 * @throws structured Error (not_initialized, POLICY_DENIAL)
 */
export function requireGenesisLedger(mirqlDir) {
  const { events } = readEvents(mirqlDir);
  if (events.length === 0 || events[0]?.type !== "mirql.genesis") {
    const err = new Error(
      `not_initialized: ${mirqlDir} has no genesis-anchored ledger; run \`mirql i genesis\` first`,
    );
    err.errorCode = "not_initialized";
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }
}
