import { trustFile } from "./trust-root.mjs";
// packages/core/fold.mjs — Canonical mathematical fold over append-only ledger events.
// Law 4 (State as a pure fold over durable ledger) & Law 3 (Single-Writer ACL).

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "./hash.mjs";
import { canWriteEvent } from "./acl.mjs";
import { verifyEvent } from "./ed25519.mjs";

/**
 * Privileged events whose emission requires cryptographic verification against keyring.json.
 */
export const PRIVILEGED_EVENTS = Object.freeze(new Set([
  "job.promoted",
  "human.approval",
  "human.intent",
  "verdict.accepted",
  "verdict.issued",
  "factory.resumed",
  "mirql.resume",
]));

/**
 * Loads trusted public keyring from disk.
 *
 * @param {string} mirqlDir
 * @returns {Record<string, any>}
 */
export function loadKeyring(mirqlDir) {
  const candidates = [
    trustFile(mirqlDir, "keyring.json"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) {
      try {
        return JSON.parse(readFileSync(c, "utf8"));
      } catch {}
    }
  }
  return {};
}

/**
 * Resolves trusted public key for a given writer namespace.
 *
 * @param {object} keyring
 * @param {string} writerNs
 * @param {string} [keyId]
 * @returns {string | null}
 */
export function getTrustedPublicKey(keyring, writerNs, keyId) {
  if (!keyring || typeof keyring !== "object" || !writerNs) return null;

  if (keyring[writerNs]) {
    const val = keyring[writerNs];
    if (typeof val === "string") return val;
    if (val && typeof val === "object" && typeof val.publicKey === "string") {
      return val.publicKey;
    }
    if (val && typeof val === "object" && typeof val.pubkey === "string") {
      return val.pubkey;
    }
  }

  if (keyring.writers && keyring.writers[writerNs]) {
    const val = keyring.writers[writerNs];
    if (typeof val === "string") return val;
    if (val && typeof val === "object" && typeof val.publicKey === "string") {
      return val.publicKey;
    }
    if (val && typeof val === "object" && typeof val.pubkey === "string") {
      return val.pubkey;
    }
  }

  if (keyId && keyring[keyId] && typeof keyring[keyId] === "object") {
    const entry = keyring[keyId];
    if (entry.ns === writerNs || entry.namespace === writerNs) {
      return entry.publicKey || entry.pubkey || null;
    }
  }

  if (keyId && keyId.startsWith("ed25519:")) {
    const rawKey = keyId.slice("ed25519:".length);
    if (keyring[rawKey] && typeof keyring[rawKey] === "object") {
      const entry = keyring[rawKey];
      if (entry.ns === writerNs || entry.namespace === writerNs) {
        return entry.publicKey || entry.pubkey || null;
      }
    }
  }

  return null;
}

/**
 * Reads ledger events from .mirql/ledger/events.jsonl.
 *
 * @param {string} mirqlDir
 * @returns {Array<{ event: object, raw: string }>}
 */
export function readLedgerEvents(mirqlDir) {
  const ledgerPath = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(ledgerPath)) return [];

  const content = readFileSync(ledgerPath, "utf8");
  const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const events = [];

  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      events.push({ event, raw: line });
    } catch {}
  }

  return events;
}

/**
 * Reads and cryptographically verifies events from .mirql/ledger/events.jsonl (Law 4 & Law 3).
 * Any forged, unsigned, or invalidly signed line is strictly rejected.
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {Array<{ event: object, raw: string }>}
 */
export function readVerifiedLedgerEvents(mirqlDir, options = {}) {
  const rawEvents = readLedgerEvents(mirqlDir);
  const keyring = options.keyring || loadKeyring(mirqlDir);
  const valid = [];

  for (const item of rawEvents) {
    const evt = item && item.event ? item.event : item;
    if (!evt || typeof evt !== "object") continue;

    const writerNs = typeof evt.writer === "object" ? evt.writer.ns : evt.writer;
    const keyId = typeof evt.writer === "object" ? evt.writer.key_id : null;

    if (!canWriteEvent(writerNs, evt.type)) {
      continue;
    }

    if (keyring && typeof keyring === "object" && Object.keys(keyring).length > 0) {
      const trustedPubkey = getTrustedPublicKey(keyring, writerNs, keyId);
      if (!trustedPubkey) {
        continue;
      }
      if (keyId && keyId !== `ed25519:${trustedPubkey}`) {
        continue;
      }
      if (!evt.sig || !evt.hash) {
        continue;
      }
      const verifyRes = verifyEvent(evt, trustedPubkey);
      if (!verifyRes.ok) {
        continue;
      }
    } else {
      if (PRIVILEGED_EVENTS.has(evt.type)) {
        continue;
      }
    }

    valid.push(item);
  }

  return valid;
}

/**
 * Pure mathematical fold over ledger events to compute system state (Law 4).
 *
 * @param {Array<object | { event: object, raw?: string }>} events
 * @param {object} [policy]
 * @param {object | null} [keyring]
 * @returns {object} folded state projection
 */
export function foldLedger(events, policy = {}, keyring = null) {
  const maxAttempts = policy.max_attempts_per_warrant ?? 3;

  const state = {
    epoch: 1,
    mode: "BUILD",
    macro_state: "BUILD",
    events_processed: 0,
    seq: 0,
    disk_seq: 0,
    disk_last_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    halted: false,
    budget_spent_micro_usd: 0,
    warrants: {},
    jobs: {},
    active_leases: {},
    verdicts: {},
    hardening_passed: false,
    probes_clean: true,
    head_sha: null,
    last_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    last_hlc: null,
    tenant_id: "mirql-core",
    metrics: {
      total_cost_micro_usd: 0,
      total_tokens_consumed: 0,
      warrants_total: 0,
      warrants_completed: 0,
      jobs_total: 0,
      jobs_completed: 0,
    },
  };

  let disk_seq = 0;
  let disk_last_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

  for (const item of events) {
    const evt = item && item.event ? item.event : item;
    const raw = item && item.raw ? item.raw : null;
    if (!evt || typeof evt !== "object") continue;

    if (typeof evt.seq === "number") {
      disk_seq = evt.seq;
    } else {
      disk_seq += 1;
    }

    if (typeof evt.hash === "string") {
      disk_last_hash = evt.hash;
    } else if (raw) {
      disk_last_hash = sha256(raw);
    } else {
      disk_last_hash = sha256(JSON.stringify(evt));
    }

    state.disk_seq = disk_seq;
    state.disk_last_hash = disk_last_hash;

    const writerNs = typeof evt.writer === "object" ? evt.writer.ns : evt.writer;
    const keyId = typeof evt.writer === "object" ? evt.writer.key_id : null;

    const isAclAuthorized = canWriteEvent(writerNs, evt.type);
    if (!isAclAuthorized) {
      continue;
    }

    if (keyring && typeof keyring === "object" && Object.keys(keyring).length > 0) {
      const trustedPubkey = getTrustedPublicKey(keyring, writerNs, keyId);
      if (!trustedPubkey) {
        continue;
      }

      if (keyId && keyId !== `ed25519:${trustedPubkey}`) {
        continue;
      }

      if (!evt.sig || !evt.hash) {
        continue;
      }

      const verifyRes = verifyEvent(evt, trustedPubkey);
      if (!verifyRes.ok) {
        continue;
      }
    } else {
      if (PRIVILEGED_EVENTS.has(evt.type)) {
        continue;
      }
    }

    state.events_processed += 1;
    state.seq = disk_seq;
    state.last_hash = disk_last_hash;

    if (typeof evt.epoch === "number" && evt.epoch > state.epoch) {
      state.epoch = evt.epoch;
    }

    if (evt.tenant_id) state.tenant_id = evt.tenant_id;
    if (evt.hlc) state.last_hlc = evt.hlc;

    if (evt.hash) {
      state.last_hash = evt.hash;
    } else if (raw) {
      state.last_hash = sha256(raw);
    } else {
      state.last_hash = sha256(JSON.stringify(evt));
    }

    switch (evt.type) {
      case "mirql.genesis": {
        state.epoch = evt.epoch ?? 1;
        state.mode = evt.payload?.macro_state ?? "BUILD";
        state.macro_state = state.mode;
        if (evt.payload?.head_sha) state.head_sha = evt.payload.head_sha;
        if (evt.payload?.tenant_id) state.tenant_id = evt.payload.tenant_id;
        break;
      }

      case "human.intent": {
        const p = evt.payload || {};
        const wId = p.warrant_id;
        if (wId && state.warrants[wId]) {
          state.warrants[wId].status = "active";
          state.warrants[wId].failed_attempts = 0;
        }
        if (state.mode === "QUIESCENT") {
          state.mode = "BUILD";
          state.macro_state = "BUILD";
        }
        break;
      }

      case "human.approval": {
        const p = evt.payload || {};
        const wId = p.warrant_id;
        if (wId && state.warrants[wId]) {
          state.warrants[wId].status = p.status || "active";
          state.warrants[wId].failed_attempts = 0;
        }
        break;
      }

      case "warrant.created": {
        const p = evt.payload || {};
        const wId = p.warrant_id || p.id;
        if (wId) {
          state.warrants[wId] = {
            id: wId,
            intent_id: p.intent_id || null,
            role: p.role || "builder",
            tier: p.tier || "flash",
            status: p.status || "active",
            budget_micro_usd: p.budget_micro_usd || 0,
            semantic_fingerprint: p.semantic_fingerprint,
            scope: p.scope,
            anchors: p.anchors,
            evidence: p.evidence,
            red_check: p.red_check,
            created_by: p.created_by,
            failed_attempts: 0,
            attempt: 1,
          };
          state.metrics.warrants_total += 1;
        }
        if (state.mode === "QUIESCENT") {
          state.mode = "BUILD";
          state.macro_state = "BUILD";
        }
        break;
      }

      case "job.enqueued":
      case "job.queued": {
        const p = evt.payload || {};
        const jId = p.job_id || p.id;
        if (jId) {
          state.jobs[jId] = {
            id: jId,
            warrant_id: p.warrant_id,
            role: p.role || "builder",
            tier: p.tier || "flash",
            attempt: p.attempt ?? 1,
            status: "queued",
          };
          state.metrics.jobs_total += 1;
        }
        if (p.warrant && p.warrant_id && !state.warrants[p.warrant_id]) {
          state.warrants[p.warrant_id] = {
            id: p.warrant_id,
            status: "active",
            failed_attempts: 0,
            attempt: p.attempt ?? 1,
            ...p.warrant,
          };
          state.metrics.warrants_total += 1;
        }
        if (state.mode === "QUIESCENT") {
          state.mode = "BUILD";
          state.macro_state = "BUILD";
        }
        break;
      }

      case "job.leased": {
        const p = evt.payload || {};
        const jId = p.job_id || p.id;
        const leasedEpoch = evt.epoch ?? p.epoch ?? (state.epoch + 1);
        if (leasedEpoch > state.epoch) state.epoch = leasedEpoch;

        const ttl = p.ttl_ms ?? p.lease_duration_ms ?? 900000;
        const leasedAt = p.leased_at_ms ?? p.timestamp_ms ?? 0;
        const expiresAt = p.expires_at_ms ?? (leasedAt + ttl);

        const job = state.jobs[jId] || { id: jId, warrant_id: p.warrant_id };
        job.status = "leased";
        job.epoch = leasedEpoch;
        job.role = p.role || job.role;
        job.tier = p.tier || job.tier;
        job.attempt = p.attempt ?? job.attempt ?? 1;
        job.leased_at_ms = leasedAt;
        job.ttl_ms = ttl;
        job.expires_at_ms = expiresAt;
        job.worker_id = p.worker_id;
        state.jobs[jId] = job;

        state.active_leases[jId] = {
          job_id: jId,
          warrant_id: p.warrant_id,
          role: job.role,
          tier: job.tier,
          attempt: job.attempt,
          epoch: leasedEpoch,
          leased_at_ms: leasedAt,
          ttl_ms: ttl,
          expires_at_ms: expiresAt,
          worker_id: p.worker_id,
        };

        if (p.warrant_id && state.warrants[p.warrant_id]) {
          if (state.warrants[p.warrant_id].status !== "completed") {
            state.warrants[p.warrant_id].status = "in_progress";
          }
        }
        break;
      }

      case "job.timeout":
      case "job.lease_expired": {
        const p = evt.payload || {};
        const jId = p.job_id;
        const warrant = state.warrants[p.warrant_id];

        const hasLiveLease = Boolean(state.active_leases[jId]);
        const isWarrantCompleted = warrant && warrant.status === "completed";

        if (!hasLiveLease || isWarrantCompleted) {
          delete state.active_leases[jId];
          break;
        }

        if (jId && state.jobs[jId]) {
          state.jobs[jId].status = "timed_out";
        }
        delete state.active_leases[jId];

        if (warrant) {
          warrant.failed_attempts = (warrant.failed_attempts || 0) + 1;
          warrant.attempt = warrant.failed_attempts + 1;
          if (warrant.failed_attempts >= maxAttempts) {
            warrant.status = "needs_human";
          } else {
            warrant.status = "active";
          }
        }
        break;
      }

      case "attempt.outcome": {
        const p = evt.payload || {};
        const jId = p.job_id;
        const warrant = state.warrants[p.warrant_id];

        const cost = p.cost_micro_usd || 0;
        const tokens = p.tokens_consumed || 0;
        state.budget_spent_micro_usd += cost;
        state.metrics.total_cost_micro_usd += cost;
        state.metrics.total_tokens_consumed += tokens;
        if (p.head_commit) state.head_sha = p.head_commit;

        const nowMs = p.nowMs ?? p.timestamp_ms ?? evt.timestamp_ms ?? evt.hlc?.wall_ms ?? (evt.ts ? Date.parse(evt.ts) : Date.now());
        const lease = state.active_leases[jId];
        const hasLiveLease = Boolean(lease && (lease.expires_at_ms === undefined || nowMs <= lease.expires_at_ms));
        const outcomeEpoch = typeof p.epoch === "number" ? p.epoch : (typeof evt.epoch === "number" ? evt.epoch : undefined);
        if (!hasLiveLease || (typeof outcomeEpoch === "number" && outcomeEpoch !== lease.epoch)) {
          break;
        }

        delete state.active_leases[jId];

        if (warrant && warrant.status === "completed") {
          break;
        }

        const job = state.jobs[jId];
        if (job) {
          job.status = p.status;
          job.outcome_verdict = p.verdict;
          state.metrics.jobs_completed += 1;
        }

        const isSuccess =
          p.status === "completed" &&
          (p.verdict === "auto_merge" || p.verdict === "pass" || !p.verdict);

        if (warrant) {
          if (isSuccess) {
            warrant.status = "completed";
            state.metrics.warrants_completed += 1;
          } else {
            warrant.failed_attempts = (warrant.failed_attempts || 0) + 1;
            warrant.attempt = warrant.failed_attempts + 1;
            if (warrant.failed_attempts >= maxAttempts) {
              warrant.status = "needs_human";
            } else {
              warrant.status = "active";
            }
          }
        }
        break;
      }

      case "verdict.accepted":
      case "verdict.issued": {
        const p = evt.payload || {};
        const writerNs = typeof evt.writer === "object" ? evt.writer.ns : evt.writer;
        state.verdicts[p.job_id] = {
          job_id: p.job_id,
          epoch: evt.epoch,
          base_sha: p.base_sha,
          status: evt.type === "verdict.accepted" ? "accepted" : p.status || "accepted",
          writer: writerNs,
        };
        break;
      }

      case "factory.halted":
      case "mirql.halt": {
        state.halted = true;
        state.mode = "HALTED";
        state.macro_state = "HALTED";
        break;
      }

      case "factory.resumed":
      case "mirql.resume": {
        state.halted = false;
        state.mode = "BUILD";
        state.macro_state = "BUILD";
        break;
      }

      case "factory.mode_changed": {
        const next = evt.payload?.to_mode;
        if (next) {
          state.mode = next;
          state.macro_state = next;
        }
        break;
      }

      case "warrant.needs_human": {
        const wId = evt.payload?.warrant_id;
        if (wId && state.warrants[wId]) {
          state.warrants[wId].status = "needs_human";
        }
        break;
      }

      case "probe.completed": {
        const p = evt.payload || {};
        if ((p.probe === "doctor" || p.type === "doctor") && p.breaker) {
          if (p.breaker.action === "trip" && p.breaker.target_subsystem === "budget") {
            state.budget_breaker_tripped = true;
          } else if (p.breaker.action === "reset" && (p.breaker.target_subsystem === "budget" || p.breaker.target_subsystem === "all")) {
            state.budget_breaker_tripped = false;
          }
        }
        break;
      }

      case "job.canary_staged": {
        const p = evt.payload || {};
        if (!state.canaries) state.canaries = {};
        state.canaries[p.canary_id] = {
          canary_id: p.canary_id,
          job_id: p.job_id,
          warrant_id: p.warrant_id,
          candidate_version: p.candidate_version,
          supervisor_version: p.supervisor_version,
          probation_window_ms: p.probation_window_ms,
          error_threshold_bp: p.error_threshold_bp,
          latency_p99_ceiling_ms: p.latency_p99_ceiling_ms,
          staged_at_ms: p.staged_at_ms,
          provenance_hash: p.provenance_hash,
          subject_digest: p.subject_digest,
          epoch: evt.epoch || p.epoch || 1,
          status: "probation",
          samples: [],
        };
        if (p.job_id && state.jobs[p.job_id]) {
          state.jobs[p.job_id].status = "canary_probation";
        }
        break;
      }

      case "job.canary_health": {
        const p = evt.payload || {};
        if (state.canaries && state.canaries[p.canary_id]) {
          const canary = state.canaries[p.canary_id];
          if (canary.status === "probation") {
            canary.samples.push(p);
            if (p.anomaly_detected) {
              canary.anomaly = true;
            }
          }
        }
        break;
      }

      case "job.canary_rollback":
      case "mirql.rollback":
      case "promotion.rollback": {
        const p = evt.payload || {};
        if (p.canary_id && state.canaries && state.canaries[p.canary_id]) {
          const canary = state.canaries[p.canary_id];
          if (canary.status !== "promoted") {
            canary.status = "rolled_back";
            canary.rollback_reason = p.reason;
            if (canary.job_id && state.jobs[canary.job_id]) {
              state.jobs[canary.job_id].status = "canary_rolled_back";
            }
          }
        }
        break;
      }

      case "job.promoted": {
        const p = evt.payload || {};
        const jId = p.job_id;
        if (jId) {
          delete state.active_leases[jId];
          if (state.jobs[jId]) {
            state.jobs[jId].status = "promoted";
          }
        }
        if (p.canary_id && state.canaries && state.canaries[p.canary_id]) {
          state.canaries[p.canary_id].status = "promoted";
        }
        if (p.promoted_version) {
          state.active_version = p.promoted_version;
        }
        if (p.warrant_id && state.warrants[p.warrant_id]) {
          state.warrants[p.warrant_id].status = "completed";
        }
        break;
      }

      default:
        break;
    }
  }

  return state;
}

/**
 * Reads ledger and folds into state, verifying against keyring if present.
 *
 * @param {string} mirqlDir
 * @param {object} [policy]
 * @returns {object}
 */
export function foldQueueState(mirqlDir, policy) {
  const rawEvents = readLedgerEvents(mirqlDir);
  const keyring = loadKeyring(mirqlDir);
  return foldLedger(rawEvents, policy, keyring);
}
