// packages/queue/ledger.mjs — Ledger I/O, Key Management, Event Folding, and Concurrency Lockfile.
import {
  readFileSync,
  writeFileSync,
  appendFileSync,
  existsSync,
  mkdirSync,
  openSync,
  closeSync,
  unlinkSync,
  statSync,
} from "node:fs";
import { join, dirname } from "node:path";
import {
  jcs,
  sha256,
  ulid,
  hlcTick,
  generateEd25519Keypair,
  signEvent,
  verifyEvent,
  validateDocument,
  canWriteEvent,
} from "../core/index.mjs";

/**
 * Privileged events whose emission requires cryptographic verification against keyring.json.
 */
const PRIVILEGED_EVENTS = new Set([
  "job.promoted",
  "human.approval",
  "human.intent",
  "verdict.accepted",
  "verdict.issued",
  "factory.resumed",
  "mirql.resume",
]);

/**
 * Acquire exclusive lockfile with retry/backoff.
 * @param {string} lockPath
 * @param {number} [timeoutMs]
 * @returns {number} file descriptor
 */
function acquireLock(lockPath, timeoutMs = 10000) {
  const start = Date.now();
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));
  while (true) {
    try {
      const fd = openSync(lockPath, "wx");
      return fd;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;

      if (Date.now() - start > timeoutMs) {
        // Break stale lock older than 15s
        try {
          const st = statSync(lockPath);
          if (Date.now() - st.mtimeMs > 15000) {
            try {
              unlinkSync(lockPath);
            } catch {}
            continue;
          }
        } catch {}
        throw new Error(`Timeout acquiring ledger lockfile at ${lockPath}`);
      }

      Atomics.wait(sleepBuf, 0, 0, 15);
    }
  }
}

/**
 * Release exclusive lockfile.
 * @param {number} fd
 * @param {string} lockPath
 */
function releaseLock(fd, lockPath) {
  try {
    if (fd !== null) closeSync(fd);
  } catch {}
  try {
    unlinkSync(lockPath);
  } catch {}
}

/**
 * Execute a function within the exclusive ledger lockfile.
 * @param {string} mirqlDir
 * @param {() => T} fn
 * @returns {T}
 */
export function withLedgerLock(mirqlDir, fn) {
  const lockPath = join(mirqlDir, "ledger.lock");
  mkdirSync(mirqlDir, { recursive: true });
  const fd = acquireLock(lockPath);
  try {
    return fn();
  } finally {
    releaseLock(fd, lockPath);
  }
}

/**
 * Load keyring from <mirqlDir>/ledger/keyring.json.
 * @param {string} mirqlDir
 * @returns {object | null}
 */
export function loadKeyring(mirqlDir) {
  const candidates = [
    join(mirqlDir, "ledger", "keyring.json"),
    join(mirqlDir, "keyring.json"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        return JSON.parse(readFileSync(p, "utf8"));
      } catch {}
    }
  }
  return null;
}

/**
 * Write or update keyring at <mirqlDir>/ledger/keyring.json.
 * @param {string} mirqlDir
 * @param {object} keyring
 * @param {object} [options]
 */
export function saveKeyring(mirqlDir, keyring, options = {}) {
  const p = join(mirqlDir, "ledger", "keyring.json");
  mkdirSync(dirname(p), { recursive: true });
  let existing = {};
  if (!options.overwrite && existsSync(p)) {
    try {
      existing = JSON.parse(readFileSync(p, "utf8"));
    } catch {}
  }
  const merged = options.overwrite ? keyring : { ...existing, ...keyring };
  writeFileSync(p, JSON.stringify(merged, null, 2) + "\n", "utf8");
}

/**
 * Helper to extract trusted public key for a writer from keyring (Fix N2).
 * The key MUST be explicitly bound to writerNs.
 * @param {object} keyring
 * @param {string} writerNs
 * @param {string} [keyId]
 * @returns {string | null}
 */
function getTrustedPublicKey(keyring, writerNs, keyId) {
  if (!keyring || typeof keyring !== "object" || !writerNs) return null;

  // 1. Direct writer namespace lookup: keyring[writerNs]
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

  // 2. keyring.writers[writerNs]
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

  // 3. Lookup by keyId, but ONLY if explicitly bound to writerNs:
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
 * Load or generate the Ed25519 keypair used by the queue writer, ensuring it is registered in keyring.json.
 *
 * @param {string} mirqlDir
 * @param {string} [customKeyFile]
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } }}
 */
export function getOrCreateQueueKeypair(mirqlDir, customKeyFile) {
  const keyPath = customKeyFile || join(mirqlDir, "keys", "queue.key.json");
  let kp;

  if (existsSync(keyPath)) {
    try {
      const parsed = JSON.parse(readFileSync(keyPath, "utf8"));
      if (parsed.privateKey && parsed.keyId) {
        kp = parsed;
      }
    } catch {}
  }

  if (!kp) {
    const generated = generateEd25519Keypair();
    kp = {
      ...generated,
      writer: {
        ns: "tool:queue",
        key_id: generated.keyId,
      },
    };

    mkdirSync(dirname(keyPath), { recursive: true });
    writeFileSync(keyPath, JSON.stringify(kp, null, 2) + "\n", "utf8");
  }

  // Ensure tool:queue is registered in <mirqlDir>/ledger/keyring.json
  const keyringPath = join(mirqlDir, "ledger", "keyring.json");
  let keyring = {};
  if (existsSync(keyringPath)) {
    try {
      keyring = JSON.parse(readFileSync(keyringPath, "utf8"));
    } catch {}
  }
  if (!keyring["tool:queue"]) {
    keyring["tool:queue"] = kp.publicKey;
    mkdirSync(dirname(keyringPath), { recursive: true });
    writeFileSync(keyringPath, JSON.stringify(keyring, null, 2) + "\n", "utf8");
  }

  return kp;
}

/**
 * Read all events from the ledger.
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
 * Pure mathematical fold over ledger events to compute queue state.
 *
 * @param {Array<object | { event: object, raw?: string }>} events
 * @param {object} [policy]
 * @param {object | null} [keyring]
 * @returns {object} folded queue state
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

    // Fix N3: Maintain Physical Hash-Chain Position on EVERY line parsed from file
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

    // Fix N1: Universal Law 3 ACL Verification for EVERY event
    const isAclAuthorized =
      canWriteEvent(writerNs, evt.type) ||
      (writerNs === "human:owner" &&
        (evt.type.startsWith("warrant.") ||
          evt.type.startsWith("mirql.") ||
          evt.type === "factory.resumed" ||
          evt.type === "mirql.resume")) ||
      (writerNs === "daemon:lifeguard" &&
        (evt.type === "factory.resumed" ||
          evt.type === "mirql.resume" ||
          evt.type === "mirql.rollback"));

    if (!isAclAuthorized) {
      // Writer namespace not authorized under Law 3 ACL -> ignore
      continue;
    }

    // Fix N1: Universal Keyring & Signature Verification if keyring exists
    if (keyring && typeof keyring === "object" && Object.keys(keyring).length > 0) {
      const trustedPubkey = getTrustedPublicKey(keyring, writerNs, keyId);
      if (!trustedPubkey) {
        // No trusted public key registered for this writer namespace -> fail closed!
        continue;
      }

      if (keyId && keyId !== `ed25519:${trustedPubkey}`) {
        // KeyId mismatch with trusted key -> fail closed!
        continue;
      }

      if (!evt.sig || !evt.hash) {
        // Missing cryptographic signature -> fail closed!
        continue;
      }

      const verifyRes = verifyEvent(evt, trustedPubkey);
      if (!verifyRes.ok) {
        // Cryptographic verification failed -> fail closed!
        continue;
      }
    } else {
      // If no keyring exists at all, privileged events must still fail closed (Fix R2)
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
        // Human intent wakes QUIESCENT mode back to BUILD
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

        // Fix R3: If warrant is already completed or job has no live lease, ignore timeout
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

        // Cost and tokens are always recorded
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
          // Stale or unleased outcome: keep cost recorded, but DO NOT modify job or warrant status!
          break;
        }

        delete state.active_leases[jId];

        // Fix R3: If the associated warrant is already completed, ignore outcome so it never resets to active!
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
        const writerNs =
          typeof evt.writer === "object" ? evt.writer.ns : evt.writer;
        state.verdicts[p.job_id] = {
          job_id: p.job_id,
          epoch: evt.epoch,
          base_sha: p.base_sha,
          status:
            evt.type === "verdict.accepted"
              ? "accepted"
              : p.status || "accepted",
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

      case "job.promoted": {
        const p = evt.payload || {};
        const jId = p.job_id;
        // Fix R3: Close active lease upon promotion
        if (jId) {
          delete state.active_leases[jId];
          if (state.jobs[jId]) {
            state.jobs[jId].status = "promoted";
          }
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
 * Read ledger and fold into state, verifying against keyring if present.
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

/**
 * Append a signed event to the ledger directly without acquiring lock (internal/under-lock use).
 *
 * @param {string} mirqlDir
 * @param {object} eventData
 * @param {object} keypair
 * @param {object} currentState
 * @returns {object} signed event
 */
export function appendLedgerEventRaw(mirqlDir, eventData, keypair, currentState) {
  const nowMs = eventData.nowMs ?? Date.now();
  const nextSeq =
    (currentState?.disk_seq !== undefined
      ? currentState.disk_seq
      : (currentState?.seq || 0)) + 1;
  const epoch = eventData.epoch ?? currentState?.epoch ?? 1;

  const eventWithoutHashSig = {
    v: 1,
    id: ulid(nowMs),
    tenant_id: eventData.tenant_id || currentState?.tenant_id || "mirql-core",
    seq: nextSeq,
    epoch,
    hlc: hlcTick(currentState?.last_hlc || null, nowMs, "queue"),
    ts: new Date(nowMs).toISOString(),
    type: eventData.type,
    writer: {
      ns: keypair.writer?.ns || "tool:queue",
      key_id: keypair.keyId,
    },
    idempotency_key: eventData.idempotency_key || `queue-${ulid(nowMs)}`,
    prev_hash:
      currentState?.disk_last_hash ||
      currentState?.last_hash ||
      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    payload: eventData.payload,
  };

  const signed = signEvent(
    eventWithoutHashSig,
    keypair.privateKey,
    keypair.keyId,
  );

  const validation = validateDocument("event", signed);
  if (!validation.valid) {
    throw new Error(
      `appendLedgerEvent: invalid event document: ${validation.errors.join("; ")}`,
    );
  }

  const ledgerPath = join(mirqlDir, "ledger", "events.jsonl");
  mkdirSync(dirname(ledgerPath), { recursive: true });
  appendFileSync(ledgerPath, jcs(signed) + "\n", "utf8");

  if (currentState) {
    currentState.seq = nextSeq;
    currentState.disk_seq = nextSeq;
    currentState.epoch = epoch;
    currentState.last_hash = signed.hash;
    currentState.disk_last_hash = signed.hash;
    currentState.last_hlc = signed.hlc;
    currentState.events_processed = (currentState.events_processed || 0) + 1;
  }

  return signed;
}

/**
 * Append a signed event to the ledger within the exclusive lockfile, updating state sequentially.
 *
 * @param {string} mirqlDir
 * @param {object} eventData
 * @param {object} keypair
 * @param {object} [currentState]
 * @returns {object} signed event
 */
export function appendLedgerEvent(mirqlDir, eventData, keypair, currentState) {
  return withLedgerLock(mirqlDir, () => {
    const diskState = foldQueueState(mirqlDir);
    return appendLedgerEventRaw(mirqlDir, eventData, keypair, diskState);
  });
}
