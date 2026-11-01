/**
 * mirql-log — the factory's cryptographic append-only ledger (Law 4).
 *
 * `.mirql/` layout (every JSON document canonicalized with RFC 8785 `jcs`,
 * Law 17 integer-only):
 *
 *   <mirqlDir>/ledger/events.jsonl   append-only newline-delimited events
 *   <mirqlDir>/ledger/keyring.json   optional { [key_id]: publicKeyBase64Url }
 *   <mirqlDir>/ledger/snapshots/     snapshot-<seq>.json fold snapshots
 *   <mirqlDir>/cache/state.json      disposable materialized fold cache
 *
 * The ledger is the single source of truth (Law 4: Event-Sourced Truth):
 * every projection is a pure deterministic fold over events.jsonl, and
 * deleting the cache is always safe — replay --rebuild-cache reproduces the
 * exact same bytes. Events are hash-chained (prev_hash -> last event hash,
 * anchored at 64 hex zeros) and Ed25519-signed envelopes; the single-writer
 * ACL of Law 3 gates every (writer.ns, type) pair.
 *
 * Programmatic API: appendEvent, verifyLedger, foldEvents, getView,
 * replayCache, createSnapshot, runCli — plus `main`, the CLI entrypoint the
 * bin/ wrappers import (it keeps the W1 stub contract for bare `--help` /
 * no-args / `status` calls and delegates everything else to runCli).
 */
import { createPrivateKey, createPublicKey, KeyObject } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import {
  EXIT_CODES,
  canWriteEvent,
  computeEventHash,
  hlcTick,
  jcs,
  jcsHash,
  sha256,
  signEvent,
  ulid,
  validateDocument,
  verifyEvent,
} from "../core/index.mjs";

/** Tool name reported by this package. */
export const TOOL = "log";

/** prev_hash anchor of the very first event in any ledger. */
export const GENESIS_PREV_HASH = `sha256:${"0".repeat(64)}`;

/** The named projections served by getView / `mirql l view`. */
export const PROJECTIONS = Object.freeze([
  "job_state",
  "orchestrator_digest",
  "human_digest",
  "phi",
  "budget",
]);

const PROJECTION_ALIASES = Object.freeze({
  state: "job_state",
  job_state: "job_state",
  orchestrator_digest: "orchestrator_digest",
  human_digest: "human_digest",
  phi: "phi",
  budget: "budget",
});

const SUBCOMMANDS = Object.freeze([
  "append",
  "verify",
  "view",
  "replay",
  "snapshot",
]);

/** Cap for the bounded recent_* lists inside the human digest. */
const RECENT_LIMIT = 10;

/** Maximum byte size of the orchestrator digest (bounded JSON summary). */
export const ORCHESTRATOR_DIGEST_MAX_BYTES = 2048;

/**
 * Domain error carrying a canonical EXIT_CODES name, thrown by the library
 * API and mapped to JSON-on-stderr + exit codes by runCli.
 */
export class LedgerError extends Error {
  /**
   * @param {"USAGE_ERROR" | "INTEGRITY_VIOLATION" | "POLICY_DENIAL"} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = "LedgerError";
    this.code = code;
    this.exitCode = EXIT_CODES[code] ?? EXIT_CODES.DOMAIN_NEGATIVE;
  }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** @param {string} mirqlDir @returns {string} */
function eventsFile(mirqlDir) {
  return join(mirqlDir, "ledger", "events.jsonl");
}

/** @param {string} mirqlDir @returns {string} */
function keyringFile(mirqlDir) {
  return join(mirqlDir, "ledger", "keyring.json");
}

/** @param {string} mirqlDir @returns {string} */
function cacheFile(mirqlDir) {
  return join(mirqlDir, "cache", "state.json");
}

/** @param {string} mirqlDir @returns {string} */
function snapshotsDir(mirqlDir) {
  return join(mirqlDir, "ledger", "snapshots");
}

/**
 * Resolve the active `.mirql` directory: explicit argument wins, then the
 * MIRQL_DIR environment variable, then `<cwd>/.mirql`.
 *
 * @param {string | undefined | null} mirqlDir
 * @returns {string} absolute path
 */
function resolveMirqlDir(mirqlDir) {
  const raw =
    typeof mirqlDir === "string" && mirqlDir.length > 0
      ? mirqlDir
      : (process.env.MIRQL_DIR ?? join(process.cwd(), ".mirql"));
  return resolvePath(raw);
}

// ---------------------------------------------------------------------------
// Ledger reading
// ---------------------------------------------------------------------------

/**
 * Read the ledger, returning parsed events paired with their raw canonical
 * lines (raw lines matter for conformance fixtures whose linkage is the
 * SHA-256 of the previous raw line rather than an envelope hash field).
 *
 * @param {string} mirqlDir
 * @returns {{ events: object[], rawLines: string[] }}
 * @throws {SyntaxError} when a line is not valid JSON
 */
function readLedger(mirqlDir) {
  const file = eventsFile(mirqlDir);
  if (!existsSync(file)) return { events: [], rawLines: [] };
  const rawLines = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length > 0) rawLines.push(trimmed);
  }
  const events = rawLines.map((raw) => JSON.parse(raw));
  return { events, rawLines };
}

/** readLedger with corrupt lines mapped to an integrity violation. */
function readLedgerSafe(mirqlDir) {
  try {
    return readLedger(mirqlDir);
  } catch (err) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      `ledger/events.jsonl is corrupt: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * The hash a ledger position contributes to the chain: the envelope `hash`
 * when present, otherwise the SHA-256 of the raw line (conformance fixtures
 * only when allowRawLine is true).
 *
 * @param {object} event
 * @param {string | undefined} rawLine
 * @param {boolean} [allowRawLine=false]
 * @returns {string}
 */
function eventHashOf(event, rawLine, allowRawLine = false) {
  if (typeof event?.hash === "string") return event.hash;
  if (allowRawLine && typeof rawLine === "string") return sha256(rawLine);
  return jcsHash(event);
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/**
 * Load `ledger/keyring.json`: a map of key_id (and/or writer namespace) to
 * either a base64url public key string (legacy) or a namespace-bound entry
 * `{ ns, publicKey }` (canonical since W5b). A missing or unparsable keyring
 * is treated as empty — the ledger itself still verifies via embedded writer
 * key ids.
 *
 * @param {string} mirqlDir
 * @returns {Record<string, unknown>}
 */
function loadKeyring(mirqlDir) {
  const file = keyringFile(mirqlDir);
  if (!existsSync(file)) return {};
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : {};
  } catch {
    return {};
  }
}

/**
 * Find the Ed25519 public key that should verify `event`'s signature:
 * options.publicKey, then keyring[event.writer.key_id], then the raw key
 * embedded in an `ed25519:<43-char-base64url>` writer key id.
 *
 * Keyring entries may be plain public-key strings (legacy) or namespace-
 * bound objects `{ ns, publicKey }` (canonical since W5b). When the entry is
 * bound to a namespace that differs from `event.writer.ns`, resolution fails
 * closed (returns null): a key registered for `tool:queue` can never verify
 * an event claiming to be written by `human:owner` (Law 3 binding).
 *
 * @param {object} event
 * @param {string} mirqlDir
 * @param {{ publicKey?: string, keyring?: Record<string, unknown> }} [options]
 * @returns {string | null} base64url raw public key, or null when unresolvable
 */
function resolvePublicKey(event, mirqlDir, options = {}) {
  const keyId = event?.writer?.key_id;
  if (typeof keyId !== "string" || keyId.length === 0) return null;
  const kFile = keyringFile(mirqlDir);
  const hasKeyring = options.keyring !== undefined || existsSync(kFile);
  if (hasKeyring) {
    const keyring = options.keyring ?? loadKeyring(mirqlDir);
    const raw = keyring[keyId];
    if (raw === undefined || raw === null) {
      return null; // key not registered in keyring: fail closed (B3)
    }
    let trustedKey = raw;
    if (typeof trustedKey === "object" && !Array.isArray(trustedKey)) {
      // Namespace-bound keyring entry: { ns, publicKey }.
      if (
        typeof trustedKey.ns === "string" &&
        trustedKey.ns.length > 0 &&
        typeof event?.writer?.ns === "string" &&
        trustedKey.ns !== event.writer.ns
      ) {
        return null; // Namespace binding violation!
      }
      trustedKey = trustedKey.publicKey ?? trustedKey.pubkey;
    }
    if (typeof trustedKey !== "string" || trustedKey.length === 0) {
      return null;
    }
    if (typeof options.publicKey === "string" && options.publicKey.length > 0) {
      if (options.publicKey !== trustedKey) {
        return null;
      }
    }
    return trustedKey;
  }
  if (typeof options.publicKey === "string" && options.publicKey.length > 0) {
    return options.publicKey;
  }
  if (keyId.startsWith("ed25519:")) {
    const embedded = keyId.slice("ed25519:".length);
    if (/^[A-Za-z0-9_-]{43}$/.test(embedded)) return embedded;
  }
  return null;
}

/** Derive `ed25519:<pubkey-b64url>` from a base64url PKCS#8 private key. */
function deriveKeyIdFromPrivate(privateKey) {
  try {
    const key =
      privateKey instanceof KeyObject
        ? privateKey
        : createPrivateKey({
            key: Buffer.from(String(privateKey), "base64url"),
            format: "der",
            type: "pkcs8",
          });
    const spki = createPublicKey(key).export({ format: "der", type: "spki" });
    return `ed25519:${spki.subarray(-32).toString("base64url")}`;
  } catch (err) {
    throw new LedgerError(
      "USAGE_ERROR",
      `invalid signing private key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Deterministic fold (Law 4)
// ---------------------------------------------------------------------------

/**
 * Pure deterministic fold over parsed ledger events. Unknown event types are
 * ignored (forward compatibility); every derived value depends only on the
 * events themselves, so the same ledger always folds to the same state.
 *
 * @param {object[]} events
 * @param {string[]} [rawLines] raw lines parallel to events (hash fallback)
 * @returns {object} rich internal fold state
 */
function richFold(events, rawLines = []) {
  const state = {
    mode: null,
    epoch: 0,
    seq: 0,
    last_event_hash: null,
    budget_spent_micro_usd: 0,
    warrants: Object.create(null),
    jobs: Object.create(null),
    by_warrant: Object.create(null),
    by_role: Object.create(null),
    phi_last: null,
    phi_history: [],
    halted: false,
    needs_human: false,
    pending_human_items: 0,
    recent_promotions: [],
    recent_rollbacks: [],
  };

  events.forEach((event, i) => {
    if (event === null || typeof event !== "object" || Array.isArray(event)) {
      return;
    }
    const raw = rawLines[i];
    if (typeof event.seq === "number") state.seq = event.seq;
    if (typeof event.epoch === "number") state.epoch = event.epoch;
    state.last_event_hash = eventHashOf(event, raw, true);

    const type = typeof event.type === "string" ? event.type : "";
    const payload =
      event.payload !== null &&
      typeof event.payload === "object" &&
      !Array.isArray(event.payload)
        ? event.payload
        : {};

    // B6: Validate costs & safe-integer constraints
    if (payload.cost_micro_usd !== undefined) {
      if (
        !Number.isSafeInteger(payload.cost_micro_usd) ||
        payload.cost_micro_usd < 0
      ) {
        throw new LedgerError(
          "INTEGRITY_VIOLATION",
          "cost_micro_usd must be a non-negative safe integer",
        );
      }
    }
    if (payload.phi_after !== undefined) {
      if (
        !Number.isSafeInteger(payload.phi_after) ||
        payload.phi_after < 0
      ) {
        throw new LedgerError(
          "INTEGRITY_VIOLATION",
          "phi_after must be a non-negative safe integer",
        );
      }
    }

    const jobId =
      typeof payload.job_id === "string" ? payload.job_id : null;
    const warrantId =
      typeof payload.warrant_id === "string" ? payload.warrant_id : null;

    if (type === "mirql.genesis") {
      if (typeof payload.macro_state === "string") state.mode = payload.macro_state;
    } else if (type === "factory.halted" || type === "mirql.halted" || type === "mirql.halt") {
      state.halted = true;
    } else if (
      type === "factory.resumed" ||
      type === "mirql.resumed" ||
      type === "mirql.resume"
    ) {
      state.halted = false;
    } else if (type === "warrant.created") {
      if (warrantId !== null) {
        state.warrants[warrantId] = {
          id: warrantId,
          intent_id:
            typeof payload.intent_id === "string" ? payload.intent_id : null,
          role: typeof payload.role === "string" ? payload.role : null,
          tier: typeof payload.tier === "string" ? payload.tier : null,
          status:
            typeof payload.status === "string" ? payload.status : "active",
          budget_micro_usd:
            typeof payload.budget_micro_usd === "number"
              ? payload.budget_micro_usd
              : 0,
        };
      }
    } else if (type === "job.leased") {
      if (jobId !== null) {
        state.jobs[jobId] = {
          id: jobId,
          warrant_id: warrantId,
          worker_id:
            typeof payload.worker_id === "string" ? payload.worker_id : null,
          status:
            typeof payload.status === "string" ? payload.status : "leased",
          outcome_verdict: null,
        };
      }
    } else if (type === "attempt.outcome") {
      const cost =
        typeof payload.cost_micro_usd === "number"
          ? payload.cost_micro_usd
          : 0;
      if (state.budget_spent_micro_usd + cost > Number.MAX_SAFE_INTEGER) {
        throw new LedgerError(
          "INTEGRITY_VIOLATION",
          "budget_spent_micro_usd overflow: exceeds Number.MAX_SAFE_INTEGER",
        );
      }
      state.budget_spent_micro_usd += cost;
      if (warrantId !== null) {
        state.by_warrant[warrantId] =
          (state.by_warrant[warrantId] ?? 0) + cost;
      }
      const role =
        typeof payload.role === "string"
          ? payload.role
          : (warrantId !== null ? state.warrants[warrantId]?.role : null) ??
            "unknown";
      state.by_role[role] = (state.by_role[role] ?? 0) + cost;
      if (jobId !== null && state.jobs[jobId]) {
        if (typeof payload.status === "string") state.jobs[jobId].status = payload.status;
        if (typeof payload.verdict === "string") {
          state.jobs[jobId].outcome_verdict = payload.verdict;
        }
      }
      if (
        warrantId !== null &&
        state.warrants[warrantId] &&
        payload.status === "completed"
      ) {
        state.warrants[warrantId].status = "completed";
      }
      if (typeof payload.phi_after === "number") {
        state.phi_last = payload.phi_after;
        state.phi_history.push({ seq: state.seq, phi: payload.phi_after });
      }
    } else if (type === "human.approval_requested" || type === "verdict.needs_human") {
      state.needs_human = true;
      state.pending_human_items += 1;
      if (jobId !== null && state.jobs[jobId]) state.jobs[jobId].status = "needs_human";
    } else if (type === "verdict.accepted" || type === "verdict.rejected") {
      if (state.pending_human_items > 0) state.pending_human_items -= 1;
      if (state.pending_human_items === 0) state.needs_human = false;
      if (jobId !== null && state.jobs[jobId]) {
        state.jobs[jobId].outcome_verdict =
          typeof payload.verdict === "string"
            ? payload.verdict
            : type.slice("verdict.".length);
        if (state.jobs[jobId].status === "needs_human") {
          state.jobs[jobId].status = type === "verdict.accepted" ? "accepted" : "rejected";
        }
      }
    } else if (type === "human.decision") {
      if (state.pending_human_items > 0) state.pending_human_items -= 1;
      if (state.pending_human_items === 0) state.needs_human = false;
    } else if (type === "promotion.completed") {
      pushBounded(state.recent_promotions, {
        seq: state.seq,
        promotion_id:
          typeof payload.promotion_id === "string" ? payload.promotion_id : jobId,
      });
    } else if (
      type === "promotion.rollback" ||
      type === "factory.rollback" ||
      type === "mirql.rollback"
    ) {
      pushBounded(state.recent_rollbacks, {
        seq: state.seq,
        promotion_id:
          typeof payload.promotion_id === "string" ? payload.promotion_id : jobId,
      });
    }
  });

  return state;
}

/** @param {unknown[]} list @param {unknown} item @returns {void} */
function pushBounded(list, item) {
  list.push(item);
  if (list.length > RECENT_LIMIT) list.shift();
}

/**
 * The pinned full materialized state (the `job_state` projection shape).
 *
 * @param {object} rich - rich fold state
 * @returns {object}
 */
function jobStateFrom(rich) {
  return {
    version: 1,
    mode: rich.mode,
    epoch: rich.epoch,
    seq: rich.seq,
    last_event_hash: rich.last_event_hash,
    budget_spent_micro_usd: rich.budget_spent_micro_usd,
    warrants: rich.warrants,
    jobs: rich.jobs,
    phi_last: rich.phi_last,
    halted: rich.halted,
    needs_human: rich.needs_human,
  };
}

/** @param {object} warrants @param {string} status @returns {number} */
function countWarrants(warrants, status) {
  let n = 0;
  for (const w of Object.values(warrants)) if (w?.status === status) n += 1;
  return n;
}

/** @param {object} jobs @param {string[]} statuses @returns {number} */
function countJobs(jobs, statuses) {
  let n = 0;
  for (const j of Object.values(jobs)) if (statuses.includes(j?.status)) n += 1;
  return n;
}

/**
 * Project a rich fold state into one of the named views.
 *
 * @param {object} rich
 * @param {string} projection
 * @returns {object}
 * @throws {LedgerError} USAGE_ERROR for an unknown projection
 */
function projectView(rich, projection) {
  const key = PROJECTION_ALIASES[projection];
  if (key === undefined) {
    throw new LedgerError(
      "USAGE_ERROR",
      `unknown projection ${JSON.stringify(projection)}; expected one of ${PROJECTIONS.join(", ")} (or "state")`,
    );
  }
  switch (key) {
    case "job_state":
      return jobStateFrom(rich);
    case "orchestrator_digest": {
      let mode = rich.mode;
      if (typeof mode === "string" && mode.length > 256) {
        mode = mode.slice(0, 256);
      }
      const digest = {
        mode,
        epoch: rich.epoch,
        seq: rich.seq,
        active_warrants: countWarrants(rich.warrants, "active"),
        queued_jobs: countJobs(rich.jobs, ["queued", "enqueued"]),
        leased_jobs: countJobs(rich.jobs, ["leased"]),
        phi_last: rich.phi_last,
        budget_spent_micro_usd: rich.budget_spent_micro_usd,
        halted: rich.halted,
      };
      while (
        typeof digest.mode === "string" &&
        digest.mode.length > 0 &&
        Buffer.byteLength(jcs(digest), "utf8") > ORCHESTRATOR_DIGEST_MAX_BYTES
      ) {
        digest.mode = digest.mode.slice(0, -1);
      }
      return digest;
    }
    case "human_digest":
      return {
        mode: rich.mode,
        epoch: rich.epoch,
        seq: rich.seq,
        pending_human_items: rich.pending_human_items,
        recent_promotions: rich.recent_promotions,
        recent_rollbacks: rich.recent_rollbacks,
        budget_spent_micro_usd: rich.budget_spent_micro_usd,
        halted: rich.halted,
      };
    case "phi":
      return { phi_last: rich.phi_last, history: rich.phi_history };
    case "budget":
    default:
      return {
        budget_spent_micro_usd: rich.budget_spent_micro_usd,
        by_warrant: rich.by_warrant,
        by_role: rich.by_role,
      };
  }
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

/**
 * Write `data` to `file` atomically: temp file in the same directory, then a
 * rename over the destination.
 *
 * @param {string} file @param {string} data @returns {void}
 */
function atomicWrite(file, data) {
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, data, "utf8");
  renameSync(tmp, file);
}

/**
 * Append one canonical line to events.jsonl. The line is a single write to
 * an O_APPEND-style handle followed by fsync, so concurrent readers see the
 * line whole or not at all.
 *
 * @param {string} mirqlDir @param {string} canonicalLine @returns {void}
 */
function appendLedgerLine(mirqlDir, canonicalLine) {
  mkdirSync(join(mirqlDir, "ledger"), { recursive: true });
  const fd = openSync(eventsFile(mirqlDir), "a");
  try {
    writeSync(fd, canonicalLine + "\n", null, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Refold the whole ledger and atomically rewrite cache/state.json.
 *
 * @param {string} mirqlDir
 * @returns {object} the materialized state that was written
 */
function updateCache(mirqlDir) {
  const { events, rawLines } = readLedgerSafe(mirqlDir);
  const state = jobStateFrom(richFold(events, rawLines));
  mkdirSync(join(mirqlDir, "cache"), { recursive: true });
  atomicWrite(cacheFile(mirqlDir), jcs(state) + "\n");
  return state;
}

// ---------------------------------------------------------------------------
// appendEvent — `mirql l append`
// ---------------------------------------------------------------------------

/**
 * Append one event to the ledger (Law 4), enforcing:
 * 1. Idempotency dedup — an already-present idempotency_key dedupes.
 * 2. Law 3 single-writer ACL — canWriteEvent(writer.ns, type) or denial.
 * 3. Hash-chain integrity — seq/prev_hash/hash (+ Ed25519 signature when a
 *    public key is resolvable) or INTEGRITY_VIOLATION.
 *
 * Two input modes:
 * - Signing mode (`options.signingKey`, optionally `options.keyId`): seq,
 *   prev_hash, hlc, id, ts and envelope defaults are auto-filled, then the
 *   event is signed, so callers only supply type/writer/payload.
 * - Envelope mode: the caller supplies a complete signed event; it is
 *   validated with validateDocument("event", ...) and chain-checked.
 *
 * @param {string} mirqlDir the `.mirql` directory
 * @param {object} eventInput event object (full envelope, or partial when
 *   signing options are given)
 * @param {object} [options]
 * @param {string} [options.signingKey] base64url PKCS#8 private key
 * @param {string} [options.privateKey] alias for signingKey
 * @param {string} [options.keyId] writer key id (derived when omitted)
 * @param {string} [options.publicKey] explicit public key for sig verification
 * @param {number} [options.nowMs] wall-clock ms (deterministic tests)
 * @param {string} [options.node] HLC node id (default "local")
 * @returns {{ status: "appended", seq: number, hash: string } |
 *           { status: "deduped", event: object }}
 * @throws {LedgerError} POLICY_DENIAL / INTEGRITY_VIOLATION / USAGE_ERROR
 */
export function appendEvent(mirqlDir, eventInput, options = {}) {
  const dir = resolveMirqlDir(mirqlDir);
  if (
    eventInput === null ||
    typeof eventInput !== "object" ||
    Array.isArray(eventInput)
  ) {
    throw new LedgerError("USAGE_ERROR", "event input must be a JSON object");
  }

  // 1. Law 3 single-writer ACL (checked BEFORE idempotency dedup).
  const writerNs =
    typeof eventInput.writer === "string"
      ? eventInput.writer
      : (eventInput.writer?.ns ?? null);
  const eventType = typeof eventInput.type === "string" ? eventInput.type : null;
  if (!canWriteEvent(writerNs, eventType)) {
    throw new LedgerError(
      "POLICY_DENIAL",
      `writer ${JSON.stringify(writerNs ?? null)} may not emit event type ${JSON.stringify(eventType ?? null)} (Law 3: single-writer ACL)`,
    );
  }

  const { events, rawLines } = readLedgerSafe(dir);

  // 2. Idempotency dedup (Law 4) scoped by (writer.ns, idempotency_key).
  if (typeof eventInput.idempotency_key === "string") {
    const existing = events.find(
      (e) =>
        e?.idempotency_key === eventInput.idempotency_key &&
        (typeof e?.writer === "string"
          ? e.writer === writerNs
          : e?.writer?.ns === writerNs),
    );
    if (existing !== undefined) {
      return { status: "deduped", event: existing };
    }
  }

  // 3. Validate costs & safe-integer constraints before append (Law 17).
  const currentState = richFold(events, rawLines);
  const currentSpend = currentState.budget_spent_micro_usd;
  const rawPayload =
    eventInput.payload !== null &&
    typeof eventInput.payload === "object" &&
    !Array.isArray(eventInput.payload)
      ? eventInput.payload
      : {};
  if (rawPayload.cost_micro_usd !== undefined) {
    if (!Number.isSafeInteger(rawPayload.cost_micro_usd) || rawPayload.cost_micro_usd < 0) {
      throw new LedgerError(
        "USAGE_ERROR",
        "cost_micro_usd must be a non-negative safe integer",
      );
    }
    if (currentSpend + rawPayload.cost_micro_usd > Number.MAX_SAFE_INTEGER) {
      throw new LedgerError(
        "USAGE_ERROR",
        "cumulative budget spend would exceed Number.MAX_SAFE_INTEGER",
      );
    }
  }
  if (rawPayload.phi_after !== undefined) {
    if (!Number.isSafeInteger(rawPayload.phi_after) || rawPayload.phi_after < 0) {
      throw new LedgerError(
        "USAGE_ERROR",
        "phi_after must be a non-negative safe integer",
      );
    }
  }

  const signingKey = options.signingKey ?? options.privateKey ?? null;
  let event;
  if (signingKey !== null) {
    event = buildAndSignEvent(
      dir,
      eventInput,
      events,
      rawLines,
      signingKey,
      options,
    );
  } else {
    event = eventInput;
    // B1: Fail closed on missing signature or unresolvable key before schema checks
    if (typeof event.sig !== "string" || event.sig.length === 0) {
      throw new LedgerError(
        "INTEGRITY_VIOLATION",
        "missing signature or unresolvable public key",
      );
    }
    if (resolvePublicKey(event, dir, options) === null) {
      throw new LedgerError(
        "INTEGRITY_VIOLATION",
        "missing signature or unresolvable public key",
      );
    }
  }

  if (signingKey !== null) {
    const check = validateDocument("event", event);
    if (!check.valid) {
      throw new LedgerError(
        "USAGE_ERROR",
        `signed event rejected by the canonical event schema: ${check.errors.join("; ")}`,
      );
    }
  } else {
    const check = validateDocument("event", event);
    if (!check.valid) {
      // Surface ACL problems inside a caller-supplied envelope as policy
      // denials; everything else is a malformed input document.
      const acl = check.errors.some((e) => e.includes("single-writer ACL"));
      throw new LedgerError(
        acl ? "POLICY_DENIAL" : "USAGE_ERROR",
        `event envelope rejected: ${check.errors.join("; ")}`,
      );
    }
  }

  // 4. Hash-chain enforcement (Law 4).
  const last = events.at(-1) ?? null;
  const expectedSeq = (typeof last?.seq === "number" ? last.seq : 0) + 1;
  const expectedPrev = last
    ? eventHashOf(last, rawLines.at(-1), false)
    : GENESIS_PREV_HASH;
  if (event.seq !== expectedSeq) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      `seq break: expected ${expectedSeq}, got ${JSON.stringify(event.seq ?? null)}`,
    );
  }
  if (event.prev_hash !== expectedPrev) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      `prev_hash break at seq ${event.seq}: expected ${expectedPrev}, got ${JSON.stringify(event.prev_hash ?? null)}`,
    );
  }
  if (event.hash !== computeEventHash(event)) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      `hash mismatch at seq ${event.seq}: envelope hash does not match its canonical content`,
    );
  }
  if (typeof event.sig !== "string" || event.sig.length === 0) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      "missing signature or unresolvable public key",
    );
  }
  const publicKey = resolvePublicKey(event, dir, options);
  if (publicKey === null) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      "missing signature or unresolvable public key",
    );
  }
  const verdict = verifyEvent(event, publicKey);
  if (!verdict.ok) {
    throw new LedgerError(
      "INTEGRITY_VIOLATION",
      `signature verification failed at seq ${event.seq}: ${verdict.reason ?? "unknown reason"}`,
    );
  }

  // 4. Atomic append + cache update.
  appendLedgerLine(dir, jcs(event));
  updateCache(dir);
  return { status: "appended", seq: event.seq, hash: event.hash };
}

/**
 * Auto-fill the envelope (seq, prev_hash, hlc, id, ts, defaults), then sign.
 *
 * @param {string} dir
 * @param {object} input
 * @param {object[]} events
 * @param {string[]} rawLines
 * @param {string} signingKey
 * @param {{ keyId?: string, nowMs?: number, node?: string }} options
 * @returns {object} signed event envelope
 */
function buildAndSignEvent(dir, input, events, rawLines, signingKey, options) {
  void dir;
  const last = events.at(-1) ?? null;
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const node =
    typeof options.node === "string" && options.node.length > 0
      ? options.node
      : "local";
  const seq = (typeof last?.seq === "number" ? last.seq : 0) + 1;
  const prevHash = last ? eventHashOf(last, rawLines.at(-1)) : GENESIS_PREV_HASH;
  const keyId =
    typeof options.keyId === "string" && options.keyId.length > 0
      ? options.keyId
      : deriveKeyIdFromPrivate(signingKey);
  const writerNs =
    typeof input.writer === "string"
      ? input.writer
      : (input.writer?.ns ?? null);
  if (typeof writerNs !== "string" || writerNs.length === 0) {
    throw new LedgerError(
      "USAGE_ERROR",
      "event input is missing writer.ns (required for the Law 3 ACL gate)",
    );
  }
  if (typeof input.type !== "string" || input.type.length === 0) {
    throw new LedgerError("USAGE_ERROR", "event input is missing type");
  }

  const base = {
    v: 1,
    id: typeof input.id === "string" ? input.id : ulid(nowMs),
    tenant_id: typeof input.tenant_id === "string" ? input.tenant_id : "mirql-core",
    seq,
    epoch: typeof input.epoch === "number" ? input.epoch : 1,
    hlc: input.hlc ?? hlcTick(last?.hlc, nowMs, node),
    ts: typeof input.ts === "string" ? input.ts : new Date(nowMs).toISOString(),
    type: input.type,
    writer: { ns: writerNs, key_id: keyId },
    idempotency_key:
      typeof input.idempotency_key === "string"
        ? input.idempotency_key
        : `auto:${seq}`,
    prev_hash: prevHash,
    payload:
      input.payload !== null &&
      typeof input.payload === "object" &&
      !Array.isArray(input.payload)
        ? input.payload
        : {},
  };
  return signEvent(base, signingKey, keyId);
}

// ---------------------------------------------------------------------------
// verifyLedger — `mirql l verify`
// ---------------------------------------------------------------------------

/**
 * Verify the whole ledger from line 1 to N:
 * 1. every line parses and is integer-only canonical JSON (Law 17);
 * 2. seq runs strictly 1..N;
 * 3. prev_hash anchors at 64 zeros and chains to the previous event's
 *    envelope hash (or the SHA-256 of the previous raw line for conformance
 *    fixtures without hash fields);
 * 4. the Law 3 single-writer ACL holds for envelope-style writers;
 * 5. when a hash/sig is present, the content hash matches and the Ed25519
 *    signature verifies against the resolvable public key.
 *
 * Supports both signed full-envelope ledgers (written by appendEvent) and
 * raw conformance fixture ledgers such as
 * conformance/golden_ledger/events.jsonl (pass --conformance, or rely on
 * the automatic raw-line prev_hash linkage).
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @param {boolean} [options.conformance] advisory flag for fixture ledgers
 * @param {string} [options.publicKey] explicit verification public key
 * @returns {{ valid: true, event_count: number, head_hash: string } |
 *           { valid: false, error: string, seq: number }}
 */
export function verifyLedger(mirqlDir, options = {}) {
  const isConformance = options.conformance === true;
  const dir = resolveMirqlDir(mirqlDir);
  const file = eventsFile(dir);
  if (!existsSync(file)) {
    return { valid: true, event_count: 0, head_hash: GENESIS_PREV_HASH };
  }

  const rawLines = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length > 0) rawLines.push(trimmed);
  }

  /** @type {object[]} */
  const events = [];
  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i];
    const seqNo = i + 1;
    let event;
    try {
      event = JSON.parse(raw);
    } catch {
      return { valid: false, error: "json_parse", seq: seqNo };
    }
    try {
      jcs(event);
    } catch {
      return { valid: false, error: "law17_violation", seq: seqNo };
    }
    if (event === null || typeof event !== "object" || Array.isArray(event)) {
      return { valid: false, error: "not_an_object", seq: seqNo };
    }
    if (event.seq !== seqNo) {
      return { valid: false, error: "seq_break", seq: seqNo };
    }
    const expectedPrev =
      i === 0 ? GENESIS_PREV_HASH : eventHashOf(events[i - 1], rawLines[i - 1], isConformance);
    if (event.prev_hash !== expectedPrev) {
      return { valid: false, error: "chain_break", seq: seqNo };
    }
    const writer = event.writer;
    if (
      writer !== null &&
      typeof writer === "object" &&
      !Array.isArray(writer) &&
      !canWriteEvent(writer.ns, event.type)
    ) {
      return { valid: false, error: "acl_denial", seq: seqNo };
    }
    if (!isConformance) {
      if (typeof event.hash !== "string" || event.hash.length === 0) {
        return { valid: false, error: "unhashed_line", seq: seqNo };
      }
      if (event.hash !== computeEventHash(event)) {
        return { valid: false, error: "hash_mismatch", seq: seqNo };
      }
      if (typeof event.sig !== "string" || event.sig.length === 0) {
        return {
          valid: false,
          error: "missing signature or unresolvable public key",
          seq: seqNo,
        };
      }
      const publicKey = resolvePublicKey(event, dir, options);
      if (publicKey === null) {
        return {
          valid: false,
          error: "missing signature or unresolvable public key",
          seq: seqNo,
        };
      }
      if (!verifyEvent(event, publicKey).ok) {
        return { valid: false, error: "signature_invalid", seq: seqNo };
      }
    } else {
      if (typeof event.hash === "string") {
        if (event.hash !== computeEventHash(event)) {
          return { valid: false, error: "hash_mismatch", seq: seqNo };
        }
      }
      if (typeof event.sig === "string") {
        const publicKey = resolvePublicKey(event, dir, options);
        if (publicKey !== null && !verifyEvent(event, publicKey).ok) {
          return { valid: false, error: "signature_invalid", seq: seqNo };
        }
      }
    }
    events.push(event);
  }

  const headHash = events.length
    ? eventHashOf(events.at(-1), rawLines.at(-1), isConformance)
    : GENESIS_PREV_HASH;
  return { valid: true, event_count: events.length, head_hash: headHash };
}

// ---------------------------------------------------------------------------
// foldEvents / getView — pure projections
// ---------------------------------------------------------------------------

/**
 * Deterministic fold over the ledger (or a plain event array), returning the
 * full materialized state (the job_state projection shape).
 *
 * @param {string | object[]} source mirqlDir, or an array of parsed events
 * @returns {object} materialized state
 */
export function foldEvents(source) {
  const { events, rawLines } =
    typeof source === "string"
      ? readLedgerSafe(resolveMirqlDir(source))
      : { events: Array.isArray(source) ? source : [], rawLines: [] };
  return jobStateFrom(richFold(events, rawLines));
}

/**
 * Pure deterministic fold over ledger/events.jsonl producing one of the five
 * named projections:
 * - job_state (alias "state")  — full materialized state
 * - orchestrator_digest        — bounded <= 2048-byte summary for the queue
 * - human_digest               — summary for the human inbox
 * - phi                        — complexity potential history + latest value
 * - budget                     — integer micro-USD spend by warrant and role
 *
 * @param {string} mirqlDir
 * @param {string} projection
 * @returns {object}
 * @throws {LedgerError} USAGE_ERROR for an unknown projection
 */
export function getView(mirqlDir, projection) {
  const dir = resolveMirqlDir(mirqlDir);
  const { events, rawLines } = readLedgerSafe(dir);
  return projectView(richFold(events, rawLines), projection);
}

// ---------------------------------------------------------------------------
// replayCache / createSnapshot
// ---------------------------------------------------------------------------

/**
 * Delete cache/state.json and rebuild it from scratch by folding
 * ledger/events.jsonl — the Law 4 proof that the cache is disposable.
 *
 * @param {string} mirqlDir
 * @returns {{ rebuilt: true, seq: number, state_hash: string }}
 * @throws {LedgerError} INTEGRITY_VIOLATION when the ledger is unreadable
 */
export function replayCache(mirqlDir) {
  const dir = resolveMirqlDir(mirqlDir);
  rmSync(cacheFile(dir), { force: true });
  const { events, rawLines } = readLedgerSafe(dir);
  const state = jobStateFrom(richFold(events, rawLines));
  const stateHash = jcsHash(state);
  mkdirSync(join(dir, "cache"), { recursive: true });
  atomicWrite(cacheFile(dir), jcs(state) + "\n");
  return { rebuilt: true, seq: state.seq, state_hash: stateHash };
}

/**
 * Fold the current ledger state and persist a snapshot at
 * `<mirqlDir>/ledger/snapshots/snapshot-<seq>.json`.
 *
 * @param {string} mirqlDir
 * @returns {{ snapshot_path: string, seq: number, state_hash: string }}
 */
export function createSnapshot(mirqlDir) {
  const dir = resolveMirqlDir(mirqlDir);
  const { events, rawLines } = readLedgerSafe(dir);
  const state = jobStateFrom(richFold(events, rawLines));
  const stateHash = jcsHash(state);
  const snapshotPath = join(snapshotsDir(dir), `snapshot-${state.seq}.json`);
  mkdirSync(snapshotsDir(dir), { recursive: true });
  atomicWrite(
    snapshotPath,
    jcs({ v: 1, seq: state.seq, state_hash: stateHash, state }) + "\n",
  );
  return { snapshot_path: snapshotPath, seq: state.seq, state_hash: stateHash };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/** Flags that never consume a following value. */
const BOOL_FLAGS = Object.freeze(
  new Set(["conformance", "rebuild-cache", "help"]),
);

/**
 * Parse `["view", "job_state", "--dir", "x", "--conformance"]` into
 * positionals and flags (supports both `--flag value` and `--flag=value`).
 *
 * @param {string[]} argv
 * @returns {{ positional: string[], flags: Record<string, string | boolean> }}
 */
function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      if (eq !== -1) {
        flags[arg.slice(2, eq)] = arg.slice(eq + 1);
      } else {
        const name = arg.slice(2);
        if (BOOL_FLAGS.has(name)) {
          flags[name] = true;
        } else if (i + 1 < argv.length) {
          flags[name] = argv[++i];
        } else {
          flags[name] = true;
        }
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

/**
 * Read all of stdin synchronously (pipe or redirect); empty when stdin is a
 * TTY or unreadable, so interactive misuse fails fast instead of hanging.
 *
 * @returns {string}
 */
function readStdinSync() {
  try {
    if (process.stdin.isTTY) return "";
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/** @param {string} text @returns {void} */
function emitLine(text) {
  process.stdout.write(text + "\n");
}

/** The W1-pinned stub contract (bare invocation, --help, status). */
function emitStubContract() {
  process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
  return EXIT_CODES.OK;
}

/** @returns {number} exit code */
function emitUsage() {
  emitLine(
    jcs({
      tool: TOOL,
      usage: "mirql-log <subcommand> [options]  (or: mirql l <subcommand>)",
      dir: "--dir <path> | MIRQL_DIR | <cwd>/.mirql",
      subcommands: {
        append:
          "append an event from --event <json>, --file <path> or stdin; optional --sign-key <privateKey> --key-id <keyId>",
        verify: "verify the hash chain; --conformance for raw fixture ledgers",
        view: `fold a projection: ${PROJECTIONS.join(" | ")}`,
        replay: "rebuild cache/state.json from events.jsonl (--rebuild-cache)",
        snapshot: "write ledger/snapshots/snapshot-<seq>.json",
      },
      exit_codes: EXIT_CODES,
    }),
  );
  return EXIT_CODES.OK;
}

/**
 * Append subcommand: load the event JSON from --event, --file or stdin and
 * hand it to appendEvent with the CLI signing options.
 *
 * @param {string} dir
 * @param {Record<string, string | boolean>} flags
 * @returns {number} exit code
 */
function cliAppend(dir, flags) {
  let input;
  if (typeof flags.event === "string") {
    try {
      input = JSON.parse(flags.event);
    } catch {
      throw new LedgerError("USAGE_ERROR", "--event is not valid JSON");
    }
  } else if (typeof flags.file === "string") {
    let text;
    try {
      text = readFileSync(flags.file, "utf8");
    } catch (err) {
      throw new LedgerError(
        "USAGE_ERROR",
        `--file is not readable: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    try {
      input = JSON.parse(text);
    } catch {
      throw new LedgerError("USAGE_ERROR", "--file does not contain valid JSON");
    }
  } else {
    const text = readStdinSync();
    if (text.trim().length === 0) {
      throw new LedgerError(
        "USAGE_ERROR",
        "no event input: pass --event <json>, --file <path>, or pipe JSON on stdin",
      );
    }
    try {
      input = JSON.parse(text);
    } catch {
      throw new LedgerError("USAGE_ERROR", "stdin does not contain valid JSON");
    }
  }

  const options = {};
  if (typeof flags["sign-key"] === "string") options.signingKey = flags["sign-key"];
  if (typeof flags["key-id"] === "string") options.keyId = flags["key-id"];
  if (typeof flags["public-key"] === "string") options.publicKey = flags["public-key"];

  emitLine(jcs(appendEvent(dir, input, options)));
  return EXIT_CODES.OK;
}

/**
 * Full CLI dispatch (mirql l <subcommand> / mirql-log <subcommand>).
 * JSON results on stdout; JSON errors ({ error, reason }) on stderr; exit
 * codes are the canonical EXIT_CODES.
 *
 * @param {string[]} argv arguments after the program/tool name
 * @returns {number} process exit code
 */
export function runCli(argv = []) {
  try {
    const { positional, flags } = parseArgs(argv);
    const sub = positional[0];
    if (sub === undefined) return emitStubContract();
    if (sub === "help") return emitUsage();

    const dir = resolveMirqlDir(
      typeof flags.dir === "string" ? flags.dir : undefined,
    );

    switch (sub) {
      case "append":
        return cliAppend(dir, flags);
      case "verify": {
        const result = verifyLedger(dir, { conformance: flags.conformance === true });
        emitLine(jcs(result));
        return result.valid ? EXIT_CODES.OK : EXIT_CODES.INTEGRITY_VIOLATION;
      }
      case "view": {
        emitLine(jcs(getView(dir, positional[1] ?? "")));
        return EXIT_CODES.OK;
      }
      case "replay": {
        // --rebuild-cache is the documented form; the replay subcommand's
        // only job is rebuilding, so the flag is accepted but not required.
        emitLine(jcs(replayCache(dir)));
        return EXIT_CODES.OK;
      }
      case "snapshot": {
        emitLine(jcs(createSnapshot(dir)));
        return EXIT_CODES.OK;
      }
      default:
        process.stderr.write(
          jcs({
            error: "USAGE_ERROR",
            reason: `unknown subcommand ${JSON.stringify(sub)}; expected one of ${SUBCOMMANDS.join(", ")}`,
          }) + "\n",
        );
        return EXIT_CODES.USAGE_ERROR;
    }
  } catch (err) {
    if (err instanceof LedgerError) {
      process.stderr.write(jcs({ error: err.code, reason: err.message }) + "\n");
      return err.exitCode;
    }
    throw err;
  }
}

/**
 * CLI entrypoint imported by bin/mirql-log.mjs and bin/mirql.mjs. Keeps the
 * W1 stub contract for bare `--help` / `-h` / `status` / no-args calls and
 * delegates every real subcommand to runCli.
 *
 * @param {string[]} argv - arguments after the program name
 * @returns {number} process exit code (see EXIT_CODES)
 */
export function main(argv = []) {
  const first = argv[0];
  if (
    argv.length === 0 ||
    first === "--help" ||
    first === "-h" ||
    first === "status"
  ) {
    return emitStubContract();
  }
  return runCli(argv);
}

export default main;
