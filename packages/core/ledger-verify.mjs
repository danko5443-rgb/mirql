import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { computeEventHash, verifyEvent } from "./ed25519.mjs";
import { jcs } from "./jcs.mjs";
import { sha256, jcsHash } from "./hash.mjs";
import { canWriteEvent } from "./acl.mjs";
import { validateDocument } from "./schema.mjs";
import { readSignedKeyring, resolveRegisteredPublicKey } from "./keyring.mjs";

class LedgerVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = this.errorCode = code;
    this.exitCode = code === "USAGE_ERROR" ? 2 : 3;
  }
}

export { LedgerVerificationError };

/** Law 4: prev_hash anchor of the very first event in any ledger. */
export const GENESIS_PREV_HASH = `sha256:${"0".repeat(64)}`;

const eventsFileOf = (mirqlDir) => join(mirqlDir, "ledger", "events.jsonl");
const integrity = (message) => new LedgerVerificationError("INTEGRITY_VIOLATION", message);

/** Non-empty trimmed lines of a text file (empty array when absent). */
function readTrimmedLines(file) {
  return existsSync(file) ? readFileSync(file, "utf8").split(/\r?\n/).map((line) => line.trim()).filter(Boolean) : [];
}

/** Atomically write the O(1) head sidecar head.json (temp file + rename, JCS, Law 17). The events_sha256 digest authenticates the ENTIRE raw events.jsonl, so any byte edited anywhere in the ledger history invalidates the sidecar and forces full re-verification. */
export function writeLedgerHeadSidecar(mirqlDir, lastEvent) {
  if (lastEvent === null || typeof lastEvent !== "object") return;
  const ledgerDir = join(mirqlDir, "ledger");
  const rawEvents = existsSync(eventsFileOf(mirqlDir)) ? readFileSync(eventsFileOf(mirqlDir), "utf8") : "";
  const file = join(ledgerDir, "head.json");
  mkdirSync(ledgerDir, { recursive: true });
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, jcs({ v: 1, seq: lastEvent.seq, hash: lastEvent.hash, prev_hash: lastEvent.prev_hash,
    ts: lastEvent.ts, writer: lastEvent.writer, sig: lastEvent.sig, events_sha256: sha256(rawEvents) }) + "\n", "utf8");
  renameSync(tmp, file);
}

const isHashString = (hash) => typeof hash === "string" && /^sha256:[a-f0-9]{64}$/.test(hash);
const isWriterObject = (writer) => writer !== null && typeof writer === "object" && !Array.isArray(writer) && typeof writer.ns === "string" && writer.ns.length > 0 && typeof writer.key_id === "string" && writer.key_id.length > 0;

/**
 * Read and verify the O(1) head sidecar against ledger/events.jsonl (Law 4,
 * Phase 6.2): head.json must parse with v=1, a safe integer seq >= 1, a
 * canonical hash, sig and writer; the ledger tail must match its seq/hash/sig
 * with an equal non-empty line count; and, with a signed keyring present, the
 * head signature must verify against the registered key. Anything else is
 * { valid: false } so callers fail closed.
 */
export function readLedgerHeadSidecar(mirqlDir) {
  const headPath = join(mirqlDir, "ledger", "head.json");
  if (!existsSync(headPath)) return { valid: false };
  const invalid = (error) => ({ valid: false, error });
  let head;
  try {
    head = JSON.parse(readFileSync(headPath, "utf8"));
  } catch (error) {
    return invalid(`head.json is not valid JSON: ${error.message}`);
  }
  if (head === null || typeof head !== "object" || Array.isArray(head)) return invalid("head.json is not an object");
  if (head.v !== 1) return invalid("head.json has an unknown version");
  if (!Number.isSafeInteger(head.seq) || head.seq < 1) return invalid("head.json seq is not a safe integer >= 1");
  if (!isHashString(head.hash)) return invalid("head.json hash is malformed");
  if (!isHashString(head.events_sha256)) return invalid("head.json events_sha256 is missing or malformed");
  if (typeof head.sig !== "string" || head.sig.length === 0) return invalid("head.json sig is missing");
  if (!isWriterObject(head.writer)) return invalid("head.json writer is malformed");

  // The whole raw ledger is authenticated by digest: any byte edited anywhere
  // in events.jsonl (not just the tail) invalidates the sidecar.
  if (!existsSync(eventsFileOf(mirqlDir))) return invalid("events.jsonl is missing");
  const rawEvents = readFileSync(eventsFileOf(mirqlDir), "utf8");
  if (sha256(rawEvents) !== head.events_sha256) return invalid("head.json events_sha256 mismatch");
  const lines = rawEvents.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return invalid("events.jsonl is missing or empty");
  if (lines.length !== head.seq) return invalid(`events.jsonl line count ${lines.length} does not match head.seq ${head.seq}`);
  let lastEvent;
  try {
    lastEvent = JSON.parse(lines.at(-1));
  } catch (error) {
    return invalid(`ledger tail is corrupt: ${error.message}`);
  }
  if (lastEvent?.seq !== head.seq || lastEvent?.hash !== head.hash || lastEvent?.sig !== head.sig) {
    return invalid("head.json is out of sync with the ledger tail");
  }

  // With a signed keyring present, the head must still verify against it.
  const ring = readSignedKeyring(mirqlDir);
  if (Object.keys(ring).length > 0) {
    const publicKey = resolveRegisteredPublicKey(lastEvent, ring);
    if (publicKey === null) return invalid("head writer key is not registered in the signed keyring");
    if (!verifyEvent(lastEvent, publicKey).ok) return invalid("head event signature does not verify");
    if (computeEventHash(lastEvent) !== lastEvent.hash) return invalid("head event content hash mismatch");
  }
  return { valid: true, seq: head.seq, hash: head.hash, lastEvent };
}

/**
 * Verify ledger chain integrity before an append (Law 4, fail closed). An
 * empty or missing ledger returns the genesis anchor; a valid head.json
 * sidecar gives the O(1) fast path (no per-event Ed25519 re-verification);
 * otherwise every line is re-verified (seq order, prev_hash continuity,
 * envelope hash) and any corruption throws
 * LedgerVerificationError("INTEGRITY_VIOLATION") before a fresh sidecar is
 * written for the verified tail.
 */
export function verifyChainBeforeAppend(mirqlDir, options = {}) {
  const rawLines = readTrimmedLines(eventsFileOf(mirqlDir));
  const genesis = { seq: 0, prevHash: GENESIS_PREV_HASH, lastEvent: null, events: [] };
  if (rawLines.length === 0) return genesis;

  const sidecar = readLedgerHeadSidecar(mirqlDir);
  if (sidecar.valid) {
    const fast = { seq: sidecar.seq, prevHash: sidecar.hash, lastEvent: sidecar.lastEvent };
    if (options.includeEvents) fast.events = rawLines.map((raw) => JSON.parse(raw));
    return fast;
  }

  const events = [];
  for (let i = 0; i < rawLines.length; i++) {
    const seqNo = i + 1;
    let event;
    try {
      event = JSON.parse(rawLines[i]);
    } catch (error) {
      throw integrity(`corrupt ledger JSON at seq ${seqNo}: ${error.message}`);
    }
    if (event === null || typeof event !== "object" || Array.isArray(event)) throw integrity(`ledger line ${seqNo} is not an event object`);
    if (event.seq !== seqNo) throw integrity(`seq break at line ${seqNo}: expected ${seqNo}, got ${JSON.stringify(event.seq ?? null)}`);
    const expectedPrev = i === 0 ? GENESIS_PREV_HASH : eventHashOf(events[i - 1], rawLines[i - 1], false);
    if (event.prev_hash !== expectedPrev) throw integrity(`prev_hash chain break at seq ${seqNo}`);
    if (typeof event.hash !== "string" || event.hash !== computeEventHash(event)) throw integrity(`hash mismatch at seq ${seqNo}: envelope hash does not match its canonical content`);
    events.push(event);
  }

  writeLedgerHeadSidecar(mirqlDir, events.at(-1));
  return { seq: events.length, prevHash: events.at(-1).hash, lastEvent: events.at(-1), events };
}

/** Read and verify one ledger snapshot without conformance or caller-key overrides. */
export function readVerifiedLedger(mirqlDir) {
  const rawLines = readTrimmedLines(eventsFileOf(mirqlDir));
  const ring = readSignedKeyring(mirqlDir);
  const result = verifyLedgerLines(rawLines, { resolvePublicKey: event => resolveRegisteredPublicKey(event, ring) });
  if (!result.valid) throw new LedgerVerificationError("INTEGRITY_VIOLATION", "Ledger authorization refused: " + result.error);
  const events = rawLines.map(line => JSON.parse(line));
  for (const event of events) {
    const check = validateDocument("event", event);
    if (!check.valid) throw new LedgerVerificationError("INTEGRITY_VIOLATION", "Invalid authorization ledger envelope: " + check.errors.join(", "));
  }
  return events;
}

export function eventHashOf(event, rawLine, allowRawLine = false) {
  if (typeof event?.hash === "string") return event.hash;
  if (allowRawLine && typeof rawLine === "string") return sha256(rawLine);
  return jcsHash(event);
}

export function verifyLedgerLines(rawLines, options = {}) {
  const isConformance = options.conformance === true;
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
      i === 0 ? `sha256:${"0".repeat(64)}` : eventHashOf(events[i - 1], rawLines[i - 1], isConformance);
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
      const publicKey = options.resolvePublicKey(event);
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
        const publicKey = options.resolvePublicKey(event);
        if (publicKey !== null && !verifyEvent(event, publicKey).ok) {
          return { valid: false, error: "signature_invalid", seq: seqNo };
        }
      }
    }
    events.push(event);
  }

  const headHash = events.length
    ? eventHashOf(events.at(-1), rawLines.at(-1), isConformance)
    : `sha256:${"0".repeat(64)}`;
  const expectedHead = options.expectHead ?? options["expect-head"];
  if (expectedHead !== undefined) {
    if (
      typeof expectedHead !== "string" ||
      expectedHead.trim().length === 0 ||
      !/^(?:sha256:)?[a-f0-9]{64}$/.test(expectedHead)
    ) {
      throw new LedgerVerificationError(
        "USAGE_ERROR",
        `expectHead must be a valid 64-hex SHA-256 hash, got ${JSON.stringify(expectedHead)}`,
      );
    }
    const normHead = headHash.startsWith("sha256:") ? headHash : `sha256:${headHash}`;
    const normExpected = expectedHead.startsWith("sha256:") ? expectedHead : `sha256:${expectedHead}`;
    if (normHead !== normExpected) {
      return {
        valid: false,
        error: "head_hash_mismatch",
        expected: expectedHead,
        actual: headHash,
      };
    }
  }
  return { valid: true, event_count: events.length, head_hash: headHash };
}
