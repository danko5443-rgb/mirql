import { readFileSync, existsSync } from "node:fs";
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

/** Read and verify one ledger snapshot without conformance or caller-key overrides. */
export function readVerifiedLedger(mirqlDir) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  const rawLines = existsSync(file) ? readFileSync(file, "utf8").split(/\r?\n/).map(line => line.trim()).filter(Boolean) : [];
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
