import { writePrivateFile, protectPrivatePaths } from "../core/private-files.mjs";
import { requireTrustForKeyCreation } from "../core/trust-root.mjs";
import { assertKeyEnrolled } from "../core/keyring.mjs";
import { trustFile, assertExternalTrustPath } from "../core/trust-root.mjs";
import { existsSync, mkdirSync, readFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { GENESIS_PREV_HASH, verifyChainBeforeAppend, writeLedgerHeadSidecar } from "../core/ledger-verify.mjs";
import {
  jcs,
  sha256,
  ulid,
  hlcTick,
  signEvent,
  generateEd25519Keypair,
  withLedgerLock,
} from "../core/index.mjs";

/**
 * Appends a signed ledger event with writer.ns = "tool:run_supervisor".
 *
 * @param {string} mirqlDir - active .mirql directory
 * @param {object} eventInput - event properties (type, payload, idempotency_key, etc.)
 * @param {object} [keypair] - Ed25519 keypair ({ privateKey, publicKey, keyId })
 * @param {object} [options]
 * @param {() => object|undefined} [options.precondition] - runs inside the ledger
 *   lock before the append; it may throw to refuse, or return an existing event
 *   to make the append an idempotent no-op.
 * @returns {object} the appended (or pre-existing) signed event envelope
 */
export function appendSupervisorEvent(mirqlDir, eventInput, keypair, options = {}) {
  return withLedgerLock(mirqlDir, () => {
  if (typeof options.precondition === "function") {
    const existing = options.precondition();
    if (existing) return existing;
  }
  const ledgerDir = join(mirqlDir, "ledger");
  mkdirSync(ledgerDir, { recursive: true });
  const eventsFile = join(ledgerDir, "events.jsonl");

  // Fail closed (Law 4): re-verify every line of the hash chain before
  // appending; any corruption throws INTEGRITY_VIOLATION.
  const chain = verifyChainBeforeAppend(mirqlDir);

  const last = chain.lastEvent;
  const nowMs = Number.isSafeInteger(eventInput.nowMs)
    ? eventInput.nowMs
    : Date.now();
  const seq = chain.seq + 1;
  const prevHash =
    typeof last?.hash === "string"
      ? last.hash
      : last
        ? sha256(jcs(last))
        : GENESIS_PREV_HASH;

  const kp = keypair ?? getOrGenerateSupervisorKey(mirqlDir);
  updateKeyring(mirqlDir, kp);
  const keyId = kp.keyId;

  const unsigned = {
    v: 1,
    id: typeof eventInput.id === "string" ? eventInput.id : ulid(nowMs),
    tenant_id:
      typeof eventInput.tenant_id === "string"
        ? eventInput.tenant_id
        : "mirql-core",
    seq,
    // H1: epoch comes from the caller (leased-job epoch) or the payload —
    // it is never unconditionally hardcoded to 1.
    epoch: Number.isSafeInteger(eventInput.epoch)
      ? eventInput.epoch
      : eventInput.payload &&
          typeof eventInput.payload === "object" &&
          Number.isSafeInteger(eventInput.payload.epoch)
        ? eventInput.payload.epoch
        : 1,
    hlc: eventInput.hlc ?? hlcTick(last?.hlc, nowMs, "local"),
    ts:
      typeof eventInput.ts === "string"
        ? eventInput.ts
        : new Date(nowMs).toISOString(),
    type: eventInput.type,
    writer: { ns: "tool:run_supervisor", key_id: keyId },
    idempotency_key:
      typeof eventInput.idempotency_key === "string"
        ? eventInput.idempotency_key
        : `supervisor:${eventInput.type}:${seq}`,
    prev_hash: prevHash,
    payload:
      eventInput.payload && typeof eventInput.payload === "object"
        ? eventInput.payload
        : {},
  };

  const signed = signEvent(unsigned, kp.privateKey, keyId);
  appendFileSync(eventsFile, jcs(signed) + "\n", "utf8");
  writeLedgerHeadSidecar(mirqlDir, signed);


  return signed;
  });
}

/**
 * Ensures keyring.json contains the public key for kp.keyId.
 *
 * @param {string} mirqlDir
 * @param {{ keyId: string, publicKey: string }} kp
 */
export function updateKeyring(mirqlDir, kp) {
  assertKeyEnrolled(mirqlDir, "tool:run_supervisor", kp);
}

/**
 * Retrieves the persisted supervisor keypair or generates a fresh one.
 * Keeps keys strictly outside the agent's working directory.
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {{ privateKey: string, publicKey: string, keyId: string }}
 */
export function getOrGenerateSupervisorKey(mirqlDir, options = {}) {
  const keysDir = options.keysDir ? assertExternalTrustPath(options.keysDir, mirqlDir) : trustFile(mirqlDir, "keys");
  const primaryPath = join(keysDir, "run_supervisor.key.json");
  const fallbackPath = join(keysDir, "run_supervisor.json");
  const candidate = existsSync(primaryPath) ? primaryPath : (existsSync(fallbackPath) ? fallbackPath : primaryPath);
  const keyPath = assertExternalTrustPath(candidate, mirqlDir);
  if (existsSync(keyPath)) {
    try {
      protectPrivatePaths([keyPath]);
      const parsed = JSON.parse(readFileSync(keyPath, "utf8"));
      if (parsed.privateKey && parsed.publicKey && parsed.keyId) {
        assertKeyEnrolled(mirqlDir, "tool:run_supervisor", parsed);
        return parsed;
      }
      throw new Error(`Incomplete supervisor keypair structure in ${keyPath}`);
    } catch (err) {
      if (err.code === "KEYRING_INTEGRITY" || err.code === "PRIVATE_PERMISSIONS") throw err;
      throw new Error(`Corrupt supervisor key file at ${keyPath}: ${err.message}`);
    }
  }

  requireTrustForKeyCreation(mirqlDir);
  const kp = generateEd25519Keypair();
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  writePrivateFile(keyPath, jcs(kp) + "\n");
  updateKeyring(mirqlDir, kp);
  return kp;
}
