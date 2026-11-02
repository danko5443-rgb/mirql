import { resolveTrustRoot, trustFile, assertExternalTrustPath } from "../core/trust-root.mjs";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  appendFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  jcs,
  sha256,
  ulid,
  hlcTick,
  signEvent,
  generateEd25519Keypair,
  withLedgerLock,
} from "../core/index.mjs";

const GENESIS_PREV_HASH = `sha256:${"0".repeat(64)}`;

/**
 * Appends a signed ledger event with writer.ns = "tool:run_supervisor".
 *
 * @param {string} mirqlDir - active .mirql directory
 * @param {object} eventInput - event properties (type, payload, idempotency_key, etc.)
 * @param {object} [keypair] - Ed25519 keypair ({ privateKey, publicKey, keyId })
 * @returns {object} the appended signed event envelope
 */
export function appendSupervisorEvent(mirqlDir, eventInput, keypair) {
  return withLedgerLock(mirqlDir, () => {
  const ledgerDir = join(mirqlDir, "ledger");
  mkdirSync(ledgerDir, { recursive: true });
  const eventsFile = join(ledgerDir, "events.jsonl");

  let events = [];
  if (existsSync(eventsFile)) {
    const raw = readFileSync(eventsFile, "utf8").trim();
    if (raw.length > 0) {
      const lines = raw.split("\n").filter((l) => l.trim().length > 0);
      events = lines.map((l, idx) => {
        try {
          return JSON.parse(l);
        } catch (err) {
          throw new Error(
            `Corrupt ledger event at line ${idx + 1} in ${eventsFile}: ${err.message}`,
          );
        }
      });
    }
  }

  const last = events.at(-1) ?? null;
  const nowMs = Number.isSafeInteger(eventInput.nowMs)
    ? eventInput.nowMs
    : Date.now();
  const seq = (typeof last?.seq === "number" ? last.seq : 0) + 1;
  const prevHash =
    typeof last?.hash === "string"
      ? last.hash
      : last
        ? sha256(jcs(last))
        : GENESIS_PREV_HASH;

  const kp = keypair ?? getOrGenerateSupervisorKey(mirqlDir);
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

  // Keep keyring in sync if needed
  updateKeyring(mirqlDir, kp);

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
  const ledgerDir = resolveTrustRoot(mirqlDir);
  mkdirSync(ledgerDir, { recursive: true, mode: 0o700 });
  const keyringPath = trustFile(mirqlDir, "keyring.json");
  let keyring = {};
  if (existsSync(keyringPath)) {
    try {
      keyring = JSON.parse(readFileSync(keyringPath, "utf8")) ?? {};
    } catch (err) {
      throw new Error(`Corrupt keyring file at ${keyringPath}: ${err.message}`);
    }
  }
  if (!keyring[kp.keyId]) {
    keyring[kp.keyId] = {
      ns: "tool:run_supervisor",
      publicKey: kp.publicKey,
    };
    writeFileSync(keyringPath, jcs(keyring) + "\n", { encoding: "utf8", mode: 0o600 });
  }
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
      const parsed = JSON.parse(readFileSync(keyPath, "utf8"));
      if (parsed.privateKey && parsed.publicKey && parsed.keyId) {
        return parsed;
      }
      throw new Error(`Incomplete supervisor keypair structure in ${keyPath}`);
    } catch (err) {
      throw new Error(`Corrupt supervisor key file at ${keyPath}: ${err.message}`);
    }
  }

  const kp = generateEd25519Keypair();
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  writeFileSync(keyPath, jcs(kp) + "\n", { encoding: "utf8", mode: 0o600 });
  updateKeyring(mirqlDir, kp);
  return kp;
}
