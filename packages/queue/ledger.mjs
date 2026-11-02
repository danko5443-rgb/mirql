import { requireTrustForKeyCreation } from "../core/trust-root.mjs";
import { readSignedKeyring, sealKeyring, assertKeyEnrolled } from "../core/keyring.mjs";
import { trustFile, assertExternalTrustPath } from "../core/trust-root.mjs";
// packages/queue/ledger.mjs — Ledger I/O, Key Management, Event Folding, and Concurrency Lockfile.
import {
  readFileSync,
  writeFileSync,
  appendFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
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
  withLedgerLock,
  foldLedger,
  readLedgerEvents,
  foldQueueState,
  PRIVILEGED_EVENTS,
  getTrustedPublicKey,
} from "../core/index.mjs";

export { withLedgerLock };
export {
  foldLedger,
  readLedgerEvents,
  foldQueueState,
  PRIVILEGED_EVENTS,
  getTrustedPublicKey,
};


/**
 * Privileged events whose emission requires cryptographic verification against keyring.json.
 */
// PRIVILEGED_EVENTS re-exported from core


// withLedgerLock is imported and re-exported from @mirql/core

/**
 * Load keyring from <trustRoot>/keyring.json.
 * @param {string} mirqlDir
 * @returns {object | null}
 */
export function loadKeyring(mirqlDir) {
  return readSignedKeyring(mirqlDir);
}

/**
 * Write or update keyring at <trustRoot>/keyring.json.
 * @param {string} mirqlDir
 * @param {object} keyring
 * @param {object} [options]
 */
export function saveKeyring(mirqlDir, keyring, options = {}) {
  return withLedgerLock(mirqlDir, () => {
    if (!options.owner) throw new Error("Keyring changes require the pinned human signing key");
    const existing = options.overwrite ? {} : readSignedKeyring(mirqlDir);
    sealKeyring(mirqlDir, { ...existing, ...keyring }, options.owner);
  });
}

/**
 * Helper to extract trusted public key for a writer from keyring (Fix N2).
 * The key MUST be explicitly bound to writerNs.
 * @param {object} keyring
 * @param {string} writerNs
 * @param {string} [keyId]
 * @returns {string | null}
 */
// getTrustedPublicKey re-exported from core


/**
 * Load or propose the queue keypair, refusing use until the human has enrolled it.
 *
 * @param {string} mirqlDir
 * @param {string} [customKeyFile]
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } }}
 */
export function getOrCreateQueueKeypair(mirqlDir, customKeyFile) {
  const keyPath = customKeyFile ? assertExternalTrustPath(customKeyFile, mirqlDir) : trustFile(mirqlDir, "keys", "queue.key.json");
  let kp;

  if (existsSync(keyPath)) {
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(keyPath, "utf8"));
    } catch (error) {
      throw new Error("Invalid persisted queue key: " + error.message);
    }
    if (!parsed.privateKey || !parsed.publicKey || !parsed.keyId) {
      throw new Error("Invalid persisted queue key: incomplete key material");
    }
    kp = parsed;
  }

  if (!kp) {
    requireTrustForKeyCreation(mirqlDir);
    const generated = generateEd25519Keypair();
    kp = {
      ...generated,
      writer: {
        ns: "tool:queue",
        key_id: generated.keyId,
      },
    };

    // H4: private keys are written with mode 0o600 inside a 0o700 directory.
    const keysDir = dirname(keyPath);
    mkdirSync(keysDir, { recursive: true, mode: 0o700 });
    try {
      chmodSync(keysDir, 0o700);
    } catch {}
    writeFileSync(keyPath, JSON.stringify(kp, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    try {
      chmodSync(keyPath, 0o600);
    } catch {}
  }

  assertKeyEnrolled(mirqlDir, "tool:queue", kp);

  return kp;
}

/**
 * Read all events from the ledger.
 *
 * @param {string} mirqlDir
 * @returns {Array<{ event: object, raw: string }>}
 */
// readLedgerEvents re-exported from core


/**
 * Pure mathematical fold over ledger events to compute queue state.
 *
 * @param {Array<object | { event: object, raw?: string }>} events
 * @param {object} [policy]
 * @param {object | null} [keyring]
 * @returns {object} folded queue state
 */
// foldLedger and foldQueueState re-exported from core


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
  assertKeyEnrolled(mirqlDir, keypair.writer?.ns ?? "tool:queue", keypair);
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
