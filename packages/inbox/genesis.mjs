// packages/inbox/genesis.mjs — Drop-in .mirql genesis bootstrapper (Law 6).
import { mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ulid,
  signEvent,
  verifyEvent,
  EXIT_CODES,
} from "../core/index.mjs";
import { generateFactoryKeypairs } from "./keys.mjs";
import {
  GENESIS_PREV_HASH,
  readEvents,
  appendEvent,
} from "./ledger.mjs";

/**
 * Initialize a complete drop-in `.mirql/` directory structure,
 * generate factory keypairs for all canonical writers, register public keys
 * in `keyring.json`, and sign + append the genesis event.
 *
 * @param {string} mirqlDir - path to .mirql directory
 * @param {object} [options]
 * @param {number} [options.nowMs]
 * @param {string} [options.idempotencyKey]
 * @param {string} [options.tenantId]
 * @param {string} [options.macroState]
 * @returns {{ status: "initialized" | "already_initialized", seq: number, hash?: string, event: object }}
 */
export function runGenesis(mirqlDir, options = {}) {
  // 1. Initialize directory layout
  mkdirSync(join(mirqlDir, "ledger", "snapshots"), { recursive: true });
  mkdirSync(join(mirqlDir, "cache"), { recursive: true });
  mkdirSync(join(mirqlDir, "keys"), { recursive: true });
  mkdirSync(join(mirqlDir, "consensus"), { recursive: true });
  mkdirSync(join(mirqlDir, "proposals"), { recursive: true });
  mkdirSync(join(mirqlDir, "warrants"), { recursive: true });

  const idempotencyKey = options.idempotencyKey || "genesis-1";

  // 2. Check for existing genesis event
  const { events } = readEvents(mirqlDir);
  if (events.length > 0 && events[0]?.type === "mirql.genesis") {
    const first = events[0];
    if (first.idempotency_key === idempotencyKey || !options.idempotencyKey) {
      return {
        status: "already_initialized",
        seq: 1,
        hash: first.hash,
        event: first,
      };
    }
  }

  // 3. Provision all canonical factory keypairs into <mirqlDir>/keys and register in keyring.json
  const keypairs = generateFactoryKeypairs(mirqlDir);
  const humanKp = keypairs["human:owner"];
  if (!humanKp?.privateKey) {
    throw new Error("Failed to provision human:owner keypair for genesis");
  }

  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const tenantId = typeof options.tenantId === "string" ? options.tenantId : "mirql-core";
  const macroState = typeof options.macroState === "string" ? options.macroState : "BUILD";

  // 4. Construct and sign the genesis event
  const genesisEnvelope = {
    v: 1,
    id: ulid(nowMs),
    tenant_id: tenantId,
    seq: 1,
    epoch: 1,
    hlc: { wall_ms: nowMs, logical: 0, node: options.node || "local" },
    ts: new Date(nowMs).toISOString(),
    type: "mirql.genesis",
    writer: {
      ns: "human:owner",
      key_id: humanKp.keyId,
    },
    idempotency_key: idempotencyKey,
    prev_hash: GENESIS_PREV_HASH,
    payload: {
      version: 1,
      macro_state: macroState,
      tenant_id: tenantId,
      genesis_at_ms: nowMs,
    },
  };

  const signedGenesis = signEvent(genesisEnvelope, humanKp.privateKey, humanKp.keyId);
  const verifyRes = verifyEvent(signedGenesis, humanKp.publicKey);
  if (!verifyRes.ok) {
    const err = new Error(`Genesis signature verification failed: ${verifyRes.reason}`);
    err.exitCode = EXIT_CODES.INTEGRITY_VIOLATION;
    throw err;
  }

  // 5. Append genesis event to ledger and create initial cache
  appendEvent(mirqlDir, signedGenesis);

  return {
    status: "initialized",
    seq: 1,
    hash: signedGenesis.hash,
    event: signedGenesis,
  };
}
