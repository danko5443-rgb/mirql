// packages/inbox/genesis.mjs — Drop-in .mirql genesis bootstrapper (Law 6).
//
// Remediation B4 (idempotency & integrity):
// - A non-empty ledger whose first event is a valid `mirql.genesis` makes
//   genesis idempotent: `{ status: "already_initialized", seq: 1 }`.
// - A non-empty ledger whose first event is NOT a valid genesis fails closed
//   with INTEGRITY_VIOLATION — genesis never appends to or overwrites a
//   foreign ledger.
// - A pre-existing keyring.json is rebuilt from scratch so attacker-planted
//   entries cannot survive.
//
// Remediation B1 (Law 6): the human:owner private key is written OUTSIDE
// `.mirql/` (`--human-key-out <path>`, default `<operatorDir>/human_owner.key.private.json`)
// with file mode 0o600; `.mirql/keys/` holds factory keys only.
import { mkdirSync, existsSync, statSync, readFileSync, rmSync } from "node:fs";
import { join, dirname, resolve as resolvePath } from "node:path";
import {
  ulid,
  signEvent,
  verifyEvent,
  EXIT_CODES,
  withLedgerLock,
} from "../core/index.mjs";
import {
  generateFactoryKeypairs,
  resolveHumanKeyPath,
  writePrivateFile,
  HUMAN_KEY_FORBIDDEN_FILES,
  HUMAN_WRITER_NS,
} from "./keys.mjs";
import {
  GENESIS_PREV_HASH,
  readEvents,
  appendEvent,
} from "./ledger.mjs";

/** Structured domain error with a machine-readable code for CLI JSON output. */
function domainError(code, message, exitCode) {
  const err = new Error(message);
  err.errorCode = code;
  err.exitCode = exitCode;
  return err;
}

/**
 * Read the first non-empty raw line of the ledger file (or null).
 * @param {string} eventsPath
 * @returns {string | null}
 */
function firstLedgerLine(eventsPath) {
  const content = readFileSync(eventsPath, "utf8");
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return null;
}

/**
 * Remove any stale human private key files inside `.mirql/keys/` (Law 6).
 * @param {string} mirqlDir
 */
function purgeStaleHumanKeys(mirqlDir) {
  const keysDir = join(mirqlDir, "keys");
  for (const name of HUMAN_KEY_FORBIDDEN_FILES) {
    const p = join(keysDir, name);
    if (existsSync(p)) {
      try {
        rmSync(p, { force: true });
      } catch {}
    }
  }
}

/**
 * Initialize a complete drop-in `.mirql/` directory structure,
 * generate factory keypairs for all canonical writers, register public keys
 * in `keyring.json` (namespace-bound), sign + append the genesis event, and
 * persist the human:owner private key OUTSIDE `.mirql/` with mode 0o600.
 *
 * @param {string} mirqlDir - path to .mirql directory
 * @param {object} [options]
 * @param {number} [options.nowMs]
 * @param {string} [options.idempotencyKey]
 * @param {string} [options.tenantId]
 * @param {string} [options.macroState]
 * @param {string} [options.humanKeyOut] - explicit path for the human private key (outside .mirql/)
 * @returns {{ status: "initialized" | "already_initialized", seq: number, hash?: string, event: object, human_key_path?: string }}
 */
export function runGenesis(mirqlDir, options = {}) {
  const dir = resolvePath(mirqlDir);
  return withLedgerLock(dir, () => {

  // 1. Ledger integrity & idempotency check BEFORE any writes (B4).
  const eventsPath = join(dir, "ledger", "events.jsonl");
  if (existsSync(eventsPath) && statSync(eventsPath).size > 0) {
    const firstLine = firstLedgerLine(eventsPath);
    let first = null;
    let parses = false;
    try {
      first = JSON.parse(firstLine ?? "");
      parses = first !== null && typeof first === "object" && !Array.isArray(first);
    } catch {
      parses = false;
    }
    if (parses && first.type === "mirql.genesis" && first.seq === 1) {
      purgeStaleHumanKeys(dir);
      return {
        status: "already_initialized",
        seq: 1,
        hash: first.hash,
        head_hash: first.hash,
        event: first,
      };
    }
    const found = parses && typeof first.type === "string" ? first.type : "unparsable";
    throw domainError(
      "INTEGRITY_VIOLATION",
      `INTEGRITY_VIOLATION: refusing genesis on non-empty ledger whose first event is not a valid mirql.genesis (found: ${found}); refusing to append or overwrite`,
      EXIT_CODES.INTEGRITY_VIOLATION,
    );
  }

  // 2. Initialize directory layout
  mkdirSync(join(dir, "ledger", "snapshots"), { recursive: true });
  mkdirSync(join(dir, "cache"), { recursive: true });
  mkdirSync(join(dir, "keys"), { recursive: true });
  mkdirSync(join(dir, "consensus"), { recursive: true });
  mkdirSync(join(dir, "proposals"), { recursive: true });
  mkdirSync(join(dir, "warrants"), { recursive: true });

  const idempotencyKey = options.idempotencyKey || "genesis-1";

  // 3. Provision all canonical writer keypairs. Factory (machine) keys are
  //    written under <dir>/keys; the human:owner private key is returned and
  //    persisted OUTSIDE .mirql below. keyring.json is rebuilt cleanly (B4).
  const humanKeyOut = resolveHumanKeyPath(dir, options);
  const keypairs = generateFactoryKeypairs(dir, { humanKeyPath: humanKeyOut });
  const humanKp = keypairs[HUMAN_WRITER_NS];
  if (!humanKp?.privateKey) {
    throw domainError(
      "key_provisioning_failed",
      "Failed to provision human:owner keypair for genesis",
      EXIT_CODES.INTEGRITY_VIOLATION,
    );
  }

  // Law 6: persist the human private key outside .mirql, mode 0o600.
  writePrivateFile(
    humanKeyOut,
    JSON.stringify(
      {
        publicKey: humanKp.publicKey,
        privateKey: humanKp.privateKey,
        keyId: humanKp.keyId,
        writer: humanKp.writer,
      },
      null,
      2,
    ) + "\n",
  );

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
    throw domainError(
      "INTEGRITY_VIOLATION",
      `Genesis signature verification failed: ${verifyRes.reason}`,
      EXIT_CODES.INTEGRITY_VIOLATION,
    );
  }

  // 5. Append genesis event to ledger and create initial cache
  appendEvent(dir, signedGenesis);

  return {
    status: "initialized",
    seq: 1,
    hash: signedGenesis.hash,
    head_hash: signedGenesis.hash,
    event: signedGenesis,
    human_key_path: humanKeyOut,
    tenant_id: tenantId,
  };
  });
}
