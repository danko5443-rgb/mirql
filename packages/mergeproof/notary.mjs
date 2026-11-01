// packages/mergeproof/notary.mjs — the mergeproof notary (Law 7: the notary
// sits OUTSIDE the blast radius of the agents whose work it judges).
//
// Responsibilities:
// - Load or generate the `notary:mergeproof` Ed25519 keypair:
//     1. an explicit key file (--key <path>), never inside agent sandboxes;
//     2. <mirqlDir>/keys/notary.key.json (provisioned by `mirql i genesis`);
//     3. <mirqlDir>/keys/mergeproof.key.json (W2 alias);
//     4. else generate + persist to keys/notary.key.json with mode 0o600
//        (H4) and register the public key in ledger/keyring.json.
// - Sign verdict documents into canonical JCS Ed25519 event envelopes under
//   writer { ns: "notary:mergeproof", key_id } (Law 3 single-writer ACL).
// - Append signed verdicts (verdict.issued / verdict.rejected /
//   verdict.needs_human / verdict.accepted) to <mirqlDir>/ledger/events.jsonl
//   under withLedgerLock, hash-chained onto the ledger head.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve as resolvePath } from "node:path";
import {
  EXIT_CODES,
  generateEd25519Keypair,
  hlcTick,
  jcs,
  jcsHash,
  sha256,
  signEvent,
  ulid,
  validateDocument,
  verifyEvent,
  withLedgerLock,
} from "../core/index.mjs";

/** The single-writer namespace of the mergeproof notary (Law 3). */
export const NOTARY_WRITER_NS = "notary:mergeproof";

/** Default notary key file inside <mirqlDir>/keys/. */
export const NOTARY_KEY_FILE = "notary.key.json";

/** W2 alias key file inside <mirqlDir>/keys/. */
export const NOTARY_KEY_ALIAS_FILE = "mergeproof.key.json";

/** prev_hash anchor of the very first event in any ledger. */
export const GENESIS_PREV_HASH = `sha256:${"0".repeat(64)}`;

/**
 * Maps a mergeproof verdict to its canonical ledger event type (Law 3 ACL:
 * notary:mergeproof may emit verdict.*, promotion.*, merge.*).
 */
export const VERDICT_EVENT_TYPES = Object.freeze({
  auto_merge: "verdict.issued",
  reject: "verdict.rejected",
  needs_human: "verdict.needs_human",
  accepted: "verdict.accepted",
});

/**
 * Structured domain error carrying a canonical EXIT_CODES name.
 *
 * @param {"USAGE_ERROR" | "INTEGRITY_VIOLATION" | "POLICY_DENIAL"} code
 * @param {string} message
 * @returns {Error & { code: string, exitCode: number }}
 */
export function notaryError(code, message) {
  const err = new Error(message);
  err.name = "NotaryError";
  err.code = code;
  err.exitCode = EXIT_CODES[code] ?? EXIT_CODES.DOMAIN_NEGATIVE;
  return err;
}

/**
 * Write a file containing private key material with mode 0o600 (H4); the
 * parent directory is created 0o700 (best-effort re-chmod on platforms that
 * ignore directory mode bits).
 *
 * @param {string} filePath
 * @param {string} contents
 */
function writePrivateFile(filePath, contents) {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {}
  writeFileSync(filePath, contents, { encoding: "utf8", mode: 0o600 });
  try {
    chmodSync(filePath, 0o600);
  } catch {}
}

/**
 * Read and structurally validate a keypair JSON document.
 *
 * @param {string} filePath
 * @returns {{ privateKey: string, publicKey: string, keyId: string } | null}
 */
function readKeypairFile(filePath) {
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      typeof parsed.privateKey === "string" &&
      typeof parsed.publicKey === "string" &&
      typeof parsed.keyId === "string"
    ) {
      return parsed;
    }
  } catch {}
  return null;
}

/**
 * Verify a keypair document is internally consistent by re-deriving the
 * signature over a probe envelope (the public key can never be spoofed).
 *
 * @param {{ privateKey: string, publicKey: string, keyId: string }} kp
 * @returns {boolean}
 */
function keypairIsCoherent(kp) {
  try {
    const probe = { probe: ulid() };
    const signed = signEvent(probe, kp.privateKey, kp.keyId);
    return verifyEvent(signed, kp.publicKey).ok;
  } catch {
    return false;
  }
}

/**
 * Register the notary public key in <mirqlDir>/ledger/keyring.json under both
 * its keyId and its namespace (namespace-bound entries, Law 3).
 *
 * @param {string} mirqlDir
 * @param {{ keyId: string, publicKey: string }} kp
 * @returns {void}
 */
function updateKeyring(mirqlDir, kp) {
  const ledgerDir = join(mirqlDir, "ledger");
  mkdirSync(ledgerDir, { recursive: true, mode: 0o700 });
  const keyringPath = join(ledgerDir, "keyring.json");
  let keyring = {};
  if (existsSync(keyringPath)) {
    try {
      keyring = JSON.parse(readFileSync(keyringPath, "utf8")) ?? {};
    } catch (err) {
      throw notaryError(
        "INTEGRITY_VIOLATION",
        `Corrupt keyring file at ${keyringPath}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  if (keyring[kp.keyId]?.publicKey === kp.publicKey) return;
  const entry = { ns: NOTARY_WRITER_NS, publicKey: kp.publicKey };
  keyring[kp.keyId] = entry;
  keyring[NOTARY_WRITER_NS] = entry;
  writeFileSync(keyringPath, jcs(keyring) + "\n", { encoding: "utf8", mode: 0o600 });
}

/**
 * Load or generate the notary keypair. Resolution order:
 *   1. options.keyPath / options.key  — explicit key file (--key)
 *   2. <mirqlDir>/keys/notary.key.json
 *   3. <mirqlDir>/keys/mergeproof.key.json (alias)
 *   4. generate fresh, persist to keys/notary.key.json (0o600) + keyring
 *
 * @param {string} mirqlDir
 * @param {{ keyPath?: string, key?: string }} [options]
 * @returns {{ privateKey: string, publicKey: string, keyId: string, sourceFile: string }}
 * @throws NotaryError when an explicit key file is unusable
 */
export function loadOrCreateNotaryKey(mirqlDir, options = {}) {
  const explicit = options.keyPath ?? options.key;
  if (typeof explicit === "string" && explicit.length > 0) {
    const abs = resolvePath(explicit);
    const kp = readKeypairFile(abs);
    if (kp === null || !keypairIsCoherent(kp)) {
      throw notaryError(
        "USAGE_ERROR",
        `--key ${explicit} is not a valid Ed25519 keypair document ({ privateKey, publicKey, keyId })`,
      );
    }
    return { ...kp, sourceFile: abs };
  }

  const keysDir = join(mirqlDir, "keys");
  for (const name of [NOTARY_KEY_FILE, NOTARY_KEY_ALIAS_FILE]) {
    const keyPath = join(keysDir, name);
    if (existsSync(keyPath)) {
      const kp = readKeypairFile(keyPath);
      if (kp !== null && keypairIsCoherent(kp)) {
        return { ...kp, sourceFile: keyPath };
      }
      throw notaryError(
        "INTEGRITY_VIOLATION",
        `Corrupt notary keypair at ${keyPath}; delete it or pass --key <path>`,
      );
    }
  }

  const generated = generateEd25519Keypair();
  const keyPath = join(keysDir, NOTARY_KEY_FILE);
  writePrivateFile(keyPath, JSON.stringify(generated, null, 2) + "\n");
  updateKeyring(mirqlDir, generated);
  return { ...generated, sourceFile: keyPath };
}

/**
 * Read the ledger, returning parsed events paired with their raw canonical
 * lines (raw lines matter for fixture ledgers whose linkage is the SHA-256
 * of the previous raw line rather than an envelope hash field).
 *
 * @param {string} mirqlDir
 * @returns {{ events: object[], rawLines: string[] }}
 */
export function readLedgerEvents(mirqlDir) {
  const file = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(file)) return { events: [], rawLines: [] };
  const rawLines = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length > 0) rawLines.push(trimmed);
  }
  return { events: rawLines.map((raw) => JSON.parse(raw)), rawLines };
}

/**
 * Build the integer-only verdict payload (Law 17) from a verdict document.
 * The payload records the judgment, never the judged agent's secrets.
 *
 * @param {object} verdictDoc the evaluator result + PR identity
 * @returns {object}
 */
export function verdictPayload(verdictDoc = {}) {
  const pr = verdictDoc.pr ?? {};
  const payload = {
    verdict: verdictDoc.verdict ?? "reject",
    rule: verdictDoc.rule ?? null,
    violation: verdictDoc.violation ?? null,
    job_id: typeof verdictDoc.job_id === "string" ? verdictDoc.job_id : null,
    warrant_id:
      typeof verdictDoc.warrant_id === "string" ? verdictDoc.warrant_id : null,
    pr_number: Number.isSafeInteger(pr.number) ? pr.number : null,
    pr_kind: typeof pr.kind === "string" ? pr.kind : null,
    head_sha: typeof pr.head_sha === "string" ? pr.head_sha : null,
    base_sha: typeof pr.base_sha === "string" ? pr.base_sha : null,
    delta_phi: Number.isSafeInteger(verdictDoc.delta_phi)
      ? verdictDoc.delta_phi
      : null,
  };
  return payload;
}

/**
 * Build and sign one verdict event envelope chained onto the given ledger
 * tail. Pure with respect to the ledger files — callers hold the lock.
 *
 * @param {object[]} events parsed ledger events
 * @param {string[]} rawLines raw ledger lines
 * @param {object} verdictDoc
 * @param {{ privateKey: string, publicKey: string, keyId: string }} keypair
 * @param {{ nowMs?: number, epoch?: number, node?: string, tenantId?: string, eventType?: string }} [options]
 * @returns {object} signed event envelope
 * @throws NotaryError for an unmappable verdict or schema violation
 */
export function buildVerdictEvent(events, rawLines, verdictDoc, keypair, options = {}) {
  const verdict = verdictDoc.verdict;
  const eventType =
    options.eventType ??
    VERDICT_EVENT_TYPES[verdict] ??
    null;
  if (typeof eventType !== "string") {
    throw notaryError(
      "USAGE_ERROR",
      `verdict ${JSON.stringify(verdict)} has no canonical event type (expected one of ${Object.keys(VERDICT_EVENT_TYPES).join(", ")})`,
    );
  }

  const last = events.at(-1) ?? null;
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const seq = (typeof last?.seq === "number" ? last.seq : 0) + 1;
  const prevHash = last
    ? typeof last.hash === "string" && last.hash.length > 0
      ? last.hash
      : sha256(rawLines.at(-1) ?? jcs(last))
    : GENESIS_PREV_HASH;

  const payload = verdictPayload(verdictDoc);
  const idem =
    typeof verdictDoc.idempotency_key === "string"
      ? verdictDoc.idempotency_key
      : `mergeproof:${payload.job_id ?? `pr-${payload.pr_number}`}:${payload.head_sha ?? "?"}:${eventType}`;

  const unsigned = {
    v: 1,
    id: typeof verdictDoc.event_id === "string" ? verdictDoc.event_id : ulid(nowMs),
    tenant_id:
      typeof options.tenantId === "string" ? options.tenantId : "mirql-core",
    seq,
    epoch: Number.isSafeInteger(options.epoch)
      ? options.epoch
      : Number.isSafeInteger(last?.epoch)
        ? last.epoch
        : 1,
    hlc: hlcTick(last?.hlc, nowMs, options.node ?? "notary"),
    ts: new Date(nowMs).toISOString(),
    type: eventType,
    writer: { ns: NOTARY_WRITER_NS, key_id: keypair.keyId },
    idempotency_key: idem,
    prev_hash: prevHash,
    payload,
  };

  const signed = signEvent(unsigned, keypair.privateKey, keypair.keyId);

  // Fail closed: the envelope must satisfy the canonical event schema and
  // its own signature before it may approach the ledger.
  const schemaCheck = validateDocument("event", signed);
  if (!schemaCheck.valid) {
    throw notaryError(
      "USAGE_ERROR",
      `signed verdict event rejected by the canonical event schema: ${schemaCheck.errors.join("; ")}`,
    );
  }
  const sigCheck = verifyEvent(signed, keypair.publicKey);
  if (!sigCheck.ok) {
    throw notaryError(
      "INTEGRITY_VIOLATION",
      `verdict signature self-check failed: ${sigCheck.reason ?? "unknown reason"}`,
    );
  }
  return signed;
}

/**
 * Sign a verdict document and append it to <mirqlDir>/ledger/events.jsonl
 * under withLedgerLock. Retrying the same verdict is idempotent (Law 4):
 * an existing (writer.ns, idempotency_key) pair dedupes instead of
 * double-appending.
 *
 * @param {string} mirqlDir
 * @param {object} verdictDoc evaluator result + PR identity
 * @param {{ keyPath?: string, key?: string, keypair?: object, nowMs?: number, eventType?: string, append?: boolean }} [options]
 * @returns {{ status: "appended" | "deduped", seq: number, hash: string, type: string, event: object, appended: boolean }}
 * @throws NotaryError USAGE_ERROR / INTEGRITY_VIOLATION
 */
export function signAndAppendVerdict(mirqlDir, verdictDoc, options = {}) {
  const dir = resolvePath(mirqlDir);
  return withLedgerLock(dir, () => {
    const keypair =
      options.keypair ??
      loadOrCreateNotaryKey(dir, { keyPath: options.keyPath, key: options.key });

    const { events, rawLines } = readLedgerEvents(dir);

    // Idempotency dedup (Law 4) scoped by writer namespace.
    const probe = buildVerdictEvent(events, rawLines, verdictDoc, keypair, options);
    const existing = events.find(
      (e) =>
        e?.idempotency_key === probe.idempotency_key &&
        (e?.writer?.ns ?? e?.writer) === NOTARY_WRITER_NS,
    );
    if (existing !== undefined) {
      return {
        status: "deduped",
        seq: existing.seq,
        hash: existing.hash ?? jcsHash(existing),
        type: existing.type,
        event: existing,
        appended: false,
      };
    }

    mkdirSync(join(dir, "ledger"), { recursive: true });
    const eventsFile = join(dir, "ledger", "events.jsonl");
    writeFileSync(
      eventsFile,
      jcs(probe) + "\n",
      { encoding: "utf8", flag: "a" },
    );

    return {
      status: "appended",
      seq: probe.seq,
      hash: probe.hash,
      type: probe.type,
      event: probe,
      appended: true,
    };
  });
}
