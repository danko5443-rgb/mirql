// packages/inbox/send.mjs — Human Intent ingestion and Warrant issuance (Law 6 & Law 11).
//
// Remediation B1 (Law 6): the human:owner signing key is never loaded
// implicitly from `.mirql/keys/`. Callers must pass `--key <path>` /
// `--signing-key <material>` or set `MIRQL_HUMAN_KEY` (outside `.mirql/`);
// otherwise the call fails closed with POLICY_DENIAL.
//
// Remediation B7 (Law 11 & 15): the human.intent event anchors the warrant
// document cryptographically — `warrant_hash = sha256(jcs(warrantDoc))` and
// the warrant's `semantic_fingerprint` are embedded in the event payload,
// and the warrant file is written to disk only AFTER the ledger append
// succeeds.
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  ulid,
  hlcTick,
  sha256,
  jcs,
  signEvent,
  verifyEvent,
  validateDocument,
  EXIT_CODES,
} from "../core/index.mjs";
import { authenticateHumanWriter } from "./keys.mjs";
import { getLastEvent, appendEvent, requireGenesisLedger } from "./ledger.mjs";

/**
 * Submit human Product Owner intent, mint a valid warrant document, append a
 * signed human.intent event anchoring the warrant (warrant_hash +
 * semantic_fingerprint), and only then persist the warrant document to
 * <mirqlDir>/warrants/<warrant_id>.json.
 *
 * @param {string} mirqlDir
 * @param {object} intentInput
 * @param {object} [options]
 * @returns {{ status: "sent", intent_id: string, warrant_id: string, warrant_hash: string, seq: number, event: object, warrant: object }}
 */
export function sendIntent(mirqlDir, intentInput, options = {}) {
  if (!intentInput || typeof intentInput !== "object") {
    const err = new Error("intentInput must be a valid JSON object");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const title = (intentInput.title || options.title || "").trim();
  if (!title) {
    const err = new Error("Intent title is required (--title <str>)");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const kind = (intentInput.kind || options.kind || "feature").toLowerCase();
  const summary = (intentInput.summary || intentInput.description || options.summary || options.description || "").trim();
  const scopeRaw = intentInput.scope || options.scope || "packages/**";
  const anchors = Array.isArray(scopeRaw) ? scopeRaw : scopeRaw.split(",").map((s) => s.trim()).filter(Boolean);
  if (anchors.length === 0) anchors.push("packages/**");

  const redCheckCmd = typeof intentInput.red_check === "string"
    ? intentInput.red_check
    : (typeof options["red-check"] === "string"
      ? options["red-check"]
      : (intentInput.red_check?.command || "npm test"));

  const rawBudget = intentInput.budget_micro_usd ?? intentInput.budget ?? options.budget ?? 1500000;
  const budget = Number(rawBudget);
  if (!Number.isSafeInteger(budget) || budget < 0) {
    const err = new Error(`budget_micro_usd must be a non-negative safe integer: got ${rawBudget}`);
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  // 0. The ledger must be initialized (first event is mirql.genesis).
  requireGenesisLedger(mirqlDir);

  // 1. Authenticate human:owner Ed25519 key — explicit credentials only (Law 6).
  //    authenticateHumanWriter throws credentials_required /
  //    namespace_binding_violation / key_mismatch as POLICY_DENIAL.
  const humanKp = authenticateHumanWriter(mirqlDir, options);

  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const warrantId = ulid(nowMs);
  const warrantClass = kind === "bug" ? "surgical" : (/^[a-z][a-z0-9_]{1,63}$/.test(kind) ? kind : "feature");

  // 2. Compute semantic fingerprint over canonical intent statement
  const intentSummary = {
    class: warrantClass,
    kind,
    red_check: redCheckCmd,
    scope: anchors,
    summary,
    title,
  };
  const semanticFingerprint = sha256(jcs(intentSummary));

  // 3. Mint schema-valid Warrant document (warrant.schema.json)
  const warrantDoc = {
    v: 1,
    id: warrantId,
    class: warrantClass,
    semantic_fingerprint: semanticFingerprint,
    anchors,
    evidence: {
      kind,
      summary,
      title,
    },
    red_check: {
      command: redCheckCmd,
      passed: false,
    },
    scope: {
      allow: anchors,
      deny: [],
    },
    budget_micro_usd: budget,
    created_by: "human:owner",
  };

  const warrantValidation = validateDocument("warrant", warrantDoc);
  if (!warrantValidation.valid) {
    const err = new Error(`Generated warrant document violates warrant.schema.json: ${warrantValidation.errors.join("; ")}`);
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  // 4. B7: anchor the warrant document cryptographically.
  const warrantHash = sha256(jcs(warrantDoc));

  // 5. Append signed human.intent event to ledger
  const { lastEvent, count, lastHash } = getLastEvent(mirqlDir);
  const seq = count + 1;
  const epoch = typeof lastEvent?.epoch === "number" ? lastEvent.epoch : 1;
  const tenantId = typeof lastEvent?.tenant_id === "string" ? lastEvent.tenant_id : "mirql-core";
  const intentId = `intent_${warrantId}`;

  const envelope = {
    v: 1,
    id: ulid(nowMs),
    tenant_id: tenantId,
    seq,
    epoch,
    hlc: hlcTick(lastEvent?.hlc, nowMs, options.node || "local"),
    ts: new Date(nowMs).toISOString(),
    type: "human.intent",
    writer: {
      ns: "human:owner",
      key_id: humanKp.keyId,
    },
    idempotency_key: options.idempotencyKey || `intent:${warrantId}`,
    prev_hash: lastHash,
    payload: {
      budget_micro_usd: budget,
      intent_id: intentId,
      kind: warrantClass,
      red_check: redCheckCmd,
      scope: anchors,
      semantic_fingerprint: semanticFingerprint,
      summary,
      title,
      warrant_hash: warrantHash,
      warrant_id: warrantId,
    },
  };

  const signedEvent = signEvent(envelope, humanKp.privateKey, humanKp.keyId);
  const verifyRes = verifyEvent(signedEvent, humanKp.publicKey);
  if (!verifyRes.ok) {
    const err = new Error(`Signature verification failed for human.intent: ${verifyRes.reason}`);
    err.exitCode = EXIT_CODES.INTEGRITY_VIOLATION;
    throw err;
  }

  appendEvent(mirqlDir, signedEvent);

  // 6. B7: persist the warrant document only AFTER ledger.append succeeded.
  const warrantsDir = join(mirqlDir, "warrants");
  mkdirSync(warrantsDir, { recursive: true });
  const warrantFile = join(warrantsDir, `${warrantId}.json`);
  writeFileSync(warrantFile, JSON.stringify(warrantDoc, null, 2) + "\n", "utf8");

  return {
    status: "sent",
    intent_id: intentId,
    warrant_id: warrantId,
    warrant_hash: warrantHash,
    seq,
    event: signedEvent,
    warrant: warrantDoc,
  };
}
