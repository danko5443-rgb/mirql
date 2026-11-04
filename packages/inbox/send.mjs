import { readVerifiedLedger } from "../core/ledger-verify.mjs";
import { isReproducerPath } from "../core/warrant.mjs";
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
  withLedgerLock,
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
  return withLedgerLock(mirqlDir, () => {
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

  // JSON intent budgets are integers; the CLI's decimal flag is parsed explicitly.
  const rawPhiBudget = intentInput.phi_budget !== undefined ? intentInput.phi_budget : options["phi-budget"];
  const phiBudget = intentInput.phi_budget === undefined && typeof rawPhiBudget === "string" && /^(0|[1-9]\d*)$/.test(rawPhiBudget)
    ? Number(rawPhiBudget) : rawPhiBudget;
  if (phiBudget !== undefined && (!Number.isSafeInteger(phiBudget) || phiBudget < 0)) {
    const error = new Error("phi_budget must be a non-negative safe integer");
    error.exitCode = EXIT_CODES.USAGE_ERROR;
    throw error;
  }

  // The daemon verifies an attempt against the reproducer the owner signed here.
  const reproducerRaw = intentInput.reproducer_test ?? options.reproducer;
  if (reproducerRaw !== undefined && !isReproducerPath(reproducerRaw)) {
    const error = new Error("The reproducer must be a repository-relative path with forward slashes (--reproducer <path>)");
    error.exitCode = EXIT_CODES.USAGE_ERROR;
    throw error;
  }

  // 0. The ledger must be initialized (first event is mirql.genesis).
  requireGenesisLedger(mirqlDir);

  // 1. Authenticate human:owner Ed25519 key — explicit credentials only (Law 6).
  //    authenticateHumanWriter throws credentials_required /
  //    namespace_binding_violation / key_mismatch as POLICY_DENIAL.
  const humanKp = authenticateHumanWriter(mirqlDir, options);

  const conflict = () => {
    const error = new Error("Idempotency conflict: this key already names a different signed submission");
    error.code = error.errorCode = "IDEMPOTENCY_CONFLICT";
    error.exitCode = EXIT_CODES.POLICY_DENIAL;
    return error;
  };
  if (options.idempotencyKey !== undefined && (typeof options.idempotencyKey !== "string" || !options.idempotencyKey.trim())) {
    const error = new Error("Idempotency key must be a nonempty string");
    error.exitCode = EXIT_CODES.USAGE_ERROR;
    throw error;
  }
  const events = readVerifiedLedger(mirqlDir);
  const previous = options.idempotencyKey ? events.find(event =>
    event.writer.ns === "human:owner" && event.idempotency_key === options.idempotencyKey) : null;
  if (previous && previous.type !== "human.intent") throw conflict();
  if (!previous && options.idempotencyKey && events.some(event =>
      event.writer.ns === "human:owner" && event.idempotency_key === options.idempotencyKey + ":warrant")) {
    throw conflict();
  }

  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const warrantId = previous?.payload.warrant_id ?? ulid(nowMs);
  const warrantClass = kind === "bug" ? "surgical" : (/^[a-z][a-z0-9_]{1,63}$/.test(kind) ? kind : "feature");

  // 2. Compute semantic fingerprint over canonical intent statement
  const intentSummary = {
    class: warrantClass,
    kind,
    red_check: redCheckCmd,
    scope: anchors,
    summary,
    title,
    ...(reproducerRaw !== undefined ? { reproducer_test: reproducerRaw } : {}),
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
      ...(reproducerRaw !== undefined ? { reproducer_test: reproducerRaw } : {}),
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
    ...(phiBudget !== undefined ? { phi_budget: phiBudget } : {}),
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
  if (previous && (previous.payload.warrant_hash !== warrantHash ||
      previous.payload.semantic_fingerprint !== semanticFingerprint ||
      previous.payload.intent_id !== `intent_${warrantId}`)) throw conflict();

  // 5. Append signed human.intent event to ledger
  const { lastEvent, count, lastHash } = getLastEvent(mirqlDir);
  const seq = previous?.seq ?? count + 1;
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

  const signedEvent = previous ?? signEvent(envelope, humanKp.privateKey, humanKp.keyId);
  const verifyRes = verifyEvent(signedEvent, humanKp.publicKey);
  if (!verifyRes.ok) {
    const err = new Error(`Signature verification failed for human.intent: ${verifyRes.reason}`);
    err.exitCode = EXIT_CODES.INTEGRITY_VIOLATION;
    throw err;
  }

  if (!previous) {
    const validation = validateDocument("event", signedEvent);
    if (!validation.valid) throw new Error("Invalid intent envelope: " + validation.errors.join(", "));
    appendEvent(mirqlDir, signedEvent);
  }

  // Recover a missing grant from the committed intent, chained to the actual head.
  const persisted = readVerifiedLedger(mirqlDir);
  const head = persisted.at(-1);
  const grantKey = signedEvent.idempotency_key + ":warrant";
  const grantPayload = {
    warrant_id: warrantId, warrant_hash: warrantHash, semantic_fingerprint: semanticFingerprint,
    anchors, scope: warrantDoc.scope, evidence: warrantDoc.evidence,
    red_check: warrantDoc.red_check, budget_micro_usd: budget,
    created_by: "human:owner", role: "builder", tier: "flash", status: "active", intent_id: intentId,
  };
  let warrantEvent = persisted.find(event => event.writer.ns === "human:owner" && event.idempotency_key === grantKey);
  if (warrantEvent && (warrantEvent.type !== "warrant.created" || jcs(warrantEvent.payload) !== jcs(grantPayload))) {
    throw conflict();
  }
  if (!warrantEvent) {
    warrantEvent = signEvent({
      ...envelope,
      id: ulid(nowMs + 1),
      seq: head.seq + 1,
      epoch: head.epoch,
      hlc: hlcTick(head.hlc, nowMs, options.node || "local"),
      type: "warrant.created",
      idempotency_key: grantKey,
      prev_hash: head.hash,
      payload: grantPayload,
    }, humanKp.privateKey, humanKp.keyId);
    const validation = validateDocument("event", warrantEvent);
    if (!validation.valid) throw new Error("Invalid warrant grant envelope: " + validation.errors.join(", "));
    appendEvent(mirqlDir, warrantEvent);
  }

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
    warrant_event: warrantEvent,
    warrant: warrantDoc,
  };
});
}
