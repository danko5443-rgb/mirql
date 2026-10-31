// packages/inbox/send.mjs — Human Intent ingestion and Warrant issuance (Law 6 & Law 11).
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
import { loadWriterKey, loadKeyring } from "./keys.mjs";
import { getLastEvent, appendEvent } from "./ledger.mjs";

/**
 * Submit human Product Owner intent, mint a valid warrant document in
 * <mirqlDir>/warrants/<warrant_id>.json, and append a signed human.intent event.
 *
 * @param {string} mirqlDir
 * @param {object} intentInput
 * @param {object} [options]
 * @returns {{ status: "sent", intent_id: string, warrant_id: string, seq: number, event: object, warrant: object }}
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

  // 1. Authenticate human:owner Ed25519 key (Law 6)
  const humanKp = loadWriterKey(mirqlDir, "human:owner", options);
  if (!humanKp?.privateKey) {
    const err = new Error("Cryptographic human signature required: no valid private key for human:owner");
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  const keyring = loadKeyring(mirqlDir);
  const trustedHumanPub = keyring["human:owner"] || (humanKp.keyId ? keyring[humanKp.keyId] : null);
  if (trustedHumanPub && humanKp.publicKey && trustedHumanPub !== humanKp.publicKey) {
    const err = new Error("Key verification failed: signing key does not match registered human:owner public key in keyring.json");
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

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

  // 4. Save warrant to <mirqlDir>/warrants/<warrant_id>.json
  const warrantsDir = join(mirqlDir, "warrants");
  mkdirSync(warrantsDir, { recursive: true });
  const warrantFile = join(warrantsDir, `${warrantId}.json`);
  writeFileSync(warrantFile, JSON.stringify(warrantDoc, null, 2) + "\n", "utf8");

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
      summary,
      title,
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

  return {
    status: "sent",
    intent_id: intentId,
    warrant_id: warrantId,
    seq,
    event: signedEvent,
    warrant: warrantDoc,
  };
}
