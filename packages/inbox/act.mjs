// packages/inbox/act.mjs — Cryptographically signed human sovereignty actions (Law 6).
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ulid,
  hlcTick,
  signEvent,
  verifyEvent,
  EXIT_CODES,
} from "../core/index.mjs";
import { loadWriterKey, loadKeyring } from "./keys.mjs";
import { getLastEvent, appendEvent } from "./ledger.mjs";

const VALID_DECISIONS = Object.freeze(["approve", "reject", "kill", "resume"]);

/**
 * Execute a cryptographically signed human decision on an item.
 * Verifies that the action is signed exclusively by human:owner.
 *
 * @param {string} mirqlDir
 * @param {object} actionInput
 * @param {object} [options]
 * @returns {{ status: "acted", decision: string, target_id: string, seq: number, event: object }}
 */
export function actOnItem(mirqlDir, actionInput, options = {}) {
  if (!actionInput || typeof actionInput !== "object") {
    const err = new Error("actionInput must be an object");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const decision = (actionInput.decision || options.decision || "").toLowerCase();
  if (!VALID_DECISIONS.includes(decision)) {
    const err = new Error(`invalid decision ${JSON.stringify(decision)}; expected one of ${VALID_DECISIONS.join(", ")}`);
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const targetId = actionInput.target_id || options["target-id"] || options.targetId;
  if (!targetId || typeof targetId !== "string") {
    const err = new Error("target_id is required (--target-id <id>)");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const reason = actionInput.reason || options.reason || "";

  // 1. Authenticate human:owner Ed25519 key (Law 6 — Silence Is Never Consent)
  const humanKp = loadWriterKey(mirqlDir, "human:owner", options);
  if (!humanKp?.privateKey) {
    const err = new Error("Action rejected: human decisions must carry a valid Ed25519 signature from human:owner");
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  const keyring = loadKeyring(mirqlDir);
  const trustedHumanPub = keyring["human:owner"] || (humanKp.keyId ? keyring[humanKp.keyId] : null);
  if (trustedHumanPub && humanKp.publicKey && trustedHumanPub !== humanKp.publicKey) {
    const err = new Error("Integrity violation: signing key does not match registered human:owner public key in keyring.json");
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  // If a non-human writer key was explicitly passed, deny it unconditionally
  if (options.writer && options.writer !== "human:owner") {
    const err = new Error(`Policy denial: non-human writer ${JSON.stringify(options.writer)} cannot execute human actions (Law 6)`);
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  // 2. Map decision to event type
  let eventType;
  if (decision === "approve") {
    eventType = "human.approval";
  } else if (decision === "reject") {
    eventType = "human.rejection";
  } else if (decision === "kill") {
    eventType = "human.kill";
  } else if (decision === "resume") {
    eventType = "human.approval";
  }

  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const { lastEvent, count, lastHash } = getLastEvent(mirqlDir);
  const seq = count + 1;
  const epoch = typeof lastEvent?.epoch === "number" ? lastEvent.epoch : 1;
  const tenantId = typeof lastEvent?.tenant_id === "string" ? lastEvent.tenant_id : "mirql-core";

  const envelope = {
    v: 1,
    id: ulid(nowMs),
    tenant_id: tenantId,
    seq,
    epoch,
    hlc: hlcTick(lastEvent?.hlc, nowMs, options.node || "local"),
    ts: new Date(nowMs).toISOString(),
    type: eventType,
    writer: {
      ns: "human:owner",
      key_id: humanKp.keyId,
    },
    idempotency_key: options.idempotencyKey || `act:${decision}:${targetId}:${seq}`,
    prev_hash: lastHash,
    payload: {
      decided_at_ms: nowMs,
      decision,
      reason,
      target_id: targetId,
    },
  };

  const signedEvent = signEvent(envelope, humanKp.privateKey, humanKp.keyId);
  const verifyRes = verifyEvent(signedEvent, humanKp.publicKey);
  if (!verifyRes.ok) {
    const err = new Error(`Signature verification failed: ${verifyRes.reason}`);
    err.exitCode = EXIT_CODES.INTEGRITY_VIOLATION;
    throw err;
  }

  // 3. Append to ledger and update state cache
  appendEvent(mirqlDir, signedEvent);

  // 4. If targetId corresponds to a proposal, update its document status
  const proposalFile = join(mirqlDir, "proposals", `${targetId}.json`);
  if (existsSync(proposalFile)) {
    try {
      const prop = JSON.parse(readFileSync(proposalFile, "utf8"));
      prop.status = decision === "approve" ? "approved" : (decision === "reject" ? "rejected" : decision);
      prop.updated_at = new Date(nowMs).toISOString();
      prop.action_reason = reason;
      writeFileSync(proposalFile, JSON.stringify(prop, null, 2) + "\n", "utf8");
    } catch {}
  }

  return {
    status: "acted",
    decision,
    target_id: targetId,
    seq,
    event: signedEvent,
  };
}
