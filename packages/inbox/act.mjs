// packages/inbox/act.mjs — Cryptographically signed human sovereignty actions (Law 6, Law 11, Law 16).
//
// Remediation B1 (Law 6): human:owner credentials are never loaded
// implicitly; `--key <path>` / `--signing-key <material>` or MIRQL_HUMAN_KEY
// (outside `.mirql/`) is required, otherwise the action fails closed with
// POLICY_DENIAL (`credentials_required`).
//
// Remediation B5: `--decision resume` emits `mirql.resume` (signed by
// human:owner, authorized by policy/writers.yaml and the reconciled Law 3
// ACL) — NOT `human.approval` — so both the mirql-queue and mirql-log folds
// lift the halt state cleanly.
//
// Remediation B8: target_id must be a Crockford ULID; lookup is confined to
// `.mirql/proposals/<target_id>.json` with directory traversal rejected.
//
// Milestone M6: 1-Tap Proposer approval ceremony converts approved proposals
// directly into active warrants, persisting the warrant document and emitting
// signed `warrant.created` to the durable ledger (Law 6, Law 11, Law 16).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  ulid,
  hlcTick,
  signEvent,
  verifyEvent,
  sha256,
  jcs,
  validateDocument,
  EXIT_CODES,
  withLedgerLock,
} from "../core/index.mjs";
import { authenticateHumanWriter } from "./keys.mjs";
import { getLastEvent, appendEvent, requireGenesisLedger } from "./ledger.mjs";

const VALID_DECISIONS = Object.freeze(["approve", "reject", "kill", "resume"]);

/** Crockford Base32 ULID (matches schemas/event.schema.json id pattern). */
const ULID_PATTERN = /^[0-9A-HJKMNPQRSTVWXYZ]{26}$/;

/** Structured domain error with a machine-readable code for CLI JSON output. */
function domainError(code, message, exitCode) {
  const err = new Error(message);
  err.errorCode = code;
  err.exitCode = exitCode;
  return err;
}

/**
 * Validate and confine a target id: strict Crockford ULID, no directory
 * traversal (`..`, `/`, `\`), lookup confined to .mirql/proposals/<id>.json.
 *
 * @param {unknown} targetId
 * @returns {string} the validated target id
 * @throws structured Error (invalid_target_id, USAGE_ERROR)
 */
function validateTargetId(targetId) {
  if (typeof targetId !== "string" || targetId.length === 0) {
    throw domainError(
      "invalid_target_id",
      "invalid_target_id: target_id is required (--target-id <26-char Crockford ULID>)",
      EXIT_CODES.USAGE_ERROR,
    );
  }
  if (
    targetId.includes("..") ||
    targetId.includes("/") ||
    targetId.includes("\\") ||
    !ULID_PATTERN.test(targetId)
  ) {
    throw domainError(
      "invalid_target_id",
      `invalid_target_id: ${JSON.stringify(targetId)} is not a 26-char Crockford ULID; directory traversal is rejected and lookup is confined to .mirql/proposals/<id>.json`,
      EXIT_CODES.USAGE_ERROR,
    );
  }
  return targetId;
}

/**
 * Execute a cryptographically signed human decision on an inbox item.
 * Verifies that the action is signed exclusively by human:owner.
 *
 * @param {string} mirqlDir
 * @param {object} actionInput
 * @param {object} [options]
 * @returns {{
 *   status: "acted",
 *   decision: string,
 *   target_id: string,
 *   seq: number,
 *   event: object,
 *   warrant_id?: string,
 *   warrant?: object,
 *   warrant_event?: object
 * }}
 */
export function actOnItem(mirqlDir, actionInput, options = {}) {
  return withLedgerLock(mirqlDir, () => {
    if (!actionInput || typeof actionInput !== "object") {
      throw domainError("invalid_input", "actionInput must be an object", EXIT_CODES.USAGE_ERROR);
    }

    const decision = (actionInput.decision || options.decision || "").toLowerCase();
    if (!VALID_DECISIONS.includes(decision)) {
      throw domainError(
        "invalid_decision",
        `invalid_decision ${JSON.stringify(decision)}; expected one of ${VALID_DECISIONS.join(", ")}`,
        EXIT_CODES.USAGE_ERROR,
      );
    }

    const targetId = validateTargetId(
      actionInput.target_id || options["target-id"] || options.targetId,
    );

    const reason = actionInput.reason || options.reason || "";

    // 1. Authenticate human:owner Ed25519 key — explicit credentials only.
    //    (Law 6 — Silence Is Never Consent; fail closed with
    //    credentials_required when no key is provided.)
    requireGenesisLedger(mirqlDir);
    const humanKp = authenticateHumanWriter(mirqlDir, options);

    // 2. B8: confine target lookup strictly to .mirql/proposals/<target_id>.json
    //    and require the file to exist before acting.
    const proposalFile = join(mirqlDir, "proposals", `${targetId}.json`);
    let prop = null;
    if (decision !== "resume") {
      if (!existsSync(proposalFile)) {
        throw domainError(
          "target_not_found",
          `target_not_found: no proposal document at proposals/${targetId}.json`,
          EXIT_CODES.USAGE_ERROR,
        );
      }
      try {
        prop = JSON.parse(readFileSync(proposalFile, "utf8"));
      } catch (parseErr) {
        throw domainError(
          "corrupt_proposal",
          `corrupt_proposal: unable to parse proposals/${targetId}.json: ${parseErr.message}`,
          EXIT_CODES.USAGE_ERROR,
        );
      }

      // B2: Check that proposal is currently pending before approve or reject
      if (decision === "approve" || decision === "reject") {
        if (prop.status && prop.status !== "pending") {
          throw domainError(
            "invalid_proposal_state",
            `invalid_proposal_state: proposal ${targetId} is already "${prop.status}" and cannot be ${decision}d again`,
            EXIT_CODES.POLICY_DENIAL,
          );
        }
      }
    }

    // 3. Map decision to event type. B5: resume emits `mirql.resume` so both
    //    the queue and log folds lift the halt cleanly (not human.approval).
    let eventType;
    if (decision === "approve") {
      eventType = "human.approval";
    } else if (decision === "reject") {
      eventType = "human.rejection";
    } else if (decision === "kill") {
      eventType = "human.kill";
    } else {
      eventType = "mirql.resume";
    }

    const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
    const { lastEvent, count, lastHash } = getLastEvent(mirqlDir);
    const seq = count + 1;
    const epoch = typeof lastEvent?.epoch === "number" ? lastEvent.epoch : 1;
    const tenantId = typeof lastEvent?.tenant_id === "string" ? lastEvent.tenant_id : "mirql-core";

    // Pre-construct and validate warrant document if decision is approve (B3: Atomicity)
    let warrantId = null;
    let warrantDoc = null;
    let warrantHash = null;
    let semanticFingerprint = null;
    let anchors = null;
    let budget = null;

    if (decision === "approve" && prop) {
      warrantId = ulid(nowMs + 1);
      const warrantClass =
        prop.kind === "bug" || prop.kind === "bugfix"
          ? "surgical"
          : (/^[a-z][a-z0-9_]{1,63}$/.test(prop.kind || "") ? prop.kind : "feature");
      const redCheckCmd = prop.red_check || "npm test";
      anchors = Array.isArray(prop.scope)
        ? prop.scope
        : (prop.scope ? [prop.scope] : ["packages/**"]);
      budget = Number.isSafeInteger(prop.budget_micro_usd) ? prop.budget_micro_usd : 1500000;

      const evidenceObj = {
        kind: prop.kind || "feature",
        proposal_id: targetId,
        summary: prop.description || prop.title || "",
        title: prop.title || "",
      };

      const intentSummary = {
        class: warrantClass,
        kind: prop.kind || "feature",
        red_check: redCheckCmd,
        scope: anchors,
        summary: prop.description || prop.title || "",
        title: prop.title || "",
      };
      semanticFingerprint = sha256(jcs(intentSummary));

      warrantDoc = {
        v: 1,
        id: warrantId,
        class: warrantClass,
        semantic_fingerprint: semanticFingerprint,
        anchors,
        evidence: evidenceObj,
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
        throw domainError(
          "invalid_warrant",
          `Generated warrant document violates warrant.schema.json: ${warrantValidation.errors.join("; ")}`,
          EXIT_CODES.USAGE_ERROR,
        );
      }
      warrantHash = sha256(jcs(warrantDoc));
    }

    // Deterministic deduplication idempotency key (B2)
    const idempotencyKey = options.idempotencyKey || `act:${decision}:${targetId}`;

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
      idempotency_key: idempotencyKey,
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
      throw domainError(
        "INTEGRITY_VIOLATION",
        `Signature verification failed: ${verifyRes.reason}`,
        EXIT_CODES.INTEGRITY_VIOLATION,
      );
    }

    // 4. Append human action to ledger and update state cache (all validations passed)
    appendEvent(mirqlDir, signedEvent);

    let warrantEvent = null;

    // 5. If targetId corresponds to a proposal, update its document status and write warrant.
    if (decision !== "resume" && prop) {
      prop.status = decision === "approve" ? "approved" : (decision === "reject" ? "rejected" : decision);
      prop.updated_at = new Date(nowMs).toISOString();
      prop.action_reason = reason;

      if (decision === "approve" && warrantDoc) {
        const warrantsDir = join(mirqlDir, "warrants");
        mkdirSync(warrantsDir, { recursive: true });
        const warrantFile = join(warrantsDir, `${warrantId}.json`);
        writeFileSync(warrantFile, JSON.stringify(warrantDoc, null, 2) + "\n", "utf8");

        // Append signed warrant.created event to ledger
        const latest = getLastEvent(mirqlDir);
        const warrantSeq = latest.count + 1;
        const warrantEnvelope = {
          v: 1,
          id: ulid(nowMs + 2),
          tenant_id: tenantId,
          seq: warrantSeq,
          epoch,
          hlc: hlcTick(latest.lastEvent?.hlc, nowMs, options.node || "local"),
          ts: new Date(nowMs).toISOString(),
          type: "warrant.created",
          writer: {
            ns: "human:owner",
            key_id: humanKp.keyId,
          },
          idempotency_key: options.idempotencyKey
            ? `${options.idempotencyKey}:warrant`
            : `warrant:${targetId}`,
          prev_hash: latest.lastHash,
          payload: {
            anchors,
            budget_micro_usd: budget,
            evidence: warrantDoc.evidence,
            id: warrantId,
            intent_id: targetId,
            proposal_id: targetId,
            red_check: warrantDoc.red_check,
            role: "builder",
            scope: warrantDoc.scope,
            semantic_fingerprint: semanticFingerprint,
            status: "active",
            tier: "flash",
            warrant_hash: warrantHash,
            warrant_id: warrantId,
          },
        };

        const signedWarrantEvent = signEvent(warrantEnvelope, humanKp.privateKey, humanKp.keyId);
        appendEvent(mirqlDir, signedWarrantEvent);
        warrantEvent = signedWarrantEvent;

        prop.warrant_id = warrantId;
        prop.warrant_hash = warrantHash;
      }

      writeFileSync(proposalFile, JSON.stringify(prop, null, 2) + "\n", "utf8");
    }

    const result = {
      status: "acted",
      decision,
      target_id: targetId,
      seq,
      event: signedEvent,
    };

    if (warrantId) {
      result.warrant_id = warrantId;
      result.warrant = warrantDoc;
      if (warrantEvent) {
        result.warrant_event = warrantEvent;
      }
    }

    return result;
  });
}
