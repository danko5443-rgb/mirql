import { ulid, hlcTick, jcs, sha256, signEvent, validateDocument, withLedgerLock } from "../core/index.mjs";
import { isHumanOnlyPath } from "../core/anti-cheat.mjs";
import { measureMergeBinding } from "../core/merge-approval.mjs";
import { readVerifiedLedger } from "../core/ledger-verify.mjs";
import { requireAuthorizedWarrant } from "../core/warrant.mjs";
import { authenticateHumanWriter } from "./keys.mjs";
import { appendEvent, requireGenesisLedger } from "./ledger.mjs";

function refusal(code, message, exitCode = 4) {
  const error = new Error(message);
  error.code = error.errorCode = code;
  error.exitCode = exitCode;
  return error;
}

/** Record the owner's approval of an immutable, measured candidate. */
export function approveMerge(mirqlDir, options = {}) {
  return withLedgerLock(mirqlDir, () => {
    requireGenesisLedger(mirqlDir);
    const owner = authenticateHumanWriter(mirqlDir, options);
    requireAuthorizedWarrant(mirqlDir, { warrantId: options.warrantId, nowMs: options.nowMs });
    const binding = measureMergeBinding(options);
    const forbidden = binding.paths.filter(path => isHumanOnlyPath(path));
    if (forbidden.length) throw refusal("TOUCH_HUMAN_ONLY", "Merge approvals cannot authorize humanOnly paths: " + forbidden.join(", "));
    const events = readVerifiedLedger(mirqlDir);
    const idempotencyKey = "merge-approved:" + sha256(jcs(binding));
    const existing = events.find(event => event.writer.ns === "human:owner" && event.idempotency_key === idempotencyKey);
    if (existing) {
      if (existing.type !== "merge.approved" || jcs(existing.payload) !== jcs(binding)) {
        throw refusal("IDEMPOTENCY_CONFLICT", "Approval identity already names a different signed record");
      }
      return { status: "already_approved", binding, event: existing };
    }
    const head = events.at(-1);
    const now = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
    const event = signEvent({
      v: 1, id: ulid(now), tenant_id: head.tenant_id, seq: head.seq + 1, epoch: head.epoch,
      hlc: hlcTick(head.hlc, now, options.node ?? "local"), ts: new Date(now).toISOString(),
      type: "merge.approved", writer: { ns: "human:owner", key_id: owner.keyId },
      idempotency_key: idempotencyKey, prev_hash: head.hash, payload: binding,
    }, owner.privateKey, owner.keyId);
    const check = validateDocument("event", event);
    if (!check.valid) throw refusal("USAGE_ERROR", "Invalid merge approval: " + check.errors.join(", "), 2);
    appendEvent(mirqlDir, event);
    return { status: "approved", binding, event };
  });
}
