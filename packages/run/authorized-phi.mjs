import { computeGitTreePhi } from "./phi.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";
import { requireAuthorizedWarrant } from "../core/warrant.mjs";
import { readVerifiedLedger } from "../core/ledger-verify.mjs";
import { jcs, sha256 } from "../core/index.mjs";

/** Ledger event recording complexity spent from a warrant's signed allowance. */
export const PHI_CONSUMED_EVENT = "warrant.phi_consumed";
const STRICT_CLASSES = ["refactor", "consolidation", "consolidator"];

function refusal(code, message) {
  const error = new Error(message);
  error.code = error.errorCode = code;
  return error;
}

function consumptionKey(warrantId, baseSha, headSha) {
  return "phi-consumed:" + sha256(jcs({ warrant_id: warrantId, base_sha: baseSha, head_sha: headSha }));
}

/**
 * Law 13 cumulative allowance: the signed phi_budget is spent across every
 * accepted transition under one warrant, never re-granted per transition.
 * Only increases are counted. A decrease does not refund the allowance,
 * because a recorded transition is not proof that it was merged. The same
 * base/head pair is recorded once, so re-verifying it is idempotent.
 *
 * @returns {{ consumed: number, existing: object|null }}
 */
function readConsumption(mirqlDir, warrantId, baseSha, headSha) {
  const key = consumptionKey(warrantId, baseSha, headSha);
  let consumed = 0;
  let existing = null;
  for (const event of readVerifiedLedger(mirqlDir)) {
    if (event.type !== PHI_CONSUMED_EVENT || event.writer?.ns !== "tool:run_supervisor") continue;
    if (event.payload?.warrant_id !== warrantId) continue;
    if (event.idempotency_key === key) { existing = event; continue; }
    const delta = event.payload.delta_phi;
    if (!Number.isSafeInteger(delta)) throw refusal("PHI_UNMEASURED", "A recorded complexity consumption is not a safe integer");
    if (delta > 0) consumed += delta;
  }
  return { consumed, existing };
}

function judge({ delta, budget, consumed, strict }) {
  const remaining = budget - consumed;
  if (strict) return { ok: delta < 0, remaining, rule: delta < 0 ? "MP-000" : "LAW_13_CONSOLIDATOR_PHI" };
  if (delta <= remaining) return { ok: true, remaining, rule: "MP-000" };
  return { ok: false, remaining, rule: delta <= budget ? "LAW_13_PHI_BUDGET_EXHAUSTED" : "LAW_13_PHI_INCREASE" };
}

/** Only immutable tree metrics and verified owner authority participate in this gate. */
export function measureAuthorizedPhi({ repoDir, baseSha, headSha, mirqlDir, warrantId, conformance = false }) {
  let warrant = null;
  if (!conformance || mirqlDir || warrantId) {
    if (!mirqlDir || !warrantId) throw refusal("WARRANT_UNAUTHORIZED", "A signed warrant is required for live complexity verification");
    warrant = requireAuthorizedWarrant(mirqlDir, { warrantId });
  }
  const base = computeGitTreePhi(repoDir, baseSha);
  const head = computeGitTreePhi(repoDir, headSha);
  const delta = head.metrics.total - base.metrics.total;
  const budget = warrant?.phi_budget ?? 0;
  const strict = STRICT_CLASSES.includes(warrant?.class);
  const { consumed } = warrant
    ? readConsumption(mirqlDir, warrant.id, base.commit_sha, head.commit_sha)
    : { consumed: 0 };
  const verdict = judge({ delta, budget, consumed, strict });
  return {
    base_sha: base.commit_sha, head_sha: head.commit_sha, base_tree: base.tree_sha, head_tree: head.tree_sha,
    phi_before: base.metrics.total, phi_after: head.metrics.total, delta_phi: delta,
    phi_budget: budget, phi_consumed: consumed, phi_remaining: verdict.remaining,
    warrant_id: warrant?.id ?? null, warrant_class: warrant?.class ?? null,
    // The signed scope patterns authorize changed non-test paths; only the
    // verified warrant document supplies them, never caller input.
    warrant_scope_allow: warrant
      ? (Array.isArray(warrant.scope?.allow) ? warrant.scope.allow
        : (Array.isArray(warrant.anchors) ? warrant.anchors : []))
      : null,
    ok: verdict.ok, rule: verdict.rule,
  };
}

/**
 * Durably spends a measured increase from the warrant's allowance. The budget
 * is re-checked inside the ledger lock, so concurrent verifications cannot
 * both spend the same remainder. Non-increasing transitions spend nothing and
 * write nothing. Without an enrolled supervisor key the spend cannot be
 * recorded, and the transition is refused (silence is never consent).
 *
 * @param {string} mirqlDir
 * @param {ReturnType<typeof measureAuthorizedPhi>} measured
 * @returns {object|null} the consumption event, or null when nothing was spent
 */
export function recordPhiConsumption(mirqlDir, measured, options = {}) {
  if (!measured?.warrant_id || measured.delta_phi <= 0) return null;
  const payload = {
    warrant_id: measured.warrant_id, base_sha: measured.base_sha, head_sha: measured.head_sha,
    base_tree: measured.base_tree, head_tree: measured.head_tree,
    delta_phi: measured.delta_phi, phi_budget: measured.phi_budget,
  };
  const keypair = options.keypair ?? getOrGenerateSupervisorKey(mirqlDir);
  return appendSupervisorEvent(mirqlDir, {
    type: PHI_CONSUMED_EVENT,
    idempotency_key: consumptionKey(measured.warrant_id, measured.base_sha, measured.head_sha),
    payload,
  }, keypair, {
    precondition: () => {
      const warrant = requireAuthorizedWarrant(mirqlDir, { warrantId: measured.warrant_id });
      const { consumed, existing } = readConsumption(mirqlDir, warrant.id, measured.base_sha, measured.head_sha);
      if (existing) return existing;
      const verdict = judge({ delta: measured.delta_phi, budget: warrant.phi_budget ?? 0, consumed,
        strict: STRICT_CLASSES.includes(warrant.class) });
      if (!verdict.ok) throw refusal(verdict.rule, "The warrant's complexity allowance was spent concurrently");
      return undefined;
    },
  });
}
