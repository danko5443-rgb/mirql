// packages/inbox/digest.mjs — Keyless, read-only factory digest renderer (Law 6).
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { readEvents, foldState } from "./ledger.mjs";

/**
 * Format integer micro-USD as a decimal string using pure integer math
 * (Law 17: zero floats, zero `.toFixed`). Truncates to 2 fractional digits.
 *
 * @param {number} micro - integer amount in micro-USD
 * @returns {string} e.g. "$1.50"
 */
export function formatMicroUsd(micro) {
  if (!Number.isSafeInteger(micro)) {
    throw new TypeError(`formatMicroUsd requires a safe integer (Law 17), got ${micro}`);
  }
  const negative = micro < 0;
  const abs = negative ? -micro : micro;
  const whole = Math.floor(abs / 1000000);
  const frac = String(abs % 1000000).padStart(6, "0").slice(0, 2);
  return `${negative ? "-" : ""}$${whole}.${frac}`;
}

/**
 * Render keyless, read-only status digest of the autonomous factory.
 * Strictly read-only: never loads private keys, never mutates ledger or cache.
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @param {string} [options.format] - "json" (default) or "markdown"
 * @returns {object | string}
 */
export function renderDigest(mirqlDir, options = {}) {
  // Read durable ledger
  const { events } = readEvents(mirqlDir);
  const state = foldState(events);

  // Compute pending human approvals
  const pendingApprovals = [];
  const resolvedTargets = new Set();

  // Find all decisions that resolved prior approval requests
  for (const evt of events) {
    if (evt.type === "human.approval" || evt.type === "human.rejection" || evt.type === "human.kill") {
      const tid = evt.payload?.target_id;
      if (tid) resolvedTargets.add(tid);
    }
  }

  for (const evt of events) {
    if (
      evt.type === "verdict.needs_human" ||
      evt.type === "human.approval_requested" ||
      evt.type === "human.escalation" ||
      evt.type === "consensus.escalation"
    ) {
      const targetId = evt.payload?.job_id || evt.payload?.warrant_id || evt.payload?.target_id || evt.id;
      if (targetId && !resolvedTargets.has(targetId)) {
        pendingApprovals.push({
          id: targetId,
          type: evt.type,
          seq: evt.seq,
          reason: evt.payload?.reason || evt.payload?.objection || "Needs human sign-off",
        });
      }
    }
  }

  // Also check active jobs in needs_human status
  for (const [jid, job] of Object.entries(state.jobs || {})) {
    if (job?.status === "needs_human" && !resolvedTargets.has(jid)) {
      if (!pendingApprovals.some((a) => a.id === jid)) {
        pendingApprovals.push({
          id: jid,
          type: "job.needs_human",
          warrant_id: job.warrant_id,
          reason: "Job escalated to human approval",
        });
      }
    }
  }

  // Read open proposals (capped at max 3)
  const proposalsDir = join(mirqlDir, "proposals");
  const pendingProposals = [];
  if (existsSync(proposalsDir)) {
    for (const entry of readdirSync(proposalsDir)) {
      if (!entry.endsWith(".json")) continue;
      try {
        const prop = JSON.parse(readFileSync(join(proposalsDir, entry), "utf8"));
        const status = prop.status || "pending";
        if (status === "pending" || status === "open" || status === "active") {
          pendingProposals.push({
            id: prop.id,
            roadmap_ref: prop.roadmap_ref,
            title: prop.title,
            status,
            action_type: prop.action_type || "1_tap_approve",
            created_at: prop.created_at,
          });
        }
      } catch {}
    }
  }

  // Sort proposals by created_at or id, cap at 3
  pendingProposals.sort((a, b) => (a.created_at || "").localeCompare(b.created_at || ""));
  const cappedProposals = pendingProposals.slice(0, 3);

  const digestObj = {
    tool: "inbox",
    mode: state.mode,
    epoch: state.epoch,
    seq: state.seq,
    head_hash: state.last_hash ?? state.last_event_hash ?? "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    halted: state.halted,
    budget_spent_micro_usd: state.budget_spent_micro_usd,
    pending_approvals: pendingApprovals,
    pending_proposals: cappedProposals,
    recent_outcomes: state.recent_outcomes,
    mutates_ledger: false,
  };

  if (options.format === "markdown") {
    return formatMarkdownDigest(digestObj);
  }

  return digestObj;
}

/**
 * Format digest object into human-readable Markdown.
 * @param {object} digest
 * @returns {string}
 */
function formatMarkdownDigest(digest) {
  const lines = [
    `# mirql Factory Digest`,
    ``,
    `- **Macro Mode:** \`${digest.mode}\``,
    `- **Epoch:** \`${digest.epoch}\``,
    `- **Sequence:** \`${digest.seq}\``,
    `- **Halted:** \`${digest.halted}\``,
    `- **Budget Spent:** \`${formatMicroUsd(digest.budget_spent_micro_usd)}\` (${digest.budget_spent_micro_usd} micro-USD)`,
    ``,
    `## Pending Approvals (${digest.pending_approvals.length})`,
  ];

  if (digest.pending_approvals.length === 0) {
    lines.push(`*No items currently awaiting human approval.*`);
  } else {
    for (const item of digest.pending_approvals) {
      lines.push(`- **[${item.type}]** \`${item.id}\`: ${item.reason}`);
    }
  }

  lines.push(``, `## Pending Proposals (${digest.pending_proposals.length})`);
  if (digest.pending_proposals.length === 0) {
    lines.push(`*No open proposals.*`);
  } else {
    for (const prop of digest.pending_proposals) {
      lines.push(`- **[${prop.roadmap_ref || "PROPOSAL"}]** \`${prop.id}\`: ${prop.title} (${prop.action_type})`);
    }
  }

  lines.push(``, `## Recent Outcomes (${digest.recent_outcomes.length})`);
  if (digest.recent_outcomes.length === 0) {
    lines.push(`*No recorded outcomes.*`);
  } else {
    for (const outcome of digest.recent_outcomes) {
      lines.push(`- seq ${outcome.seq}: \`${outcome.verdict}\` (job: \`${outcome.job_id || "none"}\`, cost: ${outcome.cost_micro_usd || 0} µUSD)`);
    }
  }

  lines.push(``);
  return lines.join("\n");
}
