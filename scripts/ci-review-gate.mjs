#!/usr/bin/env node
// scripts/ci-review-gate.mjs — finds an AI reviewer approval for a humanOnly PR.
//
// MP-001 rejects any PR that touches a humanOnly path. An Approve review from
// an account listed under `aiReviewers` in the BASE notary's policy/paths.yaml
// lets the notary run every other rule instead, capped at needs_human (never
// auto_merge). This script only decides WHO approved; the verdict stays with
// `mirql m check --human-only-reviewer <login>`.
//
// An approval counts only when all of these hold:
//   - the reviewer is in the base policy's aiReviewers list (a PR cannot add itself)
//   - the reviewer is a Bot account and is not the PR author
//   - the reviewer's latest decisive review is APPROVED
//   - that review was submitted on the exact head commit (a new push voids it)
//   - no aiReviewers account has an outstanding CHANGES_REQUESTED
//   - no comment or review body on the PR, other than the reviewer bots' own,
//     commands a bot to approve or resolve (`@coderabbitai approve`), since
//     that skips the bot's own review. A command deleted after it fired is not
//     visible here; that residual risk is documented in policy/paths.yaml.
//
// Zero external dependencies. Environment contract:
//   BASE_NOTARY_DIR - base-notary checkout root (policy source)
//   REVIEWS_PATH    - JSON lines, one GitHub review object per line
//                     (`gh api --paginate .../pulls/N/reviews --jq '.[]'`)
//   HEAD_SHA        - authoritative candidate head SHA
//   PR_AUTHOR       - PR author login
//   COMMENTS_PATH   - JSON lines, one GitHub issue comment per line
//                     (`gh api --paginate .../issues/N/comments --jq '.[]'`)
//   REVIEW_COMMENTS_PATH - JSON lines, one inline review comment per line
//                     (`gh api --paginate .../pulls/N/comments --jq '.[]'`)
//   GITHUB_OUTPUT   - (optional) receives `approver=<login>`
//
// Exit codes: 0 always when inputs parse (no approval is not an error);
// 1 when an input is missing or unreadable (fail closed: no approver).

import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DECISIVE_STATES = new Set(["APPROVED", "CHANGES_REQUESTED", "DISMISSED"]);
const APPROVE_COMMAND_RE = /@coderabbit(?:ai)?\b[^\n]*\b(?:approve|resolve)\b/i;

/**
 * True when any comment or review body not written by an allowlisted reviewer
 * bot commands a reviewer to approve or resolve. Other bots count as people
 * here: any account that can post the command can trigger it.
 */
export function hasApproveCommand(items, reviewers = []) {
  const exempt = new Set(reviewers.map((r) => r.toLowerCase()));
  return (items ?? []).some((c) => {
    const login = String(c?.user?.login ?? "").toLowerCase();
    const isReviewerBot = c?.user?.type === "Bot" && exempt.has(login);
    return !isReviewerBot && APPROVE_COMMAND_RE.test(String(c?.body ?? ""));
  });
}

/** Parses JSON-lines review output; blank lines are skipped. */
export function parseReviews(text) {
  return String(text ?? "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

/**
 * Returns the login of an allowlisted bot that approved `headSha`, or null.
 *
 * @param {object[]} reviews GitHub review objects
 * @param {{ reviewers: string[], headSha: string, author: string }} ctx
 * @returns {string | null}
 */
export function findAiApproval(reviews, { reviewers, headSha, author }) {
  if (!Array.isArray(reviews) || !headSha) return null;
  const allowed = new Set((reviewers ?? []).map((r) => r.toLowerCase()));
  const authorLc = String(author ?? "").toLowerCase();

  // Latest decisive review per allowlisted bot, in submission order.
  const latest = new Map();
  const ordered = [...reviews].sort((a, b) =>
    String(a?.submitted_at ?? "").localeCompare(String(b?.submitted_at ?? "")),
  );
  for (const r of ordered) {
    const login = r?.user?.login;
    if (typeof login !== "string" || !allowed.has(login.toLowerCase())) continue;
    if (r.user.type !== "Bot" || login.toLowerCase() === authorLc) continue;
    if (!DECISIVE_STATES.has(r.state)) continue;
    latest.set(login.toLowerCase(), r);
  }

  const decisive = [...latest.values()];
  if (decisive.some((r) => r.state === "CHANGES_REQUESTED")) return null;
  const approval = decisive.find((r) => r.state === "APPROVED" && r.commit_id === headSha);
  return approval ? approval.user.login : null;
}

export async function main(env = process.env) {
  const { BASE_NOTARY_DIR, REVIEWS_PATH, COMMENTS_PATH, REVIEW_COMMENTS_PATH, HEAD_SHA, PR_AUTHOR } = env;
  const required = { BASE_NOTARY_DIR, REVIEWS_PATH, COMMENTS_PATH, REVIEW_COMMENTS_PATH, HEAD_SHA, PR_AUTHOR };
  for (const [name, value] of Object.entries(required)) {
    if (!value) {
      console.error(`ci-review-gate: ${name} is required`);
      return 1;
    }
  }
  let reviews;
  let comments;
  try {
    reviews = parseReviews(readFileSync(REVIEWS_PATH, "utf8"));
    comments = [
      ...parseReviews(readFileSync(COMMENTS_PATH, "utf8")),
      ...parseReviews(readFileSync(REVIEW_COMMENTS_PATH, "utf8")),
    ];
  } catch (err) {
    console.error(`ci-review-gate: cannot read reviews or comments: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  const baseRoot = resolve(BASE_NOTARY_DIR);
  const { loadPathPolicies } = await import(
    pathToFileURL(resolve(baseRoot, "packages/core/anti-cheat.mjs")).href
  );
  const reviewers = loadPathPolicies(baseRoot).aiReviewers ?? [];

  const commanded = hasApproveCommand([...comments, ...reviews], reviewers);
  const approver = commanded
    ? null
    : findAiApproval(reviews, { reviewers, headSha: HEAD_SHA, author: PR_AUTHOR });
  console.log(JSON.stringify({ tool: "ci-review-gate", reviewers, approver, approve_command_seen: commanded }));
  if (approver && env.GITHUB_OUTPUT) {
    appendFileSync(env.GITHUB_OUTPUT, `approver=${approver}\n`);
  }
  return 0;
}

function isEntrypoint() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1] ?? "");
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  main().then((code) => process.exit(code));
}
