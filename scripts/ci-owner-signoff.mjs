#!/usr/bin/env node
// scripts/ci-owner-signoff.mjs — finds the repo owner's sign-off on a PR head.
//
// The owner signs off by adding the label `reviewed:<full head sha>`. CI then
// runs every other merge-proof rule, capped at needs_human, exactly as it does
// for an aiReviewers approval: the rules can still reject, and the verdict can
// never become auto_merge. Unlike an aiReviewers approval, it can also clear
// Phi growth (Law 13); it grants no warrant allowance.
//
// A sign-off counts only when all of these hold:
//   - the label names the exact head commit (a new push voids it)
//   - the repository owner added it, as a User account
//   - the label is still on the PR (a later removal voids it)
//
// The label says who clicked, not who decided: GitHub cannot tell the owner
// from an agent running under the owner's `gh` login. This is a review record,
// not a signature, and it is no defence against such an agent.
//
// Zero external dependencies. Environment contract:
//   EVENTS_PATH   - JSON lines, one GitHub issue event per line
//                   (`gh api --paginate .../issues/N/events --jq '.[]'`)
//   HEAD_SHA      - authoritative candidate head SHA
//   REPO_OWNER    - repository owner login
//   GITHUB_OUTPUT - (optional) receives `owner=<login>`
//
// Exit codes: 0 when inputs parse (no sign-off is not an error); 1 when an
// input is missing or unreadable (fail closed: no sign-off).

import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SHA_RE = /^[0-9a-f]{40}$/;

/** The sign-off label for a head commit: full SHA, since a short one can be brute-forced. */
export function signoffLabel(headSha) {
  const sha = String(headSha ?? "").toLowerCase();
  if (!SHA_RE.test(sha)) throw new Error(`not a full 40-character commit SHA: ${headSha}`);
  return `reviewed:${sha}`;
}

/** Parses JSON-lines event output; blank lines are skipped. */
export function parseEvents(text) {
  return String(text ?? "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

/**
 * Returns the owner's login when they signed off `headSha`, else null.
 *
 * @param {object[]} events GitHub issue event objects
 * @param {{ owner: string, headSha: string }} ctx
 * @returns {string | null}
 */
export function findOwnerSignoff(events, { owner, headSha }) {
  if (!Array.isArray(events) || !owner) return null;
  let label;
  try {
    label = signoffLabel(headSha);
  } catch {
    return null;
  }
  const ordered = [...events].sort((a, b) => Number(a?.id ?? 0) - Number(b?.id ?? 0));
  let signer = null;
  for (const e of ordered) {
    if (e?.label?.name !== label) continue;
    if (e.event === "labeled") signer = e.actor ?? null;
    else if (e.event === "unlabeled") signer = null;
  }
  const isOwner =
    signer?.type === "User" &&
    typeof signer.login === "string" &&
    signer.login.toLowerCase() === owner.toLowerCase();
  return isOwner ? signer.login : null;
}

export function main(env = process.env) {
  const { EVENTS_PATH, HEAD_SHA, REPO_OWNER } = env;
  const required = { EVENTS_PATH, HEAD_SHA, REPO_OWNER };
  for (const [name, value] of Object.entries(required)) {
    if (!value) {
      console.error(`ci-owner-signoff: ${name} is required`);
      return 1;
    }
  }
  let events;
  try {
    events = parseEvents(readFileSync(EVENTS_PATH, "utf8"));
  } catch (err) {
    console.error(`ci-owner-signoff: cannot read events: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  const owner = findOwnerSignoff(events, { owner: REPO_OWNER, headSha: HEAD_SHA });
  console.log(JSON.stringify({ tool: "ci-owner-signoff", head_sha: HEAD_SHA, owner }));
  if (owner && env.GITHUB_OUTPUT) {
    appendFileSync(env.GITHUB_OUTPUT, `owner=${owner}\n`);
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
  process.exit(main());
}
