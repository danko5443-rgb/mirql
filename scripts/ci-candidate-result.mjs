#!/usr/bin/env node
// scripts/ci-candidate-result.mjs — reads the untrusted candidate suite's result.
//
// PR code runs only in .github/workflows/mergeproof-candidate.yml, a
// `pull_request` workflow. The notary workflow runs in the base-branch context,
// so it must not run that code. Its `Candidate Tests (advisory)` job runs this
// script instead, and this script's exit code becomes that job's result, which
// the notary records as suite_pass_head.
//
// The result is one advisory bit. Candidate code can forge a pass, so no field
// of the run is used beyond its conclusion, and the fields a PR author controls
// (branch name, title) are never read or logged: a workflow command in one would
// otherwise run when printed to this job's log.
//
// A run counts only when all of these hold:
//   - it comes from the candidate workflow's path, on the `pull_request` event
//   - it ran on the exact head commit
//   - it is the newest such run, it finished, and it concluded `success`
//
// Do not filter on the run's `pull_requests` field: it is empty for forks.
//
// Zero external dependencies. Environment contract:
//   REPO      - owner/name of the repository
//   HEAD_SHA  - authoritative candidate head SHA
//   GH_TOKEN  - token for `gh api`, with actions: read
//
// Exit codes: 0 only when the candidate suite passed on this head; 1 for
// everything else (fail closed: suite_pass_head=false).

import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SHA_RE = /^[0-9a-f]{40}$/;
const WORKFLOW_FILE = "mergeproof-candidate.yml";
const WORKFLOW_PATH = `.github/workflows/${WORKFLOW_FILE}`;
const MAX_API_FAILURES = 3;

/** The newest run of the candidate workflow on exactly this head, else null. */
export function latestCandidateRun(runs, headSha) {
  if (!Array.isArray(runs)) return null;
  const matching = runs.filter(
    (r) => r?.path === WORKFLOW_PATH && r?.event === "pull_request" && r?.head_sha === headSha,
  );
  return matching.sort((a, b) => Number(b.run_number ?? 0) - Number(a.run_number ?? 0))[0] ?? null;
}

/**
 * Polls until the candidate run for `headSha` finishes or a limit is reached.
 * The two workflows start together, so the run may not exist on the first read.
 *
 * @returns {Promise<{ outcome: "success"|"failure"|"no_run"|"timed_out"|"api_error", run: object|null }>}
 */
export async function waitForCandidateRun({
  repo,
  headSha,
  api,
  sleep,
  now = Date.now,
  pollMs = 15_000,
  noRunMs = 5 * 60_000,
  totalMs = 20 * 60_000,
}) {
  const path = `repos/${repo}/actions/workflows/${WORKFLOW_FILE}/runs?head_sha=${headSha}&event=pull_request&per_page=20`;
  const startedAt = now();
  let run = null;
  let apiFailures = 0;
  let failedRunId = null;
  for (;;) {
    try {
      run = latestCandidateRun(api(path)?.workflow_runs, headSha) ?? run;
      apiFailures = 0;
    } catch {
      apiFailures += 1;
      if (apiFailures >= MAX_API_FAILURES) return { outcome: "api_error", run };
    }
    if (run?.status === "completed") {
      if (run.conclusion === "success") return { outcome: "success", run };
      // Reopening a PR retries a failed run on the same head. The new run may not
      // be listed yet, so one more read has to see the same failure.
      if (failedRunId === run.id) return { outcome: "failure", run };
      failedRunId = run.id;
    }
    if (now() - startedAt >= (run ? totalMs : noRunMs)) {
      return { outcome: run ? "timed_out" : "no_run", run };
    }
    await sleep(pollMs);
  }
}

const RECOVERY = "Fix the cause, or re-run the Mergeproof Candidate Suite if it was a flake, then re-run this job: re-running this job alone reads the same result.";

function failureMessage({ outcome, run }) {
  if (outcome === "no_run") {
    return "No candidate suite run exists for this head. GitHub does not run pull_request workflows on a PR with merge conflicts, and fork PR workflows may be disabled. Resolve that, then push or re-run this job.";
  }
  if (outcome === "api_error") return `Could not read candidate suite runs from the GitHub API. ${RECOVERY}`;
  if (outcome === "timed_out") return `Candidate suite run ${run.id} did not finish in time (status ${run.status}). ${RECOVERY}`;
  if (run.conclusion === "action_required") {
    return `Candidate suite run ${run.id} is waiting for a maintainer to approve this fork contributor's first run. After approving and once it passes, re-run this job.`;
  }
  return `Candidate suite run ${run.id} concluded ${run.conclusion}. ${RECOVERY}`;
}

function ghApi(path) {
  return JSON.parse(execFileSync("gh", ["api", path], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }));
}

export async function main(env = process.env, {
  api = ghApi,
  sleep = (ms) => new Promise((done) => { setTimeout(done, ms); }),
  now = Date.now,
  log = console.log,
} = {}) {
  const { REPO, HEAD_SHA } = env;
  if (!REPO) {
    log("::error::ci-candidate-result: REPO is required");
    return 1;
  }
  if (!SHA_RE.test(HEAD_SHA ?? "")) {
    log("::error::ci-candidate-result: HEAD_SHA must be a full 40-character commit SHA");
    return 1;
  }
  const result = await waitForCandidateRun({ repo: REPO, headSha: HEAD_SHA, api, sleep, now });
  log(JSON.stringify({
    tool: "ci-candidate-result",
    head_sha: HEAD_SHA,
    outcome: result.outcome,
    run_id: result.run?.id ?? null,
    conclusion: result.run?.conclusion ?? null,
  }));
  if (result.outcome === "success") return 0;
  log(`::error::${failureMessage(result)}`);
  return 1;
}

function isEntrypoint() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1] ?? "");
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  process.exit(await main());
}
