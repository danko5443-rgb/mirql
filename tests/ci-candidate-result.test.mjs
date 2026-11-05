// tests/ci-candidate-result.test.mjs — the notary's reader of the untrusted
// candidate suite. Everything except a finished, successful run on the exact
// head must fail closed.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { latestCandidateRun, main, waitForCandidateRun } from "../scripts/ci-candidate-result.mjs";

const HEAD = "a".repeat(40);
const OTHER = "b".repeat(40);
const PATH = ".github/workflows/mergeproof-candidate.yml";

function candidateRun(overrides = {}) {
  return { id: 7, run_number: 1, path: PATH, event: "pull_request", head_sha: HEAD, status: "completed", conclusion: "success", ...overrides };
}

/** A clock that only moves when the code under test sleeps, and an api that replays reads. */
function harness(reads) {
  let clock = 0;
  const paths = [];
  let index = 0;
  return {
    paths,
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
    api: (path) => {
      paths.push(path);
      const read = reads[Math.min(index, reads.length - 1)];
      index += 1;
      if (read instanceof Error) throw read;
      return { workflow_runs: read };
    },
    elapsed: () => clock,
  };
}

describe("latestCandidateRun", () => {
  it("ignores a run from another workflow path, event or head", () => {
    assert.equal(latestCandidateRun([candidateRun({ path: ".github/workflows/other.yml" })], HEAD), null);
    assert.equal(latestCandidateRun([candidateRun({ event: "pull_request_target" })], HEAD), null);
    assert.equal(latestCandidateRun([candidateRun({ event: "workflow_dispatch" })], HEAD), null);
    assert.equal(latestCandidateRun([candidateRun({ head_sha: OTHER })], HEAD), null);
  });

  it("the newest run wins, so an old pass cannot outlive a later failure", () => {
    const runs = [candidateRun({ id: 1, run_number: 1 }), candidateRun({ id: 3, run_number: 3, conclusion: "failure" }), candidateRun({ id: 2, run_number: 2 })];
    assert.equal(latestCandidateRun(runs, HEAD).id, 3);
  });

  it("does not depend on the pull_requests field, which is empty for forks", () => {
    assert.equal(latestCandidateRun([candidateRun({ pull_requests: [] })], HEAD).id, 7);
  });

  it("returns null for a missing or malformed list", () => {
    assert.equal(latestCandidateRun(undefined, HEAD), null);
    assert.equal(latestCandidateRun([null, {}], HEAD), null);
  });
});

describe("waitForCandidateRun", () => {
  const wait = (h) => waitForCandidateRun({ repo: "o/r", headSha: HEAD, api: h.api, sleep: h.sleep, now: h.now });

  it("asks for this workflow's pull_request runs on the exact head", async () => {
    const h = harness([[candidateRun()]]);
    await wait(h);
    assert.equal(h.paths[0], `repos/o/r/actions/workflows/mergeproof-candidate.yml/runs?head_sha=${HEAD}&event=pull_request&per_page=20`);
  });

  it("returns a finished result at once, without sleeping (a label re-trigger reuses it)", async () => {
    const h = harness([[candidateRun()]]);
    assert.equal((await wait(h)).outcome, "success");
    assert.equal(h.elapsed(), 0);
  });

  it("waits for a run that has not appeared yet, then for it to finish", async () => {
    const h = harness([[], [candidateRun({ status: "queued", conclusion: null })], [candidateRun({ status: "in_progress", conclusion: null })], [candidateRun()]]);
    assert.equal((await wait(h)).outcome, "success");
    assert.equal(h.paths.length, 4);
  });

  for (const conclusion of ["failure", "cancelled", "timed_out", "skipped", "neutral", "stale", "action_required", null]) {
    it(`a finished run with conclusion ${conclusion} is a failure, once a second read confirms it`, async () => {
      const h = harness([[candidateRun({ conclusion })]]);
      assert.equal((await wait(h)).outcome, "failure");
      assert.equal(h.paths.length, 2);
    });
  }

  it("a reopen's new run replaces the old failure it appeared after", async () => {
    const failed = candidateRun({ id: 1, run_number: 1, conclusion: "failure" });
    const retry = (fields) => candidateRun({ id: 2, run_number: 2, ...fields });
    const h = harness([[failed], [failed, retry({ status: "queued", conclusion: null })], [failed, retry({})]]);
    const result = await wait(h);
    assert.equal(result.outcome, "success");
    assert.equal(result.run.id, 2);
  });

  it("a failed run followed by a different failed run is confirmed on that run", async () => {
    const first = candidateRun({ id: 1, run_number: 1, conclusion: "failure" });
    const second = candidateRun({ id: 2, run_number: 2, conclusion: "failure" });
    const h = harness([[first], [first, second]]);
    const result = await wait(h);
    assert.equal(result.outcome, "failure");
    assert.equal(result.run.id, 2);
    assert.equal(h.paths.length, 3);
  });

  it("stops at the no-run limit when the run never appears (a conflicted PR gets no event)", async () => {
    const h = harness([[]]);
    assert.equal((await wait(h)).outcome, "no_run");
    assert.equal(h.elapsed(), 5 * 60_000);
  });

  it("a run that exists gets the longer limit, and timing out is not a pass", async () => {
    const h = harness([[candidateRun({ status: "in_progress", conclusion: null })]]);
    const result = await wait(h);
    assert.equal(result.outcome, "timed_out");
    assert.equal(h.elapsed(), 20 * 60_000);
  });

  it("survives a transient API failure", async () => {
    const h = harness([new Error("502"), [candidateRun()]]);
    assert.equal((await wait(h)).outcome, "success");
  });

  it("keeps a run it already saw through an API failure, so the longer limit still applies", async () => {
    const running = candidateRun({ status: "in_progress", conclusion: null });
    const h = harness([[running], new Error("502"), []]);
    const result = await wait(h);
    assert.equal(result.outcome, "timed_out");
    assert.equal(result.run.id, 7);
    assert.equal(h.elapsed(), 20 * 60_000);
  });

  it("fails closed after repeated API failures instead of waiting out the limit", async () => {
    const h = harness([new Error("404"), new Error("404"), new Error("404"), [candidateRun()]]);
    assert.equal((await wait(h)).outcome, "api_error");
    assert.equal(h.paths.length, 3);
  });
});

describe("main", () => {
  const run = async (env, reads) => {
    const h = harness(reads);
    const lines = [];
    const code = await main(env, { api: h.api, sleep: h.sleep, now: h.now, log: (l) => lines.push(l) });
    return { code, lines, text: lines.join("\n"), h };
  };
  const env = { REPO: "o/r", HEAD_SHA: HEAD };

  it("exits 0 only for a passing run on this head", async () => {
    const { code, lines } = await run(env, [[candidateRun()]]);
    assert.equal(code, 0);
    assert.deepEqual(JSON.parse(lines[0]), { tool: "ci-candidate-result", head_sha: HEAD, outcome: "success", run_id: 7, conclusion: "success" });
  });

  it("exits 1 for a failed run and says how to recover from a flake", async () => {
    const { code, text } = await run(env, [[candidateRun({ conclusion: "failure" })]]);
    assert.equal(code, 1);
    assert.match(text, /::error::Candidate suite run 7 concluded failure/);
    assert.match(text, /re-running this job alone reads the same result/);
  });

  it("names the approval an unapproved fork run is waiting for", async () => {
    const { code, text } = await run(env, [[candidateRun({ conclusion: "action_required" })]]);
    assert.equal(code, 1);
    assert.match(text, /approve this fork contributor's first run/);
  });

  it("names the likely causes when no run exists", async () => {
    const { code, text } = await run(env, [[]]);
    assert.equal(code, 1);
    assert.match(text, /merge conflicts/);
  });

  it("exits 1 when the API keeps failing or the run times out", async () => {
    assert.equal((await run(env, [new Error("500")])).code, 1);
    assert.equal((await run(env, [[candidateRun({ status: "in_progress", conclusion: null })]])).code, 1);
  });

  it("refuses missing or malformed input without calling the API", async () => {
    for (const bad of [{ HEAD_SHA: HEAD }, { REPO: "o/r" }, { REPO: "o/r", HEAD_SHA: "abc123" }, { REPO: "o/r", HEAD_SHA: `${HEAD}\n::error::x` }]) {
      const { code, h } = await run(bad, [[candidateRun()]]);
      assert.equal(code, 1);
      assert.equal(h.paths.length, 0);
    }
  });

  it("never logs a field the PR author controls, so a workflow command in one cannot run", async () => {
    const hostile = "::error::pwned ::set-output name=owner::attacker";
    const fields = { display_title: hostile, head_branch: hostile, name: hostile, head_commit: { message: hostile } };
    for (const conclusion of ["success", "failure"]) {
      const { text } = await run(env, [[candidateRun({ ...fields, conclusion })]]);
      assert.doesNotMatch(text, /pwned/);
    }
  });
});
