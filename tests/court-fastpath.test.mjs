// Court fast path and single-SHA discipline (issue #147): a Critic APPROVE at
// the head with nothing open merges on one model call, and an Advocate push
// ends the tick so the Judge never rules on a SHA the push already replaced.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPathPolicies } from "../packages/core/anti-cheat.mjs";
import { findAiApproval } from "../scripts/ci-review-gate.mjs";
import { decideCourtStep, formatCourtReceipt, parseCourtState, runCourtTick } from "../scripts/pr-court.mjs";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const REVIEWERS = loadPathPolicies(ROOT).aiReviewers;
const HEAD = "a".repeat(40);
const ENV = { ZAI_API_KEY: "test-key" };
const COURT_GIT = { GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" };
const FINDING = { id: "f1", severity: "P1", file: "src.mjs", line: 1, title: "bad", detail: "really bad" };
const SOURCE = "export const keep = 1;\nexport const remove = 2;\nexport const extra = 3;\n";
const APPROVE = { verdict: "APPROVE", summary: "clean", findings: [] };
const CRITIC = { verdict: "COMMENT", summary: "no", findings: [FINDING] };
const REBUT = { summary: "s", responses: [{ finding_id: "f1", action: "REBUT", reply: "false positive" }] };
const FIX = { summary: "s", responses: [{ finding_id: "f1", action: "AGREE_AND_FIX", reply: "fixed", patches: [{ file: "src.mjs", search: "export const remove = 2;\n", replace: "" }] }] };
const MERGE = { verdict: "MERGE", rationale: "ok", rulings: [{ finding_id: "f1", status: "OVERRULED_FALSE_POSITIVE", reason: "agreed" }] };
const REBUT_9 = { summary: "s", responses: [{ finding_id: "9", action: "REBUT", reply: "false positive" }] };
const MERGE_9 = { verdict: "MERGE", rationale: "ok", rulings: [{ finding_id: "9", status: "OVERRULED_FALSE_POSITIVE", reason: "agreed" }] };

function receipt(fields, overrides = {}) {
  return {
    user: { login: "github-actions[bot]", type: "Bot", id: 41898282 },
    performed_via_github_app: { id: 15368 },
    created_at: "2026-11-04T10:00:00Z",
    updated_at: "2026-11-04T10:00:00Z",
    body: formatCourtReceipt({ headSha: HEAD, round: 1, ...fields }),
    ...overrides,
  };
}

/** Returns queued LLM replies in order and records each request, so a stray Advocate or Judge call fails the test. */
function mockFetch(...replies) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    if (replies.length === 0) throw new Error("unexpected LLM call");
    const reply = replies.shift();
    return { ok: true, json: async () => ({ choices: [{ message: { content: JSON.stringify(reply) } }] }) };
  };
  return { fetchImpl, calls };
}

function withDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "mirql-fastpath-"));
  const done = () => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  return Promise.resolve().then(() => fn(dir)).finally(done);
}

const quiet = async (fn) => {
  const original = [console.log, console.error];
  console.log = () => {};
  console.error = () => {};
  try { return await fn(); } finally { [console.log, console.error] = original; }
};

/** A real origin and candidate clone, with a GitHub stand-in that serves the PR and records every gh call. */
function sandbox(dir) {
  const git = (cwd, ...args) => execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", env: { ...process.env, ...COURT_GIT } }).trim();
  const origin = join(dir, "origin.git");
  const seed = join(dir, "seed");
  execFileSync("git", ["init", "-q", "--bare", origin]);
  mkdirSync(seed);
  git(seed, "init", "-q");
  git(seed, "config", "core.autocrlf", "false");
  writeFileSync(join(seed, "src.mjs"), SOURCE);
  git(seed, "add", ".");
  git(seed, "commit", "-qm", "base");
  git(seed, "branch", "-M", "main");
  const baseSha = git(seed, "rev-parse", "HEAD");
  git(seed, "checkout", "-qb", "feature");
  writeFileSync(join(seed, "src.mjs"), SOURCE.replace("export const extra = 3;\n", ""));
  git(seed, "add", ".");
  git(seed, "commit", "-qm", "feature");
  git(seed, "remote", "add", "origin", origin);
  git(seed, "push", "-q", "origin", "main", "feature");
  const candidate = join(dir, "candidate");
  execFileSync("git", ["clone", "-q", "-c", "core.autocrlf=false", "-b", "feature", origin, candidate], { env: { ...process.env, ...COURT_GIT } });
  git(candidate, "fetch", "-q", "origin", "main:refs/remotes/origin/main");

  const comments = [];
  const inline = [];
  const gh = [];
  const pr = { state: "open", draft: false, author_association: "OWNER", user: { login: "ahmed-3m" }, head: { sha: git(candidate, "rev-parse", "HEAD"), ref: "feature", repo: { full_name: "o/r" } }, base: { ref: "main" } };
  const jobs = { head: "success", base: "success", gate: "success" };
  const io = {
    run(cmd, args, options = {}) {
      if (cmd !== "git") {
        gh.push([cmd, ...args]);
        return args[1] === "view" ? JSON.stringify({ closingIssuesReferences: [] }) : "";
      }
      return execFileSync(cmd, args, { encoding: "utf8", ...options, env: { ...(options.env ?? process.env), ...COURT_GIT } });
    },
    api(path) {
      if (path.endsWith("/pulls/7")) return pr;
      if (path.endsWith("/commits/main")) return { sha: baseSha };
      if (path.includes("/runs?")) return { workflow_runs: [{ id: 5, head_sha: pr.head.sha, status: "completed", conclusion: "success", run_attempt: 1, pull_requests: [{ base: { sha: baseSha } }] }] };
      if (path.includes("/jobs?")) return { jobs: [{ name: "Candidate Tests (advisory)", conclusion: jobs.head }, { name: "Base Suite (evidence)", conclusion: jobs.base }, { name: "Mergeproof Conscience Gate", conclusion: jobs.gate }] };
      throw new Error(`unexpected ${path}`);
    },
    list: (path) => (path.endsWith("/issues/7/comments") ? comments : path.endsWith("/pulls/7/comments") ? inline : []),
    post: (_repo, _pr, body) => { comments.push(receipt({}, { body })); },
  };
  const env = { ...ENV, REPO: "o/r", PR_NUMBER: "7", CANDIDATE_DIR: candidate, MIRQL_COURT_TOKEN: "token", AUTO_MERGE: "1", PATH: process.env.PATH };
  const verdicts = () => comments.filter((c) => c.body.includes("mirql-court-state")).map((c) => /"role":"(\w+)","verdict":"(\w+)"/.exec(c.body).slice(1).join(":"));
  const sync = () => { pr.head.sha = git(candidate, "rev-parse", "HEAD"); };
  return { git, origin, candidate, comments, inline, gh, pr, io, env, jobs, verdicts, sync };
}

describe("fast path: step choice", () => {
  const state = (...comments) => parseCourtState(comments, HEAD);
  const approve = receipt({ role: "critic", verdict: "APPROVE" });

  it("a clean Critic at the head goes straight to merge", () => {
    assert.equal(decideCourtStep(state(approve)), "merge");
  });

  it("an open finding, a pending Codex review or a locked courthouse suppresses it", () => {
    const commented = receipt({ role: "critic", verdict: "COMMENT", count: 1, payload: { findings: [FINDING] } });
    assert.equal(decideCourtStep(state(commented)), "advocate");
    assert.equal(decideCourtStep(state(approve), { externalFindings: [{ id: "9" }] }), "advocate");
    assert.equal(decideCourtStep(state(approve), { codexPending: true }), "wait");
    assert.equal(decideCourtStep(state(approve), { locked: true }), "recuse");
  });

  it("a pinned-bot finding reaches the Judge even after the Advocate answers it", () => {
    const answered = receipt({ role: "advocate", verdict: "REBUT", count: 1, payload: { responses: [{ finding_id: "9", action: "REBUT", reply: "no" }] } });
    assert.equal(decideCourtStep(state(approve, answered), { externalFindings: [{ id: "9" }] }), "judge");
  });

  it("without the Critic nothing is fast-pathed, and the fast path mints no Advocate round", () => {
    assert.equal(decideCourtStep(state(), { externalReviewed: true }), "judge");
    assert.equal(state(approve).advocateRounds, 0);
  });
});

describe("fast path: ticks", () => {
  it("a zero-finding Critic merges on one model call, and the receipt clears the gate", async () => {
    await withDir(async (dir) => {
      const box = sandbox(dir);
      const { fetchImpl, calls } = mockFetch(APPROVE);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl, baseDir: ROOT })), 0);
      assert.equal(calls.length, 1, "the Advocate and Judge are never called");
      const head = box.pr.head.sha;
      assert.deepEqual(box.verdicts(), ["critic:APPROVE", "judge:MERGE"]);
      assert.match(box.comments.at(-1).body, /"fast_path":true/);
      assert.equal(parseCourtState(box.comments, head).advocateRounds, 0);
      const call = box.gh.find((c) => c.includes("merge"));
      assert.ok(call, "the court lands the merge");
      assert.ok(call.includes("--match-head-commit") && call.includes(head));
      assert.equal(findAiApproval([], { reviewers: REVIEWERS, headSha: head, author: "ahmed-3m", comments: box.comments }), "mirql-judge[bot]");
    });
  });

  it("Critic findings keep the full sequence", async () => {
    await withDir(async (dir) => {
      const box = sandbox(dir);
      const { fetchImpl, calls } = mockFetch(CRITIC, REBUT, MERGE);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl, baseDir: ROOT })), 0);
      assert.equal(calls.length, 3);
      assert.deepEqual(box.verdicts(), ["critic:COMMENT", "advocate:REBUT", "judge:MERGE"]);
      assert.ok(!box.comments.some((c) => c.body.includes("fast_path")));
      assert.ok(box.gh.some((c) => c.includes("merge")));
    });
  });

  it("an Advocate push ends the tick before the Judge, and the next tick rules on the new head", async () => {
    await withDir(async (dir) => {
      const box = sandbox(dir);
      const { fetchImpl, calls } = mockFetch(CRITIC, FIX);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl, baseDir: ROOT })), 0);
      assert.equal(calls.length, 2, "no Judge call on the SHA the push replaced");
      assert.deepEqual(box.verdicts(), ["critic:COMMENT", "advocate:FIXED"]);
      const pushed = box.git(box.origin, "rev-parse", "refs/heads/feature");
      assert.notEqual(pushed, box.pr.head.sha);
      box.sync();
      const second = mockFetch(MERGE);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl: second.fetchImpl, baseDir: ROOT })), 0);
      assert.equal(second.calls.length, 1);
      assert.deepEqual(box.verdicts(), ["critic:COMMENT", "advocate:FIXED", "judge:MERGE"]);
      assert.ok(box.gh.some((c) => c.includes("merge") && c.includes(pushed)), "the merged head is the head the Judge ruled on");
    });
  });

  it("an outstanding pinned-bot finding suppresses the fast path", async () => {
    await withDir(async (dir) => {
      const box = sandbox(dir);
      box.inline.push({ id: 9, user: { login: "coderabbitai[bot]", type: "Bot" }, commit_id: box.pr.head.sha, path: "src.mjs", line: 1, body: "bug" });
      box.comments.push(receipt({ headSha: box.pr.head.sha, role: "critic", verdict: "APPROVE" }));
      const { fetchImpl, calls } = mockFetch(REBUT_9, MERGE_9);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl, baseDir: ROOT })), 0);
      assert.deepEqual(box.verdicts(), ["critic:APPROVE", "advocate:REBUT", "judge:MERGE"]);
      assert.ok(!box.comments.some((c) => c.body.includes("fast_path")));
      assert.equal(calls.length, 2, "the Judge still rules on the pinned-bot finding");
    });
  });

  it("a red gate holds the landing: the verdict stands and nothing merges", async () => {
    await withDir(async (dir) => {
      const box = sandbox(dir);
      box.jobs.gate = "failure";
      const { fetchImpl, calls } = mockFetch(APPROVE);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl, baseDir: ROOT })), 0);
      assert.equal(calls.length, 1);
      assert.deepEqual(box.verdicts(), ["critic:APPROVE", "judge:MERGE"]);
      assert.ok(!box.gh.some((c) => c.includes("merge")), "a red notary gates the fast path too");
      assert.ok(box.comments.some((c) => c.body.includes("mirql-court-landing:v1 NOTARY_NOT_RERUNNABLE")), "the stall is posted on the PR");
    });
  });

  it("a red head suite holds the fast path with no verdict, and a green re-run lands it", async () => {
    await withDir(async (dir) => {
      const box = sandbox(dir);
      box.jobs.head = "failure";
      const { fetchImpl, calls } = mockFetch(APPROVE);
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl, baseDir: ROOT })), 0);
      assert.deepEqual(box.verdicts(), ["critic:APPROVE"], "no MERGE receipt before the suites are green");
      assert.equal(calls.length, 1);
      assert.ok(!box.gh.some((c) => c.includes("merge")));
      box.jobs.head = "success";
      const green = mockFetch();
      assert.equal(await quiet(() => runCourtTick({ env: box.env, io: box.io, fetchImpl: green.fetchImpl, baseDir: ROOT })), 0);
      assert.deepEqual(box.verdicts(), ["critic:APPROVE", "judge:MERGE"]);
      assert.equal(green.calls.length, 0, "the landing needs no model call");
      assert.ok(box.gh.some((c) => c.includes("merge")));
    });
  });
});
