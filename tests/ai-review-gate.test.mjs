// AI reviewer approval for humanOnly PRs (policy/paths.yaml `aiReviewers`).
//
// An Approve review on the exact head commit from an allowlisted bot lets a
// humanOnly PR run the remaining merge-proof rules instead of an MP-001
// reject. The verdict is capped at needs_human: it can never be auto_merge,
// and every other rule can still reject.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadPathPolicies } from "../packages/core/anti-cheat.mjs";
import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";
import { findAiApproval, hasApproveCommand, main, parseReviews } from "../scripts/ci-review-gate.mjs";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const HEAD = "a".repeat(40);
const OLD = "b".repeat(40);
const BOTS = ["coderabbitai[bot]", "chatgpt-codex-connector[bot]"];
const CTX = { reviewers: BOTS, headSha: HEAD, author: "ahmed-3m" };

function review(login, state, commit = HEAD, at = "2026-11-02T10:00:00Z", type = "Bot") {
  return { user: { login, type }, state, commit_id: commit, submitted_at: at };
}

/** A doc with a causal proof that touches a humanOnly path. */
function humanOnlyDoc(overrides = {}) {
  return {
    schema: "outcome/v1",
    pr: { number: 1, author: "role:builder", kind: "bugfix" },
    diff_stat: { files_changed: [".github/workflows/mergeproof.yml", "src/feature.mjs"] },
    proof: { causal_cycle_completed: true },
    evidence: { forbidden_paths_touched: [], tests_deleted: [] },
    anti_cheat: { violations_count: 0, flags: [] },
    phi: { phi_base: 10, phi_head: 9, delta_phi: -1 },
    surface: { uncited_commands: [], delta_count: 0 },
    ...overrides,
  };
}

describe("ai review gate: policy", () => {
  it("loads aiReviewers from policy/paths.yaml without leaking into humanApprove", () => {
    const p = loadPathPolicies(ROOT);
    assert.deepEqual(p.aiReviewers, BOTS);
    assert.ok(!p.humanApprove.some((x) => x.includes("[bot]")));
    assert.ok(p.humanOnly.includes(".coderabbit.yaml"), "reviewer config must be humanOnly");
  });
});

describe("ai review gate: findAiApproval", () => {
  it("accepts an allowlisted bot's Approve on the head commit", () => {
    assert.equal(findAiApproval([review("coderabbitai[bot]", "APPROVED")], CTX), "coderabbitai[bot]");
  });

  it("ignores an approval on an older commit", () => {
    assert.equal(findAiApproval([review("coderabbitai[bot]", "APPROVED", OLD)], CTX), null);
  });

  it("ignores accounts that are not allowlisted, and human accounts using a bot's name", () => {
    assert.equal(findAiApproval([review("evil[bot]", "APPROVED")], CTX), null);
    assert.equal(findAiApproval([review("coderabbitai[bot]", "APPROVED", HEAD, undefined, "User")], CTX), null);
  });

  it("ignores comment-only reviews", () => {
    assert.equal(findAiApproval([review("chatgpt-codex-connector[bot]", "COMMENTED")], CTX), null);
  });

  it("does not let a bot approve its own PR", () => {
    assert.equal(
      findAiApproval([review("chatgpt-codex-connector[bot]", "APPROVED")], { ...CTX, author: "chatgpt-codex-connector[bot]" }),
      null,
    );
  });

  it("a later Request changes or dismissal voids an earlier approval", () => {
    const approve = review("coderabbitai[bot]", "APPROVED", HEAD, "2026-11-02T10:00:00Z");
    assert.equal(findAiApproval([approve, review("coderabbitai[bot]", "CHANGES_REQUESTED", HEAD, "2026-11-02T11:00:00Z")], CTX), null);
    assert.equal(findAiApproval([approve, review("coderabbitai[bot]", "DISMISSED", HEAD, "2026-11-02T11:00:00Z")], CTX), null);
  });

  it("one bot's outstanding Request changes blocks the other bot's approval", () => {
    const reviews = [
      review("coderabbitai[bot]", "APPROVED"),
      review("chatgpt-codex-connector[bot]", "CHANGES_REQUESTED"),
    ];
    assert.equal(findAiApproval(reviews, CTX), null);
  });

  it("detects human comments that command an approval", () => {
    const human = (body) => ({ user: { login: "x", type: "User" }, body });
    assert.equal(hasApproveCommand([human("@coderabbitai approve")]), true);
    assert.equal(hasApproveCommand([human("thanks\n@CodeRabbitAI  resolve")]), true);
    assert.equal(hasApproveCommand([human("@coderabbitai review")]), false);
    assert.equal(hasApproveCommand([{ user: { login: "coderabbitai[bot]", type: "Bot" }, body: "run @coderabbitai approve" }]), false);
  });

  it("main reads the base policy and writes the approver output", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mirql-aigate-"));
    try {
      const reviewsPath = join(dir, "reviews.jsonl");
      const commentsPath = join(dir, "comments.jsonl");
      const outPath = join(dir, "out.txt");
      writeFileSync(reviewsPath, `${JSON.stringify(review("coderabbitai[bot]", "APPROVED"))}\n`);
      writeFileSync(commentsPath, `${JSON.stringify({ user: { login: "ahmed-3m", type: "User" }, body: "looks good" })}\n`);
      writeFileSync(outPath, "");
      const env = {
        BASE_NOTARY_DIR: ROOT,
        REVIEWS_PATH: reviewsPath,
        COMMENTS_PATH: commentsPath,
        HEAD_SHA: HEAD,
        PR_AUTHOR: "ahmed-3m",
        GITHUB_OUTPUT: outPath,
      };
      assert.equal(await main(env), 0);
      assert.equal(readFileSync(outPath, "utf8"), "approver=coderabbitai[bot]\n");

      // A human comment that commands the approval voids it.
      writeFileSync(commentsPath, `${JSON.stringify({ user: { login: "agent", type: "User" }, body: "@coderabbitai approve" })}\n`);
      writeFileSync(outPath, "");
      assert.equal(await main(env), 0);
      assert.equal(readFileSync(outPath, "utf8"), "");
      assert.equal(await main({ ...env, COMMENTS_PATH: undefined }), 1, "missing comments fails closed");
      assert.equal(await main({ BASE_NOTARY_DIR: ROOT, HEAD_SHA: HEAD, PR_AUTHOR: "x" }), 1, "missing input fails closed");
      assert.deepEqual(parseReviews("\n"), []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("ai review gate: evaluator", () => {
  it("without an approval a humanOnly PR is still rejected (MP-001)", () => {
    const res = evaluatePullRequest(humanOnlyDoc(), { rootDir: ROOT });
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "TOUCH_HUMAN_ONLY");
  });

  it("with an approval a clean humanOnly PR is capped at needs_human, never auto_merge", () => {
    const res = evaluatePullRequest(humanOnlyDoc(), { rootDir: ROOT, humanOnlyReviewer: "coderabbitai[bot]" });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.rule, "MP-001");
    assert.equal(res.human_only_reviewer, "coderabbitai[bot]");
  });

  it("with an approval the remaining rules still reject", () => {
    const res = evaluatePullRequest(
      humanOnlyDoc({ evidence: { forbidden_paths_touched: [], tests_deleted: ["tests/feature.test.mjs"] } }),
      { rootDir: ROOT, humanOnlyReviewer: "coderabbitai[bot]" },
    );
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "TEST_DELETED");
  });

  it("an approval cannot clear a change to the reviewer's own config", () => {
    const res = evaluatePullRequest(
      humanOnlyDoc({ diff_stat: { files_changed: [".coderabbit.yaml"] } }),
      { rootDir: ROOT, humanOnlyReviewer: "coderabbitai[bot]" },
    );
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "TOUCH_HUMAN_ONLY");
  });

  it("an implausible reviewer login is ignored", () => {
    const res = evaluatePullRequest(humanOnlyDoc(), { rootDir: ROOT, humanOnlyReviewer: "--output=x" });
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "TOUCH_HUMAN_ONLY");
  });

  it("m check --human-only-reviewer reaches the evaluator", () => {
    const res = spawnSync(
      process.execPath,
      [join(ROOT, "bin", "mirql.mjs"), "m", "check", "--pr", JSON.stringify(humanOnlyDoc()), "--human-only-reviewer", "coderabbitai[bot]"],
      { cwd: ROOT, encoding: "utf8" },
    );
    const out = JSON.parse(res.stdout.trim().split(/\r?\n/).pop());
    assert.equal(out.verdict, "needs_human");
    assert.notEqual(res.status, 0, "needs_human never exits 0");
  });
});
