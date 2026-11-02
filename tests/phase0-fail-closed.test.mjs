import { provisionTestTrust } from "./helpers/keyring.mjs";
// Phase 0 (docs/TRUST-REMEDIATION-PLAN.md): fail-closed regression tests.
//
// Each test reproduces an exploit that worked on main before Phase 0:
// - 0.2  a self-reported doc (`m check --pr`, fixture/doc verify) reached auto_merge
// - 0.0b a suite pass without a causal proof reached auto_merge
// - 0.3  a causal proof or a `human_approved` boolean unlocked humanApprove paths
// - 0.4  `l verify` trusted the key embedded in an event when no keyring exists
// - 0.5  default refs HEAD~1/HEAD were resolved inside the moved worktree
// - 0.6  failed `git checkout` calls in the worktree were ignored
// - 0.0a the test runner could only run the tree it lives in
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { EXIT_CODES, generateEd25519Keypair, sha256, ulid } from "../packages/core/index.mjs";
import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";
import { checkAntiCheat } from "../packages/run/anti-cheat.mjs";
import { verifyAttempt } from "../packages/run/verify.mjs";
import { appendEvent, verifyLedger } from "../packages/log/index.mjs";
import { leaseNextJob, stageCanary, submitWarrant } from "../packages/queue/index.mjs";
import { getOrCreateQueueKeypair } from "../packages/queue/ledger.mjs";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const MIRQL = join(ROOT, "bin", "mirql.mjs");

function runMirql(args, opts = {}) {
  return spawnSync(process.execPath, [MIRQL, ...args], {
    cwd: opts.cwd ?? ROOT,
    encoding: "utf8",
    input: opts.input,
    env: { ...process.env, ...(opts.env ?? {}) },
  });
}

function tmp(prefix) {
  return mkdtempSync(join(tmpdir(), `mirql-p0-${prefix}-`));
}

/** A doc that claims a full causal proof on an unprotected path. */
function forgedDoc(overrides = {}) {
  return {
    schema: "outcome/v1",
    job_id: "job_forged",
    pr: { number: 1, author: "role:builder", kind: "bugfix" },
    diff_stat: { files_changed: ["src/feature.mjs", "tests/feature.test.mjs"] },
    proof: { causal_cycle_completed: true },
    evidence: { forbidden_paths_touched: [], tests_deleted: [] },
    anti_cheat: { violations_count: 0, flags: [] },
    phi: { phi_base: 10, phi_head: 9, delta_phi: -1 },
    surface: { uncited_commands: [], delta_count: 0 },
    ...overrides,
  };
}

function git(cwd, args) {
  const res = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout.trim();
}

function initRepo(dir) {
  git(dir, ["init", "-q"]);
  git(dir, ["config", "user.email", "p0@example.test"]);
  git(dir, ["config", "user.name", "p0"]);
  git(dir, ["config", "commit.gpgsign", "false"]);
}

/** Two-commit repo: base has a bug, head fixes it and adds a reproducer. */
function buildFixRepo(dir) {
  initRepo(dir);
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
  git(dir, ["add", "."]);
  git(dir, ["commit", "-q", "-m", "base"]);
  const base = git(dir, ["rev-parse", "HEAD"]);
  writeFileSync(join(dir, "src", "math.mjs"), "export const add = (a, b) => a + b;\n");
  mkdirSync(join(dir, "tests"), { recursive: true });
  writeFileSync(
    join(dir, "tests", "math.test.mjs"),
    'import assert from "node:assert/strict";\nimport test from "node:test";\nimport { add } from "../src/math.mjs";\ntest("add", () => assert.equal(add(2, 3), 5));\n',
  );
  git(dir, ["add", "."]);
  git(dir, ["commit", "-q", "-m", "head"]);
  const head = git(dir, ["rev-parse", "HEAD"]);
  return { base, head };
}

const REPRO = "node --test tests/math.test.mjs";

describe("phase 0.2: a self-reported doc never reaches auto_merge", () => {
  it("evaluatePullRequest on a forged causal proof → conformance_pass", () => {
    const res = evaluatePullRequest(forgedDoc(), { rootDir: ROOT });
    assert.notEqual(res.verdict, "auto_merge");
    assert.equal(res.verdict, "conformance_pass");
  });

  it("`m check --pr <forged doc>` does not exit 0", () => {
    const res = runMirql(["m", "check", "--pr", JSON.stringify(forgedDoc())]);
    assert.notEqual(res.status, EXIT_CODES.OK, res.stdout);
    const doc = JSON.parse(res.stdout.trim().split("\n").at(-1));
    assert.equal(doc.verdict, "conformance_pass");
  });

  it("verifyAttempt on a direct doc → not verified, conformance_pass", () => {
    const res = verifyAttempt(forgedDoc());
    assert.equal(res.verified, false);
    assert.equal(res.verdict, "conformance_pass");
  });

  it("verifyAttempt on a fixture path → not verified", () => {
    const res = verifyAttempt({
      fixture: join(ROOT, "conformance", "good_prs", "01-valid-repro-fix.json"),
    });
    assert.equal(res.verified, false);
    assert.notEqual(res.verdict, "auto_merge");
  });
});

describe("phase 0.0b: a suite pass without a causal proof → needs_human", () => {
  it("suite_pass_base + suite_pass_head only → needs_human / NO_CAUSAL_PROOF", () => {
    const res = evaluatePullRequest(
      forgedDoc({
        proof: { causal_cycle_completed: false, suite_pass_base: true, suite_pass_head: true },
      }),
      { rootDir: ROOT },
    );
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.violation, "NO_CAUSAL_PROOF");
  });
});

describe("phase 0.3: nothing self-reported unlocks a humanApprove path", () => {
  const touchesCore = forgedDoc({
    diff_stat: { files_changed: ["packages/core/acl.mjs"] },
  });

  it("causal proof on packages/core/** → needs_human / MP-005", () => {
    const res = evaluatePullRequest(touchesCore, { rootDir: ROOT });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.rule, "MP-005");
  });

  it("options.humanApproved does not unlock packages/core/**", () => {
    const res = evaluatePullRequest(touchesCore, { rootDir: ROOT, humanApproved: true });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.rule, "MP-005");
  });

  for (const flag of ["human_approved", "human_approval"]) {
    it(`checkAntiCheat ignores input.${flag}`, () => {
      const res = checkAntiCheat({ ...touchesCore, [flag]: true });
      assert.equal(res.ok, false);
      assert.equal(res.verdict, "needs_human");
    });
  }

  it("checkAntiCheat ignores evidence.human_approval", () => {
    const res = checkAntiCheat({
      ...touchesCore,
      evidence: { ...touchesCore.evidence, human_approval: true },
    });
    assert.equal(res.ok, false);
    assert.equal(res.verdict, "needs_human");
  });
});

describe("phase 0.4: no keyring → no trusted keys", () => {
  it("`l verify` fails on a ledger signed by an arbitrary key claiming human:owner", () => {
    const work = tmp("forge");
    try {
      const dir = join(work, ".mirql");
      const kp = generateEd25519Keypair();
      appendEvent(
        dir,
        {
          type: "warrant.created",
          writer: { ns: "human:owner", key_id: kp.keyId },
          payload: { forged: true },
        },
        { privateKey: kp.privateKey, keyId: kp.keyId },
      );
      assert.equal(verifyLedger(dir).valid, false);
      const res = runMirql(["l", "verify", "--dir", dir]);
      assert.equal(res.status, EXIT_CODES.INTEGRITY_VIOLATION, res.stdout + res.stderr);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  });
});

describe("phase 0.5 / 0.6: git-mode verification", () => {
  it("default refs (HEAD~1..HEAD) verify a real fix", () => {
    const repo = tmp("refs");
    try {
      buildFixRepo(repo);
      const res = verifyAttempt({ git: true, workspaceDir: repo, reproducerCommand: REPRO });
      assert.equal(res.verified, true, JSON.stringify(res));
      assert.equal(res.verdict, "auto_merge");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("a failed checkout of the base rejects with CHECKOUT_FAILED", () => {
    const repo = tmp("checkout");
    try {
      initRepo(repo);
      // A required smudge filter that always fails: any checkout that has to
      // write src/math.mjs under this attribute errors out.
      git(repo, ["config", "filter.boom.smudge", "false"]);
      git(repo, ["config", "filter.boom.clean", "cat"]);
      git(repo, ["config", "filter.boom.required", "true"]);
      mkdirSync(join(repo, "src"), { recursive: true });
      writeFileSync(join(repo, ".gitattributes"), "src/math.mjs filter=boom\n");
      writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
      git(repo, ["add", "."]);
      git(repo, ["commit", "-q", "-m", "base"]);
      const base = git(repo, ["rev-parse", "HEAD"]);
      git(repo, ["rm", "-q", "--cached", ".gitattributes"]);
      rmSync(join(repo, ".gitattributes"));
      writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a + b;\n");
      mkdirSync(join(repo, "tests"), { recursive: true });
      writeFileSync(
        join(repo, "tests", "math.test.mjs"),
        'import assert from "node:assert/strict";\nimport test from "node:test";\nimport { add } from "../src/math.mjs";\ntest("add", () => assert.equal(add(2, 3), 5));\n',
      );
      git(repo, ["add", "."]);
      git(repo, ["commit", "-q", "-m", "head"]);
      const head = git(repo, ["rev-parse", "HEAD"]);
      const res = verifyAttempt({
        git: true,
        workspaceDir: repo,
        baseSha: base,
        headSha: head,
        reproducerCommand: REPRO,
      });
      assert.equal(res.verified, false);
      assert.equal(res.verdict, "reject");
      assert.equal(res.rule, "CHECKOUT_FAILED", JSON.stringify(res));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });
});

describe("phase 0.0a: the notary's runner can run another tree", () => {
  // Guard: if the override were ignored, the child would run this very suite
  // again and recurse.
  it("MIRQL_TEST_ROOT points the runner at a different checkout", { skip: process.env.MIRQL_P0_NESTED === "1" }, () => {
    const other = tmp("root");
    try {
      mkdirSync(join(other, "tests"));
      for (const name of ["inbox.test.mjs", "e2e-tracer.test.mjs"]) {
        writeFileSync(join(other, "tests", name), 'import test from "node:test";\ntest("ok", () => {});\n');
      }
      writeFileSync(
        join(other, "tests", "zz-fail.test.mjs"),
        'import test from "node:test";\nimport assert from "node:assert/strict";\ntest("marker", () => assert.fail("P0_OTHER_ROOT_MARKER"));\n',
      );
      // Drop NODE_TEST_CONTEXT so the nested `node --test` reports as a
      // top-level run instead of streaming to this runner.
      const { NODE_TEST_CONTEXT: _ctx, ...env } = process.env;
      const res = spawnSync(process.execPath, [join(ROOT, "scripts", "run-tests.mjs")], {
        encoding: "utf8",
        env: { ...env, MIRQL_TEST_ROOT: other, MIRQL_P0_NESTED: "1" },
        timeout: 120000,
      });
      assert.notEqual(res.status, 0);
      assert.match(res.stdout + res.stderr, /P0_OTHER_ROOT_MARKER/);
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });
});

describe("security review: option injection and fail-open gates", () => {
  it("a PR doc base_sha shaped like a git option never reaches git diff", () => {
    const out = tmp("inject");
    try {
      const doc = forgedDoc({
        pr: { ...forgedDoc().pr, base_sha: `--output=${join(out, "pwn")}`, head_sha: "a".repeat(40) },
      });
      evaluatePullRequest(doc, { rootDir: ROOT, repoDir: ROOT });
      assert.deepEqual(readdirSync(out), [], "git diff wrote a file chosen by the PR doc");
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });

  it("an asserted --base that is not a hex SHA rejects with GIT_DIFF_FAILED", () => {
    const res = evaluatePullRequest(forgedDoc(), {
      rootDir: ROOT,
      repoDir: ROOT,
      targetTipSha: "--output=x",
      expectedHeadSha: "a".repeat(40),
    });
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "GIT_DIFF_FAILED");
  });

  it("verifyAttempt rejects a ref shaped like a git option", () => {
    const repo = tmp("refopt");
    try {
      buildFixRepo(repo);
      const res = verifyAttempt({
        git: true,
        workspaceDir: repo,
        baseSha: "--all",
        headSha: "HEAD",
        reproducerCommand: REPRO,
      });
      assert.equal(res.verified, false);
      assert.equal(res.verdict, "reject");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("stageCanary refuses a job with no notary verdict", () => {
    const work = tmp("canary");
    try {
      const dir = join(work, ".mirql");
      mkdirSync(dir, { recursive: true });
      provisionTestTrust(dir);
      getOrCreateQueueKeypair(dir);
      const wid = ulid();
      const sub = submitWarrant(dir, {
        v: 1,
        id: wid,
        class: "surgical",
        semantic_fingerprint: sha256(`intent: p0 canary ${wid}`),
        anchors: [{ path: "packages/queue/index.mjs" }],
        evidence: { citations: 1 },
        red_check: { reviewed: 1 },
        scope: { allow_globs: ["packages/queue/**"] },
        budget_micro_usd: 500_000,
        created_by: "human:owner",
      });
      assert.equal(sub.ok, true, sub.error);
      leaseNextJob(dir, { workerId: "p0" });
      assert.throws(
        () => stageCanary(dir, {
          jobId: sub.job_id,
          baseSha: "a".repeat(40),
          candidateVersion: "0.2.0",
          supervisorVersion: "0.1.0",
        }),
        (err) => err.errorCode === "INVALID_VERDICT",
      );
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  });
});
