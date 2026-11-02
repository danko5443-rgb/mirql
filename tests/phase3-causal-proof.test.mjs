import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyAttempt, parseTapOutput } from "../packages/run/verify.mjs";

function git(cwd, args) {
  const res = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout.trim();
}

function initRepo(dir) {
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.email", "p3@example.test"]);
  git(dir, ["config", "user.name", "p3"]);
  git(dir, ["config", "commit.gpgsign", "false"]);
}

function tmp(prefix) {
  return mkdtempSync(join(tmpdir(), `mirql-p3-${prefix}-`));
}

describe("Phase 3: Honest Causal Proof", () => {
  describe("3.5 TAP Output Parsing & Crash vs Assertion Distinction", () => {
    it("distinguishes pure assertion failure from runtime crash", () => {
      const tapAssert = `TAP version 13
# Subtest: math test
not ok 1 - math test
  ---
  duration_ms: 1.2
  failureType: 'testCodeFailure'
  error: 'Expected values to be strictly equal: -1 !== 5'
  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  ...
1..1
# tests 1
# pass 0
# fail 1`;
      const resAssert = parseTapOutput(tapAssert, 1);
      assert.equal(resAssert.isAssertionFailure, true);
      assert.equal(resAssert.isCrash, false);

      const tapCrash = `TAP version 13
# Subtest: broken import
not ok 1 - broken import
  ---
  duration_ms: 0.5
  failureType: 'testCodeFailure'
  error: 'Cannot read properties of undefined (reading add)'
  name: 'TypeError'
  ...
1..1
# tests 1
# pass 0
# fail 1`;
      const resCrash = parseTapOutput(tapCrash, 1);
      assert.equal(resCrash.isAssertionFailure, false);
      assert.equal(resCrash.isCrash, true);
    });
  });

  describe("3.2 Anti-Tautology Reproducer Specification", () => {
    it("rejects caller reproducer not present in diff", () => {
      const repo = tmp("repro-not-in-diff");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a + b;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "head without test"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        const res = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
          reproducerCommand: "node --test tests/nonexistent.test.mjs",
        });

        assert.equal(res.verified, false);
        assert.equal(res.verdict, "reject");
        assert.equal(res.rule, "REPRODUCER_NOT_IN_DIFF");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });

    it("rejects when candidate diff contains zero test files", () => {
      const repo = tmp("zero-tests");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a + b;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "head without tests"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        const res = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
        });

        assert.equal(res.verified, false);
        assert.equal(res.verdict, "reject");
        assert.equal(res.rule, "NO_REPRODUCER_TEST");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });
  });

  describe("3.5 Red-on-Base Crash Distinction", () => {
    it("rejects with RED_ON_BASE_CRASH when base throws TypeError instead of assertion failure", () => {
      const repo = tmp("base-crash");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        writeFileSync(join(repo, "src", "math.mjs"), "export const math = undefined;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base crash"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        writeFileSync(join(repo, "src", "math.mjs"), "export const math = { add: (a, b) => a + b };\n");
        mkdirSync(join(repo, "tests"), { recursive: true });
        writeFileSync(
          join(repo, "tests", "math.test.mjs"),
          'import assert from "node:assert/strict";\nimport test from "node:test";\nimport { math } from "../src/math.mjs";\ntest("math", () => assert.equal(math.add(2, 3), 5));\n',
        );
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "head"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        const res = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
        });

        assert.equal(res.verified, false);
        assert.equal(res.verdict, "reject");
        assert.equal(res.rule, "RED_ON_BASE_CRASH");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });
  });

  describe("3.3 V8 Coverage Assertion (Reproducer Relevance)", () => {
    it("rejects with REPRODUCER_IRRELEVANT when reproducer does not execute modified lines", () => {
      const repo = tmp("repro-irrelevant");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        writeFileSync(join(repo, "src", "calc.mjs"), "export function compute(x) { return x * 10; }\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        // Head changes compute() in calc.mjs, but test checks git commit message instead of calling compute!
        writeFileSync(join(repo, "src", "calc.mjs"), "export function compute(x) { return x * 20; }\n");
        mkdirSync(join(repo, "tests"), { recursive: true });
        writeFileSync(
          join(repo, "tests", "calc.test.mjs"),
          'import assert from "node:assert/strict";\nimport test from "node:test";\nimport { execSync } from "node:child_process";\ntest("irrelevant test", () => {\n  const log = execSync("git log -1 --pretty=%B", { encoding: "utf8" });\n  assert.match(log, /feat: relevant/);\n});\n',
        );
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "feat: relevant"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        const res = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
        });

        assert.equal(res.verified, false);
        assert.equal(res.verdict, "reject");
        assert.equal(res.rule, "REPRODUCER_IRRELEVANT");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });
  });

  describe("3.1 Necessity Check & Unnecessary Change Detection", () => {
    it("detects unnecessary changed file and rejects in surgical warrant mode", () => {
      const repo = tmp("unnecessary-change");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
        writeFileSync(join(repo, "src", "extra.mjs"), "export const extra = 1;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        // Head fixes math.mjs AND unnecessarily touches extra.mjs
        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a + b;\n");
        writeFileSync(join(repo, "src", "extra.mjs"), "export const extra = 2;\n");
        mkdirSync(join(repo, "tests"), { recursive: true });
        writeFileSync(
          join(repo, "tests", "math.test.mjs"),
          'import assert from "node:assert/strict";\nimport test from "node:test";\nimport { add } from "../src/math.mjs";\ntest("add", () => assert.equal(add(2, 3), 5));\n',
        );
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "head with extra unneeded file"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        // In standard mode: auto_merges but reports unnecessary_files
        const resStandard = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
        });
        assert.equal(resStandard.verified, true);
        assert.deepEqual(resStandard.proof?.necessity_check?.necessary_files, ["src/math.mjs"]);
        assert.deepEqual(resStandard.proof?.necessity_check?.unnecessary_files, ["src/extra.mjs"]);

        // In surgical mode: rejects with UNNECESSARY_CHANGE
        const resSurgical = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
          warrantClass: "surgical",
        });
        assert.equal(resSurgical.verified, false);
        assert.equal(resSurgical.verdict, "reject");
        assert.equal(resSurgical.rule, "UNNECESSARY_CHANGE");
        assert.match(resSurgical.detail, /src\/extra\.mjs/);
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });

    it("escalates to needs_human when more than 10 non-test files are modified", () => {
      const repo = tmp("too-many-files");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        for (let i = 1; i <= 12; i++) {
          writeFileSync(join(repo, "src", `f${i}.mjs`), `export const v${i} = 1;\n`);
        }
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        for (let i = 1; i <= 12; i++) {
          writeFileSync(join(repo, "src", `f${i}.mjs`), `export const v${i} = 2;\n`);
        }
        mkdirSync(join(repo, "tests"), { recursive: true });
        writeFileSync(
          join(repo, "tests", "test.test.mjs"),
          'import assert from "node:assert/strict";\nimport test from "node:test";\ntest("t", () => assert.equal(1, 1));\n',
        );
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "head 12 files"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        const res = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
        });

        assert.equal(res.verified, false);
        assert.equal(res.verdict, "needs_human");
        assert.equal(res.rule, "TOO_MANY_CHANGED_FILES");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });
  });

  describe("3.8 Determinism Sentinel", () => {
    it("rejects non-deterministic flaky reproducer on base", () => {
      const repo = tmp("flaky-repro");
      try {
        initRepo(repo);
        mkdirSync(join(repo, "src"), { recursive: true });
        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a - b;\n");
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "base"]);
        const base = git(repo, ["rev-parse", "HEAD"]);

        writeFileSync(join(repo, "src", "math.mjs"), "export const add = (a, b) => a + b;\n");
        mkdirSync(join(repo, "tests"), { recursive: true });
        // Flaky test: first run fails, second run passes via a state file!
        writeFileSync(
          join(repo, "tests", "flaky.test.mjs"),
          `import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const marker = join(tmpdir(), "mirql_flaky_marker.txt");
test("flaky test", () => {
  if (!existsSync(marker)) {
    writeFileSync(marker, "ran");
    assert.fail("first run fail");
  } else {
    try { unlinkSync(marker); } catch {}
    assert.equal(1, 1);
  }
});
`,
        );
        git(repo, ["add", "."]);
        git(repo, ["commit", "-q", "-m", "head with flaky test"]);
        const head = git(repo, ["rev-parse", "HEAD"]);

        const res = verifyAttempt({
          git: true,
          workspaceDir: repo,
          baseSha: base,
          headSha: head,
        });

        assert.equal(res.verified, false);
        assert.equal(res.verdict, "reject");
        assert.equal(res.rule, "FLAKY_REPRODUCER");
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });
  });
});
