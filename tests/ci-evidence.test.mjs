// tests/ci-evidence.test.mjs — honest Notary evidence builder (Law 6 & 7).
// Pins the contract that scripts/ci-evidence.mjs only ever reports MEASURED
// facts: suite outcomes mirror CI step conclusions, the diff is authoritative,
// and causal_cycle_completed is never assumed true.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import {
  parseBoolEnv,
  isTestFilePath,
  collectDiff,
  buildPrDoc,
} from "../scripts/ci-evidence.mjs";

function git(repoDir, ...args) {
  const res = spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 15000 });
  assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

describe("ci-evidence: honest notary evidence builder", () => {
  describe("1. parseBoolEnv", () => {
    it("accepts only affirmative strings as true", () => {
      assert.equal(parseBoolEnv("true"), true);
      assert.equal(parseBoolEnv("TRUE"), true);
      assert.equal(parseBoolEnv("1"), true);
      assert.equal(parseBoolEnv("false"), false);
      assert.equal(parseBoolEnv("0"), false);
      assert.equal(parseBoolEnv(""), false);
      assert.equal(parseBoolEnv(undefined), false);
      assert.equal(parseBoolEnv(null), false);
    });
  });

  describe("2. isTestFilePath", () => {
    it("recognizes tests/ and .test. conventions, case-insensitively", () => {
      assert.equal(isTestFilePath("tests/core.test.mjs"), true);
      assert.equal(isTestFilePath("test/a_test.mjs"), true);
      assert.equal(isTestFilePath("pkg/foo.test.js"), true);
      assert.equal(isTestFilePath("pkg\\Bar.Test.ts"), true);
      assert.equal(isTestFilePath("packages/core/index.mjs"), false);
      assert.equal(isTestFilePath(42), false);
    });
  });

  describe("3. buildPrDoc honesty", () => {
    const baseInput = {
      pr: { number: 9, base_sha: "b".repeat(40), head_sha: "h".repeat(40), author: "agent" },
      diff: { files_changed: ["packages/run/index.mjs"], tests_deleted: [] },
      suite: { pass_base: true, pass_head: true },
      phi: { delta_phi: -12 },
    };

    it("mirrors measured suite outcomes into proof fields", () => {
      const doc = buildPrDoc(baseInput);
      assert.equal(doc.proof.suite_pass_base, true);
      assert.equal(doc.proof.suite_pass_head, true);
    });

    it("never upgrades a failed suite outcome", () => {
      const doc = buildPrDoc({ ...baseInput, suite: { pass_base: false, pass_head: true } });
      assert.equal(doc.proof.suite_pass_base, false);
      assert.equal(doc.proof.suite_pass_head, true);
    });

    it("defaults causal_cycle_completed to false (Law 16: never faked)", () => {
      const doc = buildPrDoc(baseInput);
      assert.equal(doc.proof.causal_cycle_completed, false);
    });

    it("only marks causal complete when explicitly attested", () => {
      const doc = buildPrDoc({ ...baseInput, causalCompleted: true });
      assert.equal(doc.proof.causal_cycle_completed, true);
      const docLoose = buildPrDoc({ ...baseInput, causalCompleted: "yes" });
      assert.equal(docLoose.proof.causal_cycle_completed, false);
    });

    it("propagates diff, deleted tests, and integer delta_phi untouched", () => {
      const doc = buildPrDoc({
        ...baseInput,
        diff: { files_changed: ["a.mjs", "b.mjs"], tests_deleted: ["tests/old.test.mjs"] },
        phi: { delta_phi: 0 },
      });
      assert.deepEqual(doc.diff_stat.files_changed, ["a.mjs", "b.mjs"]);
      assert.deepEqual(doc.evidence.tests_deleted, ["tests/old.test.mjs"]);
      assert.equal(doc.phi.delta_phi, 0);
      assert.equal(doc.pr.kind, "pr");
    });
  });

  describe("4. collectDiff (authoritative git diff, fail-closed)", () => {
    let repo;

    it("fails closed on a non-repository directory", () => {
      const notARepo = mkdtempSync(join(tmpdir(), "mirql-ciev-norepo-"));
      try {
        const res = collectDiff("a".repeat(40), "b".repeat(40), notARepo);
        assert.equal(res.ok, false);
        assert.deepEqual(res.files, []);
        assert.deepEqual(res.deletedTests, []);
      } finally {
        rmSync(notARepo, { recursive: true, force: true });
      }
    });

    it("fails closed on missing SHAs", () => {
      const res = collectDiff("", "b".repeat(40), ".");
      assert.equal(res.ok, false);
    });

    it("reports changed files and deleted tests from a real diff", () => {
      repo = mkdtempSync(join(tmpdir(), "mirql-ciev-repo-"));
      git(repo, "init", "-q");
      git(repo, "config", "user.email", "test@mirql.local");
      git(repo, "config", "user.name", "mirql-test");

      // Base commit: source + two test files
      mkdirSync(join(repo, "src"), { recursive: true });
      mkdirSync(join(repo, "tests"), { recursive: true });
      writeFileSync(join(repo, "src", "a.mjs"), "export const a = 1;\n");
      writeFileSync(join(repo, "tests", "a.test.mjs"), "import { a } from '../src/a.mjs';\n");
      writeFileSync(join(repo, "tests", "b.test.mjs"), "export {};\n");
      git(repo, "add", "-A");
      git(repo, "commit", "-q", "-m", "base");

      // Head commit: modify source, delete one test, rename the other test out of tests/
      writeFileSync(join(repo, "src", "a.mjs"), "export const a = 2;\n");
      writeFileSync(join(repo, "src", "c.mjs"), "export const c = 3;\n");
      git(repo, "rm", "-q", "tests/a.test.mjs");
      git(repo, "mv", "tests/b.test.mjs", "src/b.mjs");
      git(repo, "add", "-A");
      git(repo, "commit", "-q", "-m", "head");

      const baseSha = git(repo, "rev-parse", "HEAD~1").trim();
      const headSha = git(repo, "rev-parse", "HEAD").trim();

      const res = collectDiff(baseSha, headSha, repo);
      assert.equal(res.ok, true, `diff should succeed: ${res.error}`);
      assert.ok(res.files.includes("src/a.mjs"), `files: ${res.files.join(",")}`);
      assert.ok(res.files.includes("src/c.mjs"), `files: ${res.files.join(",")}`);
      assert.ok(res.files.includes("src/b.mjs"), `files: ${res.files.join(",")}`);
      assert.ok(res.deletedTests.includes("tests/a.test.mjs"), `deleted: ${res.deletedTests.join(",")}`);

      // Law 6: an unknown SHA must fail closed, not return an empty diff
      const bad = collectDiff("0".repeat(40), headSha, repo);
      assert.equal(bad.ok, false);
    });
  });
});
