// tests/ci-evidence.test.mjs — honest Notary evidence builder (Law 6 & 7).
// Pins the contract that scripts/ci-evidence.mjs only ever reports MEASURED
// facts: suite outcomes mirror CI step conclusions, the diff is authoritative,
// and causal_cycle_completed is never assumed true.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import {
  parseBoolEnv,
  isTestFilePath,
  collectDiff,
  buildPrDoc,
  measureThrift,
  loadReproducerManifest,
  runReproducerScript,
  verifyCausalReproducer,
  main,
} from "../scripts/ci-evidence.mjs";
import { verifyThrift } from "../packages/run/index.mjs";

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

  describe("3b. Thrift Test producer (issue #13)", () => {
    // The real criteria engine — exactly what the base notary will inject in CI.
    // verifyThrift's own criteria internals are pinned by tests/m2-phi.test.mjs;
    // these tests pin the MEASUREMENT COMPOSITION and the pr-doc propagation.
    const input = {
      phiBase: 1000,
      phiHead: 900,
      deletedTests: [],
      filesChanged: ["packages/run/phi.mjs"],
      depsBase: 0,
      depsHead: 0,
      verifyThriftFn: verifyThrift,
    };
    const prDocBase = {
      pr: { number: 9, base_sha: "b".repeat(40), head_sha: "h".repeat(40), author: "agent" },
      diff: { files_changed: input.filesChanged, tests_deleted: [] },
      suite: { pass_base: true, pass_head: true },
      phi: { delta_phi: -100 },
    };

    it("passes only when every thrift criterion genuinely holds", () => {
      const res = measureThrift(input);
      assert.equal(res.passed, true);
      assert.deepEqual(res.reasons, []);
      assert.equal(res.evidence.surface_changed, false);
      assert.equal(res.evidence.deps_after, 0);
    });

    it("fails closed on any violated criterion (deleted tests shown; surface, deps, ΔΦ delegate to verifyThrift)", () => {
      const res = measureThrift({ ...input, deletedTests: ["tests/x.test.mjs"] });
      assert.equal(res.passed, false);
      assert.ok(res.reasons.some((r) => r.includes("Test preservation")));
    });

    it("omits the dependency criterion when package.json is unmeasurable", () => {
      const res = measureThrift({ ...input, depsBase: -1 });
      assert.equal(res.passed, true, "unmeasurable deps must not fabricate a failure");
      assert.equal(res.evidence.deps_before, -1);
    });

    it("flows the measured verdict into phi.thrift_test_passed (buildPrDoc)", () => {
      const doc = buildPrDoc({ ...prDocBase, thrift: measureThrift(input) });
      assert.equal(doc.phi.thrift_test_passed, true);
      assert.equal(doc.phi.thrift_evidence.surface_changed, false);

      const failed = measureThrift({ ...input, deletedTests: ["tests/x.test.mjs"] });
      const docFail = buildPrDoc({ ...prDocBase, thrift: failed });
      assert.equal(docFail.phi.thrift_test_passed, false);
      assert.ok(docFail.phi.thrift_reasons.length > 0);
    });

    it("detects surface.lock modification even with relative path variations", () => {
      const res1 = measureThrift({ ...input, filesChanged: ["./surface.lock"] });
      assert.equal(res1.passed, false);
      assert.equal(res1.evidence.surface_changed, true);

      const res2 = measureThrift({ ...input, filesChanged: [".\\surface.lock"] });
      assert.equal(res2.passed, false);
      assert.equal(res2.evidence.surface_changed, true);
    });

    it("fails closed when verifyThriftFn is missing or invalid", () => {
      const res = measureThrift({ ...input, verifyThriftFn: null });
      assert.equal(res.passed, false);
      assert.ok(res.reasons.some((r) => r.includes("Law 7 fail-closed")));
    });

    it("safely defaults omitted arrays without throwing", () => {
      const res = measureThrift({
        phiBase: 1000,
        phiHead: 900,
        verifyThriftFn: verifyThrift,
      });
      assert.equal(res.passed, true);
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
      try {
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
        assert.ok(res.deletedTests.includes("tests/b.test.mjs"), `renamed test must count as deleted test: ${res.deletedTests.join(",")}`);

        // Law 6: an unknown SHA must fail closed, not return an empty diff
        const bad = collectDiff("0".repeat(40), headSha, repo);
        assert.equal(bad.ok, false);
      } finally {
        rmSync(repo, { recursive: true, force: true });
      }
    });
  });

  describe("5. main entrypoint fail-closed contracts (H2 hardening)", () => {
    it("fails closed via CLI spawn when required env vars are missing", () => {
      const res = spawnSync(process.execPath, ["scripts/ci-evidence.mjs"], {
        env: {},
        encoding: "utf8",
      });
      assert.equal(res.status, 1);
      assert.ok(res.stderr.includes("missing required env"));
    });

    it("fails closed via CLI spawn when PR_NUMBER is non-numeric or float", () => {
      const res = spawnSync(process.execPath, ["scripts/ci-evidence.mjs"], {
        env: {
          BASE_NOTARY_DIR: ".",
          CANDIDATE_DIR: ".",
          BASE_SHA: "a".repeat(40),
          HEAD_SHA: "b".repeat(40),
          PR_NUMBER: "abc",
          PR_AUTHOR: "tester",
          SUITE_PASS_BASE: "true",
          SUITE_PASS_HEAD: "true",
        },
        encoding: "utf8",
      });
      assert.equal(res.status, 1);
      assert.ok(res.stderr.includes("PR_NUMBER is not a safe positive integer"));
    });

    it("end-to-end: executes successfully and writes valid pr-doc.json", () => {
      const tempDir = mkdtempSync(join(tmpdir(), "mirql-ciev-e2e-"));
      try {
        git(tempDir, "init", "-q");
        git(tempDir, "config", "user.email", "test@mirql.local");
        git(tempDir, "config", "user.name", "mirql-test");
        writeFileSync(join(tempDir, "sample.txt"), "hello\n");
        git(tempDir, "add", "-A");
        git(tempDir, "commit", "-q", "-m", "init");

        writeFileSync(join(tempDir, "sample.txt"), "hello world\n");
        git(tempDir, "add", "-A");
        git(tempDir, "commit", "-q", "-m", "update");

        const baseSha = git(tempDir, "rev-parse", "HEAD~1").trim();
        const headSha = git(tempDir, "rev-parse", "HEAD").trim();

        const outDocPath = join(tempDir, "out-pr-doc.json");
        const res = spawnSync(process.execPath, [resolve("scripts/ci-evidence.mjs")], {
          env: {
            BASE_NOTARY_DIR: resolve("."),
            CANDIDATE_DIR: tempDir,
            BASE_SHA: baseSha,
            HEAD_SHA: headSha,
            PR_NUMBER: "17",
            PR_AUTHOR: "test-author",
            SUITE_PASS_BASE: "true",
            SUITE_PASS_HEAD: "false",
            PR_DOC_PATH: outDocPath,
          },
          encoding: "utf8",
        });

        assert.equal(res.status, 0, `spawn failed: ${res.stderr}`);
        assert.ok(existsSync(outDocPath));

        const parsed = JSON.parse(readFileSync(outDocPath, "utf8"));
        assert.equal(parsed.pr.number, 17);
        assert.equal(parsed.proof.suite_pass_base, true);
        assert.equal(parsed.proof.suite_pass_head, false);
        assert.equal(parsed.proof.causal_cycle_completed, false);
        assert.ok(Array.isArray(parsed.diff_stat.files_changed));
        assert.ok(Number.isSafeInteger(parsed.phi.delta_phi));
      } finally {
        rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe("6. Verified-reproducer causal cycle (Law 16)", () => {
    /**
     * Fixture: a candidate carrying a reproducer whose script exits non-zero
     * when MIRQL_TARGET_ROOT/marker.txt says "broken", zero on "fixed".
     * baseDir gets the broken marker, candidate the fixed one — exactly the
     * red-on-base → green-on-head contract.
     */
    function makeFixture({ baseMarker = "broken", headMarker = "fixed", manifest } = {}) {
      const candidate = mkdtempSync(join(tmpdir(), "mirql-repro-cand-"));
      const base = mkdtempSync(join(tmpdir(), "mirql-repro-base-"));
      mkdirSync(join(candidate, "reproducer"), { recursive: true });
      writeFileSync(
        join(candidate, "reproducer", "entry.mjs"),
        `import { readFileSync } from "node:fs";\n` +
          `import { join } from "node:path";\n` +
          `const root = process.env.MIRQL_TARGET_ROOT;\n` +
          `if (!root) { console.error("MIRQL_TARGET_ROOT not set"); process.exit(5); }\n` +
          `const marker = readFileSync(join(root, "marker.txt"), "utf8").trim();\n` +
          `process.exit(marker === "broken" ? 3 : 0);\n`,
        "utf8",
      );
      writeFileSync(
        join(candidate, "reproducer", "manifest.json"),
        JSON.stringify(
          manifest ?? {
            description: "fixture reproducer",
            entry: "reproducer/entry.mjs",
            expect_base: "fail",
            expect_head: "pass",
          },
        ),
        "utf8",
      );
      writeFileSync(join(base, "marker.txt"), baseMarker, "utf8");
      writeFileSync(join(candidate, "marker.txt"), headMarker, "utf8");
      return { candidate, base };
    }

    it("validates the manifest fail-closed", () => {
      const { candidate, base } = makeFixture();
      try {
        assert.equal(loadReproducerManifest(candidate).ok, true);

        const noEntry = makeFixture({ manifest: { expect_base: "fail", expect_head: "pass" } });
        assert.match(loadReproducerManifest(noEntry.candidate).error, /entry/);

        const escaping = makeFixture({
          manifest: { entry: "reproducer/../../escape.mjs", expect_base: "fail", expect_head: "pass" },
        });
        assert.match(loadReproducerManifest(escaping.candidate).error, /escape/);

        const wrongExpects = makeFixture({
          manifest: { entry: "reproducer/entry.mjs", expect_base: "pass", expect_head: "pass" },
        });
        assert.match(loadReproducerManifest(wrongExpects.candidate).error, /expect_base/);

        rmSync(noEntry.candidate, { recursive: true, force: true });
        rmSync(noEntry.base, { recursive: true, force: true });
        rmSync(escaping.candidate, { recursive: true, force: true });
        rmSync(escaping.base, { recursive: true, force: true });
        rmSync(wrongExpects.candidate, { recursive: true, force: true });
        rmSync(wrongExpects.base, { recursive: true, force: true });
      } finally {
        rmSync(candidate, { recursive: true, force: true });
        rmSync(base, { recursive: true, force: true });
      }
    });

    it("verifies causal only on genuinely observed red-on-base + green-on-head", () => {
      const { candidate, base } = makeFixture();
      try {
        const res = verifyCausalReproducer({ candidateDir: candidate, baseDir: base });
        assert.equal(res.present, true);
        assert.equal(res.causal, true);
        assert.equal(res.base_exit_code, 3);
        assert.equal(res.head_exit_code, 0);
      } finally {
        rmSync(candidate, { recursive: true, force: true });
        rmSync(base, { recursive: true, force: true });
      }
    });

    it("never verifies when the defect does not reproduce on base", () => {
      const { candidate, base } = makeFixture({ baseMarker: "fixed" });

      try {
        const res = verifyCausalReproducer({ candidateDir: candidate, baseDir: base });
        assert.equal(res.causal, false, "green-on-base proves nothing");
      } finally {
        rmSync(candidate, { recursive: true, force: true });
        rmSync(base, { recursive: true, force: true });
      }
    });

    it("never verifies when the fix does not fix the head", () => {
      const { candidate, base } = makeFixture({ headMarker: "broken" });

      try {
        const res = verifyCausalReproducer({ candidateDir: candidate, baseDir: base });
        assert.equal(res.causal, false, "red-on-head means the cycle is incomplete");
        assert.equal(res.head_exit_code, 3);
      } finally {
        rmSync(candidate, { recursive: true, force: true });
        rmSync(base, { recursive: true, force: true });
      }
    });

    it("fails closed on timeout (never a verified red)", () => {
      const candidate = mkdtempSync(join(tmpdir(), "mirql-repro-hang-"));
      const base = mkdtempSync(join(tmpdir(), "mirql-repro-hangb-"));
      try {
        mkdirSync(join(candidate, "reproducer"), { recursive: true });
        writeFileSync(
          join(candidate, "reproducer", "entry.mjs"),
          `setTimeout(() => {}, 30000);\n`,
          "utf8",
        );
        writeFileSync(
          join(candidate, "reproducer", "manifest.json"),
          JSON.stringify({ entry: "reproducer/entry.mjs", expect_base: "fail", expect_head: "pass" }),
          "utf8",
        );
        const res = verifyCausalReproducer({ candidateDir: candidate, baseDir: base, timeoutMs: 1000 });
        assert.equal(res.causal, false);
        assert.ok(res.error, "timeout must be reported");
      } finally {
        rmSync(candidate, { recursive: true, force: true });
        rmSync(base, { recursive: true, force: true });
      }
    });

    it("reports present:false when the candidate carries no manifest", () => {
      const candidate = mkdtempSync(join(tmpdir(), "mirql-repro-none-"));
      try {
        const res = verifyCausalReproducer({ candidateDir: candidate, baseDir: candidate });
        assert.equal(res.present, false);
        assert.equal(res.causal, false);
      } finally {
        rmSync(candidate, { recursive: true, force: true });
      }
    });

    it("propagates measured reproducer evidence into proof (buildPrDoc)", () => {
      const doc = buildPrDoc({
        pr: { number: 9, base_sha: "b".repeat(40), head_sha: "h".repeat(40), author: "agent" },
        diff: { files_changed: [], tests_deleted: [] },
        suite: { pass_base: true, pass_head: true },
        phi: { delta_phi: -5 },
        causalCompleted: true,
        reproducer: {
          present: true, causal: true, entry: "reproducer/entry.mjs",
          base_exit_code: 3, head_exit_code: 0,
        },
      });
      assert.equal(doc.proof.causal_cycle_completed, true);
      assert.equal(doc.proof.reproducer.base_exit_code, 3);
      assert.equal(doc.proof.reproducer.head_exit_code, 0);

      const bare = buildPrDoc({
        pr: { number: 9, base_sha: "b".repeat(40), head_sha: "h".repeat(40), author: "agent" },
        diff: { files_changed: [], tests_deleted: [] },
        suite: { pass_base: true, pass_head: true },
        phi: { delta_phi: -5 },
      });
      assert.equal(bare.proof.reproducer, undefined);
    });
  });
});
