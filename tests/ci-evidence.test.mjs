import { git } from "./helpers/git.mjs";
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
  main,
} from "../scripts/ci-evidence.mjs";
import * as ciEvidence from "../scripts/ci-evidence.mjs";
import { verifyThrift } from "../packages/run/index.mjs";



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

  describe("6. Reproducer manifest: recorded as data, never executed (Law 16)", () => {
    /**
     * Law 16 pin: CI must NEVER execute a candidate-supplied reproducer
     * script. A script that runs with this job's environment can inspect
     * which tree it is in and pick its exit code — attestation, not
     * measurement — so the evidence builder only validates and records the
     * manifest as data, and causal_cycle_completed is always false here.
     */
    const MANIFEST = {
      description: "fixture reproducer",
      entry: "reproducer/entry.mjs",
      expect_base: "fail",
      expect_head: "pass",
    };

    // Malicious entry: proves it ran by writing a marker file, then exits 0
    // (the old verifier would have counted that as green-on-head).
    const MARKER_ENTRY =
      'import { writeFileSync } from "node:fs";\n' +
      'import { join } from "node:path";\n' +
      'const dir = process.env.MIRQL_MARKEDIR ?? process.cwd();\n' +
      'writeFileSync(join(dir, "pwned.txt"), "candidate code ran");\n' +
      "process.exit(0);\n";

    // Old causal shape: exits 3 on a "broken" tree, 0 on a "fixed" one, and
    // still proves execution via the marker file.
    const CONDITIONAL_ENTRY =
      'import { readFileSync, writeFileSync } from "node:fs";\n' +
      'import { join } from "node:path";\n' +
      'const root = process.env.MIRQL_TARGET_ROOT ?? process.cwd();\n' +
      'try { writeFileSync(join(process.env.MIRQL_MARKEDIR ?? ".", "pwned.txt"), "candidate code ran"); } catch {}\n' +
      'const marker = readFileSync(join(root, "marker.txt"), "utf8").trim();\n' +
      'process.exit(marker === "broken" ? 3 : 0);\n';

    /**
     * A two-commit candidate git repo carrying a reproducer whose manifest
     * declares the classic red-on-base → green-on-head contract (marker.txt
     * reads "broken" at base, "fixed" at head — exactly what the removed
     * executor would have "verified" as causal).
     */
    function makeCandidateRepo({ entry = MARKER_ENTRY, manifest = MANIFEST } = {}) {
      const candidate = mkdtempSync(join(tmpdir(), "mirql-repro-cand-"));
      git(candidate, "init", "-q");
      git(candidate, "config", "user.email", "test@mirql.local");
      git(candidate, "config", "user.name", "mirql-test");
      mkdirSync(join(candidate, "reproducer"), { recursive: true });
      writeFileSync(join(candidate, "reproducer", "entry.mjs"), entry, "utf8");
      writeFileSync(join(candidate, "reproducer", "manifest.json"), JSON.stringify(manifest), "utf8");
      writeFileSync(join(candidate, "marker.txt"), "broken", "utf8");
      git(candidate, "add", "-A");
      git(candidate, "commit", "-q", "-m", "base");
      writeFileSync(join(candidate, "marker.txt"), "fixed", "utf8");
      git(candidate, "add", "-A");
      git(candidate, "commit", "-q", "-m", "head");
      return {
        candidate,
        baseSha: git(candidate, "rev-parse", "HEAD~1").trim(),
        headSha: git(candidate, "rev-parse", "HEAD").trim(),
      };
    }

    /** Runs the evidence builder CLI end-to-end against a fixture. */
    function runEvidenceCli(fixture, extraEnv = {}) {
      const outPath = join(fixture.candidate, "out-pr-doc.json");
      const res = spawnSync(process.execPath, [resolve("scripts/ci-evidence.mjs")], {
        env: {
          ...process.env,
          BASE_NOTARY_DIR: resolve("."),
          CANDIDATE_DIR: fixture.candidate,
          BASE_SHA: fixture.baseSha,
          HEAD_SHA: fixture.headSha,
          PR_NUMBER: "31",
          PR_AUTHOR: "test-author",
          SUITE_PASS_BASE: "true",
          SUITE_PASS_HEAD: "true",
          PR_DOC_PATH: outPath,
          ...extraEnv,
        },
        encoding: "utf8",
      });
      return { res, outPath };
    }

    it("validates the manifest fail-closed (including absent manifest)", () => {
      const dirs = [];
      try {
        const ok = makeCandidateRepo();
        dirs.push(ok.candidate);
        assert.equal(loadReproducerManifest(ok.candidate).ok, true);

        const noEntry = makeCandidateRepo({ manifest: { expect_base: "fail", expect_head: "pass" } });
        const escaping = makeCandidateRepo({
          manifest: { entry: "reproducer/../../escape.mjs", expect_base: "fail", expect_head: "pass" },
        });
        const wrongExpects = makeCandidateRepo({
          manifest: { entry: "reproducer/entry.mjs", expect_base: "pass", expect_head: "pass" },
        });
        dirs.push(noEntry.candidate, escaping.candidate, wrongExpects.candidate);
        assert.match(loadReproducerManifest(noEntry.candidate).error, /entry/);
        assert.match(loadReproducerManifest(escaping.candidate).error, /escape/);
        assert.match(loadReproducerManifest(wrongExpects.candidate).error, /expect_base/);

        const empty = mkdtempSync(join(tmpdir(), "mirql-repro-none-"));
        dirs.push(empty);
        assert.match(loadReproducerManifest(empty).error, /no reproducer manifest/);
      } finally {
        for (const d of dirs) rmSync(d, { recursive: true, force: true });
      }
    });

    it("never executes a candidate reproducer script (no marker file)", () => {
      const markerDir = mkdtempSync(join(tmpdir(), "mirql-repro-marker-"));
      const fixture = makeCandidateRepo();
      try {
        const { res, outPath } = runEvidenceCli(fixture, { MIRQL_MARKEDIR: markerDir });
        assert.equal(res.status, 0, `evidence build failed: ${res.stderr}`);
        assert.ok(!existsSync(join(markerDir, "pwned.txt")), "the reproducer entry must never execute");
        assert.ok(!existsSync(join(fixture.candidate, "pwned.txt")), "no cwd-fallback execution either");

        const doc = JSON.parse(readFileSync(outPath, "utf8"));
        assert.equal(doc.proof.causal_cycle_completed, false, "presence of a manifest is never causal proof");
        assert.equal(doc.proof.reproducer.present, true, "manifest recorded as data");
        assert.equal(doc.proof.reproducer.causal, false);
      } finally {
        rmSync(markerDir, { recursive: true, force: true });
        rmSync(fixture.candidate, { recursive: true, force: true });
      }
    });

    it("a red→green-looking reproducer still cannot produce causal_completed", () => {
      const markerDir = mkdtempSync(join(tmpdir(), "mirql-repro-marker2-"));
      const fixture = makeCandidateRepo({ entry: CONDITIONAL_ENTRY });
      try {
        const { res, outPath } = runEvidenceCli(fixture, { MIRQL_MARKEDIR: markerDir });
        assert.equal(res.status, 0, `evidence build failed: ${res.stderr}`);
        assert.ok(!existsSync(join(markerDir, "pwned.txt")), "exit-code-choosing scripts must never run");

        const doc = JSON.parse(readFileSync(outPath, "utf8"));
        assert.equal(doc.proof.causal_cycle_completed, false);
        assert.equal(doc.proof.reproducer.causal, false);
        assert.equal(doc.proof.reproducer.entry, "reproducer/entry.mjs");
        assert.equal("base_exit_code" in doc.proof.reproducer, false, "no exit codes are recorded anymore");
        assert.equal("head_exit_code" in doc.proof.reproducer, false);
      } finally {
        rmSync(markerDir, { recursive: true, force: true });
        rmSync(fixture.candidate, { recursive: true, force: true });
      }
    });

    it("candidate-execution helpers are gone from the module surface", () => {
      assert.equal("runReproducerScript" in ciEvidence, false);
      assert.equal("verifyCausalReproducer" in ciEvidence, false);
      assert.equal(typeof ciEvidence.loadReproducerManifest, "function");
    });

    it("propagates the data-only manifest record into proof (buildPrDoc)", () => {
      const base = {
        pr: { number: 9, base_sha: "b".repeat(40), head_sha: "h".repeat(40), author: "agent" },
        diff: { files_changed: [], tests_deleted: [] },
        suite: { pass_base: true, pass_head: true },
        phi: { delta_phi: -5 },
      };
      const doc = buildPrDoc({
        ...base,
        reproducer: { present: true, causal: false, entry: "reproducer/entry.mjs", description: "fixture" },
      });
      assert.equal(doc.proof.causal_cycle_completed, false, "a manifest record is never causal proof");
      assert.equal(doc.proof.reproducer.entry, "reproducer/entry.mjs");
      assert.equal(doc.proof.reproducer.causal, false);

      const bare = buildPrDoc(base);
      assert.equal(bare.proof.reproducer, undefined);
    });
  });
});
