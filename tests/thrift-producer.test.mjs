// tests/thrift-producer.test.mjs — Law 13 Thrift Test producer (issue #13).
// The evaluator fail-closes THRIFT_TEST_FAILED on consolidations unless
// phi.thrift_test_passed === true — and until now NOTHING could produce that
// flag from real measurements. Pins the producer end to end on real git
// fixtures and the ci-evidence wiring contract.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { runThriftTest } from "../packages/run/thrift.mjs";
import { main as runMain } from "../packages/run/index.mjs";
import { buildPrDoc } from "../scripts/ci-evidence.mjs";

function git(repoDir, ...args) {
  const res = spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 15000 });
  assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

/**
 * Base: a helper duplicated across two modules (double phi).
 * Head (consolidation): one shared module, both importers use it (net delete).
 */
function makeConsolidationRepo(mode = "clean") {
  const repo = mkdtempSync(join(tmpdir(), "mirql-thrift-prod-"));
  git(repo, "init", "-q");
  git(repo, "config", "user.email", "t@mirql.local");
  git(repo, "config", "user.name", "t");
  git(repo, "config", "core.autocrlf", "false");
  mkdirSync(join(repo, "src"), { recursive: true });

  const DUPLICATE = `export function clampLo(n) {\n  if (n < 0) return 0;\n  return n;\n}\n`;
  writeFileSync(join(repo, "src", "a.mjs"), DUPLICATE);
  writeFileSync(join(repo, "src", "b.mjs"), DUPLICATE);
  writeFileSync(join(repo, "surface.lock"), JSON.stringify({ v: 1, bins: ["mirql"], commands: ["mirql m check"] }));
  if (mode === "test-deleted") {
    // The test exists in BASE and is deleted by head — a real regression
    mkdirSync(join(repo, "tests"), { recursive: true });
    writeFileSync(join(repo, "tests", "old.test.mjs"), "export {};\n");
  }
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "base");

  // Consolidation: single shared implementation, a.mjs re-exports it
  writeFileSync(join(repo, "src", "shared.mjs"), DUPLICATE);
  writeFileSync(join(repo, "src", "a.mjs"), `export { clampLo } from "./shared.mjs";\n`);
  writeFileSync(join(repo, "src", "b.mjs"), `export { clampLo } from "./shared.mjs";\n`);
  if (mode === "test-deleted") {
    git(repo, "rm", "-q", "tests/old.test.mjs");
  } else if (mode === "surface-changed") {
    writeFileSync(join(repo, "surface.lock"), JSON.stringify({ v: 1, bins: ["mirql", "mirql-extra"], commands: ["mirql m check"] }));
  }
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "head");
  return repo;
}

function makeGrowthRepo() {
  const repo = mkdtempSync(join(tmpdir(), "mirql-thrift-grow-"));
  git(repo, "init", "-q");
  git(repo, "config", "user.email", "t@mirql.local");
  git(repo, "config", "user.name", "t");
  git(repo, "config", "core.autocrlf", "false");
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "a.mjs"), "export const a = 1;\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "base");
  writeFileSync(join(repo, "src", "b.mjs"), "export const b = 2;\nexport const c = 3;\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "head");
  return repo;
}

describe("thrift test producer (issue #13)", () => {
  it("a real consolidation MEASURES a passing thrift test", () => {
    const repo = makeConsolidationRepo("clean");
    try {
      const res = runThriftTest({ repoDir: repo, baseRef: "HEAD~1", headRef: "HEAD" });
      assert.equal(res.thrift_test_passed, true, JSON.stringify(res.reasons));
      assert.equal(res.verdict, "pass");
      assert.ok(res.delta_phi < 0, "consolidation must strictly decrease phi");
      assert.ok(res.evidence.phi_base > res.evidence.phi_head);
      assert.deepEqual(res.evidence.tests_deleted, []);
      assert.equal(res.evidence.surface_changed, false);
      assert.equal(res.evidence.deps_before, 0);
      assert.equal(res.evidence.deps_after, 0);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("a growing PR honestly fails thrift (no ΔΦ reduction)", () => {
    const repo = makeGrowthRepo();
    try {
      const res = runThriftTest({ repoDir: repo, baseRef: "HEAD~1" });
      assert.equal(res.thrift_test_passed, false);
      assert.ok(res.reasons.some((r) => r.includes("did not strictly decrease")));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("deleted tests fail thrift", () => {
    const repo = makeConsolidationRepo("test-deleted");
    try {
      const res = runThriftTest({ repoDir: repo, baseRef: "HEAD~1" });
      assert.equal(res.thrift_test_passed, false);
      assert.deepEqual(res.evidence.tests_deleted, ["tests/old.test.mjs"]);
      assert.ok(res.reasons.some((r) => r.includes("Test preservation")));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("surface.lock changes fail thrift", () => {
    const repo = makeConsolidationRepo("surface-changed");
    try {
      const res = runThriftTest({ repoDir: repo, baseRef: "HEAD~1" });
      assert.equal(res.thrift_test_passed, false);
      assert.equal(res.evidence.surface_changed, true);
      assert.ok(res.reasons.some((r) => r.includes("surface")));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("fails closed outside a git repository", () => {
    const notARepo = mkdtempSync(join(tmpdir(), "mirql-thrift-norepo-"));
    try {
      const res = runThriftTest({ repoDir: notARepo, baseRef: "HEAD~1" });
      assert.equal(res.thrift_test_passed, false);
      assert.match(res.error, /not a git repository/);
    } finally {
      rmSync(notARepo, { recursive: true, force: true });
    }
  });

  it("CLI: mirql r thrift exits 0 on a passing consolidation, 1 otherwise", () => {
    const good = makeConsolidationRepo("clean");
    const bad = makeGrowthRepo();
    try {
      const okCode = runMain(["thrift", "--base", "HEAD~1", "--repo", good]);
      assert.equal(okCode, 0);
      const badCode = runMain(["thrift", "--base", "HEAD~1", "--repo", bad]);
      assert.equal(badCode, 1);
    } finally {
      rmSync(good, { recursive: true, force: true });
      rmSync(bad, { recursive: true, force: true });
    }
  });
});

describe("ci-evidence thrift wiring contract (issue #13)", () => {
  const baseInput = {
    pr: { number: 9, base_sha: "b".repeat(40), head_sha: "h".repeat(40), author: "agent" },
    diff: { files_changed: ["packages/run/a.mjs"], tests_deleted: [] },
    suite: { pass_base: true, pass_head: true },
    phi: { delta_phi: -12 },
  };

  it("absent thrift leaves the flag out entirely (non-consolidations never claim it)", () => {
    const doc = buildPrDoc(baseInput);
    assert.equal("thrift_test_passed" in doc.phi, false);
  });

  it("thrift verdicts are mirrored honestly — only a real boolean true passes", () => {
    const pass = buildPrDoc({ ...baseInput, thrift: { passed: true, evidence: { phi_base: 40, phi_head: 28 } } });
    assert.equal(pass.phi.thrift_test_passed, true);
    assert.equal(pass.phi.thrift_evidence.phi_base, 40);

    const failed = buildPrDoc({ ...baseInput, thrift: { passed: false, reasons: ["no ΔΦ reduction"] } });
    assert.equal(failed.phi.thrift_test_passed, false);
    assert.deepEqual(failed.phi.thrift_reasons, ["no ΔΦ reduction"]);

    const loose = buildPrDoc({ ...baseInput, thrift: { passed: "yes" } });
    assert.equal(loose.phi.thrift_test_passed, false);
  });
});
