// tests/m2-phi.test.mjs — Milestone M2: Monotone Potential Phi Engine & Thrift Tests (Law 13 & Law 17).
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  computePhi,
  checkPhiReduction,
  evaluatePhiGate,
  verifyThrift,
} from "../packages/run/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

describe("Milestone M2: Monotone Potential Phi Engine & Thrift Gate (Law 13)", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-m2-test-"));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("1. Deterministic AST Metric Extractor (computePhi)", () => {
    it("extracts integer-only metrics across all dimensions on real codebase", () => {
      const phi = computePhi(ROOT);

      assert.ok(Number.isSafeInteger(phi.loc), "loc must be safe integer");
      assert.ok(Number.isSafeInteger(phi.export_count), "export_count must be safe integer");
      assert.ok(Number.isSafeInteger(phi.cyclomatic), "cyclomatic must be safe integer");
      assert.ok(Number.isSafeInteger(phi.dep_count), "dep_count must be safe integer");
      assert.ok(Number.isSafeInteger(phi.dup_blocks), "dup_blocks must be safe integer");
      assert.ok(Number.isSafeInteger(phi.debt_markers), "debt_markers must be safe integer");
      assert.ok(Number.isSafeInteger(phi.max_nesting_depth), "max_nesting_depth must be safe integer");
      assert.ok(Number.isSafeInteger(phi.total), "total must be safe integer");

      assert.ok(phi.loc > 0, "loc must be positive");
      assert.equal(phi.dep_count, 0, "Law 0: external dependency count must be 0");
      assert.ok(phi.total > phi.loc, "total must be composite sum");
    });

    it("accurately detects debt markers in source files", () => {
      const pkgDir = join(tempDir, "pkg");
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(
        join(pkgDir, "code.mjs"),
        `// TODO: optimize algorithm\n// FIXME: edge case crash\n// HACK: workaround\n// XXX: review\nexport const x = 1;\n`,
        "utf8",
      );

      const phi = computePhi(tempDir);
      assert.equal(phi.debt_markers, 4, "Must detect exactly 4 debt markers");
      assert.equal(phi.export_count, 1, "Must detect 1 export");
    });

    it("measures block nesting depth deterministically", () => {
      const pkgDir = join(tempDir, "pkg");
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(
        join(pkgDir, "deep.mjs"),
        `export function deep() { if (true) { while (false) { try { [ ( { a: 1 } ) ] } catch {} } } }\n`,
        "utf8",
      );

      const phi = computePhi(tempDir);
      assert.ok(phi.max_nesting_depth >= 4, "Nesting depth must reflect nested blocks");
    });

    it("counts package modules unreachable from tests as test gaps (Law 13 test-gap term)", () => {
      const pkgDir = join(tempDir, "packages", "lib");
      const testsDir = join(tempDir, "tests");
      mkdirSync(pkgDir, { recursive: true });
      mkdirSync(testsDir, { recursive: true });
      writeFileSync(join(pkgDir, "a.mjs"), "export const a = 1;\n", "utf8");
      writeFileSync(
        join(testsDir, "other.test.mjs"),
        `import assert from "node:assert/strict";\nit("t", () => assert.ok(true));\n`,
        "utf8",
      );

      const before = computePhi(tempDir);
      assert.ok(Number.isSafeInteger(before.test_gaps), "test_gaps must be safe integer (Law 17)");
      assert.equal(before.test_gaps, 1, "package module unreachable from tests must count as a gap");

      // Covering the module from a test file removes the gap and lowers total.
      // The cover file is a single bare side-effect import so its own metric
      // contribution is exactly +1 loc — the drop is then exactly the gap weight.
      writeFileSync(
        join(testsDir, "cover.test.mjs"),
        `import "../packages/lib/a.mjs";\n`,
        "utf8",
      );
      const after = computePhi(tempDir);
      assert.equal(after.test_gaps, 0, "imported module must no longer be a gap");
      assert.equal(after.loc, before.loc + 1, "cover file contributes exactly one loc");
      assert.equal(after.total, before.total - 6 + 1, "total must drop by the gap weight (6) minus the cover file's one loc");
      assert.ok(after.total < before.total, "covering a test gap must strictly lower total");
    });

    it("counts transitive import coverage, not just direct imports", () => {
      const pkgDir = join(tempDir, "packages", "lib");
      const testsDir = join(tempDir, "tests");
      mkdirSync(pkgDir, { recursive: true });
      mkdirSync(testsDir, { recursive: true });
      writeFileSync(join(pkgDir, "inner.mjs"), "export const inner = 1;\n", "utf8");
      writeFileSync(
        join(pkgDir, "outer.mjs"),
        `import { inner } from "./inner.mjs";\nexport const outer = inner + 1;\n`,
        "utf8",
      );
      writeFileSync(
        join(testsDir, "t.test.mjs"),
        `import { outer } from "../packages/lib/outer.mjs";\nit("t", () => { if (outer !== 2) throw new Error("x"); });\n`,
        "utf8",
      );

      const phi = computePhi(tempDir);
      assert.equal(phi.test_gaps, 0, "transitively imported module must count as covered");
    });

    it("scopes test gaps to packages/ — bin and scripts tooling never counted", () => {
      const binDir = join(tempDir, "bin");
      const scriptsDir = join(tempDir, "scripts");
      const testsDir = join(tempDir, "tests");
      mkdirSync(binDir, { recursive: true });
      mkdirSync(scriptsDir, { recursive: true });
      mkdirSync(testsDir, { recursive: true });
      writeFileSync(join(binDir, "cli.mjs"), "export const cli = 1;\n", "utf8");
      writeFileSync(join(scriptsDir, "tool.mjs"), "export const tool = 1;\n", "utf8");
      writeFileSync(
        join(testsDir, "t.test.mjs"),
        `it("t", () => {});\n`,
        "utf8",
      );

      const phi = computePhi(tempDir);
      assert.equal(phi.test_gaps, 0, "bin/ and scripts/ files are not gap candidates");
    });
  });

  describe("2. Monotone Potential Ratchet (Law 13)", () => {
    it("allows non-increasing potential for regular builder PRs (deltaPhi <= 0)", () => {
      const rEqual = checkPhiReduction(1000, 1000, false);
      assert.equal(rEqual.ok, true);
      assert.equal(rEqual.delta_phi, 0);

      const rDrop = checkPhiReduction(1000, 950, false);
      assert.equal(rDrop.ok, true);
      assert.equal(rDrop.delta_phi, -50);
    });

    it("rejects complexity increases for builder PRs (deltaPhi > 0)", () => {
      const rIncrease = checkPhiReduction(1000, 1050, false);
      assert.equal(rIncrease.ok, false);
      assert.equal(rIncrease.delta_phi, 50);
    });

    it("strictly requires negative potential delta for consolidator role (deltaPhi < 0)", () => {
      const rEqualConsolidator = checkPhiReduction(1000, 1000, true);
      assert.equal(rEqualConsolidator.ok, false);

      const rIncreaseConsolidator = checkPhiReduction(1000, 1020, true);
      assert.equal(rIncreaseConsolidator.ok, false);

      const rDropConsolidator = checkPhiReduction(1000, 980, true);
      assert.equal(rDropConsolidator.ok, true);
      assert.equal(rDropConsolidator.delta_phi, -20);
    });

    it("Law 17: rejects non-safe-integer inputs with TypeError", () => {
      assert.throws(() => checkPhiReduction(100.5, 95), TypeError);
      assert.throws(() => checkPhiReduction(100, "95"), TypeError);
      assert.throws(() => checkPhiReduction(NaN, 95), TypeError);
    });
  });

  describe("3. Gate Evaluator (evaluatePhiGate)", () => {
    it("approves clean non-increasing deltaPhi with auto_merge", () => {
      const res = evaluatePhiGate({ phiBefore: 200, phiAfter: 190, role: "builder" });
      assert.equal(res.ok, true);
      assert.equal(res.verdict, "auto_merge");
      assert.equal(res.delta_phi, -10);
    });

    it("rejects phi increase with LAW_13_PHI_INCREASE", () => {
      const res = evaluatePhiGate({ phiBefore: 200, phiAfter: 205, role: "builder" });
      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.equal(res.rule, "LAW_13_PHI_INCREASE");
      assert.equal(res.violation, "PHI_INCREASED");
    });

    it("rejects consolidator without strict reduction with LAW_13_CONSOLIDATOR_PHI", () => {
      const res = evaluatePhiGate({ phiBefore: 200, phiAfter: 200, role: "consolidator" });
      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.equal(res.rule, "LAW_13_CONSOLIDATOR_PHI");
      assert.equal(res.violation, "CONSOLIDATOR_PHI_NOT_DECREASED");
    });

    it("rejects refactor kind without strict reduction with LAW_13_CONSOLIDATOR_PHI", () => {
      const res = evaluatePhiGate({ phiBefore: 200, phiAfter: 200, kind: "refactor" });
      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.equal(res.rule, "LAW_13_CONSOLIDATOR_PHI");
      assert.equal(res.violation, "CONSOLIDATOR_PHI_NOT_DECREASED");
    });

    it("fails closed on missing delta_phi with LAW_13_PHI_MISSING (Law 6)", () => {
      const res1 = evaluatePhiGate({});
      assert.equal(res1.ok, false);
      assert.equal(res1.verdict, "reject");
      assert.equal(res1.rule, "LAW_13_PHI_MISSING");
      assert.equal(res1.violation, "MISSING_PHI");

      const res2 = evaluatePhiGate({ author: "consolidator" });
      assert.equal(res2.ok, false);
      assert.equal(res2.verdict, "reject");
      assert.equal(res2.rule, "LAW_13_PHI_MISSING");
    });

    it("allows feature growth when within explicit featureBudget", () => {
      const res = evaluatePhiGate({
        phiBefore: 100,
        phiAfter: 150,
        featureBudget: 100,
      });
      assert.equal(res.ok, true);
      assert.equal(res.verdict, "auto_merge");
      assert.equal(res.delta_phi, 50);

      const resOver = evaluatePhiGate({
        phiBefore: 100,
        phiAfter: 250,
        featureBudget: 100,
      });
      assert.equal(resOver.ok, false);
      assert.equal(resOver.verdict, "reject");
      assert.equal(resOver.rule, "LAW_13_PHI_INCREASE");
    });
  });

  describe("4. Law 13 Thrift Test (verifyThrift)", () => {
    it("passes refactoring candidate with negative deltaPhi and preserved tests and surface", () => {
      const res = verifyThrift({
        phiBefore: 500,
        phiAfter: 450,
        testsPreserved: true,
        surfacePreserved: true,
      });

      assert.equal(res.ok, true);
      assert.equal(res.verdict, "pass");
      assert.equal(res.delta_phi, -50);
      assert.equal(res.thrift_score, 50);
      assert.equal(res.reasons.length, 0);
    });

    it("fails closed when testsPreserved or surfacePreserved is omitted (Law 6)", () => {
      const res = verifyThrift({
        phiBefore: 500,
        phiAfter: 450,
      });

      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.ok(res.reasons.some((r) => r.includes("fail-closed")));
    });

    it("rejects refactoring candidate if tests were weakened or deleted", () => {
      const res = verifyThrift({
        phiBefore: 500,
        phiAfter: 450,
        testsPreserved: false,
        surfacePreserved: true,
      });

      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.ok(res.reasons.some((r) => r.includes("Test preservation")));
    });

    it("rejects refactoring candidate if public surface was modified without approval", () => {
      const res = verifyThrift({
        phiBefore: 500,
        phiAfter: 450,
        testsPreserved: true,
        surfacePreserved: false,
      });

      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.ok(res.reasons.some((r) => r.includes("Public surface preserved")));
    });

    it("rejects refactoring candidate if external dependency count increased", () => {
      const res = verifyThrift({
        phiBefore: 500,
        phiAfter: 450,
        testsPreserved: true,
        surfacePreserved: true,
        depCountBefore: 0,
        depCountAfter: 1,
      });

      assert.equal(res.ok, false);
      assert.equal(res.verdict, "reject");
      assert.ok(res.reasons.some((r) => r.includes("Redundant dependency")));
    });
  });
});
