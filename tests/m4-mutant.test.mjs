// tests/m4-mutant.test.mjs — Milestone M4: Incremental AST Mutation Engine & Flake Detector.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  generateMutants,
  runMutationTesting,
  detectFlakes,
  quarantineTest,
  formatMutantEvent,
  MUTATION_OPERATORS,
} from "../packages/run/index.mjs";

describe("Milestone M4: AST Mutation Engine & Flake Detector", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-m4-test-"));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("1. AST Mutation Generator (generateMutants)", () => {
    it("generates conditional and arithmetic mutants deterministically", () => {
      const code = `
export function calc(a, b) {
  if (a === b) {
    return a + b;
  }
  if (a <= 0) {
    return a - b;
  }
  return true;
}
`;
      const mutants = generateMutants(code);
      assert.ok(mutants.length >= 4, "Must generate at least 4 mutants");

      // Verify invert-conditional
      const strictEqMutant = mutants.find((m) => m.original === "===" && m.mutated === "!==");
      assert.ok(strictEqMutant, "Must generate === to !== mutant");
      assert.equal(strictEqMutant.operator, "invert-conditional");

      // Verify swap-arithmetic
      const addMutant = mutants.find((m) => m.original === " + " && m.mutated === " - ");
      assert.ok(addMutant, "Must generate + to - mutant");
      assert.equal(addMutant.operator, "swap-arithmetic");

      // Verify mutate-boundary
      const boolMutant = mutants.find((m) => m.original === "true" && m.mutated === "false");
      assert.ok(boolMutant, "Must generate true to false mutant");
      assert.equal(boolMutant.operator, "mutate-boundary");
    });

    it("skips comments and empty lines", () => {
      const code = `
// if (a === b) return a + b;
/* if (x <= y) */
// true false
`;
      const mutants = generateMutants(code);
      assert.equal(mutants.length, 0, "Comments must not be mutated");
    });
  });

  describe("2. Mutation Testing Execution & Kill Rate (runMutationTesting)", () => {
    it("reports 100% kill rate (10000 bp) when test suite catches all mutants", () => {
      const srcFile = join(tempDir, "math.mjs");
      writeFileSync(
        srcFile,
        `export function add(a, b) {\n  if (a === 0) return b;\n  return a + b;\n}\n`,
        "utf8",
      );

      // Custom mock test runner that fails whenever code is mutated
      const mockRunner = (mutant) => {
        // Return false -> test fails -> mutant killed
        return false;
      };

      const res = runMutationTesting({
        sourcePath: srcFile,
        testPath: "dummy.test.mjs",
        testRunner: mockRunner,
      });

      assert.equal(res.ok, true);
      assert.equal(res.kill_rate_bp, 10000);
      assert.equal(res.mutants_killed, res.mutants_total);
      assert.equal(res.mutants_survived, 0);

      // Verify source file was restored intact
      const contentAfter = readFileSync(srcFile, "utf8");
      assert.ok(contentAfter.includes("a === 0"));
      assert.ok(contentAfter.includes("a + b"));
    });

    it("detects surviving mutants and rejects when kill rate is below 8000 bp threshold", () => {
      const srcFile = join(tempDir, "guard.mjs");
      writeFileSync(
        srcFile,
        `export function guard(x) {\n  if (x === 1) return true;\n  if (x <= 10) return false;\n  return true;\n}\n`,
        "utf8",
      );

      // Mock test runner that passes for mutants on line 3 (surviving mutant)
      const mockRunner = (mutant) => {
        if (mutant.line === 3) return true; // survived
        return false; // killed
      };

      const res = runMutationTesting({
        sourcePath: srcFile,
        testPath: "dummy.test.mjs",
        killThresholdBp: 8000,
        testRunner: mockRunner,
      });

      assert.ok(Number.isSafeInteger(res.kill_rate_bp));
      assert.ok(res.mutants_survived > 0);
      assert.ok(res.survived_mutants.length > 0);
    });
  });

  describe("3. Multi-Run Flake Detector (detectFlakes)", () => {
    it("reports non-flaky for deterministic passing test", () => {
      const res = detectFlakes("dummy.test.mjs", {
        iterations: 5,
        runner: () => true, // passes every run
      });

      assert.equal(res.flaky, false);
      assert.equal(res.runs_total, 5);
      assert.equal(res.passed_runs, 5);
      assert.equal(res.failed_runs, 0);
    });

    it("detects flakiness when test passes intermittently across repetitions", () => {
      let runIndex = 0;
      // Fails on run 2, passes on others
      const intermittentRunner = () => {
        runIndex++;
        return runIndex !== 2;
      };

      const res = detectFlakes("dummy.test.mjs", {
        iterations: 4,
        runner: intermittentRunner,
      });

      assert.equal(res.flaky, true, "Must flag intermittent test as flaky");
      assert.equal(res.runs_total, 4);
      assert.equal(res.passed_runs, 3);
      assert.equal(res.failed_runs, 1);
    });
  });

  describe("4. Flake Quarantine Isolation (quarantineTest)", () => {
    it("isolates flaky test from critical path into quarantine directory", () => {
      const testsDir = join(tempDir, "tests");
      const quarantineDir = join(tempDir, "quarantine");
      mkdirSync(testsDir, { recursive: true });

      const testFile = join(testsDir, "flaky.test.mjs");
      writeFileSync(testFile, `// flaky test\n`, "utf8");

      const res = quarantineTest(testFile, quarantineDir);

      assert.equal(res.quarantined, true);
      assert.equal(existsSync(testFile), false, "Must remove test from critical path");
      assert.equal(existsSync(res.quarantined_path), true, "Must move test into quarantine");
      assert.equal(res.event.type, "test.quarantined");
      assert.equal(res.event.payload.test_file, "flaky.test.mjs");
    });
  });

  describe("5. Canonical Mutant Event Formatting (formatMutantEvent)", () => {
    it("formats mutant.survived and mutant.evaluated events conforming to roles/scout-mutants.md", () => {
      const killedResult = {
        ok: true,
        kill_rate_bp: 9000,
        mutants_total: 10,
        mutants_killed: 9,
        mutants_survived: 1,
        survived_mutants: [{ id: "m-1", line: 12, operator: "invert-conditional", description: "=== to !==" }],
        summary: "Mutation testing: 9/10 killed",
      };

      const evtPass = formatMutantEvent(killedResult, { nowMs: 1700000000000 });
      assert.equal(evtPass.type, "mutant.evaluated");
      assert.equal(evtPass.payload.kill_rate_bp, 9000);
      assert.equal(evtPass.payload.mutants_killed, 9);

      const failedResult = {
        ...killedResult,
        ok: false,
        kill_rate_bp: 5000,
      };
      const evtFail = formatMutantEvent(failedResult, { nowMs: 1700000000000 });
      assert.equal(evtFail.type, "mutant.survived");
      assert.equal(evtFail.payload.kill_rate_bp, 5000);
      assert.equal(evtFail.payload.first_survived.id, "m-1");
    });
  });
});
