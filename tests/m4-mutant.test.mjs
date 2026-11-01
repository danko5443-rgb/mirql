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
  formatKillTestNeededEvent,
  MUTATION_OPERATORS,
  runCli,
} from "../packages/run/index.mjs";
import { EXIT_CODES } from "../packages/core/index.mjs";

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

    it("generates remove-call mutants for standalone function statements", () => {
      const code = `
export function processItem(item) {
  notifyWatcher(item);
  return item.value;
}
`;
      const mutants = generateMutants(code);
      const removeMutant = mutants.find((m) => m.operator === "remove-call");
      assert.ok(removeMutant, "Must generate remove-call mutant");
      assert.ok(removeMutant.mutated.includes("/* notifyWatcher(item); */"));
      assert.equal(removeMutant.line, 3);
    });

    it("restricts mutant generation to changedLines in incremental mode", () => {
      const code = `
export function compute(a, b) {
  const x = a + b;
  const y = a === b;
  return x * y;
}
`;
      // Only mutate line 4 (a === b)
      const mutants = generateMutants(code, { changedLines: [4] });
      assert.equal(mutants.length, 1);
      assert.equal(mutants[0].line, 4);
      assert.equal(mutants[0].operator, "invert-conditional");
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

      // Custom mock test runner: baseline passes (true), mutants fail test (false) -> killed
      const mockRunner = (mutant) => {
        if (mutant.isBaseline) return true;
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

    it("aborts and returns BASELINE_TEST_FAILED when baseline tests fail on unmutated code", () => {
      const srcFile = join(tempDir, "broken.mjs");
      writeFileSync(srcFile, `export function broken() { return false; }\n`, "utf8");

      // Baseline fails
      const mockRunner = (mutant) => {
        if (mutant.isBaseline) return false;
        return true;
      };

      const res = runMutationTesting({
        sourcePath: srcFile,
        testPath: "dummy.test.mjs",
        testRunner: mockRunner,
      });

      assert.equal(res.ok, false);
      assert.equal(res.error, "BASELINE_TEST_FAILED");
      assert.equal(res.kill_rate_bp, 0);
      assert.equal(res.mutants_total, 0);
    });

    it("detects surviving mutants and rejects when kill rate is below 8000 bp threshold", () => {
      const srcFile = join(tempDir, "guard.mjs");
      writeFileSync(
        srcFile,
        `export function guard(x) {\n  if (x === 1) return true;\n  if (x <= 10) return false;\n  return true;\n}\n`,
        "utf8",
      );

      // Mock test runner that passes baseline, and passes line 3 (surviving mutant)
      const mockRunner = (mutant) => {
        if (mutant.isBaseline) return true;
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
    it("isolates flaky test from critical path and records event to ledger", () => {
      const testsDir = join(tempDir, "tests");
      const quarantineDir = join(tempDir, "quarantine");
      mkdirSync(testsDir, { recursive: true });

      const testFile = join(testsDir, "flaky.test.mjs");
      writeFileSync(testFile, `// flaky test\n`, "utf8");

      const ledgerEntries = [];
      const appendLedger = (evt) => ledgerEntries.push(evt);

      const res = quarantineTest(testFile, quarantineDir, { appendLedger });

      assert.equal(res.quarantined, true);
      assert.equal(existsSync(testFile), false, "Must remove test from critical path");
      assert.equal(existsSync(res.quarantined_path), true, "Must move test into quarantine");
      assert.equal(res.event.type, "test.quarantined");
      assert.equal(res.event.payload.test_file, "flaky.test.mjs");
      assert.equal(ledgerEntries.length, 1);
      assert.equal(ledgerEntries[0].type, "test.quarantined");
    });
  });

  describe("5. Canonical Mutant Event Formatting (formatMutantEvent & formatKillTestNeededEvent)", () => {
    it("formats mutant.evaluated and mutant.survived events conforming to roles/scout-mutants.md", () => {
      const killedResult = {
        ok: true,
        kill_rate_bp: 9000,
        mutants_total: 10,
        mutants_killed: 9,
        mutants_survived: 1,
        survived_mutants: [{ id: "m-1", file: "src.mjs", line: 12, operator: "invert-conditional", original: "===", mutated: "!==", description: "=== to !==" }],
        summary: "Mutation testing: 9/10 killed",
      };

      const evtPass = formatMutantEvent(killedResult, { file: "src.mjs", nowMs: 1700000000000 });
      assert.equal(evtPass.type, "mutant.evaluated");
      assert.equal(evtPass.payload.kill_rate_bp, 9000);
      assert.equal(evtPass.payload.mutants_killed, 9);

      const failedResult = {
        ...killedResult,
        ok: false,
        kill_rate_bp: 5000,
      };
      const evtFail = formatMutantEvent(failedResult, { file: "src.mjs", nowMs: 1700000000000 });
      assert.equal(evtFail.type, "mutant.survived");
      assert.equal(evtFail.payload.file, "src.mjs");
      assert.equal(evtFail.payload.line, 12);
      assert.equal(evtFail.payload.status, "survived");
      assert.equal(evtFail.payload.mutation_applied, "=== -> !==");

      const killNeededEvt = formatKillTestNeededEvent(failedResult.survived_mutants[0], { nowMs: 1700000000000 });
      assert.equal(killNeededEvt.type, "mutant.kill_test_needed");
      assert.equal(killNeededEvt.payload.file, "src.mjs");
      assert.equal(killNeededEvt.payload.line, 12);
      assert.ok(killNeededEvt.payload.recommendation.includes("invert-conditional"));
    });
  });

  describe("6. CLI Dispatch for mirql r mutant", () => {
    it("returns USAGE_ERROR (exit code 2) when --source or --test is missing", () => {
      const code1 = runCli(["mutant"]);
      assert.equal(code1, EXIT_CODES.USAGE_ERROR);

      const code2 = runCli(["mutant", "--source", "nonexistent.mjs"]);
      assert.equal(code2, EXIT_CODES.USAGE_ERROR);
    });
  });
});
