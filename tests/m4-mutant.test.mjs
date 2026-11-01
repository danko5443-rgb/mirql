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
  maskStringsAndComments,
  extractChangedLines,
  MUTATION_OPERATORS,
  runCli,
  runProbe,
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

    it("strictly splices code tokens and never mutates string literals or inline block comments", () => {
      // 1. log("a + b", x + y); -> log("a + b", x - y);
      const code1 = 'export function f1(x, y) { log("a + b", x + y); }\n';
      const m1 = generateMutants(code1);
      assert.equal(m1.length, 1);
      assert.ok(m1[0].mutatedCode.includes('log("a + b", x - y);'));

      // 2. const s = "true" || true; -> const s = "true" || false;
      const code2 = 'export function f2() { const s = "true" || true; return s; }\n';
      const m2 = generateMutants(code2);
      assert.equal(m2.length, 1);
      assert.ok(m2[0].mutatedCode.includes('const s = "true" || false;'));

      // 3. "x === y" && a === b -> "x === y" && a !== b
      const code3 = 'export function f3(a, b) { if ("x === y" && a === b) return 1; }\n';
      const m3 = generateMutants(code3);
      assert.equal(m3.length, 1);
      assert.ok(m3[0].mutatedCode.includes('if ("x === y" && a !== b)'));

      // 4. const t = 1; /* a === b */ -> 0 mutants
      const code4 = 'export function f4() { const t = 1; /* a === b */ return t; }\n';
      const m4 = generateMutants(code4);
      assert.equal(m4.length, 0, "Inline block comments must be completely masked");

      // 5. /* note */ if (a === b) -> if (a !== b)
      const code5 = 'export function f5(a, b) { /* note */ if (a === b) return 1; }\n';
      const m5 = generateMutants(code5);
      assert.equal(m5.length, 1);
      assert.ok(m5[0].mutatedCode.includes('if (a !== b)'));
    });

    it("masks multi-line block comments spanning multiple lines and regex literals", () => {
      // Multi-line block comment with operator on middle line
      const multiLineCode = `
export function fMulti() {
  const x = 1; /* start
   a === b
   end */ const y = 2;
  return x + y;
}
`;
      const mutantsMulti = generateMutants(multiLineCode);
      // Only x + y should be mutated (1 mutant), the a === b inside comment must be skipped
      assert.equal(mutantsMulti.length, 1);
      assert.equal(mutantsMulti[0].original, " + ");

      // Regex literal with operator inside
      const regexCode = `
export function fRegex(s) {
  return /a + b/.test(s);
}
`;
      const mutantsRegex = generateMutants(regexCode);
      assert.equal(mutantsRegex.length, 0, "Operators inside regex literals must be masked");
    });

    it("skips string literals, comments, and identifiers containing target words", () => {
      // String with "a === b" and identifier "construed" containing "true"
      const code = `
export function testFilter() {
  const construed = "a === b"; // check a === b
  return construed;
}
`;
      const mutants = generateMutants(code);
      assert.equal(mutants.length, 0, "Strings, comments, and identifier substrings must not be mutated");
    });

    it("generates remove-call mutants only for standalone call statements", () => {
      const code = `
export function processItem(item) {
  const total = compute(item);
  notifyWatcher(item);
  return total;
}
`;
      const mutants = generateMutants(code);
      const removeMutants = mutants.filter((m) => m.operator === "remove-call");
      assert.equal(removeMutants.length, 1, "Must generate exactly 1 remove-call mutant");
      assert.ok(removeMutants[0].mutated.includes("/* notifyWatcher(item); */"));
      assert.equal(removeMutants[0].line, 4);
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

    it("parses git diff hunk headers to extract changed line numbers accurately", () => {
      const diffText = `
@@ -10,0 +12,3 @@
+line 12
+line 13
+line 14
@@ -30,2 +35,1 @@
-old line
+line 35
`;
      const lines = extractChangedLines(diffText);
      assert.ok(lines.has(12));
      assert.ok(lines.has(13));
      assert.ok(lines.has(14));
      assert.ok(lines.has(35));
      assert.equal(lines.has(10), false);
      assert.equal(lines.size, 4);
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
      writeFileSync(srcFile, `export function broken(a) {\n  if (a === 1) return true;\n  return false;\n}\n`, "utf8");

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

    it("restores source file from pre-existing .mutant-bak if a previous process crashed", () => {
      const srcFile = join(tempDir, "crashed.mjs");
      const bakFile = `${srcFile}.mutant-bak`;
      writeFileSync(srcFile, `// corrupted mutated code\n`, "utf8");
      writeFileSync(bakFile, `export function clean() { return 1 + 2; }\n`, "utf8");

      const res = runMutationTesting({
        sourcePath: srcFile,
        testPath: "dummy.test.mjs",
        testRunner: () => true,
      });

      // After starting, the crash backup must have been restored
      const restored = readFileSync(srcFile, "utf8");
      assert.ok(restored.includes("clean()"));
      assert.equal(existsSync(bakFile), false, "Backup must be cleaned up");
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

    it("executes real spawnSync runner against a genuine Node.js test file", () => {
      const srcFile = join(tempDir, "real_code.mjs");
      const testFile = join(tempDir, "real_code.test.mjs");

      writeFileSync(
        srcFile,
        `export function multiply(a, b) {\n  if (a === 0) return 0;\n  return a * b;\n}\n`,
        "utf8",
      );

      // Test suite that asserts both branch and multiplication
      writeFileSync(
        testFile,
        `import test from "node:test";\nimport assert from "node:assert/strict";\nimport { multiply } from "./real_code.mjs";\n\ntest("multiplies correctly", () => {\n  assert.equal(multiply(0, 5), 0);\n  assert.equal(multiply(2, 3), 6);\n});\n`,
        "utf8",
      );

      const res = runMutationTesting({
        sourcePath: srcFile,
        testPath: testFile,
      });

      assert.equal(res.ok, true);
      assert.ok(res.kill_rate_bp >= 8000, "Kill rate must meet >= 8000 bp threshold");
      assert.ok(res.mutants_killed > 0);
      // Original source must remain unchanged after mutation testing
      const content = readFileSync(srcFile, "utf8");
      assert.ok(content.includes("a * b"));
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
    it("isolates flaky test from critical path and avoids overwrite collisions", () => {
      const testsDir = join(tempDir, "tests");
      const quarantineDir = join(tempDir, "quarantine");
      mkdirSync(testsDir, { recursive: true });

      const testFile1 = join(testsDir, "flaky.test.mjs");
      writeFileSync(testFile1, `// flaky test 1\n`, "utf8");

      const res1 = quarantineTest(testFile1, quarantineDir);
      assert.equal(res1.quarantined, true);
      assert.equal(existsSync(res1.quarantined_path), true);

      // Create a second test with same name to test collision avoidance
      const testFile2 = join(testsDir, "flaky.test.mjs");
      writeFileSync(testFile2, `// flaky test 2\n`, "utf8");

      const res2 = quarantineTest(testFile2, quarantineDir);
      assert.equal(res2.quarantined, true);
      assert.notEqual(res1.quarantined_path, res2.quarantined_path, "Must not overwrite existing quarantined file");
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

  describe("6. CLI Dispatch for mirql r mutant and mirql r flake", () => {
    it("returns USAGE_ERROR when missing arguments or attempting to lower threshold below 8000 bp floor", () => {
      const code1 = runCli(["mutant"]);
      assert.equal(code1, EXIT_CODES.USAGE_ERROR);

      const code2 = runCli(["mutant", "--source", "nonexistent.mjs"]);
      assert.equal(code2, EXIT_CODES.USAGE_ERROR);

      const code3 = runCli(["mutant", "--source", "a.mjs", "--test", "b.mjs", "--threshold", "5000"]);
      assert.equal(code3, EXIT_CODES.USAGE_ERROR, "Cannot lower threshold below 8000 bp floor");

      const code4 = runCli(["mutant", "--source", "a.mjs", "--test", "b.mjs", "--max-mutants", "0"]);
      assert.equal(code4, EXIT_CODES.USAGE_ERROR, "max-mutants must be > 0");
    });

    it("runs mirql r flake via CLI and exits 0 on passing test", () => {
      const testFile = join(tempDir, "pass.test.mjs");
      writeFileSync(testFile, `import test from "node:test";\nimport assert from "node:assert/strict";\ntest("passes", () => { assert.ok(true); });\n`, "utf8");

      const code = runCli(["flake", "--test", testFile, "--iterations", "2"]);
      assert.equal(code, EXIT_CODES.OK);
    });
  });

  describe("7. Probe mutants wiring", () => {
    it("fails closed with not_implemented when source and test are omitted", () => {
      const res = runProbe({ probe: "mutants", dir: tempDir });
      assert.equal(res.ok, false);
      assert.equal(res.probe.status, "not_implemented");
      assert.equal(res.probe.type, "mutants");
    });

    it("runs mutants probe successfully when target source and test are provided", () => {
      const srcFile = join(tempDir, "probe_math.mjs");
      const testFile = join(tempDir, "probe_math.test.mjs");
      writeFileSync(srcFile, `export function add(a, b) { if (a === 0) return b; return a + b; }\n`, "utf8");
      writeFileSync(testFile, `import test from "node:test";\nimport assert from "node:assert/strict";\nimport { add } from "./probe_math.mjs";\ntest("adds", () => { assert.equal(add(0, 2), 2); assert.equal(add(2, 3), 5); });\n`, "utf8");

      const res = runProbe({
        probe: "mutants",
        dir: tempDir,
        source: srcFile,
        test: testFile,
      });
      assert.equal(res.ok, true);
      assert.equal(res.probe.status, "pass");
      assert.equal(res.probe.type, "mutants");
      assert.ok(res.probe.kill_rate_bp >= 8000);
    });
  });
});
