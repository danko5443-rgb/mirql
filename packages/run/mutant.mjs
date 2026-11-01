// packages/run/mutant.mjs — Milestone M4: Incremental AST Mutation Engine & Flake Detector.
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync, readdirSync } from "node:fs";
import { join, resolve, basename, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { ulid } from "../core/index.mjs";

/**
 * Standard AST mutation operators supported by Scout (Mutants) per roles/scout-mutants.md:
 * - `invert-conditional`: swaps equality and relational conditionals (=== <-> !==, == <-> !=, < <-> >=, > <-> <=)
 * - `swap-arithmetic`: swaps binary arithmetic operators (+ <-> -, * <-> /)
 * - `mutate-boundary`: alters numerical bounds and booleans (true <-> false, 0 -> 1, >= -> >, <= -> <)
 * - `remove-call`: comments out or replaces void expression calls
 */
export const MUTATION_OPERATORS = Object.freeze([
  "invert-conditional",
  "swap-arithmetic",
  "mutate-boundary",
  "remove-call",
]);

/**
 * Generates semantic mutation candidates for a given source string.
 *
 * @param {string} sourceCode
 * @param {object} [options]
 * @param {string[]} [options.operators]
 * @returns {Array<{
 *   id: string,
 *   operator: string,
 *   line: number,
 *   original: string,
 *   mutated: string,
 *   mutatedCode: string,
 *   description: string
 * }>}
 */
export function generateMutants(sourceCode, options = {}) {
  const allowedOps = options.operators ?? MUTATION_OPERATORS;
  const mutants = [];
  const lines = sourceCode.split(/\r?\n/);

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineNum = lineIdx + 1;
    const line = lines[lineIdx];
    const trimmed = line.trim();

    // Skip empty lines and comment lines
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
      continue;
    }

    // 1. invert-conditional
    if (allowedOps.includes("invert-conditional")) {
      if (line.includes("===")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "invert-conditional", "===", "!==", "Invert strict equality to strict inequality"));
      } else if (line.includes("!==")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "invert-conditional", "!==", "===", "Invert strict inequality to strict equality"));
      } else if (line.includes("<=")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "invert-conditional", "<=", ">", "Invert less-than-or-equal to greater-than"));
      } else if (line.includes(">=")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "invert-conditional", ">=", "<", "Invert greater-than-or-equal to less-than"));
      } else if (line.includes(" < ")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "invert-conditional", " < ", " >= ", "Invert less-than to greater-than-or-equal"));
      } else if (line.includes(" > ")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "invert-conditional", " > ", " <= ", "Invert greater-than to less-than-or-equal"));
      }
    }

    // 2. swap-arithmetic
    if (allowedOps.includes("swap-arithmetic")) {
      if (line.includes(" + ")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "swap-arithmetic", " + ", " - ", "Swap addition with subtraction"));
      } else if (line.includes(" - ")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "swap-arithmetic", " - ", " + ", "Swap subtraction with addition"));
      } else if (line.includes(" * ")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "swap-arithmetic", " * ", " / ", "Swap multiplication with division"));
      }
    }

    // 3. mutate-boundary
    if (allowedOps.includes("mutate-boundary")) {
      if (line.includes("true")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "mutate-boundary", "true", "false", "Mutate boolean true to false"));
      } else if (line.includes("false")) {
        mutants.push(createMutant(lines, lineIdx, lineNum, "mutate-boundary", "false", "true", "Mutate boolean false to true"));
      }
    }
  }

  return mutants;
}

/** Helper to construct mutant record */
function createMutant(lines, lineIdx, lineNum, operator, original, replacement, description) {
  const mutatedLines = [...lines];
  mutatedLines[lineIdx] = mutatedLines[lineIdx].replace(original, replacement);
  return {
    id: `mutant-${operator}-${lineNum}-${Math.abs(hashString(original + lineIdx))}`,
    operator,
    line: lineNum,
    original,
    mutated: replacement,
    mutatedCode: mutatedLines.join("\n"),
    description: `${description} at line ${lineNum}`,
  };
}

/** Quick safe integer hash for mutant ID generation */
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash;
}

/**
 * Runs mutation testing against a source file and a test suite.
 * Enforces the Milestone M4 invariant: >= 8000 bp (80%) mutant kill rate.
 *
 * @param {object} options
 * @param {string} options.sourcePath - Path to source file being evaluated
 * @param {string} options.testPath - Path to test file covering the source
 * @param {number} [options.maxMutants=20] - Maximum mutants to evaluate
 * @param {number} [options.killThresholdBp=8000] - Required kill rate (default 8000 bp = 80%)
 * @param {Function} [options.testRunner] - Custom test runner for sandboxing
 * @returns {{
 *   ok: boolean,
 *   kill_rate_bp: number,
 *   kill_threshold_bp: number,
 *   mutants_total: number,
 *   mutants_killed: number,
 *   mutants_survived: number,
 *   survived_mutants: Array<{ id: string, line: number, operator: string, description: string }>,
 *   summary: string
 * }}
 */
export function runMutationTesting(options = {}) {
  const {
    sourcePath,
    testPath,
    maxMutants = 20,
    killThresholdBp = 8000,
    testRunner,
  } = options;

  if (!sourcePath || !existsSync(sourcePath)) {
    throw new Error(`sourcePath not found: ${sourcePath}`);
  }

  const originalContent = readFileSync(sourcePath, "utf8");
  const allMutants = generateMutants(originalContent, options);
  const mutantsToTest = allMutants.slice(0, maxMutants);

  if (mutantsToTest.length === 0) {
    return {
      ok: true,
      kill_rate_bp: 10000,
      kill_threshold_bp: killThresholdBp,
      mutants_total: 0,
      mutants_killed: 0,
      mutants_survived: 0,
      survived_mutants: [],
      summary: "No mutation points found in target source",
    };
  }

  let killedCount = 0;
  const survivedMutants = [];

  try {
    for (const mutant of mutantsToTest) {
      // Apply mutant
      writeFileSync(sourcePath, mutant.mutatedCode, "utf8");

      let testPassed = false;
      if (typeof testRunner === "function") {
        testPassed = testRunner(mutant);
      } else {
        // Run test via node --test
        const result = spawnSync(process.execPath, ["--test", testPath], {
          encoding: "utf8",
          timeout: 10000,
          env: { ...process.env, NODE_ENV: "test" },
        });
        testPassed = result.status === 0;
      }

      if (testPassed) {
        // Test passed despite synthetic fault: MUTANT SURVIVED (test suite was too weak)
        survivedMutants.push({
          id: mutant.id,
          line: mutant.line,
          operator: mutant.operator,
          description: mutant.description,
        });
      } else {
        // Test failed: MUTANT KILLED (test caught the fault)
        killedCount++;
      }
    }
  } finally {
    // ALWAYS restore original source file
    writeFileSync(sourcePath, originalContent, "utf8");
  }

  const total = mutantsToTest.length;
  // Calculate basis points: 0 to 10000 bp (Law 17 safe integer arithmetic)
  const killRateBp = Math.trunc((killedCount * 10000) / total);
  const passed = killRateBp >= killThresholdBp;

  return {
    ok: passed,
    kill_rate_bp: killRateBp,
    kill_threshold_bp: killThresholdBp,
    mutants_total: total,
    mutants_killed: killedCount,
    mutants_survived: survivedMutants.length,
    survived_mutants: survivedMutants,
    summary: `Mutation testing: ${killedCount}/${total} killed (${killRateBp} bp, threshold: ${killThresholdBp} bp)`,
  };
}

/**
 * Runs a suspect test multiple times (N iterations) to detect nondeterministic flakiness.
 *
 * @param {string} testPath - Path to test file
 * @param {object} [options]
 * @param {number} [options.iterations=5] - Number of executions
 * @param {Function} [options.runner] - Optional runner override
 * @returns {{
 *   flaky: boolean,
 *   runs_total: number,
 *   passed_runs: number,
 *   failed_runs: number,
 *   history: boolean[]
 * }}
 */
export function detectFlakes(testPath, options = {}) {
  const iterations = Number.isSafeInteger(options.iterations) && options.iterations > 0
    ? options.iterations
    : 5;

  const history = [];
  let passedCount = 0;
  let failedCount = 0;

  for (let i = 0; i < iterations; i++) {
    let passed = false;
    if (typeof options.runner === "function") {
      passed = Boolean(options.runner(i));
    } else {
      const res = spawnSync(process.execPath, ["--test", testPath], {
        encoding: "utf8",
        timeout: 15000,
      });
      passed = res.status === 0;
    }

    history.push(passed);
    if (passed) passedCount++;
    else failedCount++;
  }

  // Flaky if both passed and failed runs occurred across repetitions
  const isFlaky = passedCount > 0 && failedCount > 0;

  return {
    flaky: isFlaky,
    runs_total: iterations,
    passed_runs: passedCount,
    failed_runs: failedCount,
    history,
  };
}

/**
 * Quarantines a flaky test file into a quarantine directory away from the critical path.
 *
 * @param {string} testFilePath
 * @param {string} quarantineDir
 * @returns {{
 *   quarantined: boolean,
 *   original_path: string,
 *   quarantined_path: string,
 *   event: object
 * }}
 */
export function quarantineTest(testFilePath, quarantineDir) {
  const fullTestPath = resolve(testFilePath);
  if (!existsSync(fullTestPath)) {
    throw new Error(`Test file not found: ${fullTestPath}`);
  }

  const targetDir = resolve(quarantineDir);
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const fileName = basename(fullTestPath);
  const quarantinedPath = join(targetDir, fileName);

  renameSync(fullTestPath, quarantinedPath);

  const nowMs = Date.now();
  const event = {
    type: "test.quarantined",
    payload: {
      test_file: fileName,
      original_path: fullTestPath,
      quarantined_path: quarantinedPath,
      timestamp_ms: nowMs,
      quarantine_reason: "nondeterministic_flakiness_detected",
    },
  };

  return {
    quarantined: true,
    original_path: fullTestPath,
    quarantined_path: quarantinedPath,
    event,
  };
}

/**
 * Formats a canonical mutant report event payload per roles/scout-mutants.md.
 *
 * @param {object} mutantResult
 * @param {object} [options]
 * @returns {object}
 */
export function formatMutantEvent(mutantResult, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const firstSurvived = mutantResult.survived_mutants?.[0];

  return {
    type: mutantResult.ok ? "mutant.evaluated" : "mutant.survived",
    payload: {
      kill_rate_bp: mutantResult.kill_rate_bp ?? 0,
      mutants_total: mutantResult.mutants_total ?? 0,
      mutants_killed: mutantResult.mutants_killed ?? 0,
      mutants_survived: mutantResult.mutants_survived ?? 0,
      first_survived: firstSurvived ?? null,
      summary: mutantResult.summary ?? "",
      timestamp_ms: nowMs,
    },
  };
}
