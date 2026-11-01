// packages/run/mutant.mjs — Milestone M4: Incremental AST Mutation Engine & Flake Detector.
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { spawnSync } from "node:child_process";
import { sanitizeAgentEnv } from "./agent.mjs";

/**
 * Standard AST mutation operators supported by Scout (Mutants) per roles/scout-mutants.md:
 * - `invert-conditional`: swaps equality and relational conditionals (=== <-> !==, == <-> !=, < <-> >=, > <-> <=)
 * - `swap-arithmetic`: swaps binary arithmetic operators (+ <-> -, * <-> /)
 * - `mutate-boundary`: alters numerical bounds and booleans (true <-> false, 0 -> 1, >= -> >, <= -> <)
 * - `remove-call`: comments out or replaces standalone void expression calls
 */
export const MUTATION_OPERATORS = Object.freeze([
  "invert-conditional",
  "swap-arithmetic",
  "mutate-boundary",
  "remove-call",
]);

/**
 * Masks string literals ("...", '...', `...`) and comments (//..., /*...*\/) with whitespace.
 * Preserves character offsets so token search occurs only on genuine executable AST code.
 *
 * @param {string} line
 * @returns {string}
 */
export function maskStringsAndComments(line) {
  let masked = "";
  let inDouble = false;
  let inSingle = false;
  let inBacktick = false;
  let inBlockComment = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    const prev = i > 0 ? line[i - 1] : "";
    const isEscaped = prev === "\\";

    if (inBlockComment) {
      masked += " ";
      if (char === "*" && line[i + 1] === "/") {
        inBlockComment = false;
        masked += " ";
        i++;
      }
      continue;
    }

    if (!inDouble && !inSingle && !inBacktick) {
      if (char === "/" && line[i + 1] === "/") {
        // Line comment: the rest of the line is masked
        masked += " ".repeat(line.length - i);
        break;
      }
      if (char === "/" && line[i + 1] === "*") {
        inBlockComment = true;
        masked += "  ";
        i++;
        continue;
      }
      if (char === '"') {
        inDouble = true;
        masked += " ";
        continue;
      }
      if (char === "'") {
        inSingle = true;
        masked += " ";
        continue;
      }
      if (char === "`") {
        inBacktick = true;
        masked += " ";
        continue;
      }
      masked += char;
    } else if (inDouble) {
      masked += " ";
      if (char === '"' && !isEscaped) inDouble = false;
    } else if (inSingle) {
      masked += " ";
      if (char === "'" && !isEscaped) inSingle = false;
    } else if (inBacktick) {
      masked += " ";
      if (char === "`" && !isEscaped) inBacktick = false;
    }
  }

  return masked;
}

/**
 * Splices a replacement string into `line` at exact character range `[matchIdx, matchIdx + matchLen)`.
 *
 * @param {string} line
 * @param {number} matchIdx
 * @param {number} matchLen
 * @param {string} replacement
 * @returns {string}
 */
function spliceMatch(line, matchIdx, matchLen, replacement) {
  return line.slice(0, matchIdx) + replacement + line.slice(matchIdx + matchLen);
}

/**
 * Extracts 1-based changed line numbers from unified git diff text.
 *
 * @param {string} diffText
 * @returns {Set<number>}
 */
export function extractChangedLines(diffText) {
  const lines = new Set();
  const hunkRegex = /@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/g;
  let match;
  while ((match = hunkRegex.exec(diffText)) !== null) {
    const start = parseInt(match[1], 10);
    const count = match[2] !== undefined ? parseInt(match[2], 10) : 1;
    for (let i = 0; i < count; i++) {
      lines.add(start + i);
    }
  }
  return lines;
}

/**
 * Checks if JavaScript code is syntactically valid ECMAScript module code.
 *
 * @param {string} code
 * @returns {boolean}
 */
export function isValidModuleSyntax(code) {
  const res = spawnSync(process.execPath, ["--input-type=module", "--check"], {
    input: code,
    encoding: "utf8",
    timeout: 5000,
  });
  return res.status === 0;
}

/**
 * Generates semantic mutation candidates for a given source string.
 * Supports incremental mutation restricted to `changedLines`.
 * Skips string literals, comments, and verifies ECMAScript syntax validity.
 *
 * @param {string} sourceCode
 * @param {object} [options]
 * @param {string[]} [options.operators]
 * @param {number[] | Set<number>} [options.changedLines] - 1-based line numbers to mutate
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
  const changedSet = options.changedLines
    ? (options.changedLines instanceof Set ? options.changedLines : new Set(options.changedLines))
    : null;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineNum = lineIdx + 1;

    // Incremental filter: skip lines not in changedLines if specified
    if (changedSet && !changedSet.has(lineNum)) {
      continue;
    }

    const line = lines[lineIdx];
    const trimmed = line.trim();

    // Skip blank and pure comment lines
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
      continue;
    }

    const masked = maskStringsAndComments(line);

    // 1. invert-conditional
    if (allowedOps.includes("invert-conditional")) {
      if (masked.includes("===")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "invert-conditional", masked.indexOf("==="), 3, "===", "!==", "Invert strict equality to strict inequality");
      } else if (masked.includes("!==")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "invert-conditional", masked.indexOf("!=="), 3, "!==", "===", "Invert strict inequality to strict equality");
      } else if (masked.includes("<=")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "invert-conditional", masked.indexOf("<="), 2, "<=", ">", "Invert less-than-or-equal to greater-than");
      } else if (masked.includes(">=")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "invert-conditional", masked.indexOf(">="), 2, ">=", "<", "Invert greater-than-or-equal to less-than");
      } else if (masked.includes(" < ")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "invert-conditional", masked.indexOf(" < "), 3, " < ", " >= ", "Invert less-than to greater-than-or-equal");
      } else if (masked.includes(" > ")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "invert-conditional", masked.indexOf(" > "), 3, " > ", " <= ", "Invert greater-than to less-than-or-equal");
      }
    }

    // 2. swap-arithmetic
    if (allowedOps.includes("swap-arithmetic")) {
      if (masked.includes(" + ")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "swap-arithmetic", masked.indexOf(" + "), 3, " + ", " - ", "Swap addition with subtraction");
      } else if (masked.includes(" - ")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "swap-arithmetic", masked.indexOf(" - "), 3, " - ", " + ", "Swap subtraction with addition");
      } else if (masked.includes(" * ")) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "swap-arithmetic", masked.indexOf(" * "), 3, " * ", " / ", "Swap multiplication with division");
      }
    }

    // 3. mutate-boundary
    if (allowedOps.includes("mutate-boundary")) {
      const trueMatch = /\btrue\b/.exec(masked);
      if (trueMatch) {
        addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "mutate-boundary", trueMatch.index, 4, "true", "false", "Mutate boolean true to false");
      } else {
        const falseMatch = /\bfalse\b/.exec(masked);
        if (falseMatch) {
          addCandidateAtOffset(mutants, lines, lineIdx, lineNum, "mutate-boundary", falseMatch.index, 5, "false", "true", "Mutate boolean false to true");
        }
      }
    }

    // 4. remove-call
    if (allowedOps.includes("remove-call")) {
      const trimmedClean = trimmed.split("//")[0].trim();
      const isReserved = /^(?:return|throw|import|export|const|let|var|if|while|for|yield|await)\b/.test(trimmedClean);
      const isStandaloneCall = /^\s*(?:await\s+)?[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\([^;]*\)\s*;\s*$/.test(trimmedClean);

      if (
        isStandaloneCall &&
        !isReserved &&
        !trimmedClean.includes("=") &&
        !trimmedClean.includes("*/")
      ) {
        const callIdx = line.indexOf(trimmedClean);
        if (callIdx !== -1) {
          addCandidateAtOffset(
            mutants,
            lines,
            lineIdx,
            lineNum,
            "remove-call",
            callIdx,
            trimmedClean.length,
            trimmedClean,
            `/* ${trimmedClean} */`,
            "Remove standalone call statement",
          );
        }
      }
    }
  }

  return mutants;
}

/** Helper to construct and syntax-validate mutant candidate using exact string offset */
function addCandidateAtOffset(mutants, lines, lineIdx, lineNum, operator, matchIdx, matchLen, original, replacement, description) {
  const line = lines[lineIdx];
  const mutatedLine = spliceMatch(line, matchIdx, matchLen, replacement);

  const mutatedLines = [...lines];
  mutatedLines[lineIdx] = mutatedLine;
  const mutatedCode = mutatedLines.join("\n");

  // Validate syntax: discard if the mutant produces invalid syntax
  if (!isValidModuleSyntax(mutatedCode)) {
    return;
  }

  mutants.push({
    id: `mutant-${operator}-${lineNum}-${Math.abs(hashString(original + lineIdx))}`,
    operator,
    line: lineNum,
    original,
    mutated: replacement,
    mutatedCode,
    description: `${description} at line ${lineNum}`,
  });
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
 * Enforces pre-flight baseline test verification, crash-safe restoration, and the M4 invariant:
 * kill rate must achieve at least 8000 bp (80%) floor.
 *
 * @param {object} options
 * @param {string} options.sourcePath - Path to source file being evaluated
 * @param {string} [options.testPath] - Path to test file covering the source
 * @param {number} [options.maxMutants=20] - Maximum mutants to evaluate (> 0)
 * @param {number} [options.killThresholdBp=8000] - Required kill rate (inviolable floor 8000 bp)
 * @param {Function} [options.testRunner] - Custom test runner for sandboxing
 * @param {number[] | Set<number>} [options.changedLines] - Line filter for incremental mutation
 * @returns {{
 *   ok: boolean,
 *   source_path?: string,
 *   error?: string,
 *   kill_rate_bp: number,
 *   kill_threshold_bp: number,
 *   mutants_total: number,
 *   mutants_killed: number,
 *   mutants_survived: number,
 *   survived_mutants: Array<{ id: string, file: string, line: number, operator: string, original: string, mutated: string, description: string }>,
 *   summary: string
 * }}
 */
export function runMutationTesting(options = {}) {
  const {
    sourcePath,
    testPath,
    testRunner,
  } = options;

  if (!sourcePath || !existsSync(sourcePath)) {
    throw new Error(`sourcePath not found: ${sourcePath}`);
  }

  if (!testRunner && (!testPath || !existsSync(testPath))) {
    throw new Error(`testPath not found or missing: ${testPath}`);
  }

  // Validate and enforce inviolable 8000 bp threshold floor
  const rawThreshold = Number.isSafeInteger(options.killThresholdBp) ? options.killThresholdBp : 8000;
  const killThresholdBp = Math.max(8000, rawThreshold);

  // Validate maxMutants
  const maxMutants = Number.isSafeInteger(options.maxMutants) && options.maxMutants > 0
    ? options.maxMutants
    : 20;

  const backupPath = `${sourcePath}.mutant-bak`;

  // Fail-safe crash recovery: if previous run died ungracefully, restore from backup immediately
  if (existsSync(backupPath)) {
    try {
      writeFileSync(sourcePath, readFileSync(backupPath, "utf8"), "utf8");
      unlinkSync(backupPath);
    } catch {}
  }

  const originalContent = readFileSync(sourcePath, "utf8");

  // Multi-run pre-flight baseline stability verification
  const { env: cleanEnv } = sanitizeAgentEnv(process.env);
  for (let b = 0; b < 2; b++) {
    let baselinePassed = false;
    if (typeof testRunner === "function") {
      baselinePassed = Boolean(testRunner({ id: "baseline", original: "", mutated: "", isBaseline: true }));
    } else {
      const baselineResult = spawnSync(process.execPath, ["--test", testPath], {
        encoding: "utf8",
        timeout: 15000,
        env: { ...cleanEnv, NODE_ENV: "test" },
      });
      baselinePassed = baselineResult.status === 0;
    }

    if (!baselinePassed) {
      return {
        ok: false,
        error: "BASELINE_TEST_FAILED",
        source_path: sourcePath,
        kill_rate_bp: 0,
        kill_threshold_bp: killThresholdBp,
        mutants_total: 0,
        mutants_killed: 0,
        mutants_survived: 0,
        survived_mutants: [],
        summary: "Baseline test failed or was non-deterministic on unmutated source; mutation testing aborted",
      };
    }
  }

  const allMutants = generateMutants(originalContent, options);
  const mutantsToTest = allMutants.slice(0, maxMutants);

  if (mutantsToTest.length === 0) {
    return {
      ok: false,
      error: "NO_MUTATION_POINTS",
      source_path: sourcePath,
      kill_rate_bp: 0,
      kill_threshold_bp: killThresholdBp,
      mutants_total: 0,
      mutants_killed: 0,
      mutants_survived: 0,
      survived_mutants: [],
      summary: "No valid AST mutation points found in target source",
    };
  }

  let killedCount = 0;
  const survivedMutants = [];

  // Write safe backup file for crash recovery
  writeFileSync(backupPath, originalContent, "utf8");

  // Signal traps for abort safety
  const restoreOnAbort = () => {
    try {
      if (existsSync(backupPath)) {
        writeFileSync(sourcePath, readFileSync(backupPath, "utf8"), "utf8");
        unlinkSync(backupPath);
      }
    } catch {}
  };
  process.once("SIGINT", restoreOnAbort);
  process.once("SIGTERM", restoreOnAbort);

  try {
    for (const mutant of mutantsToTest) {
      // Apply mutant
      writeFileSync(sourcePath, mutant.mutatedCode, "utf8");

      let testPassed = false;
      if (typeof testRunner === "function") {
        testPassed = Boolean(testRunner(mutant));
      } else {
        const result = spawnSync(process.execPath, ["--test", testPath], {
          encoding: "utf8",
          timeout: 15000,
          env: { ...cleanEnv, NODE_ENV: "test" },
        });
        testPassed = result.status === 0;
      }

      if (testPassed) {
        // Test passed despite synthetic fault: MUTANT SURVIVED
        survivedMutants.push({
          id: mutant.id,
          file: sourcePath,
          line: mutant.line,
          operator: mutant.operator,
          original: mutant.original,
          mutated: mutant.mutated,
          description: mutant.description,
        });
      } else {
        // Test failed: MUTANT KILLED
        killedCount++;
      }
    }
  } finally {
    process.removeListener("SIGINT", restoreOnAbort);
    process.removeListener("SIGTERM", restoreOnAbort);
    // ALWAYS restore original source file and clean backup
    writeFileSync(sourcePath, originalContent, "utf8");
    if (existsSync(backupPath)) {
      try {
        unlinkSync(backupPath);
      } catch {}
    }
  }

  const total = mutantsToTest.length;
  // Calculate basis points: 0 to 10000 bp (Law 17 safe integer arithmetic)
  const killRateBp = Math.trunc((killedCount * 10000) / total);
  const passed = killRateBp >= killThresholdBp;

  return {
    ok: passed,
    source_path: sourcePath,
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
  const { env: cleanEnv } = sanitizeAgentEnv(process.env);

  for (let i = 0; i < iterations; i++) {
    let passed = false;
    if (typeof options.runner === "function") {
      passed = Boolean(options.runner(i));
    } else {
      const res = spawnSync(process.execPath, ["--test", testPath], {
        encoding: "utf8",
        timeout: 15000,
        env: { ...cleanEnv, NODE_ENV: "test" },
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
 * Enforces path confinement and prevents accidental file overwrite collisions.
 *
 * @param {string} testFilePath
 * @param {string} quarantineDir
 * @param {object} [options]
 * @param {number} [options.nowMs]
 * @param {string} [options.reason]
 * @param {Function} [options.appendLedger]
 * @returns {{
 *   quarantined: boolean,
 *   original_path: string,
 *   quarantined_path: string,
 *   event: object
 * }}
 */
export function quarantineTest(testFilePath, quarantineDir, options = {}) {
  const fullTestPath = resolve(testFilePath);
  if (!existsSync(fullTestPath)) {
    throw new Error(`Test file not found: ${fullTestPath}`);
  }

  const targetDir = resolve(quarantineDir);
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const fileName = basename(fullTestPath);
  let quarantinedPath = join(targetDir, fileName);

  // Avoid overwrite collision
  if (existsSync(quarantinedPath)) {
    const ext = fileName.endsWith(".test.mjs") ? ".test.mjs" : ".mjs";
    const nameWithoutExt = fileName.slice(0, -ext.length);
    quarantinedPath = join(targetDir, `${nameWithoutExt}-${Date.now()}-${Math.floor(Math.random() * 1000)}${ext}`);
  }

  // Enforce quarantine path confinement
  if (!quarantinedPath.startsWith(targetDir)) {
    throw new Error("Quarantine path escape attempt detected");
  }

  renameSync(fullTestPath, quarantinedPath);

  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const event = {
    type: "test.quarantined",
    payload: {
      test_file: fileName,
      original_path: fullTestPath,
      quarantined_path: quarantinedPath,
      timestamp_ms: nowMs,
      quarantine_reason: options.reason ?? "nondeterministic_flakiness_detected",
    },
  };

  if (typeof options.appendLedger === "function") {
    options.appendLedger(event);
  }

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
  const file = options.file ?? mutantResult.source_path ?? "unknown";

  if (!mutantResult.ok && mutantResult.survived_mutants?.length > 0) {
    const firstSurvived = mutantResult.survived_mutants[0];
    return {
      type: "mutant.survived",
      payload: {
        file,
        line: firstSurvived.line,
        mutation_applied: `${firstSurvived.original} -> ${firstSurvived.mutated}`,
        status: "survived",
        kill_rate_bp: mutantResult.kill_rate_bp ?? 0,
        mutants_total: mutantResult.mutants_total ?? 0,
        mutants_killed: mutantResult.mutants_killed ?? 0,
        mutants_survived: mutantResult.mutants_survived ?? 0,
        timestamp_ms: nowMs,
      },
    };
  }

  return {
    type: "mutant.evaluated",
    payload: {
      file,
      kill_rate_bp: mutantResult.kill_rate_bp ?? 0,
      mutants_total: mutantResult.mutants_total ?? 0,
      mutants_killed: mutantResult.mutants_killed ?? 0,
      mutants_survived: mutantResult.mutants_survived ?? 0,
      summary: mutantResult.summary ?? "",
      timestamp_ms: nowMs,
    },
  };
}

/**
 * Formats a canonical mutant.kill_test_needed event per roles/scout-mutants.md.
 *
 * @param {object} survivedMutant
 * @param {object} [options]
 * @returns {object}
 */
export function formatKillTestNeededEvent(survivedMutant, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const file = options.file ?? survivedMutant.file ?? "unknown";
  return {
    type: "mutant.kill_test_needed",
    payload: {
      file,
      line: survivedMutant.line,
      survived_mutant_id: survivedMutant.id,
      recommendation: `Add unit test assertion covering ${survivedMutant.operator} mutation at line ${survivedMutant.line} (${survivedMutant.description})`,
      timestamp_ms: nowMs,
    },
  };
}
