// packages/run/mutant.mjs — Milestone M4: Incremental AST Mutation Engine & Flake Detector.
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  renameSync,
  unlinkSync,
  cpSync,
  rmSync,
  mkdtempSync,
  chmodSync,
  lstatSync,
} from "node:fs";
import { join, resolve, basename, dirname, relative } from "node:path";
import { tmpdir } from "node:os";
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
 * @param {boolean} [initialInBlockComment=false]
 * @returns {{ masked: string, inBlockComment: boolean, length: number, trim(): string, toString(): string }}
 */
export function maskStringsAndComments(line, initialInBlockComment = false) {
  let masked = "";
  let inDouble = false;
  let inSingle = false;
  let inBacktick = false;
  let inBlockComment = Boolean(initialInBlockComment);

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
      // Mask regular expression literals
      if (char === "/" && !isEscaped) {
        const before = masked.trimEnd();
        const lastChar = before.slice(-1);
        const isRegexPrefix =
          !before ||
          "=(:[{,;!&|?+-~^%*<>".includes(lastChar) ||
          /\b(?:return|throw|yield|typeof|delete|void|case|in|instanceof)$/.test(before);
        if (isRegexPrefix) {
          let closingIdx = -1;
          for (let j = i + 1; j < line.length; j++) {
            if (line[j] === "/" && line[j - 1] !== "\\") {
              closingIdx = j;
              break;
            }
          }
          if (closingIdx !== -1) {
            masked += " ".repeat(closingIdx - i + 1);
            i = closingIdx;
            continue;
          }
        }
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

  return {
    masked,
    inBlockComment,
    get length() { return masked.length; },
    trim() { return masked.trim(); },
    toString() { return masked; },
    includes(sub) { return masked.includes(sub); },
    indexOf(sub) { return masked.indexOf(sub); },
    slice(s, e) { return masked.slice(s, e); },
    [Symbol.toPrimitive]() { return masked; },
  };
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

  let inBlockComment = false;
  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineNum = lineIdx + 1;
    const line = lines[lineIdx];

    const maskRes = maskStringsAndComments(line, inBlockComment);
    const masked = maskRes.masked;
    const wasInBlockComment = inBlockComment;
    inBlockComment = maskRes.inBlockComment;

    // Incremental filter: skip lines not in changedLines if specified
    if (changedSet && !changedSet.has(lineNum)) {
      continue;
    }

    const trimmed = line.trim();

    // Skip blank lines and lines with zero executable code outside comments
    if (!trimmed || trimmed.startsWith("//") || !masked.trim()) {
      continue;
    }

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
 * True when the path looks like a test file (same rule as the mergeproof
 * evaluator and CI evidence builder).
 * @param {string} p
 * @returns {boolean}
 */
function isTestFilePath(p) {
  const norm = String(p ?? "").replaceAll("\\", "/").toLowerCase();
  return (
    norm.startsWith("tests/") ||
    norm.startsWith("test/") ||
    norm.includes(".test.") ||
    norm.includes("_test.")
  );
}

/**
 * Locates a BOUNDED workspace root to snapshot for sandboxed mutation:
 *   1. the git root containing the source, when there is one; otherwise
 *   2. the shared directory when source and tests are colocated in it.
 * Anything else (disjoint trees, unbounded shared ancestors) returns null —
 * callers must fail closed rather than copy an unbounded directory.
 *
 * @param {string} sourcePath
 * @param {string|string[]} [testPaths]
 * @returns {string | null}
 */
function findWorkspaceRoot(sourcePath, testPaths) {
  const sourceDir = dirname(resolve(sourcePath));
  let dir = sourceDir;
  while (true) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  const first = Array.isArray(testPaths) ? testPaths[0] : testPaths;
  if (first && dirname(resolve(first)).toLowerCase() === sourceDir.toLowerCase()) {
    return sourceDir;
  }
  return null;
}

/**
 * Creates a throwaway sandbox copy of the workspace (issue #14): mutants are
 * written into the copy, never into the real tree. A SIGKILL between mutant
 * runs can leak at most a temp directory — the real workspace is untouched.
 *
 * @param {string} sourcePath
 * @param {string|string[]} testPaths
 * @returns {{ root: string, source: string, tests: string[] } | null}
 */
function makeSandbox(sourcePath, testPaths) {
  const root = findWorkspaceRoot(sourcePath, testPaths);
  if (!root) return null;

  let sandboxRoot = null;
  try {
    sandboxRoot = mkdtempSync(join(tmpdir(), "mirql-mutant-"));
    cpSync(root, sandboxRoot, {
      recursive: true,
      filter: (src) => {
        const name = basename(src);
        return name !== ".git" && name !== "node_modules" && name !== ".mirql";
      },
    });

    const map = (abs) => join(sandboxRoot, relative(root, abs));
    const sandboxSource = map(resolve(sourcePath));
    const rawTestPaths = (Array.isArray(testPaths) ? testPaths : [testPaths]).filter(Boolean);
    const sandboxTests = rawTestPaths.map(map);
    if (!existsSync(sandboxSource) || sandboxTests.some((t) => !existsSync(t))) {
      rmSync(sandboxRoot, { recursive: true, force: true });
      return null;
    }

    // Dissolve symlinks on the mutation path in the sandbox (issue #14 / B1):
    // If sandboxSource is a symlink, writeFileSync would mutate the target outside the sandbox.
    // Replace symlink with real file content inside the sandbox.
    try {
      const st = lstatSync(sandboxSource);
      if (st.isSymbolicLink()) {
        unlinkSync(sandboxSource);
        writeFileSync(sandboxSource, readFileSync(resolve(sourcePath)));
      }
    } catch {}

    for (let i = 0; i < sandboxTests.length; i++) {
      const t = sandboxTests[i];
      const realT = rawTestPaths[i];
      try {
        const tst = lstatSync(t);
        if (tst.isSymbolicLink()) {
          unlinkSync(t);
          writeFileSync(t, readFileSync(resolve(realT)));
        }
      } catch {}
    }

    // cpSync preserves file modes; the sandbox owns its copies, so the mutation
    // target must be writable even if the real file was read-only.
    try {
      chmodSync(sandboxSource, 0o666);
    } catch {}
    return { root: sandboxRoot, source: sandboxSource, tests: sandboxTests };
  } catch (err) {
    if (sandboxRoot && existsSync(sandboxRoot)) {
      try {
        rmSync(sandboxRoot, { recursive: true, force: true });
      } catch {}
    }
    return null;
  }
}

/**
 * Runs mutation testing against a source file and a test suite.
 * Enforces pre-flight baseline test verification and the M4 invariant:
 * kill rate must achieve at least 8000 bp (80%) floor.
 *
 * Isolation contract (issue #14): with the default spawn runner, the engine
 * snapshots the workspace to a temp sandbox and mutates ONLY the copy — the
 * real source file is never written. A crash (including SIGKILL from the
 * lifeguard, which cannot run signal traps) leaves the real tree intact.
 * A legacy `<source>.mutant-bak` from pre-isolation versions is still healed
 * on entry. When a custom `testRunner` is provided the engine writes nothing
 * at all — the runner receives each mutant and decides how to test it.
 *
 * @param {object} options
 * @param {string} options.sourcePath - Path to source file being evaluated
 * @param {string|string[]} [options.testPath] - Test file(s) covering the source
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

  const testPaths = Array.isArray(testPath) ? testPath : [testPath];

  if (!testRunner && (testPaths.length === 0 || testPaths.some((t) => !t || !existsSync(t)))) {
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

  // Fail-safe crash recovery: heal workspaces corrupted by pre-isolation
  // versions (which mutated the real file under a .mutant-bak backup).
  if (existsSync(backupPath)) {
    try {
      writeFileSync(sourcePath, readFileSync(backupPath, "utf8"), "utf8");
      unlinkSync(backupPath);
    } catch {}
  }

  const originalContent = readFileSync(sourcePath, "utf8");

  // Sandbox the run when using the real spawn runner (isolation, issue #14).
  // A custom testRunner already isolates by contract (it applies mutant.mutatedCode
  // itself); writing the real file for it was pure collateral risk.
  let sandbox = null;
  if (typeof testRunner !== "function") {
    sandbox = makeSandbox(sourcePath, testPaths);
    if (!sandbox) {
      return {
        ok: false,
        error: "SANDBOX_UNAVAILABLE",
        source_path: sourcePath,
        kill_rate_bp: 0,
        kill_threshold_bp: killThresholdBp,
        mutants_total: 0,
        mutants_killed: 0,
        mutants_survived: 0,
        survived_mutants: [],
        summary: "Cannot build an isolated sandbox for this source/test layout; refusing to mutate the real workspace",
      };
    }
  }

  const mutationTarget = sandbox ? sandbox.source : null;
  const spawnTestPaths = sandbox ? sandbox.tests : testPaths;

  try {
    // Multi-run pre-flight baseline stability verification
    const { env: cleanEnv } = sanitizeAgentEnv(process.env);
    for (let b = 0; b < 2; b++) {
      let baselinePassed = false;
      if (typeof testRunner === "function") {
        baselinePassed = Boolean(testRunner({ id: "baseline", original: "", mutated: "", isBaseline: true }));
      } else {
        const baselineResult = spawnSync(process.execPath, ["--test", ...spawnTestPaths], {
          encoding: "utf8",
          timeout: 15000,
          env: { ...cleanEnv, NODE_ENV: "test" },
        });
        if (baselineResult.error) {
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
            summary: `Baseline test runner error: ${baselineResult.error.message}`,
          };
        }
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

    for (const mutant of mutantsToTest) {
      // Apply mutant — ONLY ever inside the sandbox copy (or the custom runner)
      if (mutationTarget) {
        writeFileSync(mutationTarget, mutant.mutatedCode, "utf8");
      }

      let testPassed = false;
      if (typeof testRunner === "function") {
        testPassed = Boolean(testRunner(mutant));
      } else {
        const result = spawnSync(process.execPath, ["--test", ...spawnTestPaths], {
          encoding: "utf8",
          timeout: 15000,
          env: { ...cleanEnv, NODE_ENV: "test" },
        });
        if (result.error) {
          throw new Error(`Test runner failed executing mutant ${mutant.id}: ${result.error.message}`);
        }
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
  } finally {
    if (sandbox) {
      try {
        rmSync(sandbox.root, { recursive: true, force: true });
      } catch {}
    }
  }
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
