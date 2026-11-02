import { readFileSync, readdirSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { EXIT_CODES, isTestFilePath, normalizePath } from "../core/index.mjs";
import { sanitizeAgentEnv } from "./agent.mjs";
import {
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "./anti-cheat.mjs";
import { evaluatePhiGate } from "./phi.mjs";
import { extractChangedLines } from "./mutant.mjs";

/**
 * Verifies a candidate fix/feature across the deterministic checks (Laws 10, 13, 16):
 * 1. AST / Anti-Cheat Gate: MP-001 through MP-005 rules.
 * 2. Law 13 Complexity Potential Gate: Delta Phi <= 0 (strictly < 0 for consolidator).
 * 3. Law 16 Triple-Execution Red-Green-ReRed sequence:
 *    - Red-on-Base: reproducer must fail with test assertion failure (exit 1). Crashes or passes are rejected.
 *    - Green-on-Head: full suite and reproducer pass on head (exit 0).
 *    - Re-Red: reproducer fails (exit 1) when non-test changes are reverted. Tautological tests are rejected.
 * 4. Fail-closed: missing proof, missing runner, or non-integer exit codes reject.
 *
 * @param {object} options
 * @returns {any} verification result
 */
export function verifyAttempt(options = {}) {
  // 1. Fixture mode
  if (options.fixture) {
    return verifyFixture(options.fixture);
  }

  // 2. Direct PR or outcome object without runner
  if (
    options.diff_stat !== undefined ||
    options.pr !== undefined ||
    options.evidence !== undefined ||
    options.anti_cheat !== undefined
  ) {
    const antiCheatCheck = checkAntiCheat(options);
    const phiCheck = checkPhiLaw13(options, options);
    if (!phiCheck.ok) {
      return {
        verified: false,
        verdict: phiCheck.verdict,
        rule: phiCheck.rule,
        violation: phiCheck.violation,
        detail: phiCheck.detail,
        evidence: options.evidence ?? {},
      };
    }
    return evaluateCheckResult(antiCheatCheck, options);
  }

  // 3. Execution verification mode (Triple-Execution Red-Green-ReRed)
  return verifyExecutionAttempt(options);
}

/**
 * Checks Law 13 Complexity Potential: Delta Phi <= 0 (and strictly < 0 for consolidator).
 */
function checkPhiLaw13(options, fixture = {}) {
  const phiBase =
    options.phiBefore ??
    options.phi_base ??
    fixture.phi?.phi_base ??
    fixture.phi?.phi_before;
  const phiHead =
    options.phiAfter ??
    options.phi_head ??
    fixture.phi?.phi_head ??
    fixture.phi?.phi_after;

  let deltaPhi =
    options.deltaPhi ??
    options.delta_phi ??
    fixture.phi?.delta_phi;

  if (deltaPhi === undefined && phiBase !== undefined && phiHead !== undefined) {
    deltaPhi = phiHead - phiBase;
  }

  const author =
    options.author ??
    options.role ??
    fixture.pr?.author ??
    fixture.author ??
    "";
  const isConsolidator = String(author).toLowerCase().includes("consolidator");

  if (deltaPhi !== undefined && Number.isSafeInteger(deltaPhi)) {
    if (deltaPhi > 0) {
      return {
        ok: false,
        rule: "LAW_13_PHI_INCREASE",
        violation: "PHI_INCREASED",
        verdict: "reject",
        detail: `Law 13 invariant violation: complexity potential increased (\u0394\u03a6 = +${deltaPhi} > 0).`,
      };
    }
    if (isConsolidator && deltaPhi >= 0) {
      return {
        ok: false,
        rule: "LAW_13_CONSOLIDATOR_PHI",
        violation: "CONSOLIDATOR_PHI_NOT_DECREASED",
        verdict: "reject",
        detail: `Law 13 invariant violation: consolidator role requires strictly decreasing complexity potential (\u0394\u03a6 must be < 0, got ${deltaPhi}).`,
      };
    }
  }

  return { ok: true };
}

/**
 * Verifies a PR/Outcome fixture file.
 */
function verifyFixture(fixtureInput) {
  let fixture;
  if (typeof fixtureInput === "string") {
    const fullPath = resolve(fixtureInput);
    if (!existsSync(fullPath)) {
      throw new Error(`Fixture file not found: ${fullPath}`);
    }
    fixture = JSON.parse(readFileSync(fullPath, "utf8"));
  } else if (typeof fixtureInput === "object" && fixtureInput !== null) {
    fixture = fixtureInput;
  } else {
    throw new TypeError("Invalid fixture parameter");
  }

  const antiCheatCheck = checkAntiCheat(fixture);
  if (!antiCheatCheck.ok) {
    return evaluateCheckResult(antiCheatCheck, fixture);
  }

  const phiCheck = checkPhiLaw13(fixture, fixture);
  if (!phiCheck.ok) {
    return {
      verified: false,
      verdict: phiCheck.verdict,
      rule: phiCheck.rule,
      violation: phiCheck.violation,
      detail: phiCheck.detail,
      evidence: fixture.evidence ?? {},
    };
  }

  return evaluateCheckResult(antiCheatCheck, fixture);
}

/**
 * Formats the evaluation result according to the Law 10 specification.
 * Enforces fail-closed proof validation.
 */
function evaluateCheckResult(check, fixture = {}) {
  if (check.ok) {
    // Fail closed: proof must be present
    // C1: causal proof STRICTLY requires proof.causal_cycle_completed === true.
    // A self-reported `suite_pass_head` is not causal evidence of a fix and
    // must never substitute for the completed Red-Green-ReRed cycle.
    const proof = fixture.proof;
    const hasProof =
      proof &&
      typeof proof === "object" &&
      proof.causal_cycle_completed === true;

    if (!hasProof) {
      return {
        verified: false,
        verdict: "reject",
        rule: "MISSING_PROOF",
        violation: "MISSING_PROOF",
        detail: "Fail closed: proof is missing or incomplete in verification target.",
        evidence: fixture.evidence ?? {},
      };
    }

    // Phase 0.2: a fixture or doc carries a self-reported proof. It can pass
    // conformance, never verification; auto_merge comes only from git mode.
    return {
      verified: false,
      verdict: "conformance_pass",
      rule: "MP-000",
      violation: null,
      detail: "Self-reported proof satisfies every rule; not measured, so not verified.",
      evidence: fixture.evidence ?? {},
      proof: fixture.proof,
      phi: fixture.phi ?? {},
    };
  }

  return {
    verified: false,
    verdict: check.verdict ?? "reject",
    rule: check.rule,
    violation: check.violation,
    detail: check.detail,
    evidence: fixture.evidence ?? {},
    flags: check.flags ?? [],
  };
}

/**
 * Executes the Triple-Execution Red-Green-ReRed sequence against a real git repository.
 *
 * H2 (isolation): the triple-run NEVER executes in the live working tree.
 * A disposable `git worktree` is created under the OS temp directory
 * (`mirql-verify-wt-*`) and every checkout/test command runs inside it, so
 * the user's checked-out branch and any uncommitted/untracked files are
 * completely untouched. The worktree is force-removed in a `finally` block.
 *
 * H3 (env sanitization): candidate runner commands are spawned with the
 * sanitized environment from `sanitizeAgentEnv` — MIRQL_HUMAN_KEY, AI
 * provider API keys, and every other non-allowlisted variable are stripped
 * from child processes; only safe variables (PATH, NODE_ENV, SystemRoot,
 * TEMP, ...) survive.
 *
 * H5 (anti-cheat wiring): the base..head diff is fed into `checkAntiCheat`
 * before any verdict is returned. A humanOnly path (e.g. CONSTITUTION.md)
 * modified in the diff escalates to `{ verified: false, verdict:
 * "needs_human", rule: "MP-001" }`; deleted test files reject under MP-002;
 * other anti-cheat violations reject or escalate per their rule.
 */
/**
 * Canonical TAP reporter output parser (Phase 3.5).
 */
export function parseTapOutput(output, exitCode) {
  const text = String(output ?? "");
  const hasNotOk = /not ok \d+/i.test(text);
  const hasOk = /ok \d+/i.test(text);
  const hasFailCount = /# fail\s+[1-9]\d*/i.test(text);
  const isCrash = /TypeError|ReferenceError|SyntaxError|RangeError|Cannot find module|MODULE_NOT_FOUND|ERR_MODULE_NOT_FOUND/i.test(text);
  const isAssertion = /AssertionError|ERR_ASSERTION|operator:\s*['"]?[a-zA-Z]+['"]?|expected:\s*/i.test(text);
  const isAssertionFailure = exitCode === 1 && !isCrash && (isAssertion || hasNotOk);
  return {
    exitCode,
    isAssertionFailure,
    isCrash,
    hasNotOk,
    hasOk,
    hasFailCount,
  };
}

/**
 * V8 Coverage line execution mapper (Phase 3.3).
 */
export function checkV8Coverage(coverageDir, workspaceDir, changedLinesPerFile) {
  if (!existsSync(coverageDir)) return { executedChangedLines: false, coveredFiles: [], totalCovered: 0 };
  const coveredFiles = new Set();
  const coveredLinesMap = new Map();

  let covFiles = [];
  try {
    covFiles = readdirSync(coverageDir).filter(f => f.endsWith(".json"));
  } catch {
    return { executedChangedLines: false, coveredFiles: [], totalCovered: 0 };
  }

  for (const covFile of covFiles) {
    try {
      const data = JSON.parse(readFileSync(join(coverageDir, covFile), "utf8"));
      if (!Array.isArray(data.result)) continue;
      for (const entry of data.result) {
        if (!entry.url || !Array.isArray(entry.functions)) continue;
        let filePath = entry.url;
        if (filePath.startsWith("file:///")) {
          try { filePath = fileURLToPath(filePath); } catch { filePath = filePath.slice(8); }
        } else if (filePath.startsWith("file://")) {
          filePath = filePath.slice(7);
        }
        filePath = normalizePath(filePath);

        for (const [targetRel, targetLines] of changedLinesPerFile.entries()) {
          const normTarget = normalizePath(targetRel);
          if (filePath.endsWith(normTarget)) {
            const absPath = join(workspaceDir, targetRel);
            if (!existsSync(absPath)) continue;
            coveredFiles.add(targetRel);
            const srcContent = readFileSync(absPath, "utf8");
            const lineOffsets = [0];
            for (let i = 0; i < srcContent.length; i++) {
              if (srcContent[i] === "\n") lineOffsets.push(i + 1);
            }

            for (const fn of entry.functions) {
              if (!Array.isArray(fn.ranges)) continue;
              for (const range of fn.ranges) {
                if (!range || range.count <= 0) continue;
                for (const lineNum of targetLines) {
                  if (lineNum < 1 || lineNum > lineOffsets.length) continue;
                  const startOffset = lineOffsets[lineNum - 1];
                  const endOffset = lineNum < lineOffsets.length ? lineOffsets[lineNum] - 1 : srcContent.length;
                  if (Math.max(range.startOffset, startOffset) < Math.min(range.endOffset, endOffset)) {
                    if (!coveredLinesMap.has(targetRel)) coveredLinesMap.set(targetRel, new Set());
                    coveredLinesMap.get(targetRel).add(lineNum);
                  }
                }
              }
            }
          }
        }
      }
    } catch {}
  }

  let totalCovered = 0;
  for (const set of coveredLinesMap.values()) totalCovered += set.size;
  return {
    executedChangedLines: totalCovered > 0,
    coveredFiles: [...coveredFiles],
    coveredLinesMap: Object.fromEntries([...coveredLinesMap.entries()].map(([k, v]) => [k, [...v]])),
    totalCovered,
  };
}

/**
 * Executes honest causal proof against a real git repository (Phase 3).
 */
function verifyGitRepository(options) {
  const repoDir = options.workspaceDir ?? options.repoDir ?? process.cwd();
  const baseRef = options.baseCommit ?? options.baseSha ?? "HEAD~1";
  const headRef = options.headCommit ?? options.headSha ?? "HEAD";

  function git(args, cwd = repoDir) {
    return spawnSync("git", args, { cwd, encoding: "utf8", timeout: 30000 });
  }

  function runCmd(cmd, cwd = repoDir, extraEnv = {}) {
    const { env: cleanEnv } = sanitizeAgentEnv(process.env);
    const res = spawnSync(cmd, {
      shell: true,
      cwd,
      env: { ...cleanEnv, ...extraEnv },
      encoding: "utf8",
      timeout: 30000,
    });
    let code = res.status;
    if (res.signal) code = 128 + 15;
    else if (code === null || code === undefined) code = 1;
    return { exitCode: code, stdout: res.stdout, stderr: res.stderr };
  }

  const resolveCommit = (ref) => {
    const res = git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
    return res.error || res.status !== 0 ? null : res.stdout.trim();
  };
  const baseSha = resolveCommit(baseRef);
  const headSha = resolveCommit(headRef);
  if (baseSha === null || headSha === null) {
    const bad = baseSha === null ? baseRef : headRef;
    return {
      verified: false,
      verdict: "reject",
      rule: "GIT_DIFF_FAILED",
      violation: "GIT_DIFF_FAILED",
      detail: `cannot resolve ${JSON.stringify(bad)} to a commit in ${repoDir}`,
    };
  }

  const diffRes = git(["diff", "--name-status", baseSha, headSha]);
  if (diffRes.error || diffRes.status !== 0) {
    return {
      verified: false,
      verdict: "reject",
      rule: "GIT_DIFF_FAILED",
      violation: "GIT_DIFF_FAILED",
      detail: `git diff ${baseSha}..${headSha} failed in ${repoDir}: ${
        diffRes.stderr ?? diffRes.error?.message ?? "unknown git error"
      }`,
    };
  }

  const changeEntries = [];
  for (const line of diffRes.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    const parts = trimmed.split("\t");
    if (parts.length < 2 || !/^[A-Z]+\d*$/.test(parts[0])) continue;
    const status = parts[0][0];
    if (status === "R" || status === "C") {
      changeEntries.push({ status: "A", path: parts[parts.length - 1] });
    } else {
      changeEntries.push({ status, path: parts[1] });
    }
  }

  const allChanged = changeEntries.map((e) => e.path);
  const deletedTests = changeEntries
    .filter((e) => e.status === "D" && isTestFilePath(e.path))
    .map((e) => e.path);

  const antiCheatCheck = checkAntiCheat({
    diff_stat: { files_changed: allChanged },
    evidence: {
      tests_deleted: deletedTests,
      ...(deletedTests.length > 0
        ? { detail: `Git diff deletes test file(s): ${deletedTests.join(", ")}` }
        : {}),
    },
  });

  if (!antiCheatCheck.ok) {
    return {
      verified: false,
      verdict:
        antiCheatCheck.rule === "MP-001"
          ? "needs_human"
          : (antiCheatCheck.verdict ?? "reject"),
      rule: antiCheatCheck.rule,
      violation: antiCheatCheck.violation,
      detail: antiCheatCheck.detail,
      flags: antiCheatCheck.flags ?? [],
      checks: { anti_cheat: { passed: false, violations_count: 1 } },
    };
  }

  const testFiles = allChanged.filter(isTestFilePath);
  const nonTestFiles = allChanged.filter((f) => !isTestFilePath(f));
  const nonTestSourceFiles = nonTestFiles.filter((f) => /\.(?:[cm]?[jt]s|jsx|tsx)$/i.test(f));

  // Cap non-test files to 10 for surgical causal verification; >10 escalates to human review
  if (nonTestFiles.length > 10) {
    return {
      verified: false,
      verdict: "needs_human",
      rule: "TOO_MANY_CHANGED_FILES",
      violation: "TOO_MANY_CHANGED_FILES",
      detail: `Candidate modifies ${nonTestFiles.length} non-test files (cap is 10); requires human review.`,
    };
  }

  // Determine reproducer test file (Phase 3.2 Anti-tautology exploit prevention)
  let reproducerFile = null;
  let reproducerCmd = null;

  if (options.reproducerFile) {
    if (!testFiles.includes(options.reproducerFile) && !options.fixture && !options.conformance) {
      return {
        verified: false,
        verdict: "reject",
        rule: "REPRODUCER_NOT_IN_DIFF",
        violation: "REPRODUCER_NOT_IN_DIFF",
        detail: `Specified reproducer ${options.reproducerFile} was not added or modified in the candidate diff.`,
      };
    }
    reproducerFile = options.reproducerFile;
  } else if (typeof options.reproducerCommand === "string") {
    const m = options.reproducerCommand.match(/node\s+(?:--test\s+)?(\S+)/);
    if (m && testFiles.includes(m[1])) {
      reproducerFile = m[1];
    } else if (options.fixture || options.conformance) {
      reproducerCmd = options.reproducerCommand;
    } else if (testFiles.length > 0) {
      reproducerFile = testFiles[0];
    } else if (options.allowNoTests || options.warrantClass === "refactor" || options.warrantClass === "consolidation") {
      reproducerFile = null;
    } else {
      return {
        verified: false,
        verdict: "reject",
        rule: "REPRODUCER_NOT_IN_DIFF",
        violation: "REPRODUCER_NOT_IN_DIFF",
        detail: "Caller-supplied reproducer command does not correspond to a test file in the candidate diff.",
      };
    }
  } else if (testFiles.length > 0) {
    reproducerFile = testFiles[0];
  } else if (!options.allowNoTests && options.warrantClass !== "refactor" && options.warrantClass !== "consolidation") {
    return {
      verified: false,
      verdict: "reject",
      rule: "NO_REPRODUCER_TEST",
      violation: "NO_REPRODUCER_TEST",
      detail: "Candidate diff contains no added or modified test files to verify causal proof.",
    };
  }

  if (reproducerFile) {
    reproducerCmd = `"${process.execPath}" --test --test-reporter=tap ${reproducerFile}`;
  } else if (!reproducerCmd) {
    reproducerCmd = options.reproducerCommand ?? "npm test";
  }

  let worktreeDir = null;
  let covDir = null;
  try {
    worktreeDir = mkdtempSync(join(tmpdir(), "mirql-verify-wt-"));
    const addRes = git(["worktree", "add", "--detach", worktreeDir, headSha]);
    if (addRes.error || addRes.status !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "WORKTREE_SETUP_FAILED",
        violation: "WORKTREE_SETUP_FAILED",
        detail: `Failed to create disposable verification worktree at ${worktreeDir}: ${
          addRes.stderr ?? addRes.error?.message ?? "unknown git error"
        }`,
      };
    }

    const gitWt = (args) => git(args, worktreeDir);

    const checkout = (args) => {
      const res = gitWt(["checkout", ...args]);
      if (res.error || res.status !== 0) {
        return {
          verified: false,
          verdict: "reject",
          rule: "CHECKOUT_FAILED",
          violation: "CHECKOUT_FAILED",
          detail: `git checkout ${args.join(" ")} failed in the verification worktree: ${
            res.stderr || res.error?.message || "unknown git error"
          }`,
        };
      }
      return null;
    };

    const checkoutBaseWithHeadTests = () =>
      checkout([baseSha, "--force"]) ??
      (testFiles.length > 0 ? checkout([headSha, "--", ...testFiles]) : null);

    // 1. Red on Base: base code with the head reproducer test(s) retained.
    // Phase 3.8: Determinism Sentinel (run Red twice).
    const redCheckout = checkoutBaseWithHeadTests();
    if (redCheckout !== null) return redCheckout;

    const redRes1 = runCmd(reproducerCmd, worktreeDir);
    const redRes2 = runCmd(reproducerCmd, worktreeDir);

    if (redRes1.exitCode !== redRes2.exitCode) {
      return {
        verified: false,
        verdict: "reject",
        rule: "FLAKY_REPRODUCER",
        violation: "FLAKY_REPRODUCER",
        detail: `Red-on-base reproducer is non-deterministic (run 1: exit ${redRes1.exitCode}, run 2: exit ${redRes2.exitCode}).`,
        checks: {
          red_on_base: { passed: false, exitCode1: redRes1.exitCode, exitCode2: redRes2.exitCode },
        },
      };
    }

    if (!Number.isInteger(redRes1.exitCode)) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_INTEGER_EXIT_CODE",
        violation: "NON_INTEGER_EXIT_CODE",
        detail: "Red-on-base reproducer returned non-integer exit code.",
      };
    }

    if (redRes1.exitCode === 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RED_ON_BASE_FAILED",
        violation: "RED_ON_BASE_FAILED",
        detail: `Reproducer passed on base commit (must fail on base). stdout: ${redRes1.stdout}, stderr: ${redRes1.stderr}`,
        checks: { red_on_base: { passed: false, exitCode: redRes1.exitCode } },
      };
    }

    const tapRed = parseTapOutput(redRes1.stdout + "\n" + redRes1.stderr, redRes1.exitCode);
    if (!tapRed.isAssertionFailure) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RED_ON_BASE_CRASH",
        violation: "RED_ON_BASE_CRASH",
        detail: `Reproducer crashed on base with exit code ${redRes1.exitCode}; assertion failure (exit 1) required.`,
        checks: { red_on_base: { passed: false, exitCode: redRes1.exitCode, isCrash: tapRed.isCrash } },
      };
    }

    // 2. Green on Head: full head state.
    // Phase 3.3: Run with V8 Coverage.
    const greenCheckout = checkout([headSha, "--force"]);
    if (greenCheckout !== null) return greenCheckout;

    covDir = mkdtempSync(join(tmpdir(), "mirql-v8cov-"));
    const greenRes1 = runCmd(reproducerCmd, worktreeDir, { NODE_V8_COVERAGE: covDir });

    if (!Number.isInteger(greenRes1.exitCode) || greenRes1.exitCode !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "GREEN_ON_HEAD_FAILED",
        violation: "GREEN_ON_HEAD_FAILED",
        detail: `Reproducer failed on head commit (exit ${greenRes1.exitCode}; exit 0 required).`,
        checks: {
          red_on_base: { passed: true, exitCode: 1, runs: 2 },
          green_on_head: { passed: false, exitCode: greenRes1.exitCode },
        },
      };
    }

    // Phase 3.8: Determinism Sentinel (repeat Green).
    const greenRes2 = runCmd(reproducerCmd, worktreeDir);
    if (!Number.isInteger(greenRes2.exitCode) || greenRes2.exitCode !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_DETERMINISTIC_TEST",
        violation: "NON_DETERMINISTIC_TEST",
        detail: "Flake sentinel: reproducer passed initially on head but failed on repetition (non-deterministic outcome).",
        checks: {
          red_on_base: { passed: true, exitCode: 1, runs: 2 },
          green_on_head: { passed: true, exitCode: 0 },
          flake_sentinel: { passed: false, exitCode: greenRes2.exitCode },
        },
      };
    }

    // Phase 3.4: Full Test Suite
    const hasPackageJson = existsSync(join(worktreeDir, "package.json"));
    const fullTestCmd = options.testCommand ?? (hasPackageJson ? "npm test" : reproducerCmd);
    const fullRes = runCmd(fullTestCmd, worktreeDir);
    if (!Number.isInteger(fullRes.exitCode) || fullRes.exitCode !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "GREEN_ON_HEAD_FAILED",
        violation: "GREEN_ON_HEAD_FAILED",
        detail: `Full test suite failed on head commit (exit ${fullRes.exitCode}; exit 0 required).`,
        checks: {
          red_on_base: { passed: true, exitCode: 1, runs: 2 },
          green_on_head: { passed: true, exitCode: 0, runs: 2 },
          full_suite: { passed: false, exitCode: fullRes.exitCode },
        },
      };
    }

    // Phase 3.3: V8 Coverage Analysis
    const changedLinesMap = new Map();
    for (const f of nonTestSourceFiles) {
      const diffOut = gitWt(["diff", "-U0", baseSha, headSha, "--", f]);
      if (diffOut.status === 0 && diffOut.stdout) {
        changedLinesMap.set(f, extractChangedLines(diffOut.stdout));
      }
    }

    let coverageReport = null;
    if (nonTestSourceFiles.length > 0) {
      coverageReport = checkV8Coverage(covDir, worktreeDir, changedLinesMap);
      let totalChangedLines = 0;
      for (const set of changedLinesMap.values()) totalChangedLines += set.size;

      if (totalChangedLines > 0 && !coverageReport.executedChangedLines) {
        return {
          verified: false,
          verdict: "reject",
          rule: "REPRODUCER_IRRELEVANT",
          violation: "REPRODUCER_IRRELEVANT",
          detail: "Reproducer executed zero modified lines in the changed source files.",
          checks: {
            red_on_base: { passed: true, exitCode: 1, runs: 2 },
            green_on_head: { passed: true, exitCode: 0, runs: 2 },
            coverage: { passed: false, covered_files: coverageReport.coveredFiles },
          },
        };
      }
    }

    // Phase 3.1: Necessity Check (replacing Re-Red)
    const necessaryFiles = [];
    const unnecessaryFiles = [];

    for (const f of nonTestFiles) {
      const revCheck = checkout([baseSha, "--", f]);
      if (revCheck !== null) return revCheck;

      const revRes = runCmd(reproducerCmd, worktreeDir);
      const tapRev = parseTapOutput(revRes.stdout + "\n" + revRes.stderr, revRes.exitCode);

      if (tapRev.isAssertionFailure) {
        necessaryFiles.push(f);
      } else {
        unnecessaryFiles.push(f);
      }

      const restCheck = checkout([headSha, "--", f]);
      if (restCheck !== null) return restCheck;
    }

    if (nonTestFiles.length > 0 && necessaryFiles.length === 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RE_RED_FAILED",
        violation: "RE_RED_FAILED",
        detail: "Necessity check failed: reproducer still passed when each non-test file was reverted (tautological or disconnected test).",
        checks: {
          red_on_base: { passed: true, exitCode: 1, runs: 2 },
          green_on_head: { passed: true, exitCode: 0, runs: 2 },
          necessity_check: {
            passed: false,
            tested_files: nonTestFiles,
            necessary_files: [],
            unnecessary_files: unnecessaryFiles,
          },
        },
      };
    }

    if (unnecessaryFiles.length > 0 && (options.warrantClass === "surgical" || options.surgical === true)) {
      return {
        verified: false,
        verdict: "reject",
        rule: "UNNECESSARY_CHANGE",
        violation: "UNNECESSARY_CHANGE",
        detail: `Surgical warrant violated: unnecessary changed files detected: ${unnecessaryFiles.join(", ")}`,
        checks: {
          red_on_base: { passed: true, exitCode: 1, runs: 2 },
          green_on_head: { passed: true, exitCode: 0, runs: 2 },
          necessity_check: {
            passed: false,
            tested_files: nonTestFiles,
            necessary_files: necessaryFiles,
            unnecessary_files: unnecessaryFiles,
          },
        },
      };
    }

    return {
      verified: true,
      verdict: "auto_merge",
      rule: "MP-000",
      proof: {
        causal_cycle_completed: true,
        base_fail_runs: 2,
        head_pass_runs: 2,
        full_suite_passed: true,
        reproducer_relevant: coverageReport ? coverageReport.executedChangedLines : true,
        necessity_check: {
          tested_files: nonTestFiles,
          necessary_files: necessaryFiles,
          unnecessary_files: unnecessaryFiles,
        },
      },
      checks: {
        red_on_base: { passed: true, exitCode: 1, runs: 2 },
        green_on_head: { passed: true, exitCode: 0, runs: 2 },
        necessity_check: {
          passed: nonTestFiles.length === 0 || necessaryFiles.length > 0,
          necessary_count: necessaryFiles.length,
          unnecessary_count: unnecessaryFiles.length,
        },
        anti_cheat: { passed: true, violations_count: 0 },
      },
    };
  } finally {
    if (covDir !== null) {
      try { rmSync(covDir, { recursive: true, force: true }); } catch {}
    }
    if (worktreeDir !== null) {
      try { git(["worktree", "remove", "--force", worktreeDir]); } catch {}
      try { rmSync(worktreeDir, { recursive: true, force: true }); } catch {}
    }
  }
}

/**
 * Executes or evaluates the Triple-Execution Red-Green-ReRed sequence.
 */
function verifyExecutionAttempt(options = {}) {
  // A. AST & Anti-Cheat gate first
  if (Array.isArray(options.modifiedFiles) && options.modifiedFiles.length > 0) {
    const humanCheck = checkHumanOnlyPaths(options.modifiedFiles);
    if (!humanCheck.ok) {
      return {
        verified: false,
        verdict: "reject",
        rule: "MP-001",
        violation: "TOUCH_HUMAN_ONLY",
        detail: `Modified forbidden humanOnly path(s): ${humanCheck.forbidden.join(", ")}`,
      };
    }
  }

  if (typeof options.sourceCode === "string") {
    const catchCheck = checkSwallowedExceptions(options.sourceCode);
    if (!catchCheck.ok) {
      return {
        verified: false,
        verdict: "reject",
        rule: "MP-003",
        violation: "ANTI_CHEAT_VIOLATION",
        detail: "Source contains empty catch block swallowing exceptions.",
      };
    }

    const weakenCheck = checkTestWeakenings(options.sourceCode);
    if (!weakenCheck.ok) {
      return {
        verified: false,
        verdict: "reject",
        rule: "MP-002",
        violation: "TEST_DELETED",
        detail: "Test weakenings (skipped/only/todo tests) detected.",
      };
    }
  } else if (
    typeof options.sourceCode === "object" &&
    options.sourceCode !== null
  ) {
    for (const [file, code] of Object.entries(options.sourceCode)) {
      const catchCheck = checkSwallowedExceptions(code, file);
      if (!catchCheck.ok) {
        return {
          verified: false,
          verdict: "reject",
          rule: "MP-003",
          violation: "ANTI_CHEAT_VIOLATION",
          detail: `Empty catch block in ${file}`,
        };
      }
      const weakenCheck = checkTestWeakenings(code, file);
      if (!weakenCheck.ok) {
        return {
          verified: false,
          verdict: "reject",
          rule: "MP-002",
          violation: "TEST_DELETED",
          detail: `Skipped/weakened tests in ${file}`,
        };
      }
    }
  }

  // B. Law 13: Phi Gate
  const phiCheck = checkPhiLaw13(options);
  if (!phiCheck.ok) {
    return {
      verified: false,
      verdict: phiCheck.verdict,
      rule: phiCheck.rule,
      violation: phiCheck.violation,
      detail: phiCheck.detail,
    };
  }

  // C. Git-based execution verification mode
  if (options.git === true || (options.workspaceDir && options.baseSha && !options.runCheck)) {
    return verifyGitRepository(options);
  }

  // D. Execution verification stages via runCheck callback (Phase 3.7: unified pipeline)
  if (typeof options.runCheck === "function") {
    const runCheck = options.runCheck;
    const step = (stage) => runCheck({ stage });
    const checkRed = (base) => {
      if (!base || base.exitCode === null || !Number.isInteger(base.exitCode)) {
        return {
          verified: false,
          verdict: "reject",
          rule: "NON_INTEGER_EXIT_CODE",
          violation: "NON_INTEGER_EXIT_CODE",
          detail: "Red-on-base check returned null or non-integer exit code.",
        };
      }
      if (base.exitCode === 0) {
        return {
          verified: false,
          verdict: "reject",
          rule: "RED_ON_BASE_FAILED",
          violation: "RED_ON_BASE_FAILED",
          detail: "Reproducer passed on base commit (must fail on base).",
          checks: { red_on_base: { passed: false, exitCode: base.exitCode } },
        };
      }
      if (base.exitCode !== 1) {
        return {
          verified: false,
          verdict: "reject",
          rule: "RED_ON_BASE_CRASH",
          violation: "RED_ON_BASE_CRASH",
          detail: `A crash on base is not a valid red: exit code ${base.exitCode} (assertion failure exit 1 required).`,
          checks: { red_on_base: { passed: false, exitCode: base.exitCode } },
        };
      }
      return null;
    };
    const checkHead = (base, head) => {
      if (!head || head.exitCode === null || !Number.isInteger(head.exitCode) || head.exitCode !== 0) {
        return {
          verified: false,
          verdict: "reject",
          rule: "GREEN_ON_HEAD_FAILED",
          violation: "GREEN_ON_HEAD_FAILED",
          detail: "Test suite failed on head commit (must pass on head).",
          checks: {
            red_on_base: { passed: true, exitCode: base.exitCode },
            green_on_head: { passed: false, exitCode: head?.exitCode },
          },
        };
      }
      return null;
    };
    const checkReRed = (base, head, reRed) => {
      if (!reRed || reRed.exitCode === null || !Number.isInteger(reRed.exitCode)) {
        return {
          verified: false,
          verdict: "reject",
          rule: "NON_INTEGER_EXIT_CODE",
          violation: "NON_INTEGER_EXIT_CODE",
          detail: "Re-red check returned null or non-integer exit code.",
        };
      }
      if (reRed.exitCode === 0) {
        return {
          verified: false,
          verdict: "reject",
          rule: "RE_RED_FAILED",
          violation: "RE_RED_FAILED",
          detail: "Re-red patch-reversal check failed: reproducer still passed when src/ was reverted (tautological test).",
          checks: {
            red_on_base: { passed: true, exitCode: base.exitCode },
            green_on_head: { passed: true, exitCode: head.exitCode },
            re_red_on_revert: { passed: false, exitCode: reRed.exitCode },
          },
        };
      }
      if (reRed.exitCode !== 1) {
        return {
          verified: false,
          verdict: "reject",
          rule: "RE_RED_FAILED",
          violation: "RE_RED_FAILED",
          detail: `Re-red reproducer did not fail with test assertion failure (exit 1, got ${reRed.exitCode}).`,
          checks: {
            red_on_base: { passed: true, exitCode: base.exitCode },
            green_on_head: { passed: true, exitCode: head.exitCode },
            re_red_on_revert: { passed: false, exitCode: reRed.exitCode },
          },
        };
      }
      return null;
    };
    const success = (base, head, reRed) => ({
      verified: true,
      verdict: "auto_merge",
      rule: "MP-000",
      proof: {
        causal_cycle_completed: true,
        base_fail_runs: 1,
        head_pass_runs: 1,
        re_red_runs: 1,
      },
      checks: {
        red_on_base: { passed: true, exitCode: base.exitCode },
        green_on_head: { passed: true, exitCode: head.exitCode },
        re_red_on_revert: { passed: true, exitCode: reRed.exitCode },
        anti_cheat: { passed: true, violations_count: 0 },
      },
    });

    const firstResult = step("red_on_base");
    if (firstResult && typeof firstResult.then === "function") {
      return (async () => {
        const base = await firstResult;
        const errBase = checkRed(base);
        if (errBase) return errBase;
        const head = await step("green_on_head");
        const errHead = checkHead(base, head);
        if (errHead) return errHead;
        const reRed = await step("re_red_on_revert");
        const errReRed = checkReRed(base, head, reRed);
        if (errReRed) return errReRed;
        return success(base, head, reRed);
      })();
    }

    const errBase = checkRed(firstResult);
    if (errBase) return errBase;
    const head = step("green_on_head");
    const errHead = checkHead(firstResult, head);
    if (errHead) return errHead;
    const reRed = step("re_red_on_revert");
    const errReRed = checkReRed(firstResult, head, reRed);
    if (errReRed) return errReRed;
    return success(firstResult, head, reRed);
  }

  // B1: Fail closed if no runner/callback or proof is provided!
  return {
    verified: false,
    verdict: "reject",
    rule: "MISSING_RUNNER",
    violation: "MISSING_RUNNER",
    detail: "Fail closed: No callback/runner or valid verification proof provided.",
  };
}
