import { readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { EXIT_CODES } from "../core/index.mjs";
import { sanitizeAgentEnv } from "./agent.mjs";
import {
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "./anti-cheat.mjs";
import { evaluatePhiGate } from "./phi.mjs";

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

    return {
      verified: true,
      verdict: "auto_merge",
      rule: "MP-000",
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
function verifyGitRepository(options) {
  const repoDir = options.workspaceDir ?? options.repoDir ?? process.cwd();
  const baseSha = options.baseCommit ?? options.baseSha ?? "HEAD~1";
  const headSha = options.headCommit ?? options.headSha ?? "HEAD";
  const reproducerCmd = options.reproducerCommand ?? options.reproducer ?? "npm test";
  const fullTestCmd = options.testCommand ?? reproducerCmd;

  function git(args, cwd = repoDir) {
    return spawnSync("git", args, { cwd, encoding: "utf8", timeout: 30000 });
  }

  function runCmd(cmd, cwd = repoDir) {
    // H3: never inherit the full process environment — strip secrets.
    const { env: cleanEnv } = sanitizeAgentEnv(process.env);
    const res = spawnSync(cmd, {
      shell: true,
      cwd,
      env: cleanEnv,
      encoding: "utf8",
      timeout: 30000,
    });
    let code = res.status;
    if (res.signal) code = 128 + 15;
    else if (code === null || code === undefined) code = 1;
    return { exitCode: code, stdout: res.stdout, stderr: res.stderr };
  }

  const isTestPath = (f) => /test|spec/i.test(f) || f.startsWith("tests/");

  // Identify files changed between base and head, including change status
  // (H5: deletions of test files must be detectable for MP-002).
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
      // Rename/copy: the surviving (destination) path is the changed file.
      changeEntries.push({ status: "A", path: parts[parts.length - 1] });
    } else {
      changeEntries.push({ status, path: parts[1] });
    }
  }

  const allChanged = changeEntries.map((e) => e.path);
  const deletedTests = changeEntries
    .filter((e) => e.status === "D" && isTestPath(e.path))
    .map((e) => e.path);

  // H5: anti-cheat gate over the git diff BEFORE running the triple-execution.
  const antiCheatCheck = checkAntiCheat({
    diff_stat: { files_changed: allChanged },
    evidence: {
      tests_deleted: deletedTests,
      ...(deletedTests.length > 0
        ? { detail: `Git diff deletes test file(s): ${deletedTests.join(", ")}` }
        : {}),
    },
    human_approved: options.humanApproved === true || options.human_approval === true,
  });

  if (!antiCheatCheck.ok) {
    return {
      verified: false,
      // H5: touching a humanOnly path in a git diff escalates to a human.
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

  const testFiles = allChanged.filter((f) => isTestPath(f));

  // H2: everything below runs inside a disposable worktree — the live
  // working tree of `repoDir` is never checked out, reset, or touched.
  let worktreeDir = null;
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

    // 1. Red on Base: base code with the head reproducer tests retained
    gitWt(["checkout", baseSha, "--force"]);
    if (testFiles.length > 0) {
      gitWt(["checkout", headSha, "--", ...testFiles]);
    }
    const redRes = runCmd(reproducerCmd, worktreeDir);
    if (!Number.isInteger(redRes.exitCode)) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_INTEGER_EXIT_CODE",
        violation: "NON_INTEGER_EXIT_CODE",
        detail: "Red-on-base reproducer returned non-integer exit code.",
      };
    }
    if (redRes.exitCode === 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RED_ON_BASE_FAILED",
        violation: "RED_ON_BASE_FAILED",
        detail: `Reproducer passed on base commit (must fail on base). stdout: ${redRes.stdout}, stderr: ${redRes.stderr}`,
        checks: { red_on_base: { passed: false, exitCode: redRes.exitCode } },
      };
    }
    if (redRes.exitCode !== 1) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RED_ON_BASE_CRASH",
        violation: "RED_ON_BASE_CRASH",
        detail: `Reproducer crashed on base with exit code ${redRes.exitCode}; assertion failure (exit 1) required.`,
        checks: { red_on_base: { passed: false, exitCode: redRes.exitCode } },
      };
    }

    // 2. Green on Head: full head state
    gitWt(["checkout", headSha, "--force"]);
    const greenRes = runCmd(fullTestCmd, worktreeDir);
    if (!Number.isInteger(greenRes.exitCode) || greenRes.exitCode !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "GREEN_ON_HEAD_FAILED",
        violation: "GREEN_ON_HEAD_FAILED",
        detail: "Full test suite failed on head commit (must pass on head).",
        checks: {
          red_on_base: { passed: true, exitCode: 1 },
          green_on_head: { passed: false, exitCode: greenRes.exitCode },
        },
      };
    }

    // 2b. Flake Sentinel: repeat head test to guarantee determinism (M4 Invariant)
    const flakeRep = runCmd(fullTestCmd, worktreeDir);
    if (!Number.isInteger(flakeRep.exitCode) || flakeRep.exitCode !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_DETERMINISTIC_TEST",
        violation: "NON_DETERMINISTIC_TEST",
        detail: "Flake sentinel: test passed initially on head but failed on repetition (non-deterministic outcome).",
        checks: {
          red_on_base: { passed: true, exitCode: 1 },
          green_on_head: { passed: true, exitCode: 0 },
          flake_sentinel: { passed: false, exitCode: flakeRep.exitCode },
        },
      };
    }

    // 3. Re-Red: revert every non-test change (base code + head tests). A
    // full base checkout handles added AND deleted non-test files correctly.
    gitWt(["checkout", baseSha, "--force"]);
    if (testFiles.length > 0) {
      gitWt(["checkout", headSha, "--", ...testFiles]);
    }
    const reRedRes = runCmd(reproducerCmd, worktreeDir);
    if (!Number.isInteger(reRedRes.exitCode)) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_INTEGER_EXIT_CODE",
        violation: "NON_INTEGER_EXIT_CODE",
        detail: "Re-red reproducer returned non-integer exit code.",
      };
    }
    if (reRedRes.exitCode === 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RE_RED_FAILED",
        violation: "RE_RED_FAILED",
        detail:
          "Re-red patch-reversal check failed: reproducer still passed when src/ was reverted (tautological test).",
        checks: {
          red_on_base: { passed: true, exitCode: 1 },
          green_on_head: { passed: true, exitCode: 0 },
          re_red_on_revert: { passed: false, exitCode: reRedRes.exitCode },
        },
      };
    }
    if (reRedRes.exitCode !== 1) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RE_RED_FAILED",
        violation: "RE_RED_FAILED",
        detail: `Re-red reproducer failed with crash (exit ${reRedRes.exitCode}) instead of test assertion failure (exit 1).`,
        checks: {
          red_on_base: { passed: true, exitCode: 1 },
          green_on_head: { passed: true, exitCode: 0 },
          re_red_on_revert: { passed: false, exitCode: reRedRes.exitCode },
        },
      };
    }

    return {
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
        red_on_base: { passed: true, exitCode: 1 },
        green_on_head: { passed: true, exitCode: 0 },
        re_red_on_revert: { passed: true, exitCode: 1 },
        anti_cheat: { passed: true, violations_count: 0 },
      },
    };
  } finally {
    // H2: always dispose of the disposable worktree. The live working tree
    // was never touched, so no restore checkout is needed.
    if (worktreeDir !== null) {
      try {
        git(["worktree", "remove", "--force", worktreeDir]);
      } catch {}
      try {
        rmSync(worktreeDir, { recursive: true, force: true });
      } catch {}
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

  // D. Execution verification stages via runCheck callback
  if (typeof options.runCheck === "function") {
    const runCheck = options.runCheck;

    const baseResult = runCheck({ stage: "red_on_base" });
    if (baseResult && typeof baseResult.then === "function") {
      return (async () => {
        const base = await baseResult;
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

        const head = await runCheck({ stage: "green_on_head" });
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

        const reRed = await runCheck({ stage: "re_red_on_revert" });
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
            detail:
              "Re-red patch-reversal check failed: reproducer still passed when src/ was reverted (tautological test).",
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

        return {
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
        };
      })();
    }

    // Synchronous execution branch
    if (!baseResult || baseResult.exitCode === null || !Number.isInteger(baseResult.exitCode)) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_INTEGER_EXIT_CODE",
        violation: "NON_INTEGER_EXIT_CODE",
        detail: "Red-on-base check returned null or non-integer exit code.",
      };
    }
    if (baseResult.exitCode === 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RED_ON_BASE_FAILED",
        violation: "RED_ON_BASE_FAILED",
        detail: "Reproducer passed on base commit (must fail on base).",
        checks: {
          red_on_base: { passed: false, exitCode: baseResult.exitCode },
        },
      };
    }
    if (baseResult.exitCode !== 1) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RED_ON_BASE_CRASH",
        violation: "RED_ON_BASE_CRASH",
        detail: `A crash on base is not a valid red: exit code ${baseResult.exitCode} (assertion failure exit 1 required).`,
        checks: {
          red_on_base: { passed: false, exitCode: baseResult.exitCode },
        },
      };
    }

    const headResult = runCheck({ stage: "green_on_head" });
    if (!headResult || headResult.exitCode === null || !Number.isInteger(headResult.exitCode) || headResult.exitCode !== 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "GREEN_ON_HEAD_FAILED",
        violation: "GREEN_ON_HEAD_FAILED",
        detail: "Test suite failed on head commit (must pass on head).",
        checks: {
          red_on_base: { passed: true, exitCode: baseResult.exitCode },
          green_on_head: { passed: false, exitCode: headResult?.exitCode },
        },
      };
    }

    const reRedResult = runCheck({ stage: "re_red_on_revert" });
    if (!reRedResult || reRedResult.exitCode === null || !Number.isInteger(reRedResult.exitCode)) {
      return {
        verified: false,
        verdict: "reject",
        rule: "NON_INTEGER_EXIT_CODE",
        violation: "NON_INTEGER_EXIT_CODE",
        detail: "Re-red check returned null or non-integer exit code.",
      };
    }
    if (reRedResult.exitCode === 0) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RE_RED_FAILED",
        violation: "RE_RED_FAILED",
        detail:
          "Re-red patch-reversal check failed: reproducer still passed when src/ was reverted (tautological test).",
        checks: {
          red_on_base: { passed: true, exitCode: baseResult.exitCode },
          green_on_head: { passed: true, exitCode: headResult.exitCode },
          re_red_on_revert: { passed: false, exitCode: reRedResult.exitCode },
        },
      };
    }
    if (reRedResult.exitCode !== 1) {
      return {
        verified: false,
        verdict: "reject",
        rule: "RE_RED_FAILED",
        violation: "RE_RED_FAILED",
        detail: `Re-red reproducer did not fail with test assertion failure (exit 1, got ${reRedResult.exitCode}).`,
        checks: {
          red_on_base: { passed: true, exitCode: baseResult.exitCode },
          green_on_head: { passed: true, exitCode: headResult.exitCode },
          re_red_on_revert: { passed: false, exitCode: reRedResult.exitCode },
        },
      };
    }

    return {
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
        red_on_base: { passed: true, exitCode: baseResult.exitCode },
        green_on_head: { passed: true, exitCode: headResult.exitCode },
        re_red_on_revert: { passed: true, exitCode: reRedResult.exitCode },
        anti_cheat: { passed: true, violations_count: 0 },
      },
    };
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
