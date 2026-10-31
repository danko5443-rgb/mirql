import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import { EXIT_CODES } from "../core/index.mjs";
import {
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "./anti-cheat.mjs";

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
    const proof = fixture.proof;
    const hasProof =
      proof &&
      typeof proof === "object" &&
      (proof.causal_cycle_completed === true || proof.suite_pass_head === true);

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
 */
function verifyGitRepository(options) {
  const repoDir = options.workspaceDir ?? options.repoDir ?? process.cwd();
  const baseSha = options.baseCommit ?? options.baseSha ?? "HEAD~1";
  const headSha = options.headCommit ?? options.headSha ?? "HEAD";
  const reproducerCmd = options.reproducerCommand ?? options.reproducer ?? "npm test";
  const fullTestCmd = options.testCommand ?? reproducerCmd;

  function git(args) {
    const res = spawnSync("git", args, {
      cwd: repoDir,
      encoding: "utf8",
      timeout: 30000,
    });
    return res;
  }

  function runCmd(cmd) {
    const cleanEnv = { ...process.env };
    for (const k of Object.keys(cleanEnv)) {
      if (k.startsWith("NODE_TEST_")) {
        delete cleanEnv[k];
      }
    }
    const res = spawnSync(cmd, {
      shell: true,
      cwd: repoDir,
      env: cleanEnv,
      encoding: "utf8",
      timeout: 30000,
    });
    let code = res.status;
    if (res.signal) code = 128 + 15;
    else if (code === null || code === undefined) code = 1;
    return { exitCode: code, stdout: res.stdout, stderr: res.stderr };
  }

  // Identify files changed between base and head
  const diffRes = git(["diff", "--name-only", baseSha, headSha]);
  const allChanged = diffRes.stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const testFiles = allChanged.filter(
    (f) => /test|spec/i.test(f) || f.startsWith("tests/"),
  );
  const nonTestFiles = allChanged.filter(
    (f) => !/test|spec/i.test(f) && !f.startsWith("tests/"),
  );

  try {
    // 1. Red on Base: checkout base code, retain reproducer test from head
    git(["checkout", baseSha, "--force"]);
    if (testFiles.length > 0) {
      git(["checkout", headSha, "--", ...testFiles]);
    }
    const redRes = runCmd(reproducerCmd);
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

    // 2. Green on Head: checkout full head state
    git(["checkout", headSha, "--force"]);
    const greenRes = runCmd(fullTestCmd);
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

    // 3. Re-Red: revert non-test files while keeping test changes
    if (nonTestFiles.length > 0) {
      git(["checkout", baseSha, "--", ...nonTestFiles]);
    }
    const reRedRes = runCmd(reproducerCmd);
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
    git(["checkout", headSha, "--force"]);
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
