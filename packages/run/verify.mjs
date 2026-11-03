import { readFileSync, existsSync, mkdtempSync, rmSync, realpathSync } from "node:fs";
import { resolve, join, dirname, delimiter, relative, isAbsolute, sep } from "node:path";
import { tmpdir, constants as osConstants } from "node:os";
import { spawnSync } from "node:child_process";
import { EXIT_CODES, isTestFilePath } from "../core/index.mjs";
import { sanitizeAgentEnv } from "./agent.mjs";
import {
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "./anti-cheat.mjs";
import { findExactMergeApproval } from "../core/merge-approval.mjs";
import { parsePathPolicies } from "../core/anti-cheat.mjs";
import { measureAuthorizedPhi, recordPhiConsumption } from "./authorized-phi.mjs";
import { requireAuthorizedWarrant } from "../core/warrant.mjs";
import { evaluatePhiGate } from "./phi.mjs";
import { extractChangedLines } from "./mutant.mjs";
import { parseTapOutput, checkV8Coverage } from "./causal-evidence.mjs";
export { parseTapOutput, checkV8Coverage } from "./causal-evidence.mjs";

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
 * Executes honest causal proof against a real git repository (Phase 3).
 */
function verifyGitRepository(options) {
  let repoDir = options.workspaceDir ?? options.repoDir ?? process.cwd();
  const baseRef = options.baseCommit ?? options.baseSha ?? "HEAD~1";
  const headRef = options.headCommit ?? options.headSha ?? "HEAD";

  function git(args, cwd = repoDir) {
    return spawnSync("git", ["--no-replace-objects", "--no-pager", "-c", "core.fsmonitor=false", ...args], { cwd, encoding: "utf8", timeout: 30000, windowsHide: true });
  }

  // Resolve the installed npm CLI outside the candidate before executing it.
  // Searching from its working directory would let a candidate-local npm.cmd win.
  const rootInfo = git(["--no-replace-objects", "rev-parse", "--show-toplevel"]);
  if (rootInfo.error || rootInfo.status !== 0) {
    return { verified: false, verdict: "reject", rule: "GIT_DIFF_FAILED", violation: "GIT_DIFF_FAILED",
      detail: "Cannot resolve the authoritative Git repository root." };
  }
  repoDir = resolve(rootInfo.stdout.replace(/\r?\n$/, ""));
  const npmRepository = repoDir;
  const npmRoots = [dirname(process.execPath), ...(process.env.PATH ?? process.env.Path ?? "").split(delimiter).filter(isAbsolute)];
  const npmCandidates = npmRoots.flatMap(root => [
    join(root, "node_modules", "npm", "bin", "npm-cli.js"),
    join(root, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
    join(root, "npm"),
  ]);
  let npmCli = null;
  for (const candidate of npmCandidates) {
    try {
      const path = realpathSync(candidate);
      const fromRepo = relative(npmRepository, path);
      if (path.endsWith(sep + "npm-cli.js") &&
          (isAbsolute(fromRepo) || fromRepo === ".." || fromRepo.startsWith(".." + sep))) {
        npmCli = path;
        break;
      }
    } catch { continue; } // A missing installation candidate supplies no runner.
  }

  // Only explicit conformance commands use a shell.
  // A reproducer filename is always passed as one argument to the Node runner.
  function runCommand(command, args, cwd, extraEnv = {}) {
    const { env: cleanEnv } = sanitizeAgentEnv(process.env);
    const spawnOptions = {
      shell: args === null, cwd, env: { ...cleanEnv, ...extraEnv },
      encoding: "utf8", timeout: 30000, windowsHide: true,
    };
    const res = args === null
      ? spawnSync(command, spawnOptions)
      : spawnSync(command, args, spawnOptions);
    const code = res.signal ? 128 + (osConstants.signals[res.signal] ?? 1) : res.status;
    return { exitCode: code, stdout: res.stdout ?? "", stderr: res.stderr ?? "",
      timedOut: res.error?.code === "ETIMEDOUT" };
  }

  const resolveCommit = (ref) => {
    const res = git(["rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`]);
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

  const diffRes = git(["diff", "--no-relative", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-status", "-z", baseSha, headSha, "--"]);
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
  const fields = diffRes.stdout.split("\0");
  if (fields.at(-1) === "") fields.pop();
  if (fields.length % 2 !== 0) {
    return { verified: false, verdict: "reject", rule: "GIT_DIFF_FAILED", violation: "GIT_DIFF_FAILED",
      detail: "Malformed NUL-delimited Git path measurement." };
  }
  for (let i = 0; i < fields.length; i += 2) {
    if (!/^[A-Z]$/.test(fields[i]) || !fields[i+1]) {
      return { verified: false, verdict: "reject", rule: "GIT_DIFF_FAILED", violation: "GIT_DIFF_FAILED",
        detail: "Invalid measured Git change entry." };
    }
    changeEntries.push({ status: fields[i], path: fields[i+1] });
  }
  const policyEntry = git(["ls-tree", "-z", baseSha, "--", "policy/paths.yaml"]);
  let policyText = "";
  if (policyEntry.error || policyEntry.status !== 0 ||
      (policyEntry.stdout && !/^100(?:644|755) blob [a-f0-9]+\tpolicy\/paths\.yaml\0$/.test(policyEntry.stdout))) {
    return { verified: false, verdict: "reject", rule: "POLICY_UNVERIFIED", violation: "POLICY_UNVERIFIED",
      detail: "Cannot read a regular path-policy blob from the base commit." };
  }
  if (policyEntry.stdout) {
    const policy = git(["show", baseSha + ":policy/paths.yaml"]);
    if (policy.error || policy.status !== 0) {
      return { verified: false, verdict: "reject", rule: "POLICY_UNVERIFIED", violation: "POLICY_UNVERIFIED",
        detail: "Cannot read the immutable base path policy." };
    }
    policyText = policy.stdout;
  }
  const policies = parsePathPolicies(policyText);

  const allChanged = changeEntries.map((e) => e.path);
  const deletedTests = changeEntries
    .filter((e) => e.status === "D" && isTestFilePath(e.path))
    .map((e) => e.path);

  let antiCheatCheck = checkAntiCheat({
    diff_stat: { files_changed: allChanged },
    evidence: {
      tests_deleted: deletedTests,
      ...(deletedTests.length > 0
        ? { detail: `Git diff deletes test file(s): ${deletedTests.join(", ")}` }
        : {}),
    },
  }, policies);
  let approvalRecord = null;
  if (antiCheatCheck.rule === "MP-005" && options.mirqlDir && options.warrantId) {
    try {
      approvalRecord = findExactMergeApproval(options.mirqlDir, {
        workspaceDir: repoDir, baseSha, headSha, warrantId: options.warrantId,
      });
      if (approvalRecord) antiCheatCheck = { ok: true, rule: "MP-000", verdict: "auto_merge" };
    } catch {
      // Invalid authority is a closed gate, never permission to continue.
      antiCheatCheck = { ...antiCheatCheck, detail: "The exact owner approval could not be verified." };
    }
  }

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

  const conformance = options.conformance === true;
  let reproducerFile = options.reproducerFile ?? null;
  let conformanceCommand = null;
  if (reproducerFile !== null && !testFiles.includes(reproducerFile)) {
    return { verified: false, verdict: "reject", rule: "REPRODUCER_NOT_IN_DIFF",
      violation: "REPRODUCER_NOT_IN_DIFF", detail: "The reproducer must be an added or modified test file." };
  }
  if (reproducerFile === null) {
    if (conformance && typeof options.reproducerCommand === "string") {
      conformanceCommand = options.reproducerCommand;
    } else if (typeof options.reproducerCommand === "string") {
      // Preserve selection of a canonical legacy path, without executing its command.
      const match = options.reproducerCommand.match(/^node\s+(?:--test\s+)?(\S+)$/);
      reproducerFile = match && testFiles.includes(match[1]) ? match[1] : (testFiles[0] ?? null);
    } else reproducerFile = testFiles[0] ?? null;
  }
  if (reproducerFile === null && conformanceCommand === null) {
    const rule = typeof options.reproducerCommand === "string" ? "REPRODUCER_NOT_IN_DIFF" : "NO_REPRODUCER_TEST";
    return { verified: false, verdict: "reject", rule, violation: rule,
      detail: "Candidate diff contains no added or modified reproducer test file." };
  }
  const runReproducer = (cwd, extraEnv = {}) => reproducerFile !== null
    ? runCommand(process.execPath, ["--test", "--test-reporter=tap", resolve(cwd, reproducerFile)], cwd, extraEnv)
    : runCommand(conformanceCommand, null, cwd, extraEnv);

  let measuredPhi;
  try {
    measuredPhi = measureAuthorizedPhi({ repoDir, baseSha, headSha,
      mirqlDir: options.mirqlDir, warrantId: options.warrantId, conformance });
  } catch (error) {
    const rule = error.code === "WARRANT_UNAUTHORIZED" ? error.code : "PHI_UNMEASURED";
    return { verified: false, verdict: "needs_human", rule, violation: rule,
      detail: "Immutable complexity and its signed authority could not be verified." };
  }
  if (!measuredPhi.ok) return { verified: false, verdict: "reject", rule: measuredPhi.rule,
    violation: "PHI_INCREASED", phi: measuredPhi };

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

    const redRes1 = runReproducer(worktreeDir);
    const redRes2 = runReproducer(worktreeDir);

    const redEvidence1 = parseTapOutput(redRes1.stdout + "\n" + redRes1.stderr, redRes1.exitCode);
    const redEvidence2 = parseTapOutput(redRes2.stdout + "\n" + redRes2.stderr, redRes2.exitCode);
    if (redRes1.exitCode !== redRes2.exitCode ||
        redEvidence1.isAssertionFailure !== redEvidence2.isAssertionFailure ||
        redEvidence1.isCrash !== redEvidence2.isCrash) {
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

    const tapRed = redEvidence1;
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
    const greenRes1 = runReproducer(worktreeDir, { NODE_V8_COVERAGE: covDir });

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
    const greenRes2 = runReproducer(worktreeDir);
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
    // A passing reproducer never substitutes for the project's full suite.
    const fullRes = npmCli === null
      ? { exitCode: null, stdout: "", stderr: "Cannot locate an installed npm CLI outside the candidate" }
      : runCommand(process.execPath, [npmCli, "test"], worktreeDir);
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

    const restorePath = (commit, file) => {
      const entry = gitWt(["ls-tree", "-z", commit, "--", file]);
      if (entry.error || entry.status !== 0) {
        return { verified: false, verdict: "reject", rule: "CHECKOUT_FAILED",
          violation: "CHECKOUT_FAILED", detail: "Cannot measure the rollback path in its Git tree." };
      }
      if (entry.stdout) return checkout([commit, "--", file]);
      // An addition has no base blob; a deletion has no head blob. Restore absence.
      const remove = gitWt(["rm", "--force", "--ignore-unmatch", "--", file]);
      return remove.error || remove.status !== 0
        ? { verified: false, verdict: "reject", rule: "CHECKOUT_FAILED",
            violation: "CHECKOUT_FAILED", detail: "Cannot restore an absent rollback path." }
        : null;
    };
    for (const f of nonTestFiles) {
      const revCheck = restorePath(baseSha, f);
      if (revCheck !== null) return revCheck;

      const revRes = runReproducer(worktreeDir);
      const tapRev = parseTapOutput(revRes.stdout + "\n" + revRes.stderr, revRes.exitCode);

      if (tapRev.isAssertionFailure) {
        necessaryFiles.push(f);
      } else if (revRes.exitCode === 0 && !revRes.timedOut) {
        unnecessaryFiles.push(f);
      } else {
        const rule = revRes.timedOut ? "NECESSITY_CHECK_TIMEOUT" : "NECESSITY_CHECK_CRASH";
        return { verified: false, verdict: "reject", rule, violation: rule,
          detail: `Rollback of ${f} did not produce a passing test or a genuine assertion failure.`,
          checks: { necessity_check: { passed: false, file: f, exitCode: revRes.exitCode } } };
      }

      const restCheck = restorePath(headSha, f);
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

    if (unnecessaryFiles.length > 0 && measuredPhi.warrant_class === "surgical") {
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

    let phiConsumption = null;
    if (!conformance) {
      try { requireAuthorizedWarrant(options.mirqlDir, { warrantId: options.warrantId }); }
      catch { return { verified: false, verdict: "needs_human", rule: "WARRANT_UNAUTHORIZED", violation: "WARRANT_UNAUTHORIZED" }; }
      // Law 13: an accepted increase is spent from the cumulative signed allowance.
      try { phiConsumption = recordPhiConsumption(options.mirqlDir, measuredPhi, { keypair: options.supervisorKeypair }); }
      catch (error) {
        if (typeof error.code === "string" && error.code.startsWith("LAW_13_")) {
          return { verified: false, verdict: "reject", rule: error.code, violation: "PHI_INCREASED", phi: measuredPhi };
        }
        return { verified: false, verdict: "needs_human", rule: "PHI_CONSUMPTION_UNRECORDED", violation: "PHI_CONSUMPTION_UNRECORDED",
          phi: measuredPhi, detail: "The complexity spend could not be durably recorded: " + error.message };
      }
    }
    return {
      phi: phiConsumption ? { ...measuredPhi, consumption_event: phiConsumption.hash } : measuredPhi,
      verified: !conformance,
      verdict: conformance ? "conformance_pass" : "auto_merge",
      rule: conformance ? "CONFORMANCE_ONLY" : "MP-000",
      proof: {
        ...(approvalRecord ? { human_approval_hash: approvalRecord.hash } : {}),
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
        full_suite: { passed: true, exitCode: fullRes.exitCode },
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

  // C. Git-based execution verification mode
  if (options.git === true || (options.workspaceDir && options.baseSha && !options.runCheck)) {
    return verifyGitRepository(options);
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
