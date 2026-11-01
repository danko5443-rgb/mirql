// packages/run/anti-cheat.mjs — AST anti-cheat gate and path policy checker for attempt execution.
// Primitives are canonically implemented in @mirql/core (Law 13: zero duplication).

import {
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
  normalizePath,
  isPathMatchingPattern,
  loadPathPolicies,
  isHumanOnlyPath,
  isHumanApprovePath,
  extractBalancedBlock,
  isEffectivelyEmpty,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "../core/index.mjs";

export {
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
  normalizePath,
  isPathMatchingPattern,
  loadPathPolicies,
  isHumanOnlyPath,
  isHumanApprovePath,
  extractBalancedBlock,
  isEffectivelyEmpty,
  checkSwallowedExceptions,
  checkTestWeakenings,
};

/**
 * Loads humanOnly patterns from policy/paths.yaml.
 *
 * @param {string} [rootDir=process.cwd()]
 * @returns {string[]}
 */
export function loadHumanOnlyPatterns(rootDir = process.cwd()) {
  return loadPathPolicies(rootDir).humanOnly;
}

/**
 * Checks an array of file paths for humanOnly policy violations (MP-001).
 *
 * @param {string[]} filePaths
 * @param {string[]} [patterns]
 * @returns {{ ok: boolean, forbidden: string[] }}
 */
export function checkHumanOnlyPaths(filePaths = [], patterns) {
  const forbidden = [];
  for (const p of filePaths) {
    if (isHumanOnlyPath(p, patterns)) {
      forbidden.push(p);
    }
  }
  return {
    ok: forbidden.length === 0,
    forbidden,
  };
}

/**
 * Checks an array of file paths for humanApprove policy match (MP-005).
 *
 * @param {string[]} filePaths
 * @param {string[]} [patterns]
 * @returns {{ ok: boolean, paths: string[] }}
 */
export function checkHumanApprovePaths(filePaths = [], patterns) {
  const matched = [];
  for (const p of filePaths) {
    if (isHumanApprovePath(p, patterns)) {
      matched.push(p);
    }
  }
  return {
    ok: matched.length === 0,
    paths: matched,
  };
}

/**
 * Comprehensive anti-cheat evaluator for PR fixtures or attempt options.
 * Evaluates rules MP-001 through MP-005 deterministically WITHOUT reading
 * `expected_rule` or `violation_type`.
 *
 * @param {object} input - PR fixture object or attempt verification context
 * @returns {{ ok: boolean, rule: string, violation?: string, verdict: string, detail?: string, flags?: string[] }}
 */
export function checkAntiCheat(input = {}) {
  const evidence = input.evidence ?? {};
  const antiCheat = input.anti_cheat ?? {};
  const surface = input.surface ?? {};
  const diffStat = input.diff_stat ?? {};
  const proof = input.proof ?? {};

  // Collect modified files
  const filesChanged = [
    ...(Array.isArray(diffStat.files_changed) ? diffStat.files_changed : []),
    ...(Array.isArray(input.modifiedFiles) ? input.modifiedFiles : []),
    ...(Array.isArray(evidence.forbidden_paths_touched)
      ? evidence.forbidden_paths_touched
      : []),
  ];

  // 1. MP-001: TOUCH_HUMAN_ONLY
  const humanCheck = checkHumanOnlyPaths(filesChanged);
  if (!humanCheck.ok) {
    return {
      ok: false,
      rule: "MP-001",
      violation: "TOUCH_HUMAN_ONLY",
      verdict: "reject",
      detail: `PR touched forbidden humanOnly path(s): ${humanCheck.forbidden.join(", ")}`,
    };
  }

  // 2. MP-002: TEST_DELETED / Test Weakenings
  const hasTestsDeleted =
    (Array.isArray(evidence.tests_deleted) && evidence.tests_deleted.length > 0) ||
    (typeof evidence.test_count_drop === "number" && evidence.test_count_drop > 0) ||
    (typeof evidence.test_count_base === "number" &&
      typeof evidence.test_count_head === "number" &&
      evidence.test_count_head < evidence.test_count_base) ||
    (typeof proof.cases_dropped === "number" && proof.cases_dropped > 0);

  if (hasTestsDeleted) {
    return {
      ok: false,
      rule: "MP-002",
      violation: "TEST_DELETED",
      verdict: "reject",
      detail:
        evidence.detail ??
        "PR deleted existing test file or decreased total test suite count.",
    };
  }

  if (typeof input.sourceCode === "string") {
    const weakenCheck = checkTestWeakenings(input.sourceCode);
    if (!weakenCheck.ok) {
      return {
        ok: false,
        rule: "MP-002",
        violation: "TEST_DELETED",
        verdict: "reject",
        detail: weakenCheck.details.join("; "),
      };
    }
  }

  // 3. MP-003: ANTI_CHEAT_VIOLATION
  const hasAntiCheatFlags =
    (typeof antiCheat.violations_count === "number" &&
      antiCheat.violations_count > 0) ||
    (Array.isArray(antiCheat.flags) && antiCheat.flags.length > 0);

  if (hasAntiCheatFlags) {
    return {
      ok: false,
      rule: "MP-003",
      violation: "ANTI_CHEAT_VIOLATION",
      verdict: "reject",
      detail:
        antiCheat.detail ??
        "Anti-cheat violation detected: empty catch block, swallowed exception, or illicit mock/stub.",
      flags: antiCheat.flags ?? [],
    };
  }

  if (typeof input.sourceCode === "string") {
    const swallowCheck = checkSwallowedExceptions(input.sourceCode);
    if (!swallowCheck.ok) {
      return {
        ok: false,
        rule: "MP-003",
        violation: "ANTI_CHEAT_VIOLATION",
        verdict: "reject",
        detail: `Found ${swallowCheck.violations.length} swallowed exception(s)`,
        flags: swallowCheck.violations.map((v) => v.pattern),
      };
    }
  }

  // 4. MP-004: STALE_BASE
  const claimedBase = evidence.claimed_base_sha ?? input.claimed_base_sha;
  const currentTip = evidence.current_tip_sha ?? input.current_tip_sha;
  if (claimedBase && currentTip && claimedBase !== currentTip) {
    return {
      ok: false,
      rule: "MP-004",
      violation: "STALE_BASE",
      verdict: "reject",
      detail: `PR base SHA ${claimedBase} is stale against target tip ${currentTip}.`,
    };
  }

  // 5. MP-005: UNCITED_SURFACE / humanApprove
  const hasUncitedSurface =
    Array.isArray(surface.uncited_commands) &&
    surface.uncited_commands.length > 0;

  const approveCheck = checkHumanApprovePaths(filesChanged);
  const touchesHumanApprove = !approveCheck.ok;

  const isHumanApproved =
    Boolean(input.human_approved || input.human_approval || evidence.human_approval);

  // C1: causal proof STRICTLY requires the completed triple-execution cycle.
  // A self-reported `suite_pass_head` is not causal evidence and must not
  // unlock humanApprove surfaces (MP-005).
  const hasCausalProof = proof?.causal_cycle_completed === true;

  if (hasUncitedSurface || (touchesHumanApprove && !hasCausalProof && !isHumanApproved)) {
    return {
      ok: false,
      rule: "MP-005",
      violation: "UNCITED_SURFACE",
      verdict: "needs_human",
      detail: hasUncitedSurface
        ? `PR introduces uncited surface commands: ${surface.uncited_commands.join(", ")}`
        : `PR touches humanApprove path(s) [${approveCheck.paths.join(", ")}] without causal proof; requires human sign-off.`,
    };
  }

  // All rules passed -> MP-000 auto_merge
  return {
    ok: true,
    rule: "MP-000",
    verdict: "auto_merge",
  };
}
