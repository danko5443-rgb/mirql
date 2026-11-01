// packages/mergeproof/evaluator.mjs — the deterministic merge-proof rule engine.
//
// Laws enforced (see CONSTITUTION.md):
// - Law 3 / Law 10: merge verdicts are mechanical, never negotiated.
// - Law 5 (Base-Pinned Mortal Verdicts): MP-004 STALE_BASE.
// - Law 6 (Silence Is Never Consent): MP-005 UNCITED_SURFACE → needs_human.
// - Law 7 (Notary Outside Blast Radius): candidate claims cross-checked against git.
// - Law 13 (Monotone Potential Phi & Thrift Test): ΔΦ ≤ 0 (strictly < 0 for
//   refactor/consolidation) and thrift pass for consolidations. Missing ΔΦ fails closed.
// - Law 16 (GREEN Must Be Causal): auto_merge requires a completed causal
//   cycle (Red-Green-ReRed) or a proven suite pass — never self-reported
//   `suite_pass_head` alone (fail closed with MISSING_PROOF).
//
// Rule table (aligned with the conformance corpus):
//   MP-000 auto_merge   clean causal proof, no humanOnly paths, no deleted
//                       tests, violations_count === 0, ΔΦ ≤ 0
//   MP-001 reject       TOUCH_HUMAN_ONLY   (policy/paths.yaml humanOnly)
//   MP-002 reject       TEST_DELETED       (deleted tests / count drop /
//                       weakenings like .skip / .only / .todo)
//   MP-003 reject       ANTI_CHEAT_VIOLATION (swallowed exceptions, flags)
//   MP-004 reject       STALE_BASE         (base_sha ≠ target tip / lease TTL)
//   MP-005 needs_human  UNCITED_SURFACE    (surface.lock deltas or humanApprove
//                       paths without causal proof / human sign-off)
//   LAW_13 reject       PHI_INCREASE / PHI_NOT_DECREASED / THRIFT_TEST_FAILED
//
// The evaluator NEVER reads `expected_verdict`, `expected_rule` or
// `violation_type` from a PR document — every verdict is derived
// deterministically from the evidence itself.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
  normalizePath,
  isPathMatchingPattern,
  loadPathPolicies,
  isHumanOnlyPath,
  isHumanApprovePath,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "../core/index.mjs";

/** Tool name reported by this package. */
export const TOOL = "mergeproof";

export {
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
  normalizePath,
  isPathMatchingPattern,
  loadPathPolicies,
  isHumanOnlyPath,
  isHumanApprovePath,
  checkSwallowedExceptions,
  checkTestWeakenings,
};

/** The canonical rule identifiers and their verdicts. */
export const RULES = Object.freeze({
  "MP-000": { verdict: "auto_merge", violation: null },
  "MP-001": { verdict: "reject", violation: "TOUCH_HUMAN_ONLY" },
  "MP-002": { verdict: "reject", violation: "TEST_DELETED" },
  "MP-003": { verdict: "reject", violation: "ANTI_CHEAT_VIOLATION" },
  "MP-004": { verdict: "reject", violation: "STALE_BASE" },
  "MP-005": { verdict: "needs_human", violation: "UNCITED_SURFACE" },
  LAW_13: { verdict: "reject", violation: "PHI_INCREASE" },
});

/**
 * Helper to construct a verdict failure payload.
 *
 * @param {string} rule
 * @param {string} violation
 * @param {"reject" | "needs_human"} verdict
 * @param {string} detail
 * @param {object} [extra]
 * @returns {object}
 */
function fail(rule, violation, verdict, detail, extra = {}) {
  return {
    ok: false,
    rule,
    violation,
    verdict,
    detail,
    flags: extra.flags ?? [],
    ...extra,
  };
}

/**
 * Extracts a list of touched file paths from a PR or outcome document.
 *
 * @param {object} doc
 * @returns {string[]}
 */
export function collectChangedFiles(doc = {}) {
  const seen = new Set();
  const list = [];
  function add(p) {
    if (typeof p !== "string" || p.trim().length === 0) return;
    const norm = normalizePath(p);
    if (!seen.has(norm)) {
      seen.add(norm);
      list.push(norm);
    }
  }

  const diffStat = doc.diff_stat ?? {};
  if (Array.isArray(diffStat.files_changed)) {
    for (const f of diffStat.files_changed) add(f);
  }
  if (Array.isArray(doc.modifiedFiles)) {
    for (const f of doc.modifiedFiles) add(f);
  }
  const evidence = doc.evidence ?? {};
  if (Array.isArray(evidence.forbidden_paths_touched)) {
    for (const f of evidence.forbidden_paths_touched) add(f);
  }
  return list;
}

/**
 * Resolve the integer delta_phi metric from the PR document.
 * Returns undefined if no integer metric is present.
 *
 * @param {object} doc
 * @returns {number | undefined}
 */
export function resolveDeltaPhi(doc = {}) {
  const phi = doc.phi ?? {};
  if (Number.isSafeInteger(phi.delta_phi)) return phi.delta_phi;
  if (
    Number.isSafeInteger(phi.phi_base) &&
    Number.isSafeInteger(phi.phi_head)
  ) {
    return phi.phi_head - phi.phi_base;
  }
  if (Number.isSafeInteger(doc.delta_phi)) return doc.delta_phi;
  return undefined;
}

/**
 * Queries git diff --name-only base...head if git and a repository are available.
 *
 * @param {string} baseSha
 * @param {string} headSha
 * @param {string} [repoDir]
 * @returns {string[]}
 */
export function getGitDiffFiles(baseSha, headSha, repoDir = process.cwd()) {
  if (!baseSha || !headSha || !existsSync(join(repoDir, ".git"))) {
    return [];
  }
  try {
    const res = spawnSync(
      "git",
      ["diff", "--name-only", `${baseSha}...${headSha}`],
      { cwd: repoDir, encoding: "utf8", timeout: 10000 },
    );
    if (res.status === 0 && res.stdout) {
      return res.stdout
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
    }
  } catch {}
  return [];
}

/**
 * Evaluates a PR / outcome document against MP-000..MP-005 and Law 13.
 *
 * Deterministic and pure with respect to `prDoc`: it never consults
 * `expected_verdict`, `expected_rule` or `violation_type`.
 *
 * Options:
 * - `rootDir`        — repo root for policy/paths.yaml (default: cwd)
 * - `targetTipSha`   — authoritative target tip SHA for MP-004 (CLI --base)
 * - `expectedHeadSha`— authoritative head SHA for MP-004 (CLI --head)
 * - `humanApproved`  — explicit affirmative human sign-off from verified source (unlocks MP-005)
 * - `repoDir`        — directory of git repository to cross-check diffs against reality (Law 7)
 *
 * @param {object} prDoc PR fixture or outcome document
 * @param {object} [options]
 * @returns {{ ok: boolean, rule: string, violation: string | null, verdict: string, detail: string, flags: string[], checks: object }}
 */
export function evaluatePullRequest(prDoc = {}, options = {}) {
  const evidence = prDoc.evidence ?? {};
  const antiCheat = prDoc.anti_cheat ?? {};
  const surface = prDoc.surface ?? {};
  const proof = prDoc.proof ?? {};
  const pr = prDoc.pr ?? {};
  const kind = typeof pr.kind === "string" ? pr.kind.toLowerCase() : "";
  const author = typeof pr.author === "string" ? pr.author.toLowerCase() : "";

  // Collect modified files from PR document
  const filesChanged = collectChangedFiles(prDoc);

  // Law 7 (Notary Outside Blast Radius): cross-check against actual git diff if repo is available
  const baseSha = options.targetTipSha ?? pr.base_sha ?? evidence.claimed_base_sha;
  const headSha = options.expectedHeadSha ?? pr.head_sha ?? evidence.current_tip_sha;
  const repoDir = options.repoDir ?? options.rootDir ?? process.cwd();

  if (baseSha && headSha) {
    const gitFiles = getGitDiffFiles(baseSha, headSha, repoDir);
    for (const gf of gitFiles) {
      const norm = normalizePath(gf);
      if (!filesChanged.includes(norm)) {
        filesChanged.push(norm);
      }
    }
  }

  const policies = loadPathPolicies(options.rootDir);

  // Law 3 & 6: A PR document CANNOT self-approve via inline json flags!
  // humanApproved is ONLY valid if supplied through options from an external signed event or verified caller.
  const humanApproved = options.humanApproved === true;

  const checks = {
    human_only: true,
    tests_deleted: true,
    anti_cheat: true,
    stale_base: true,
    surface: true,
    phi: true,
    proof: true,
  };

  // --- MP-001: TOUCH_HUMAN_ONLY -------------------------------------------
  const forbidden = filesChanged.filter((f) =>
    isHumanOnlyPath(f, policies.humanOnly),
  );
  if (forbidden.length > 0) {
    checks.human_only = false;
    return fail(
      "MP-001",
      "TOUCH_HUMAN_ONLY",
      "reject",
      `PR touched forbidden humanOnly path(s): ${forbidden.join(", ")}`,
      { checks, forbidden_paths: forbidden },
    );
  }

  // --- MP-002: TEST_DELETED -----------------------------------------------
  const testsDeleted = Array.isArray(evidence.tests_deleted)
    ? evidence.tests_deleted
    : [];
  const countDrop =
    (Number.isSafeInteger(evidence.test_count_drop) &&
      evidence.test_count_drop > 0) ||
    (Number.isSafeInteger(evidence.test_count_base) &&
      Number.isSafeInteger(evidence.test_count_head) &&
      evidence.test_count_head < evidence.test_count_base) ||
    (Number.isSafeInteger(proof.cases_dropped) && proof.cases_dropped > 0);

  if (testsDeleted.length > 0 || countDrop) {
    checks.tests_deleted = false;
    const detail =
      evidence.detail ??
      (testsDeleted.length > 0
        ? `PR deleted existing test file(s): ${testsDeleted.join(", ")}`
        : `PR reduced overall test suite count (base: ${evidence.test_count_base ?? "?"}, head: ${evidence.test_count_head ?? "?"}, drop: ${evidence.test_count_drop ?? proof.cases_dropped ?? "?"}).`);
    return fail("MP-002", "TEST_DELETED", "reject", detail, {
      checks,
      tests_deleted: testsDeleted,
    });
  }

  if (prDoc.sourceCode || prDoc.source_code) {
    const src = prDoc.sourceCode ?? prDoc.source_code;
    const weakenScan = scanSources(src, checkTestWeakenings);
    if (weakenScan !== null) {
      checks.tests_deleted = false;
      return fail(
        "MP-002",
        "TEST_DELETED",
        "reject",
        `Test weakening detected in ${weakenScan.file}: ${weakenScan.details.join("; ")}`,
        { checks, flags: weakenScan.details },
      );
    }
  }

  // --- MP-003: ANTI_CHEAT_VIOLATION ---------------------------------------
  const antiCheatFlags = Array.isArray(antiCheat.flags) ? antiCheat.flags : [];
  const violationsCount = Number.isSafeInteger(antiCheat.violations_count)
    ? antiCheat.violations_count
    : antiCheatFlags.length;

  if (violationsCount > 0 || antiCheatFlags.length > 0) {
    checks.anti_cheat = false;
    const detail =
      antiCheat.detail ??
      `Anti-cheat gate flagged ${violationsCount} violation(s): ${antiCheatFlags.join(", ") || "swallowed exceptions / test weakening detected."}`;
    return fail(
      "MP-003",
      "ANTI_CHEAT_VIOLATION",
      "reject",
      detail,
      { checks, flags: antiCheatFlags },
    );
  }

  if (prDoc.sourceCode || prDoc.source_code) {
    const src = prDoc.sourceCode ?? prDoc.source_code;
    const swallowScan = scanSources(src, checkSwallowedExceptions, (r) => r.ok);
    if (swallowScan !== null) {
      checks.anti_cheat = false;
      return fail(
        "MP-003",
        "ANTI_CHEAT_VIOLATION",
        "reject",
        `Swallowed exception detected in ${swallowScan.file}${swallowScan.line ? ` at line ${swallowScan.line}` : ""}`,
        { checks, flags: swallowScan.details },
      );
    }
  }

  // --- MP-004: STALE_BASE -------------------------------------------------
  const claimedBase =
    typeof pr.base_sha === "string" && pr.base_sha.length > 0
      ? pr.base_sha
      : typeof evidence.claimed_base_sha === "string" && evidence.claimed_base_sha.length > 0
        ? evidence.claimed_base_sha
        : null;

  const currentTip =
    typeof options.targetTipSha === "string" && options.targetTipSha.length > 0
      ? options.targetTipSha
      : typeof evidence.current_tip_sha === "string" && evidence.current_tip_sha.length > 0
        ? evidence.current_tip_sha
        : null;

  // Law 6: Missing base_sha when targetTip is asserted must FAIL CLOSED
  if (currentTip !== null && (!claimedBase || claimedBase !== currentTip)) {
    checks.stale_base = false;
    return fail(
      "MP-004",
      "STALE_BASE",
      "reject",
      claimedBase
        ? `Claimed base SHA ${claimedBase} does not match current target tip ${currentTip}.`
        : `PR is missing base_sha; cannot verify against target tip ${currentTip}.`,
      { checks, claimed_base_sha: claimedBase, current_tip_sha: currentTip },
    );
  }

  const leaseExpired =
    Number.isSafeInteger(evidence.elapsed_since_lease_ms) &&
    Number.isSafeInteger(evidence.lease_ttl_ms) &&
    evidence.elapsed_since_lease_ms > evidence.lease_ttl_ms;

  const expectedHead =
    typeof options.expectedHeadSha === "string" && options.expectedHeadSha.length > 0
      ? options.expectedHeadSha
      : null;

  const headMismatch =
    expectedHead !== null &&
    typeof pr.head_sha === "string" &&
    pr.head_sha.length > 0 &&
    pr.head_sha !== expectedHead;

  if (leaseExpired || (claimedBase !== null && currentTip !== null && claimedBase !== currentTip) || headMismatch) {
    checks.stale_base = false;
    const detail = leaseExpired
      ? `Lease TTL expired: ${evidence.elapsed_since_lease_ms}ms elapsed > ${evidence.lease_ttl_ms}ms TTL.`
      : headMismatch
        ? `PR head_sha ${pr.head_sha} does not match the actual head ${expectedHead}.`
        : `Claimed base SHA ${claimedBase} does not match current target tip ${currentTip}.`;
    return fail("MP-004", "STALE_BASE", "reject", evidence.detail ?? detail, {
      checks,
      claimed_base_sha: claimedBase,
      current_tip_sha: currentTip,
    });
  }

  // --- MP-005: UNCITED_SURFACE ----------------------------------------------
  const uncitedCommands = Array.isArray(surface.uncited_commands)
    ? surface.uncited_commands
    : [];
  const isUncitedSurface =
    uncitedCommands.length > 0 ||
    (Number.isSafeInteger(surface.delta_count) &&
      surface.delta_count > 0 &&
      !surface.roadmap_ref);

  const hasCausalProof = proof.causal_cycle_completed === true;
  const approvePaths = filesChanged.filter((f) =>
    isHumanApprovePath(f, policies.humanApprove),
  );
  const touchesHumanApproveWithoutApproval =
    approvePaths.length > 0 && !hasCausalProof && !humanApproved;

  if (isUncitedSurface || touchesHumanApproveWithoutApproval) {
    checks.surface = false;
    const detail = isUncitedSurface
      ? `PR modified public surface without cited roadmap reference: ${uncitedCommands.join(", ")}`
      : `PR touched humanApprove path(s) [${approvePaths.join(", ")}] without causal proof or human sign-off.`;
    return fail("MP-005", "UNCITED_SURFACE", "needs_human", detail, {
      checks,
      uncited_commands: uncitedCommands,
      human_approve_paths: approvePaths,
    });
  }

  // --- Law 13: Monotone Potential Phi ----------------------------------------
  const deltaPhi = resolveDeltaPhi(prDoc);
  const isConsolidation = kind === "refactor" || kind === "consolidation" || author.includes("consolidator");

  // Law 6: Missing ΔΦ fails closed! Every PR must report a valid safe integer delta_phi
  if (deltaPhi === undefined || !Number.isSafeInteger(deltaPhi)) {
    checks.phi = false;
    return fail(
      "LAW_13",
      "MISSING_PHI",
      "reject",
      "Law 13 invariant violation: delta_phi is missing or not a safe integer.",
      { checks },
    );
  }

  if (deltaPhi > 0) {
    checks.phi = false;
    return fail(
      "LAW_13",
      "PHI_INCREASE",
      "reject",
      `Law 13 invariant violation: complexity potential increased (delta_phi = +${deltaPhi} > 0).`,
      { checks, delta_phi: deltaPhi },
    );
  }
  if (isConsolidation) {
    if (deltaPhi >= 0) {
      checks.phi = false;
      return fail(
        "LAW_13",
        "PHI_NOT_DECREASED",
        "reject",
        `Law 13 invariant violation: ${kind || author} requires strictly decreasing complexity potential (delta_phi < 0, got ${deltaPhi}).`,
        { checks, delta_phi: deltaPhi },
      );
    }
    if (prDoc.phi?.thrift_test_passed !== true) {
      checks.phi = false;
      return fail(
        "LAW_13",
        "THRIFT_TEST_FAILED",
        "reject",
        "Law 13 invariant violation: refactor/consolidation requires a passing thrift test (phi.thrift_test_passed !== true).",
        { checks, delta_phi: deltaPhi },
      );
    }
  }

  // --- MP-000: auto_merge ------------------------------------------------------
  // Fail closed: clean causal proof requires proof.causal_cycle_completed === true
  // OR a proven suite pass (suite_pass_base AND suite_pass_head).
  const hasSuiteProof =
    proof.suite_pass_base === true && proof.suite_pass_head === true;
  if (!hasCausalProof && !hasSuiteProof) {
    checks.proof = false;
    return fail(
      "MP-000",
      "MISSING_PROOF",
      "reject",
      "Fail closed: proof is missing or incomplete (no causal_cycle_completed and no proven suite pass).",
      { checks },
    );
  }

  return {
    ok: true,
    rule: "MP-000",
    violation: null,
    verdict: "auto_merge",
    detail: "Clean causal proof; all merge-proof rules satisfied.",
    flags: [],
    checks,
  };
}

/**
 * Runs `scanner` over sourceCode (a string or a { file: code } record),
 * returning the first failing file description or null when clean.
 *
 * @param {string | Record<string, string> | undefined} sourceCode
 * @param {(code: string, file?: string) => { ok: boolean, details?: string[] }} scanner
 * @param {(result: object) => boolean} [isOk]
 * @returns {{ file: string, details: string[], line?: number } | null}
 */
function scanSources(sourceCode, scanner, isOk = (r) => r.ok) {
  if (typeof sourceCode === "string") {
    const result = scanner(sourceCode);
    if (!isOk(result)) {
      return { file: "source", details: result.details ?? [] };
    }
    return null;
  }
  if (sourceCode !== null && typeof sourceCode === "object") {
    for (const [file, code] of Object.entries(sourceCode)) {
      if (typeof code !== "string") continue;
      const result = scanner(code, file);
      if (!isOk(result)) {
        return {
          file,
          details: result.details ?? [],
          line: Array.isArray(result.violations) && result.violations[0]?.line,
        };
      }
    }
  }
  return null;
}
