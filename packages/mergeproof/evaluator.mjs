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
  isTestFilePath,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "../core/index.mjs";
import { phiWarrantAllowance } from "../core/phi-warrant.mjs";

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

/** Helper to construct a verdict failure payload. */
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

/** Law 8 gate: `sandbox: "none"` evidence caps a passing verdict at needs_human — never auto_merge (nor doc-only conformance_pass). */
function capUnsandboxedVerdict(result, prDoc = {}) {
  if (prDoc?.sandbox !== "none" && prDoc?.evidence?.sandbox !== "none") return result;
  if (result.verdict !== "auto_merge" && result.verdict !== "conformance_pass") return result;
  return fail("UNSANDBOXED_EXECUTION", "SANDBOX_NONE", "needs_human",
    'Execution ran with sandbox: "none" (no OS/container isolation); human review required.',
    { checks: result.checks ?? {}, flags: [...(result.flags ?? []), "UNSANDBOXED_EXECUTION"], reasons: [...(result.reasons ?? []), "UNSANDBOXED_EXECUTION"] });
}

/** Extracts a list of touched file paths from a PR or outcome document. */
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

/** Resolve the integer delta_phi metric from the PR document. Returns undefined if no integer metric is present. */
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

/** Canonical test file path recognizer shared across mergeproof checks. */
export { isTestFilePath } from '../core/index.mjs';

/** Files that steer an aiReviewers account: CodeRabbit config, AGENTS.md (Codex review guidelines) and the agent instruction files CodeRabbit reads as code guidelines by default. Every pattern matches at any depth (see isReviewerConfigPath). An AI approval never clears a PR that touches one: that PR may be reviewed under its own instructions. / */
const AI_REVIEWER_CONFIG_PATTERNS = Object.freeze([
  ".coderabbit.yaml",
  ".coderabbit.yml",
  "roles/judge.md",
  "AGENTS.md",
  "AGENTS.override.md",
  "AGENT.md",
  "CLAUDE.md",
  "GEMINI.md",
  ".cursorrules",
  ".windsurfrules",
  ".cursor/rules/**",
  ".clinerules/**",
  ".rules/**",
  ".github/copilot-instructions.md",
  ".github/instructions/**",
]);

/** PR Court receipts are LLM verdicts: they may clear humanApprove, never the Courthouse Lock (humanOnly). */
const COURT_REVIEWERS = Object.freeze(["mirql-judge[bot]", "mirql-critic[bot]"]);

/** True when a path is, or lies under, a reviewer config pattern at any depth. */
export function isReviewerConfigPath(filePath) {
  const norm = normalizePath(filePath);
  return AI_REVIEWER_CONFIG_PATTERNS.some((pat) => {
    const normPat = normalizePath(pat);
    if (normPat.endsWith("/**")) {
      return `/${norm}/`.includes(`/${normPat.slice(0, -3)}/`);
    }
    return isPathMatchingPattern(norm, pat);
  });
}

const REVIEWER_LOGIN_RE =/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/;

/** Returns the reviewer login if it is a plausible GitHub login, else null. */
function validReviewerLogin(login) {
  return typeof login === "string" && REVIEWER_LOGIN_RE.test(login) ? login : null;
}

const GIT_SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;

/** Queries git diff --name-status base...head if git and a repository are available. Returns { ok: true, files: string[], deletedFiles: string[] } on success, or { ok: false, error: string, files: [], deletedFiles: [] } on failure. */
export function getGitDiffInfo(baseSha, headSha, repoDir = process.cwd()) {
  if (!baseSha || !headSha) {
    return { ok: true, files: [], deletedFiles: [] };
  }
  // The SHAs can come from an untrusted PR doc. Accept only full hex object
  // ids so a value like "--output=<path>" can never be parsed as a git option.
  for (const sha of [baseSha, headSha]) {
    if (typeof sha !== "string" || !GIT_SHA_RE.test(sha)) {
      return { ok: false, error: `invalid commit sha: ${JSON.stringify(sha)}`, files: [], deletedFiles: [] };
    }
  }
  const gitDir = join(repoDir, ".git");
  if (!existsSync(gitDir)) {
    return {
      ok: false,
      error: `Directory ${repoDir} is not a git repository`,
      files: [],
      deletedFiles: [],
    };
  }
  try {
    const res = spawnSync(
      "git",
      ["diff", "--name-status", "--end-of-options", `${baseSha}...${headSha}`],
      { cwd: repoDir, encoding: "utf8", timeout: 10000 },
    );
    if (res.status !== 0) {
      const err = res.stderr ? res.stderr.trim() : `git exit code ${res.status}`;
      return { ok: false, error: err, files: [], deletedFiles: [] };
    }
    const lines = (res.stdout || "")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const files = [];
    const deletedFiles = [];
    for (const line of lines) {
      const parts = line.split("\t");
      const status = parts[0];
      if (status.startsWith("R") && parts.length >= 3) {
        const oldFile = parts[1];
        const newFile = parts[2];
        files.push(newFile);
        if (isTestFilePath(oldFile) && !isTestFilePath(newFile)) {
          deletedFiles.push(oldFile);
        }
      } else if (parts.length >= 2) {
        const filePath = parts[1];
        files.push(filePath);
        if (status.startsWith("D")) {
          deletedFiles.push(filePath);
        }
      }
    }
    return { ok: true, files, deletedFiles };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      files: [],
      deletedFiles: [],
    };
  }
}

/** Backward compatibility alias for getGitDiffInfo.files. */
export function getGitDiffFiles(baseSha, headSha, repoDir = process.cwd()) {
  const info = getGitDiffInfo(baseSha, headSha, repoDir);
  return info.ok ? info.files : [];
}

/** Evaluates a PR / outcome document against MP-000..MP-005 and Law 13. */
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
  const assertedBase = options.targetTipSha;
  const assertedHead = options.expectedHeadSha;
  const baseSha = assertedBase ?? pr.base_sha ?? evidence.claimed_base_sha;
  const headSha = assertedHead ?? pr.head_sha ?? evidence.current_tip_sha;
  const repoDir = options.repoDir ?? options.rootDir ?? process.cwd();

  const checks = {
    human_only: true,
    tests_deleted: true,
    anti_cheat: true,
    stale_base: true,
    surface: true,
    phi: null,
    proof: true,
  };

  let gitDeletedFiles = [];
  if (baseSha && headSha) {
    const diffInfo = getGitDiffInfo(baseSha, headSha, repoDir);
    if (!diffInfo.ok) {
      if (assertedBase && assertedHead) {
        // Law 7 & Law 6: Fail closed when authoritative --base and --head are asserted and git diff fails
        return fail(
          "LAW_7",
          "GIT_DIFF_FAILED",
          "reject",
          `Authoritative git diff failed between ${baseSha} and ${headSha}: ${diffInfo.error}`,
          { checks: { ...checks, git: false }, error: diffInfo.error },
        );
      }
    } else {
      for (const gf of diffInfo.files) {
        const norm = normalizePath(gf);
        if (!filesChanged.includes(norm)) {
          filesChanged.push(norm);
        }
      }
      gitDeletedFiles = diffInfo.deletedFiles;
    }
  }

  const policies = loadPathPolicies(options.rootDir);

  // --- MP-001: TOUCH_HUMAN_ONLY -------------------------------------------
  const forbidden = filesChanged.filter((f) =>
    isHumanOnlyPath(f, policies.humanOnly),
  );
  // A PR that changes an AI reviewer's own config may be reviewed under that
  // config, so its approval cannot clear MP-001; a human must merge it.
  const touchesReviewerConfig = filesChanged.some(isReviewerConfigPath);
  const humanOnlyReviewer = touchesReviewerConfig ? null : validReviewerLogin(options.humanOnlyReviewer);
  // Only the repo owner's sign-off can let Phi growth continue (Law 13); an AI
  // approval arrives as humanOnlyReviewer alone and never has this effect.
  const ownerSignoff = touchesReviewerConfig ? null : validReviewerLogin(options.ownerSignoff);
  if (forbidden.length > 0) {
    checks.human_only = false;
  }
  if (forbidden.length > 0 && (!humanOnlyReviewer || COURT_REVIEWERS.includes(humanOnlyReviewer))) {
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
    ? [...evidence.tests_deleted]
    : [];

  // Check test deletions discovered directly via authoritative git diff (Point 3)
  for (const df of gitDeletedFiles) {
    if (isTestFilePath(df)) {
      const norm = normalizePath(df);
      if (!testsDeleted.includes(norm)) {
        testsDeleted.push(norm);
      }
    }
  }

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
    const weakenScan = scanSources(src, (code, file) =>
      checkWeakeningAgainstBase(code, file, assertedBase, assertedHead, repoDir));
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
    const swallowScan = scanSources(src, (code, file) =>
      checkSwallowedAgainstBase(code, file, assertedBase, assertedHead, repoDir));
    if (swallowScan !== null) {
      checks.anti_cheat = false;
      return fail(
        "MP-003",
        "ANTI_CHEAT_VIOLATION",
        "reject",
        `Swallowed exception detected in ${swallowScan.file}${swallowScan.line ? ` at line ${swallowScan.line}` : ""}${swallowScan.detail ? `: ${swallowScan.detail}` : ""}`,
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

  if (leaseExpired || headMismatch) {
    checks.stale_base = false;
    const detail = leaseExpired
      ? `Lease TTL expired: ${evidence.elapsed_since_lease_ms}ms elapsed > ${evidence.lease_ttl_ms}ms TTL.`
      : `PR head_sha ${pr.head_sha} does not match the actual head ${expectedHead}.`;
    return fail("MP-004", "STALE_BASE", "reject", evidence.detail ?? detail, {
      checks,
      claimed_base_sha: claimedBase,
      current_tip_sha: currentTip,
    });
  }

  // --- MP-005: UNCITED_SURFACE (facts here, verdict after Law 13) --------------
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
  // Phase 0.3: a self-reported proof or a caller boolean never unlocks a
  // humanApprove path — touching one always escalates to a human.
  const touchesHumanApprove = approvePaths.length > 0;
  checks.surface = !(isUncitedSurface || touchesHumanApprove);

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

  // Growth inside the owner's signed warrant is authorized. Refactors and
  // consolidations must shrink Phi whoever signs off and whatever is warranted.
  const phiAllowance = phiWarrantAllowance(options.rootDir, options.phiWarrant, options.phiSpent);
  const phiGrowthWarranted = deltaPhi > 0 && !isConsolidation && deltaPhi <= phiAllowance;
  const phiGrowthSignedOff = deltaPhi > 0 && !phiGrowthWarranted && ownerSignoff !== null && !isConsolidation;
  if (deltaPhi > 0 && !phiGrowthWarranted) {
    checks.phi = false;
  }
  if (deltaPhi > 0 && !phiGrowthWarranted && !phiGrowthSignedOff) {
    return fail(
      "LAW_13",
      "PHI_INCREASE",
      "reject",
      `Law 13 invariant violation: complexity potential increased (delta_phi = +${deltaPhi} > 0). ${phiAllowance > 0 ? `The signed warrant allows only +${phiAllowance} for this PR (what is left, capped by its per-PR limit)` : "The notary sees no signed warrant with allowance left, so the authorized allowance is 0"}; a human must decide this merge (the repo owner's reviewed:<head sha> label can clear this, capped at needs_human).`,
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
  if (!phiGrowthSignedOff) {
    checks.phi = true;
  }

  const reviewerRecord = humanOnlyReviewer && (forbidden.length > 0 || touchesHumanApprove)
    ? { human_only_reviewer: humanOnlyReviewer }
    : {};
  const surfaceHold = () => fail(
    "MP-005",
    "UNCITED_SURFACE",
    "needs_human",
    isUncitedSurface
      ? `PR modified public surface without cited roadmap reference: ${uncitedCommands.join(", ")}`
      : `PR touched humanApprove path(s) [${approvePaths.join(", ")}] ; human review required.`,
    { checks, uncited_commands: uncitedCommands, human_approve_paths: approvePaths, delta_phi: deltaPhi, ...reviewerRecord },
  );
  // A reviewer only clears the hold: the proof rules below still run.
  if (!checks.surface && !humanOnlyReviewer) return surfaceHold();

  // --- MP-000 ------------------------------------------------------------------
  // Fail closed: a doc needs causal_cycle_completed === true or a proven suite
  // pass (suite_pass_base AND suite_pass_head) to get past this point.
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

  // Phase 0.0b / Law 16: a suite pass is not a causal proof.
  if (!hasCausalProof) {
    checks.proof = false;
    return fail(
      "LAW_16",
      "NO_CAUSAL_PROOF",
      "needs_human",
      "Suite passes on base and head, but no causal proof (red-green-re-red) was measured; human review required." +
        (phiGrowthSignedOff ? ` Phi also grew by +${deltaPhi} under the owner's sign-off.` : "") +
        (phiGrowthWarranted ? ` Phi grew by +${deltaPhi}, inside the +${phiAllowance} left on the signed warrant.` : ""),
      { checks, ...reviewerRecord },
    );
  }

  if (phiGrowthSignedOff) {
    return fail(
      "LAW_13",
      "PHI_INCREASE",
      "needs_human",
      `Phi grew by +${deltaPhi} and the repo owner signed off as ${ownerSignoff}; no warrant allowance covered it; merge is manual, never auto_merge.`,
      {
        checks,
        delta_phi: deltaPhi,
        owner_signoff: ownerSignoff,
        ...(forbidden.length > 0 ? { forbidden_paths: forbidden } : {}),
        ...reviewerRecord,
      },
    );
  }

  if (forbidden.length > 0) {
    return fail(
      "MP-001",
      "TOUCH_HUMAN_ONLY",
      "needs_human",
      `humanOnly path(s) [${forbidden.join(", ")}] approved by ${humanOnlyReviewer}; all other rules passed; merge is manual, never auto_merge.`,
      { checks, forbidden_paths: forbidden, human_only_reviewer: humanOnlyReviewer },
    );
  }
  if (!checks.surface) return surfaceHold();

  // Phase 0.2: every proof field in a PR doc is self-reported, so the best a
  // doc can earn is conformance_pass. auto_merge comes only from a measured
  // causal cycle (run/verify.mjs git mode) or, from Phase 2, a notary-signed doc.
  // Phase 5 (Law 8): unsandboxed execution caps even that at needs_human.
  return capUnsandboxedVerdict({
    ok: true,
    rule: "MP-000",
    violation: null,
    verdict: "conformance_pass",
    detail: "All merge-proof rules satisfied by the self-reported proof; it would auto-merge if the proof were measured.",
    flags: [],
    checks,
  }, prDoc);
}

/**
 * Lines of `code` the candidate changed, or null when that cannot be established.
 * Only the caller-asserted --base/--head may answer this: SHAs in the PR document
 * are the candidate's own claim, and claiming base == head would empty the diff.
 * A deletion has no line of its own, so both lines around it count as changed;
 * removing a handler can leave a catch resting on a marker nobody added to it.
 */
function changedLinesSinceBase(code, file, baseSha, headSha, repoDir) {
  if (!GIT_SHA_RE.test(baseSha ?? "") || !GIT_SHA_RE.test(headSha ?? "")) return null;
  const git = (...args) => spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 10000 });

  // The line numbers below describe the head blob, so they only apply to that exact text.
  const blob = git("cat-file", "blob", `${headSha}:${file}`);
  if (blob.status !== 0) return null;
  const unifyEol = (text) => text.replace(/\r\n/g, "\n");
  if (unifyEol(blob.stdout) !== unifyEol(code)) return null;

  // --text and friends: a candidate's .gitattributes must not be able to turn its
  // changes into "Binary files differ", which has no hunks and would look untouched.
  const diff = git(
    "--literal-pathspecs", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--text", "-U0",
    "--end-of-options", `${baseSha}...${headSha}`, "--", file,
  );
  if (diff.status !== 0) return null;
  const hunks = [...diff.stdout.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)];
  if (diff.stdout.length > 0 && hunks.length === 0) return null;

  const changed = new Set();
  for (const [, startText, countText] of hunks) {
    const start = Number(startText);
    const count = countText === undefined ? 1 : Number(countText);
    if (count === 0) changed.add(start).add(start + 1);
    for (let i = 0; i < count; i++) changed.add(start + i);
  }
  return changed;
}

/** MP-003 scan where a marker counts only on a catch unchanged since the asserted base. Git runs only if the strict scan fails. */
function checkSwallowedAgainstBase(code, file, baseSha, headSha, repoDir) {
  const strict = checkSwallowedExceptions(code, file);
  if (strict.ok || !file) return strict;
  const changedLines = changedLinesSinceBase(code, file, baseSha, headSha, repoDir);
  return changedLines ? checkSwallowedExceptions(code, file, { changedLines }) : strict;
}

/**
 * MP-002 scan scoped like the MP-003 one: only test files can weaken tests, and
 * only a line the candidate changed counts, so pre-existing `t.skip(...)` on an
 * untouched line cannot lock a PR out of the gate. Weakening-shaped text inside
 * strings and comments is already ignored by the scanner. When the changed
 * lines cannot be established the strict verdict stands: fail closed.
 */
function checkWeakeningAgainstBase(code, file, baseSha, headSha, repoDir) {
  if (file && !isTestFilePath(file)) return { ok: true, count: 0, details: [] };
  const strict = checkTestWeakenings(code, file);
  if (strict.ok || !file) return strict;
  const changedLines = changedLinesSinceBase(code, file, baseSha, headSha, repoDir);
  return changedLines ? checkTestWeakenings(code, file, { changedLines }) : strict;
}

/** Runs `scanner` over sourceCode (a string or a { file: code } record), returning the first failing file description or null when clean. */
function scanSources(sourceCode, scanner, isOk = (r) => r.ok) {
  if (typeof sourceCode === "string") {
    const result = scanner(sourceCode);
    if (!isOk(result)) {
      return { file: "source", details: result.details ?? [], detail: result.violations?.[0]?.detail };
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
          detail: result.violations?.[0]?.detail,
        };
      }
    }
  }
  return null;
}
