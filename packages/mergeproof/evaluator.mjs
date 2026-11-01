// packages/mergeproof/evaluator.mjs — the deterministic merge-proof rule engine.
//
// Laws enforced (see CONSTITUTION.md):
// - Law 3 / Law 10: merge verdicts are mechanical, never negotiated.
// - Law 5 (Base-Pinned Mortal Verdicts): MP-004 STALE_BASE.
// - Law 6 (Silence Is Never Consent): MP-005 UNCITED_SURFACE → needs_human.
// - Law 13 (Monotone Potential Phi & Thrift Test): ΔΦ ≤ 0 (strictly < 0 for
//   refactor/consolidation) and thrift pass for consolidations.
// - Law 16 (GREEN Must Be Causal): auto_merge requires a completed causal
//   cycle (Red-Green-ReRed) or a proven suite pass — never a self-reported
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

/** Tool name reported by this package. */
export const TOOL = "mergeproof";

/**
 * Default humanOnly patterns if policy/paths.yaml cannot be loaded.
 * Must stay in sync with policy/paths.yaml (mirrored from the canonical file).
 */
export const DEFAULT_HUMAN_ONLY_PATTERNS = Object.freeze([
  "CONSTITUTION.md",
  "NOT-ROADMAP.md",
  "policy/**",
  "conformance/**",
  ".github/**",
]);

/**
 * Default humanApprove patterns if policy/paths.yaml cannot be loaded.
 */
export const DEFAULT_HUMAN_APPROVE_PATTERNS = Object.freeze([
  "schemas/**",
  "packages/core/**",
  "packages/log/**",
  "packages/queue/**",
  "packages/run/verify*",
  "package.json",
]);

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
 * Normalizes a file path for policy matching:
 * - Backslashes to forward slashes
 * - Resolve relative `.` / `..` segments
 * - Strip trailing dots from path segments (preserving `.`/`..`)
 * - Case-folding (lower-case)
 *
 * @param {string} p
 * @returns {string}
 */
export function normalizePath(p) {
  if (typeof p !== "string") return "";
  const parts = p.replaceAll("\\", "/").split("/");
  const resolved = [];
  for (let part of parts) {
    if (!part || part === ".") continue;
    if (part !== ".." && part.endsWith(".")) {
      part = part.replace(/\.+$/, "");
    }
    if (!part || part === ".") continue;
    if (part === "..") {
      if (resolved.length > 0) resolved.pop();
    } else {
      resolved.push(part);
    }
  }
  return resolved.join("/").toLowerCase();
}

/**
 * Loads path policies from <rootDir>/policy/paths.yaml, falling back to the
 * frozen defaults when the file is absent. Canonical defaults are always
 * unioned in so a trimmed policy file can never widen access.
 *
 * @param {string} [rootDir=process.cwd()]
 * @returns {{ humanOnly: string[], humanApprove: string[] }}
 */
export function loadPathPolicies(rootDir = process.cwd()) {
  const yamlPath = join(rootDir, "policy", "paths.yaml");
  const humanOnly = [];
  const humanApprove = [];

  if (existsSync(yamlPath)) {
    const lines = readFileSync(yamlPath, "utf8").split(/\r?\n/);
    let section = null;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("humanOnly:")) {
        section = "humanOnly";
      } else if (trimmed.startsWith("humanApprove:")) {
        section = "humanApprove";
      } else if (trimmed.endsWith(":") && !trimmed.startsWith("#")) {
        section = null;
      } else if (trimmed.startsWith("-") && section !== null) {
        const item = trimmed
          .replace(/^-\s*["']?/, "")
          .replace(/["']?\s*$/, "");
        if (item.length > 0) {
          if (section === "humanOnly") humanOnly.push(item);
          else if (section === "humanApprove") humanApprove.push(item);
        }
      }
    }
  }

  for (const def of DEFAULT_HUMAN_ONLY_PATTERNS) {
    if (!humanOnly.includes(def)) humanOnly.push(def);
  }
  for (const def of DEFAULT_HUMAN_APPROVE_PATTERNS) {
    if (!humanApprove.includes(def)) humanApprove.push(def);
  }
  return { humanOnly, humanApprove };
}

/**
 * Checks if a normalized file path matches a policy pattern.
 *
 * @param {string} normalizedPath
 * @param {string} pattern
 * @returns {boolean}
 */
export function isPathMatchingPattern(normalizedPath, pattern) {
  const normPat = normalizePath(pattern);
  if (normPat.endsWith("/**")) {
    const prefix = normPat.slice(0, -3);
    return normalizedPath === prefix || normalizedPath.startsWith(prefix + "/");
  }
  if (normPat.endsWith("*")) {
    const prefix = normPat.slice(0, -1);
    return normalizedPath.startsWith(prefix);
  }
  return normalizedPath === normPat || normalizedPath.endsWith("/" + normPat);
}

/**
 * Checks if a given file path matches any humanOnly pattern.
 *
 * @param {string} filePath
 * @param {string[]} [patterns]
 * @returns {boolean}
 */
export function isHumanOnlyPath(filePath, patterns) {
  const norm = normalizePath(filePath);
  const rulePatterns = patterns ?? loadPathPolicies().humanOnly;
  return rulePatterns.some((pattern) => isPathMatchingPattern(norm, pattern));
}

/**
 * Checks if a given file path matches any humanApprove pattern.
 *
 * @param {string} filePath
 * @param {string[]} [patterns]
 * @returns {boolean}
 */
export function isHumanApprovePath(filePath, patterns) {
  const norm = normalizePath(filePath);
  const rulePatterns = patterns ?? loadPathPolicies().humanApprove;
  return rulePatterns.some((pattern) => isPathMatchingPattern(norm, pattern));
}

// ---------------------------------------------------------------------------
// Source scanners (MP-002 weakenings / MP-003 swallowed exceptions)
// ---------------------------------------------------------------------------

/**
 * Strips comments and string/template literals from source text (F1
 * string-concealment semantics: an `process.exit` mentioned only inside a
 * string or comment never satisfies a scanner).
 *
 * @param {string} text
 * @returns {string}
 */
function stripConcealment(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/(["'`])(?:\\.|(?!\1)[\s\S])*?\1/g, "");
}

/**
 * Scans source for test weakenings (MP-002): `.skip`, `.only`, `.todo`,
 * bracket-string forms, `xit`/`xtest`/`xdescribe`, `t.skip()`, `{skip:true}`.
 *
 * @param {string} sourceCode
 * @param {string} [filename]
 * @returns {{ ok: boolean, count: number, details: string[] }}
 */
export function checkTestWeakenings(sourceCode, filename) {
  const patterns = [
    /\b(?:it|test|describe|context|suite)\s*\.\s*(?:skip|only|todo)\b/g,
    /\bx(?:it|test|describe)\b/g,
    /\b(?:it|test|describe)\s*\[\s*['"`](?:skip|only|todo)['"`]\s*\]/g,
    /\bt\s*\.\s*(?:skip|todo)\s*\(/g,
    /\{\s*skip\s*:\s*(?:true|1)\s*\}/g,
  ];

  let totalCount = 0;
  for (const re of patterns) {
    const matches = sourceCode.match(re);
    if (matches) totalCount += matches.length;
  }

  return {
    ok: totalCount === 0,
    count: totalCount,
    details:
      totalCount > 0
        ? [`Found ${totalCount} test weakening construct(s) in ${filename ?? "source"}`]
        : [],
  };
}

/**
 * Scans source for swallowed exceptions (MP-003): empty catch blocks,
 * no-op promise `.catch()` handlers, and uncaughtException /
 * unhandledRejection handlers that neither rethrow nor exit. Concealment
 * via strings, template literals, or comments is stripped first (F1).
 *
 * @param {string} sourceCode
 * @param {string} [filename]
 * @returns {{ ok: boolean, violations: Array<{ file?: string, pattern: string, line: number }> }}
 */
export function checkSwallowedExceptions(sourceCode, filename) {
  const violations = [];

  function isEffectivelyEmpty(bodyText) {
    let cleaned = bodyText
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "");
    cleaned = cleaned.replace(
      /if\s*\(\s*(?:0|false)\s*\)\s*(?:throw\s+[^;]+;?|\{[^}]*\})/g,
      "",
    );
    cleaned = cleaned.replace(/(["'`])(?:\\.|(?!\1)[\s\S])*?\1/g, "");
    cleaned = cleaned.replace(/\bvoid\s+[a-zA-Z0-9_$.]+/g, "");
    cleaned = cleaned.replace(/\b(?:const|let|var)\s+[a-zA-Z0-9_$]+\s*=\s*;/g, "");
    cleaned = cleaned.replace(/[{};]/g, "").trim();
    return cleaned.length === 0;
  }

  // 1. Standard catch blocks (balanced braces, string-aware).
  const catchStartRegex = /catch\s*(?:\([^)]*\))?\s*\{/g;
  let match;
  while ((match = catchStartRegex.exec(sourceCode)) !== null) {
    const { body, endIdx } = extractBalancedBlock(sourceCode, match.index + match[0].length);
    if (isEffectivelyEmpty(body)) {
      violations.push({
        file: filename,
        pattern: sourceCode.slice(match.index, endIdx),
        line: sourceCode.slice(0, match.index).split("\n").length,
      });
    }
  }

  // 2. Promise .catch(): .catch(() => {}), .catch(e => { void e }), .catch(function() {})
  const promiseCatchRegex =
    /\.catch\s*\(\s*(?:async\s*)?(?:(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>\s*\{([^}]*)\})|(?:function\s*\([^)]*\)\s*\{([^}]*)\})|(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>\s*([^,)\n]*)))\s*\)/g;
  while ((match = promiseCatchRegex.exec(sourceCode)) !== null) {
    const body = match[1] ?? match[2] ?? match[3] ?? "";
    if (isEffectivelyEmpty(body)) {
      violations.push({
        file: filename,
        pattern: match[0],
        line: sourceCode.slice(0, match.index).split("\n").length,
      });
    }
  }

  // 3. Global uncaughtException / unhandledRejection handlers must rethrow
  //    or exit — after concealment stripping (F1).
  const uncaughtHeaderRegex =
    /process\s*\.\s*(?:on|once|addListener|prependListener)\s*\(\s*['"](?:uncaughtException|unhandledRejection)['"]\s*,\s*(?:async\s*)?(?:(?:(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>|function\s*(?:[a-zA-Z0-9_$]+\s*)?\([^)]*\))\s*(\{)?)|([a-zA-Z0-9_$.]+))/g;
  while ((match = uncaughtHeaderRegex.exec(sourceCode)) !== null) {
    const hasBrace = match[1] === "{";
    let handlerBody = "";
    let uncaughtEnd = match.index + match[0].length;

    if (hasBrace) {
      const res = extractBalancedBlock(sourceCode, match.index + match[0].length);
      handlerBody = res.body;
      uncaughtEnd = res.endIdx;
    } else {
      let pCount = 1;
      let idx = match.index + match[0].length;
      while (idx < sourceCode.length && pCount > 0) {
        if (sourceCode[idx] === "(") pCount++;
        else if (sourceCode[idx] === ")") pCount--;
        if (pCount > 0) handlerBody += sourceCode[idx];
        idx++;
      }
      uncaughtEnd = idx;
    }

    const strippedBody = stripConcealment(handlerBody);
    if (isEffectivelyEmpty(handlerBody) || !/(?:process\.exit|throw\b)/.test(strippedBody)) {
      violations.push({
        file: filename,
        pattern: sourceCode.slice(match.index, uncaughtEnd),
        line: sourceCode.slice(0, match.index).split("\n").length,
        detail: "Empty or non-rethrowing uncaughtException / unhandledRejection handler",
      });
    }
  }

  return { ok: violations.length === 0, violations };
}

/**
 * Extracts a balanced `{ ... }` block starting after the opening brace,
 * skipping over string literals and comments.
 *
 * @param {string} sourceCode
 * @param {number} startIdx
 * @returns {{ body: string, endIdx: number }}
 */
function extractBalancedBlock(sourceCode, startIdx) {
  let braceCount = 1;
  let idx = startIdx;
  let body = "";
  while (idx < sourceCode.length && braceCount > 0) {
    const ch = sourceCode[idx];
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      body += ch;
      idx++;
      while (idx < sourceCode.length) {
        const qCh = sourceCode[idx];
        body += qCh;
        if (qCh === "\\") {
          idx++;
          if (idx < sourceCode.length) body += sourceCode[idx];
        } else if (qCh === quote) {
          break;
        }
        idx++;
      }
    } else if (ch === "/" && sourceCode[idx + 1] === "/") {
      while (idx < sourceCode.length && sourceCode[idx] !== "\n") {
        body += sourceCode[idx];
        idx++;
      }
    } else if (ch === "/" && sourceCode[idx + 1] === "*") {
      body += "/*";
      idx += 2;
      while (
        idx < sourceCode.length - 1 &&
        !(sourceCode[idx] === "*" && sourceCode[idx + 1] === "/")
      ) {
        body += sourceCode[idx];
        idx++;
      }
      if (idx < sourceCode.length - 1) {
        body += "*/";
        idx += 2;
        continue;
      }
    } else {
      if (ch === "{") braceCount++;
      else if (ch === "}") braceCount--;
      if (braceCount > 0) body += ch;
    }
    idx++;
  }
  return { body, endIdx: idx };
}

// ---------------------------------------------------------------------------
// The rule engine
// ---------------------------------------------------------------------------

/**
 * Collects every file path a PR document claims to touch.
 *
 * @param {object} prDoc
 * @returns {string[]}
 */
function collectChangedFiles(prDoc) {
  const diffStat = prDoc.diff_stat ?? {};
  const evidence = prDoc.evidence ?? {};
  const files = [
    ...(Array.isArray(diffStat.files_changed) ? diffStat.files_changed : []),
    ...(Array.isArray(prDoc.modifiedFiles) ? prDoc.modifiedFiles : []),
    ...(Array.isArray(evidence.forbidden_paths_touched)
      ? evidence.forbidden_paths_touched
      : []),
  ];
  return [...new Set(files)];
}

/**
 * Resolves the Law 13 delta_phi from a PR document: explicit delta_phi wins,
 * else phi_head - phi_base when both are safe integers, else undefined.
 *
 * @param {object} prDoc
 * @returns {number | undefined}
 */
function resolveDeltaPhi(prDoc) {
  const phi = prDoc.phi ?? {};
  if (Number.isSafeInteger(phi.delta_phi)) return phi.delta_phi;
  if (Number.isSafeInteger(phi.phi_base) && Number.isSafeInteger(phi.phi_head)) {
    return phi.phi_head - phi.phi_base;
  }
  return undefined;
}

/**
 * Fails the evaluation with a rule result.
 *
 * @param {string} rule
 * @param {string} violation
 * @param {string} verdict
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
 * Evaluates a PR / outcome document against MP-000..MP-005 and Law 13.
 *
 * Deterministic and pure with respect to `prDoc`: it never consults
 * `expected_verdict`, `expected_rule` or `violation_type`. Options:
 * - `rootDir`        — repo root for policy/paths.yaml (default: cwd)
 * - `targetTipSha`   — authoritative target tip SHA for MP-004 (CLI --base)
 * - `expectedHeadSha`— authoritative head SHA for MP-004 (CLI --head)
 * - `humanApproved`  — explicit affirmative human sign-off (unlocks MP-005)
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
  const filesChanged = collectChangedFiles(prDoc);
  const policies = loadPathPolicies(options.rootDir);
  const humanApproved =
    options.humanApproved === true ||
    prDoc.human_approved === true ||
    prDoc.human_approval === true ||
    evidence.human_approval === true;

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
    (Number.isSafeInteger(proof.test_count_base) &&
      Number.isSafeInteger(proof.test_count_head) &&
      proof.test_count_head < proof.test_count_base) ||
    (Number.isSafeInteger(proof.cases_dropped) && proof.cases_dropped > 0);

  if (testsDeleted.length > 0 || countDrop) {
    checks.tests_deleted = false;
    return fail(
      "MP-002",
      "TEST_DELETED",
      "reject",
      evidence.detail ??
        "PR deleted existing test file(s) or decreased total test suite count.",
      { checks, tests_deleted: testsDeleted },
    );
  }

  // Source-level test weakenings (when source is supplied).
  const weakenResult = scanSources(prDoc.sourceCode ?? prDoc.sources, checkTestWeakenings);
  if (weakenResult !== null) {
    checks.tests_deleted = false;
    return fail(
      "MP-002",
      "TEST_DELETED",
      "reject",
      `Test weakenings detected in ${weakenResult.file}: ${weakenResult.details.join("; ")}`,
      { checks },
    );
  }

  // --- MP-003: ANTI_CHEAT_VIOLATION ----------------------------------------
  // Do NOT trust a self-reported violations_count === 0 when flags or
  // details exist — and never honor violations_count > 0 as clean either.
  const flagged =
    (Array.isArray(antiCheat.flags) &&
      (antiCheat.flags.includes("SWALLOWED_EXCEPTION") ||
        antiCheat.flags.includes("EMPTY_CATCH_BLOCK"))) ||
    (Array.isArray(antiCheat.details) && antiCheat.details.length > 0) ||
    (Number.isSafeInteger(antiCheat.violations_count) &&
      antiCheat.violations_count > 0);

  if (flagged) {
    checks.anti_cheat = false;
    return fail(
      "MP-003",
      "ANTI_CHEAT_VIOLATION",
      "reject",
      evidence.detail ??
        "PR swallowed error exceptions using empty catch blocks (anti-cheat scan failed).",
      { checks, flags: antiCheat.flags ?? ["SWALLOWED_EXCEPTION"] },
    );
  }

  const swallowResult = scanSources(
    prDoc.sourceCode ?? prDoc.sources,
    (code, file) => checkSwallowedExceptions(code, file),
    (result) => result.ok,
  );
  if (swallowResult !== null) {
    checks.anti_cheat = false;
    return fail(
      "MP-003",
      "ANTI_CHEAT_VIOLATION",
      "reject",
      `Source contains swallowed exception(s) in ${swallowResult.file} (line ${swallowResult.line}).`,
      { checks, flags: ["SWALLOWED_EXCEPTION"] },
    );
  }

  // --- MP-004: STALE_BASE ---------------------------------------------------
  const claimedBase =
    (typeof pr.base_sha === "string" && pr.base_sha) ||
    (typeof evidence.claimed_base_sha === "string" && evidence.claimed_base_sha) ||
    null;
  const currentTip =
    typeof options.targetTipSha === "string" && options.targetTipSha.length > 0
      ? options.targetTipSha
      : typeof evidence.current_tip_sha === "string"
        ? evidence.current_tip_sha
        : null;
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

  if (
    leaseExpired ||
    (claimedBase !== null && currentTip !== null && claimedBase !== currentTip) ||
    headMismatch
  ) {
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

  // C1 (causal proof): ONLY a completed causal cycle (or a human sign-off)
  // unlocks humanApprove surfaces; a self-reported suite_pass_head never does.
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
  if (deltaPhi !== undefined && deltaPhi > 0) {
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
    if (deltaPhi !== undefined && deltaPhi >= 0) {
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
  // Fail closed: clean causal proof means proof.causal_cycle_completed === true
  // OR a proven suite pass (suite_pass_base AND suite_pass_head — the
  // consolidation path). Anything less is MISSING_PROOF.
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
 * returning the first failing file description or null when everything is
 * clean.
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
