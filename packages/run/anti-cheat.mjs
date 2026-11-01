import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";

/**
 * Default humanOnly patterns if policy/paths.yaml cannot be loaded.
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

/**
 * Normalizes a file path:
 * - Backslashes to forward slashes
 * - Strip trailing dots from path segments (preserving . and ..)
 * - Resolve relative `.` and `..` segments
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
 * Loads path policies from policy/paths.yaml.
 *
 * @param {string} [rootDir=process.cwd()]
 * @returns {{ humanOnly: string[], humanApprove: string[] }}
 */
export function loadPathPolicies(rootDir = process.cwd()) {
  const yamlPath = join(rootDir, "policy", "paths.yaml");
  if (!existsSync(yamlPath)) {
    return {
      humanOnly: [...DEFAULT_HUMAN_ONLY_PATTERNS],
      humanApprove: [...DEFAULT_HUMAN_APPROVE_PATTERNS],
    };
  }

  let content;
  try {
    content = readFileSync(yamlPath, "utf8");
  } catch (err) {
    throw new Error(`Failed to read policy/paths.yaml: ${err.message}`);
  }

  const lines = content.split(/\r?\n/);
  let section = null;
  const humanOnly = [];
  const humanApprove = [];

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
        if (section === "humanOnly") {
          humanOnly.push(item);
        } else if (section === "humanApprove") {
          humanApprove.push(item);
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
 * Loads humanOnly patterns from policy/paths.yaml.
 *
 * @param {string} [rootDir=process.cwd()]
 * @returns {string[]}
 */
export function loadHumanOnlyPatterns(rootDir = process.cwd()) {
  return loadPathPolicies(rootDir).humanOnly;
}

/**
 * Checks if a normalized file path matches a pattern.
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
  return (
    normalizedPath === normPat ||
    normalizedPath.endsWith("/" + normPat)
  );
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
  const rulePatterns = patterns ?? loadHumanOnlyPatterns();
  for (const pattern of rulePatterns) {
    if (isPathMatchingPattern(norm, pattern)) return true;
  }
  return false;
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
  for (const pattern of rulePatterns) {
    if (isPathMatchingPattern(norm, pattern)) return true;
  }
  return false;
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
 * Scans source code for empty catch blocks that swallow exceptions (MP-003).
 * Catches:
 * - `catch(e){;}`
 * - `catch(e){ void e }`
 * - `.catch(() => {})`
 * - `catch(e){ /* ignore *\/ }`
 * - `catch(e){ if(0) throw e }`
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

    // Strip dead throws like `if (0) throw e` or `if (false) { throw e; }`
    cleaned = cleaned.replace(
      /if\s*\(\s*(?:0|false)\s*\)\s*(?:throw\s+[^;]+;?|\{[^}]*\})/g,
      "",
    );

    // Strip void expressions like `void e` or `void 0`
    cleaned = cleaned.replace(/\bvoid\s+[a-zA-Z0-9_$.]+/g, "");

    // Strip semicolons, empty blocks, and whitespace
    cleaned = cleaned.replace(/[{};]/g, "").trim();

    return cleaned.length === 0;
  }

  // 1. Standard catch blocks: parse with balanced braces
  const catchStartRegex = /catch\s*(?:\([^)]*\))?\s*\{/g;
  let match;
  while ((match = catchStartRegex.exec(sourceCode)) !== null) {
    let braceCount = 1;
    let idx = match.index + match[0].length;
    let body = "";
    while (idx < sourceCode.length && braceCount > 0) {
      const ch = sourceCode[idx];
      if (ch === "{") braceCount++;
      else if (ch === "}") braceCount--;
      if (braceCount > 0) body += ch;
      idx++;
    }

    if (isEffectivelyEmpty(body)) {
      const upToMatch = sourceCode.slice(0, match.index);
      const line = upToMatch.split("\n").length;
      violations.push({
        file: filename,
        pattern: sourceCode.slice(match.index, idx),
        line,
      });
    }
  }

  // 2. Promise .catch(): .catch(() => {}), .catch(e => { void e }), .catch(function() {})
  const promiseCatchRegex =
    /\.catch\s*\(\s*(?:async\s*)?(?:(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>\s*\{([^}]*)\})|(?:function\s*\([^)]*\)\s*\{([^}]*)\})|(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>\s*([^,)\n]*)))\s*\)/g;
  while ((match = promiseCatchRegex.exec(sourceCode)) !== null) {
    const arrowBody = match[1];
    const funcBody = match[2];
    const exprBody = match[3];
    const body = arrowBody ?? funcBody ?? exprBody ?? "";

    if (isEffectivelyEmpty(body)) {
      const upToMatch = sourceCode.slice(0, match.index);
      const line = upToMatch.split("\n").length;
      violations.push({
        file: filename,
        pattern: match[0],
        line,
      });
    }
  }

  return {
    ok: violations.length === 0,
    violations,
  };
}

/**
 * Scans source code for test weakenings (MP-002):
 * - `.skip`: `it.skip`, `test.skip`, `describe.skip`
 * - `.only`: `it.only`, `test.only`, `describe.only`
 * - `.todo`: `it.todo`, `test.todo`
 * - `{skip:true}` / `{skip: 1}`
 * - `t.skip()`
 * - `describe['skip']`, `it['skip']`, `test['skip']`
 * - `xit`, `xtest`, `xdescribe`
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
        detail: "Test weakenings (skipped/only/todo tests) detected in source.",
      };
    }
  }

  // 3. MP-003: ANTI_CHEAT_VIOLATION (swallowed exceptions)
  // Do NOT trust self-reported violations_count if flags or details exist!
  const hasSwallowedFlags =
    (Array.isArray(antiCheat.flags) &&
      (antiCheat.flags.includes("SWALLOWED_EXCEPTION") ||
        antiCheat.flags.includes("EMPTY_CATCH_BLOCK"))) ||
    (Array.isArray(antiCheat.details) && antiCheat.details.length > 0);

  if (hasSwallowedFlags) {
    return {
      ok: false,
      rule: "MP-003",
      violation: "ANTI_CHEAT_VIOLATION",
      verdict: "reject",
      detail:
        evidence.detail ??
        "PR swallowed error exceptions using empty catch blocks.",
      flags: antiCheat.flags ?? ["SWALLOWED_EXCEPTION"],
    };
  }

  if (typeof input.sourceCode === "string") {
    const catchCheck = checkSwallowedExceptions(input.sourceCode);
    if (!catchCheck.ok) {
      return {
        ok: false,
        rule: "MP-003",
        violation: "ANTI_CHEAT_VIOLATION",
        verdict: "reject",
        detail: "Source contains empty catch block swallowing exceptions.",
        flags: ["SWALLOWED_EXCEPTION"],
      };
    }
  }

  // 4. MP-004: STALE_BASE
  const isStaleBase =
    (evidence.claimed_base_sha &&
      evidence.current_tip_sha &&
      evidence.claimed_base_sha !== evidence.current_tip_sha) ||
    (typeof evidence.elapsed_since_lease_ms === "number" &&
      typeof evidence.lease_ttl_ms === "number" &&
      evidence.elapsed_since_lease_ms > evidence.lease_ttl_ms);

  if (isStaleBase) {
    return {
      ok: false,
      rule: "MP-004",
      violation: "STALE_BASE",
      verdict: "reject",
      detail:
        evidence.detail ??
        "Claimed base SHA does not match current tip or lease TTL expired.",
    };
  }

  // 5. MP-005: UNCITED_SURFACE / humanApprove paths
  const isUncitedSurface =
    (Array.isArray(surface.uncited_commands) && surface.uncited_commands.length > 0) ||
    (typeof surface.delta_count === "number" &&
      surface.delta_count > 0 &&
      !surface.roadmap_ref);

  // C1: causal proof STRICTLY requires the completed triple-execution cycle.
  // A self-reported `suite_pass_head` is not causal evidence and must not
  // unlock humanApprove surfaces (MP-005).
  const hasCausalProof = proof?.causal_cycle_completed === true;

  const humanApproveCheck = checkHumanApprovePaths(filesChanged);
  const touchesHumanApproveWithoutApproval =
    !humanApproveCheck.ok &&
    !hasCausalProof &&
    !input.human_approved &&
    !input.human_approval &&
    !evidence.human_approval;

  if (isUncitedSurface || touchesHumanApproveWithoutApproval) {
    return {
      ok: false,
      rule: "MP-005",
      violation: "UNCITED_SURFACE",
      verdict: "needs_human",
      detail:
        evidence.detail ??
        (isUncitedSurface
          ? "PR modified public surface without cited roadmap reference."
          : `PR touched humanApprove path(s) [${humanApproveCheck.paths.join(", ")}] without affirmative human authorization.`),
    };
  }

  // All rules satisfied: auto_merge
  return {
    ok: true,
    rule: "MP-000",
    verdict: "auto_merge",
  };
}
