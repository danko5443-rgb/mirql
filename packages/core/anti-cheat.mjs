// packages/core/anti-cheat.mjs — canonical AST anti-cheat scanners and path policy checkers.
// Shared by packages/run, packages/mergeproof, and verification gates (Law 13: zero duplication).

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Default humanOnly patterns if policy/paths.yaml cannot be loaded.
 */
export const DEFAULT_HUMAN_ONLY_PATTERNS = Object.freeze([
  "CONSTITUTION.md",
  "NOT-ROADMAP.md",
  "policy/**",
  ".github/**",
  "roles/judge.md",
  ".coderabbit.yaml",
  ".coderabbit.yml",
  "AGENTS.md",
]);

/**
 * Default humanApprove patterns if policy/paths.yaml cannot be loaded.
 */
export const DEFAULT_HUMAN_APPROVE_PATTERNS = Object.freeze([
  "bin/**",
  "scripts/**",
  "conformance/**",
  "schemas/**",
  "packages/core/**",
  "packages/log/**",
  "packages/queue/**",
  "packages/run/verify*",
  "package.json",
]);

/**
 * Normalizes a file path for policy matching:
 * - Backslashes to forward slashes
 * - Collapse multiple slashes
 * - Resolve relative . and .. segments
 * - Strip trailing dots from segments
 * - Lowercase for case-insensitive matching
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
 * Canonical test file path check (Phase 3.6).
 * Matches test directory prefix or test file suffix.
 *
 * @param {string} p
 * @returns {boolean}
 */
export function isTestFilePath(p) {
  if (typeof p !== "string") return false;
  const norm = normalizePath(p);
  return (
    /(?:^|\/)tests?(?:\/|$)/.test(norm) ||
    norm.includes("/__tests__/") ||
    /\.(?:test|spec)\.[cm]?[jt]s$/.test(norm)
  );
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
 * Loads path policies from <rootDir>/policy/paths.yaml, falling back to canonical defaults.
 *
 * @param {string} [rootDir=process.cwd()]
 * @returns {{ humanOnly: string[], humanApprove: string[], aiReviewers: string[] }}
 */
export function loadPathPolicies(rootDir = process.cwd()) {
  const pathsFile = join(rootDir, "policy", "paths.yaml");
  let content = "";
  if (existsSync(pathsFile)) {
    try { content = readFileSync(pathsFile, "utf8"); }
    catch (error) {
      // An unreadable policy file falls back to the mandatory default guards.
      content = "";
      void error;
    }
  }
  return parsePathPolicies(content);
}

/** Parse a captured policy document, retaining the mandatory default guards. */
export function parsePathPolicies(content = "") {
  const humanOnly = [];
  const humanApprove = [];
  const aiReviewers = [];
  let currentSection = null;
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("humanOnly:")) {
      currentSection = "humanOnly";
      continue;
    }
    if (trimmed.startsWith("humanApprove:")) {
      currentSection = "humanApprove";
      continue;
    }
    if (trimmed.startsWith("aiReviewers:")) {
      currentSection = "aiReviewers";
      continue;
    }
    // Any other top-level key ends the current list.
    if (/^[A-Za-z_][\w-]*:/.test(trimmed)) {
      currentSection = null;
      continue;
    }
    if (trimmed.startsWith("-")) {
      const val = trimmed.replace(/^-\s*/, "").replace(/["']/g, "").trim();
      if (val) {
        if (currentSection === "humanOnly") humanOnly.push(val);
        else if (currentSection === "humanApprove") humanApprove.push(val);
        else if (currentSection === "aiReviewers") aiReviewers.push(val);
      }
    }
  }

  for (const def of DEFAULT_HUMAN_ONLY_PATTERNS) {
    if (!humanOnly.includes(def)) humanOnly.push(def);
  }
  for (const def of DEFAULT_HUMAN_APPROVE_PATTERNS) {
    if (!humanApprove.includes(def)) humanApprove.push(def);
  }

  return { humanOnly, humanApprove, aiReviewers };
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
 * Extract a balanced `{ ... }` block from source code starting after `{`,
 * correctly skipping string literals, template literals, comments, and regex literals.
 *
 * @param {string} sourceCode
 * @param {number} startIdx - index immediately after the opening `{`
 * @returns {{ body: string, endIdx: number }}
 */
export function extractBalancedBlock(sourceCode, startIdx) {
  let braceCount = 1;
  let idx = startIdx;
  let body = "";

  while (idx < sourceCode.length && braceCount > 0) {
    const ch = sourceCode[idx];

    // String literals and template literals
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
      // Line comment
      while (idx < sourceCode.length && sourceCode[idx] !== "\n") {
        body += sourceCode[idx];
        idx++;
      }
      if (idx < sourceCode.length) body += sourceCode[idx];
    } else if (ch === "/" && sourceCode[idx + 1] === "*") {
      // Block comment
      body += "/*";
      idx += 2;
      while (idx < sourceCode.length - 1 && !(sourceCode[idx] === "*" && sourceCode[idx + 1] === "/")) {
        body += sourceCode[idx];
        idx++;
      }
      if (idx < sourceCode.length - 1) {
        body += "*/";
        idx += 2;
        continue;
      }
    } else if (ch === "/") {
      // Regex literal vs division operator:
      // A slash starts a regex literal if preceded by punctuation/operator/keyword,
      // not by an identifier or closing paren/bracket.
      const prevTrimmed = body.trimEnd();
      const prevChar = prevTrimmed.slice(-1);
      const isRegexStart =
        !prevChar ||
        /[=([,:;!&|?{}]/.test(prevChar) ||
        /\breturn$/.test(prevTrimmed);

      if (isRegexStart) {
        body += "/";
        idx++;
        while (idx < sourceCode.length) {
          const rCh = sourceCode[idx];
          body += rCh;
          if (rCh === "\\") {
            idx++;
            if (idx < sourceCode.length) body += sourceCode[idx];
          } else if (rCh === "/") {
            // Include trailing flags
            while (idx + 1 < sourceCode.length && /[a-z]/i.test(sourceCode[idx + 1])) {
              idx++;
              body += sourceCode[idx];
            }
            break;
          }
          idx++;
        }
      } else {
        body += ch;
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

/**
 * Checks if a catch block or handler body is effectively empty or dead code.
 *
 * @param {string} bodyText
 * @returns {boolean}
 */
export function isEffectivelyEmpty(bodyText) {
  let cleaned = bodyText
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");

  // Strip dead throws like `if (0) throw e` or `if (false) { throw e; }`
  cleaned = cleaned.replace(
    /if\s*\(\s*(?:0|false)\s*\)\s*(?:throw\s+[^;]+;?|\{[^}]*\})/g,
    "",
  );

  // Strip string literals
  cleaned = cleaned.replace(/(["'`])(?:\\.|(?!\1)[\s\S])*?\1/g, "");

  // Strip regex literals
  cleaned = cleaned.replace(/\/(?:\\.|[^\/\\\n])+\/[a-z]*/g, "");

  // Strip void expressions like `void e` or `void 0`
  cleaned = cleaned.replace(/\bvoid\s+[a-zA-Z0-9_$.]+/g, "");

  // Strip empty if/while/for statements (supporting arbitrary nested parentheses, e.g. if (f(e)) {})
  const branchRegex = /\b(?:if|while|for)\s*\(/g;
  let bm;
  while ((bm = branchRegex.exec(cleaned)) !== null) {
    let pCount = 1;
    let idx = bm.index + bm[0].length;
    while (idx < cleaned.length && pCount > 0) {
      if (cleaned[idx] === "(") pCount++;
      else if (cleaned[idx] === ")") pCount--;
      idx++;
    }
    if (pCount === 0) {
      const rest = cleaned.slice(idx);
      const afterParen = rest.match(/^\s*(?:\{\s*\}|;)/);
      if (afterParen) {
        const matchLen = (idx - bm.index) + afterParen[0].length;
        cleaned = cleaned.slice(0, bm.index) + cleaned.slice(bm.index + matchLen);
        branchRegex.lastIndex = bm.index;
      }
    }
  }

  // Strip variable declarations with no-op or dead assignments or empty initializers
  cleaned = cleaned.replace(
    /\b(?:const|let|var)\s+[a-zA-Z0-9_$]+\s*(?:=\s*(?:\{\s*\}|\[\s*\]|null|undefined|void\s+[a-zA-Z0-9_$.]+|true|false)?)?\s*;/g,
    "",
  );

  // Strip semicolons, empty blocks, and whitespace
  cleaned = cleaned.replace(/[{};]/g, "").trim();

  return cleaned.length === 0;
}

/**
 * A catch body that only names the caught error (`e`, `e;`, `void e`) is a swallow
 * with extra steps: the exception is observed and discarded, which MP-003 refuses
 * exactly like an empty body. The marker rules are unchanged.
 */
export function isErrorReferenceOnly(bodyText, paramName) {
  if (typeof paramName !== "string" || !/^[A-Za-z_$][\w$]*$/.test(paramName)) return false;
  const cleaned = bodyText
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/(["'`])(?:\\.|(?!\1)[\s\S])*?\1/g, "")
    .trim();
  // `$` is legal in identifiers and an anchor in a RegExp: escape it so `e$` cannot forge a pattern.
  const literal = paramName.replace(/\$/g, "\\$");
  return new RegExp(`^(?:void\\s+)?${literal};?$`).test(cleaned);
}

/**
 * MP-003 exemption marker: `// mp-003-allow: <reason>` (or the block-comment
 * form) in a catch body records why the silence is intended. The comment comes
 * from the source being scanned, so it proves nothing by itself: it only exempts
 * a catch the candidate left untouched, which means it was already accepted into
 * the base. Nothing here checks that a reviewer read it; that is the base's job.
 */
const MP003_ALLOW_RE = /(?:\/\/|\/\*)\s*mp-003-allow\s*:/i;
const MP003_MARKER_REFUSED =
  "mp-003-allow marker refused: it only exempts a catch unchanged from the authoritative base, and this one was changed or its base could not be verified";

/**
 * Maps which characters of `sourceCode` never execute: line comments, block
 * comments, string literals, and template literals, delimiters included. Every
 * other character — live code, whitespace, newlines — maps to "0" at the same
 * index, so a regex match on the original text can be tested with
 * `mask[match.index] === "1"` without disturbing index or line math. Template
 * `${...}` interpolation bodies stay live code (they run); only the `${` and
 * its matching `}` belong to the literal. Regex literals are masked too, so a
 * quote inside `/['"`]/ cannot masquerade as a string opener and blind the
 * scan; telling them apart from division uses the same prev-token rule as
 * extractBalancedBlock, and an opening `/` that never closes on its own line
 * resumes live scanning at the line end.
 *
 * @param {string} sourceCode
 * @returns {string} same-length string of "0" (code) and "1" (literal) flags
 */
function computeLiteralMask(sourceCode) {
  const n = sourceCode.length;
  const flags = new Array(n).fill("0");
  const mark = (i) => { flags[i] = "1"; };
  // One frame per open `${`: the brace depth suspended when it opened, restored
  // when its matching `}` returns scanning to the template.
  const interps = [];
  let depth = 0;
  let state = "code";
  // Recent live, non-whitespace characters: the regex/division tiebreaker uses
  // the same rule as extractBalancedBlock — a `/` starts a regex literal only
  // after an operator/punctuator or `return`, never after an identifier or a
  // closing paren/bracket, which would make it division.
  let liveTail = "";
  const isRegexStart = () => {
    const prevChar = liveTail.slice(-1);
    return !prevChar || /[=([,:;!&|?{}]/.test(prevChar) || /\breturn$/.test(liveTail);
  };
  for (let i = 0; i < n; i++) {
    const ch = sourceCode[i];
    const next = i + 1 < n ? sourceCode[i + 1] : "";
    if (state === "code") {
      if (ch === "/" && next === "/") {
        mark(i); mark(i + 1); i++; state = "lineComment";
      } else if (ch === "/" && next === "*") {
        mark(i); mark(i + 1); i++; state = "blockComment";
      } else if (ch === "/") {
        if (isRegexStart()) { mark(i); state = "regex"; liveTail = ""; }
        else liveTail = (liveTail + ch).slice(-12);
      } else if (ch === "'" || ch === '"' || ch === "`") {
        mark(i); state = ch === "'" ? "single" : ch === '"' ? "double" : "template";
      } else if (interps.length > 0 && ch === "{") {
        depth++;
      } else if (interps.length > 0 && ch === "}") {
        if (depth === 0) { mark(i); depth = interps.pop(); state = "template"; }
        else depth--;
      } else if (!/\s/.test(ch)) {
        liveTail = (liveTail + ch).slice(-12);
      }
    } else if (state === "lineComment") {
      if (ch === "\n") state = "code"; else mark(i);
    } else if (state === "blockComment") {
      mark(i);
      if (ch === "*" && next === "/") { mark(i + 1); i++; state = "code"; }
    } else if (state === "single" || state === "double") {
      mark(i);
      if (ch === "\\") { if (next !== "") { mark(i + 1); i++; } }
      else if ((state === "single" && ch === "'") || (state === "double" && ch === '"')) state = "code";
    } else if (state === "regex") {
      mark(i);
      if (ch === "\\") { if (next !== "") { mark(i + 1); i++; } }
      else if (ch === "/") {
        while (i + 1 < n && /[a-z]/i.test(sourceCode[i + 1])) { mark(i + 1); i++; }
        state = "code"; liveTail = "";
      } else if (ch === "\n") {
        // A regex literal cannot span lines: an opening `/` that never closes
        // was really division or broken code. Resume live scanning next line.
        state = "code";
      }
    } else { // template
      mark(i);
      if (ch === "\\") { if (next !== "") { mark(i + 1); i++; } }
      else if (ch === "`") state = "code";
      else if (ch === "$" && next === "{") { mark(i); mark(i + 1); i++; interps.push(depth); depth = 0; state = "code"; }
    }
  }
  return flags.join("");
}

/**
 * Scans source code for empty catch blocks and swallowed exceptions (MP-003).
 *
 * @param {string} sourceCode
 * @param {string} [filename]
 * @param {{ changedLines?: Set<number> }} [scope] - 1-based lines of sourceCode the
 *   candidate changed, from a trusted source. A marker exempts a catch only when
 *   this is given and no line of the catch is in it. Omitted, no marker counts.
 *   Under a scope, a catch in a *test file* untouched by the candidate is also
 *   exempt without a marker: tests/ was never inside the marker ratchet, so its
 *   silence was already accepted into the base. Production files keep the exact
 *   marker contract.
 * @returns {{ ok: boolean, violations: Array<{ file?: string, pattern: string, line: number, detail?: string }> }}
 */
export function checkSwallowedExceptions(sourceCode, filename, { changedLines } = {}) {
  const violations = [];
  const lineAt = (idx) => sourceCode.slice(0, idx).split("\n").length;
  const literal = computeLiteralMask(sourceCode);
  const testFile = isTestFilePath(filename);
  const markerExempts = (text, startIdx, endIdx) => {
    if (!MP003_ALLOW_RE.test(text) || !(changedLines instanceof Set)) return false;
    for (let line = lineAt(startIdx), last = lineAt(endIdx); line <= last; line++) {
      if (changedLines.has(line)) return false;
    }
    return true;
  };
  // Test files were never inside the marker ratchet (it walks packages/, bin/,
  // scripts/), so under a scope an untouched catch there is base-accepted
  // silence: exempt it without demanding a marker. A catch the candidate
  // touched still flags, marker or not.
  const scopeExempts = (startIdx, endIdx) => {
    if (!testFile || !(changedLines instanceof Set)) return false;
    for (let line = lineAt(startIdx), last = lineAt(endIdx); line <= last; line++) {
      if (changedLines.has(line)) return false;
    }
    return true;
  };
  const describe = (text, detail) => (MP003_ALLOW_RE.test(text) ? MP003_MARKER_REFUSED : detail);

  // 1. Standard catch blocks: parse with balanced braces (ignoring strings, comments, regexes).
  //    A plain identifier parameter is captured for the reference-only check; a destructured
  //    binding `catch ({ message })` still matches (no capture), so it keeps its empty-body check.
  const catchStartRegex = /catch\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|\((?:[^)]*)\))?\s*\{/g;
  let match;
  while ((match = catchStartRegex.exec(sourceCode)) !== null) {
    if (literal[match.index] === "1") continue; // catch-shaped text in a comment or string never executes
    const { body, endIdx: catchEnd } = extractBalancedBlock(sourceCode, match.index + match[0].length);
    if ((isEffectivelyEmpty(body) || isErrorReferenceOnly(body, match[1])) && !markerExempts(body, match.index, catchEnd) && !scopeExempts(match.index, catchEnd)) {
      const upToMatch = sourceCode.slice(0, match.index);
      const line = upToMatch.split("\n").length;
      violations.push({
        file: filename,
        pattern: sourceCode.slice(match.index, catchEnd),
        line,
        detail: describe(body),
      });
    }
  }

  // 2. Promise .catch(): parse with balanced block extraction (never truncated by inner braces)
  const promiseCatchRegex = /\.catch\s*\(/g;
  let pcMatch;
  while ((pcMatch = promiseCatchRegex.exec(sourceCode)) !== null) {
    if (literal[pcMatch.index] === "1") continue; // .catch-shaped text in a comment or string never executes
    const afterParen = pcMatch.index + pcMatch[0].length;
    let idx = afterParen;
    let foundBrace = -1;
    let pCount = 1;
    while (idx < sourceCode.length && pCount > 0) {
      const ch = sourceCode[idx];
      if (ch === "(") pCount++;
      else if (ch === ")") pCount--;
      else if (ch === "{" && foundBrace === -1) {
        foundBrace = idx;
        break;
      }
      idx++;
    }

    if (foundBrace !== -1) {
      const { body, endIdx } = extractBalancedBlock(sourceCode, foundBrace + 1);
      // Handler head: `(x) =>`, `x =>`, or `function (x)` / `function name(x)`.
      const arrowParam = /(?:(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|\b([A-Za-z_$][\w$]*))\s*=>|function\s*(?:[A-Za-z_$][\w$]*\s*)?\(\s*([A-Za-z_$][\w$]*)\s*\))\s*\{?\s*$/.exec(sourceCode.slice(afterParen, foundBrace + 1));
      const arrowParamName = arrowParam ? (arrowParam[1] ?? arrowParam[2] ?? arrowParam[3]) : null;
      if ((isEffectivelyEmpty(body) || isErrorReferenceOnly(body, arrowParamName)) && !markerExempts(body, pcMatch.index, endIdx) && !scopeExempts(pcMatch.index, endIdx)) {
        const upToMatch = sourceCode.slice(0, pcMatch.index);
        const line = upToMatch.split("\n").length;
        violations.push({
          file: filename,
          pattern: sourceCode.slice(pcMatch.index, endIdx + 1),
          line,
          detail: describe(body, "Swallowed Promise .catch() block"),
        });
      }
    } else {
      let p2 = 1;
      let j = afterParen;
      while (j < sourceCode.length && p2 > 0) {
        const ch = sourceCode[j];
        if (ch === "(") p2++;
        else if (ch === ")") {
          p2--;
          if (p2 === 0) break;
        }
        j++;
      }
      const argStr = sourceCode.slice(afterParen, j).trim();
      const arrowMatch = argStr.match(/=>\s*(.*)$/);
      if (arrowMatch) {
        const expr = arrowMatch[1].trim();
        const exprParam = /(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|\b([A-Za-z_$][\w$]*))\s*=>/.exec(argStr);
        const exprParamName = exprParam ? (exprParam[1] ?? exprParam[2]) : null;
        if ((isEffectivelyEmpty(expr) || isErrorReferenceOnly(expr, exprParamName)) && !markerExempts(expr, pcMatch.index, j) && !scopeExempts(pcMatch.index, j)) {
          const upToMatch = sourceCode.slice(0, pcMatch.index);
          const line = upToMatch.split("\n").length;
          violations.push({
            file: filename,
            pattern: sourceCode.slice(pcMatch.index, j + 1),
            line,
            detail: describe(expr, "Swallowed Promise .catch() expression"),
          });
        }
      }
    }
  }

  // 3. Global uncaughtException / unhandledRejection swallowing
  const uncaughtHeaderRegex =
    /process\s*\.\s*(?:on|once|addListener|prependListener)\s*\(\s*['"](?:uncaughtException|unhandledRejection)['"]\s*,\s*(?:async\s*)?(?:(?:(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>|function\s*(?:[a-zA-Z0-9_$]+\s*)?\([^)]*\))\s*(\{)?)|([a-zA-Z0-9_$.]+))/g;

  while ((match = uncaughtHeaderRegex.exec(sourceCode)) !== null) {
    if (literal[match.index] === "1") continue; // handler-shaped text in a comment or string never executes
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

    // Strip comments, strings, template literals, and regex literals
    const strippedBody = handlerBody
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "")
      .replace(/(["'`])(?:\\.|(?!\1)[\s\S])*?\1/g, "")
      .replace(/\/(?:\\.|[^\/\\\n])+\/[a-z]*/g, "");

    // Must call process.exit(...) or throw an error
    const hasExitCall = /\bprocess\s*\.\s*exit\s*\(/.test(strippedBody);
    const hasThrow = /\bthrow\b/.test(strippedBody);

    if ((isEffectivelyEmpty(handlerBody) || (!hasExitCall && !hasThrow)) && !scopeExempts(match.index, uncaughtEnd)) {
      const upToMatch = sourceCode.slice(0, match.index);
      const line = upToMatch.split("\n").length;
      violations.push({
        file: filename,
        pattern: sourceCode.slice(match.index, uncaughtEnd),
        line,
        detail: "Empty or non-rethrowing uncaughtException / unhandledRejection handler",
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
 * Weakening-shaped text inside comments and string/template literals never
 * executes, so it is ignored: a fixture that quotes `it.skip(...)` to prove the
 * gate catches it is not itself a weakening. Under a changed-line scope only
 * lines the candidate touched count, so a pre-existing `t.skip(...)` on an
 * untouched line cannot lock a PR out; without a scope every live match counts.
 *
 * @param {string} sourceCode
 * @param {string} [filename]
 * @param {{ changedLines?: Set<number> }} [scope] - 1-based lines of sourceCode the
 *   candidate changed, from a trusted source.
 * @returns {{ ok: boolean, count: number, details: string[] }}
 */
export function checkTestWeakenings(sourceCode, filename, { changedLines } = {}) {
  const patterns = [
    /\b(?:it|test|describe|context|suite)\s*\.\s*(?:skip|only|todo)\b/g,
    /\bx(?:it|test|describe)\b/g,
    /\b(?:it|test|describe)\s*\[\s*['"`](?:skip|only|todo)['"`]\s*\]/g,
    /\{\s*skip\s*:\s*(?:true|1)\s*\}/g,
    /\bt\s*\.\s*skip\s*\(/g,
  ];

  const literal = computeLiteralMask(sourceCode);
  const details = [];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(sourceCode)) !== null) {
      if (literal[m.index] === "1") continue; // weakening-shaped text in a comment or string never executes
      const upTo = sourceCode.slice(0, m.index);
      const line = upTo.split("\n").length;
      if (changedLines instanceof Set && !changedLines.has(line)) continue; // the candidate did not touch this line
      details.push(
        filename
          ? `${filename}:${line} matched weakening pattern ${m[0]}`
          : `line ${line}: matched weakening pattern ${m[0]}`,
      );
    }
  }

  return {
    ok: details.length === 0,
    count: details.length,
    details,
  };
}
