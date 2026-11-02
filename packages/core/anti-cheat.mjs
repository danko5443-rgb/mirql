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
  "conformance/**",
  ".github/**",
  "scripts/**",
  "bin/**",
  ".coderabbit.yaml",
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
  const humanOnly = [];
  const humanApprove = [];
  const aiReviewers = [];
  const pathsFile = join(rootDir, "policy", "paths.yaml");

  if (existsSync(pathsFile)) {
    try {
      const content = readFileSync(pathsFile, "utf8");
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
    } catch {}
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
 * Scans source code for empty catch blocks and swallowed exceptions (MP-003).
 *
 * @param {string} sourceCode
 * @param {string} [filename]
 * @returns {{ ok: boolean, violations: Array<{ file?: string, pattern: string, line: number, detail?: string }> }}
 */
export function checkSwallowedExceptions(sourceCode, filename) {
  const violations = [];

  // 1. Standard catch blocks: parse with balanced braces (ignoring strings, comments, regexes)
  const catchStartRegex = /catch\s*(?:\([^)]*\))?\s*\{/g;
  let match;
  while ((match = catchStartRegex.exec(sourceCode)) !== null) {
    const { body, endIdx: catchEnd } = extractBalancedBlock(sourceCode, match.index + match[0].length);
    if (isEffectivelyEmpty(body)) {
      const upToMatch = sourceCode.slice(0, match.index);
      const line = upToMatch.split("\n").length;
      violations.push({
        file: filename,
        pattern: sourceCode.slice(match.index, catchEnd),
        line,
      });
    }
  }

  // 2. Promise .catch(): parse with balanced block extraction (never truncated by inner braces)
  const promiseCatchRegex = /\.catch\s*\(/g;
  let pcMatch;
  while ((pcMatch = promiseCatchRegex.exec(sourceCode)) !== null) {
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
      if (isEffectivelyEmpty(body)) {
        const upToMatch = sourceCode.slice(0, pcMatch.index);
        const line = upToMatch.split("\n").length;
        violations.push({
          file: filename,
          pattern: sourceCode.slice(pcMatch.index, endIdx + 1),
          line,
          detail: "Swallowed Promise .catch() block",
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
        if (isEffectivelyEmpty(expr)) {
          const upToMatch = sourceCode.slice(0, pcMatch.index);
          const line = upToMatch.split("\n").length;
          violations.push({
            file: filename,
            pattern: sourceCode.slice(pcMatch.index, j + 1),
            line,
            detail: "Swallowed Promise .catch() expression",
          });
        }
      }
    }
  }

  // 3. Global uncaughtException / unhandledRejection swallowing
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

    // Strip comments, strings, template literals, and regex literals
    const strippedBody = handlerBody
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "")
      .replace(/(["'`])(?:\\.|(?!\1)[\s\S])*?\1/g, "")
      .replace(/\/(?:\\.|[^\/\\\n])+\/[a-z]*/g, "");

    // Must call process.exit(...) or throw an error
    const hasExitCall = /\bprocess\s*\.\s*exit\s*\(/.test(strippedBody);
    const hasThrow = /\bthrow\b/.test(strippedBody);

    if (isEffectivelyEmpty(handlerBody) || (!hasExitCall && !hasThrow)) {
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
 * @param {string} sourceCode
 * @param {string} [filename]
 * @returns {{ ok: boolean, count: number, details: string[] }}
 */
export function checkTestWeakenings(sourceCode, filename) {
  const patterns = [
    /\b(?:it|test|describe|context|suite)\s*\.\s*(?:skip|only|todo)\b/g,
    /\bx(?:it|test|describe)\b/g,
    /\b(?:it|test|describe)\s*\[\s*['"`](?:skip|only|todo)['"`]\s*\]/g,
    /\{\s*skip\s*:\s*(?:true|1)\s*\}/g,
    /\bt\s*\.\s*skip\s*\(/g,
  ];

  const details = [];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(sourceCode)) !== null) {
      const upTo = sourceCode.slice(0, m.index);
      const line = upTo.split("\n").length;
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
