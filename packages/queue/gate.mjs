// packages/queue/gate.mjs — Law 9 NOT-ROADMAP.md negative-space gate.
import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { EXIT_CODES } from "../core/index.mjs";

/**
 * Machine-readable forbidden rules matched from NOT-ROADMAP.md
 */
const FORBIDDEN_RULES = [
  {
    id: "nr-0001",
    reason: "Never auto-approve HUMAN verdicts on timeout",
    patterns: [
      /auto[-_ ]?approve/i,
      /auto_approve_timeout_s/i,
      /timeout auto[-_ ]?approval/i,
      /\bnr-0001\b/i,
    ],
  },
  {
    id: "nr-0002",
    reason: "Direct agent git push or branch merge without Notary proof",
    patterns: [
      /autonomous merge/i,
      /merge without (?:notary )?proof/i,
      /git_push/i,
      /merge_branch/i,
      /direct agent git push/i,
      /\bnr-0002\b/i,
    ],
  },
  {
    id: "nr-0003",
    reason: "Floating-point currency, budget, or timestamp arithmetic in consensus layers",
    patterns: [
      /floating[- ]point/i,
      /float_numbers/i,
      /fractional_cents/i,
      /float cost/i,
      /\bnr-0003\b/i,
    ],
  },
  {
    id: "nr-0004",
    reason: "Ambient outbound network access inside worker execution sandboxes",
    patterns: [
      /ambient (?:outbound )?network/i,
      /allow_egress/i,
      /unrestricted_dns/i,
      /\bnr-0004\b/i,
    ],
  },
  {
    id: "nr-0005",
    reason: "Bypassing base-fail reproduction (RED-to-GREEN causality requirement)",
    patterns: [
      /bypass(?:ing)? base[-_ ]?fail/i,
      /skip_base_fail/i,
      /trust_unreproduced_green/i,
      /unreproduced green/i,
      /\bnr-0005\b/i,
    ],
  },
];

/**
 * Find NOT-ROADMAP.md by walking up from starting directory.
 * @param {string} startDir
 * @returns {string | null}
 */
export function findNotRoadmapPath(startDir) {
  let curr = resolve(startDir || process.cwd());
  while (true) {
    const candidate = join(curr, "NOT-ROADMAP.md");
    if (existsSync(candidate)) return candidate;
    const parent = resolve(curr, "..");
    if (parent === curr) break;
    curr = parent;
  }
  return null;
}

/**
 * Checks a warrant document against Law 9 forbidden negative-space patterns.
 *
 * @param {object} warrantInput
 * @param {string} [notRoadmapContent]
 * @returns {{ allowed: boolean, id?: string, reason?: string, exit_code?: number }}
 */
export function checkNotRoadmapGate(warrantInput, notRoadmapContent) {
  if (!warrantInput || typeof warrantInput !== "object") {
    return { allowed: true };
  }

  // Extract all text content from warrantInput
  const textCorpus = collectTextCorpus(warrantInput);

  // If NOT-ROADMAP.md content was provided, parse json entries if present
  const dynamicRules = [];
  if (notRoadmapContent) {
    const jsonMatch = notRoadmapContent.match(/```json\r?\n([\s\S]*?)\r?\n```/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[1]);
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            dynamicRules.push(item);
          }
        }
      } catch {
        // ignore JSON parse error in markdown
      }
    }
  }

  // Check built-in patterns
  for (const rule of FORBIDDEN_RULES) {
    for (const pattern of rule.patterns) {
      if (pattern.test(textCorpus)) {
        return {
          allowed: false,
          id: rule.id,
          reason: rule.reason,
          exit_code: EXIT_CODES.POLICY_DENIAL,
        };
      }
    }
  }

  // Check dynamic rules from NOT-ROADMAP.md
  for (const item of dynamicRules) {
    if (item.id && textCorpus.toLowerCase().includes(item.id.toLowerCase())) {
      return {
        allowed: false,
        id: item.id,
        reason: item.reason,
        exit_code: EXIT_CODES.POLICY_DENIAL,
      };
    }
    if (item.reason && textCorpus.toLowerCase().includes(item.reason.toLowerCase())) {
      return {
        allowed: false,
        id: item.id,
        reason: item.reason,
        exit_code: EXIT_CODES.POLICY_DENIAL,
      };
    }
    if (Array.isArray(item.surface_delta)) {
      for (const delta of item.surface_delta) {
        if (textCorpus.includes(delta)) {
          return {
            allowed: false,
            id: item.id,
            reason: item.reason,
            exit_code: EXIT_CODES.POLICY_DENIAL,
          };
        }
      }
    }
  }

  return { allowed: true };
}

/**
 * Collect all string and key values from an object into a single searchable text string.
 * @param {unknown} val
 * @returns {string}
 */
function collectTextCorpus(val) {
  if (val === null || val === undefined) return "";
  if (typeof val === "string") return val;
  if (typeof val === "number" || typeof val === "boolean") return String(val);
  if (Array.isArray(val)) {
    return val.map(collectTextCorpus).join(" ");
  }
  if (typeof val === "object") {
    const parts = [];
    for (const [k, v] of Object.entries(val)) {
      parts.push(k);
      parts.push(collectTextCorpus(v));
    }
    return parts.join(" ");
  }
  return "";
}
