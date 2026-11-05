// packages/queue/gate.mjs — Law 9 NOT-ROADMAP.md negative-space gate.
import { EXIT_CODES } from "../core/index.mjs";
import { FORBIDDEN_RULES, findUp, corpusMatchesRule, collectTextCorpus } from "../core/not-roadmap.mjs";

/**
 * Find NOT-ROADMAP.md by walking up from starting directory.
 * @param {string} startDir
 * @returns {string | null}
 */
export function findNotRoadmapPath(startDir) {
  return findUp(startDir, "NOT-ROADMAP.md");
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

  const denial = (rule) => ({
    allowed: false,
    id: rule.id,
    reason: rule.reason,
    exit_code: EXIT_CODES.POLICY_DENIAL,
  });

  // Check built-in patterns
  for (const rule of FORBIDDEN_RULES) {
    for (const pattern of rule.patterns) {
      if (pattern.test(textCorpus)) return denial(rule);
    }
  }

  // Check dynamic rules from NOT-ROADMAP.md
  for (const item of dynamicRules) {
    if (corpusMatchesRule(item, textCorpus)) return denial(item);
  }

  return { allowed: true };
}
