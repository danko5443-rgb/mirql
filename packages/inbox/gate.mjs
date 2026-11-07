// packages/inbox/gate.mjs — Intake validation gates: ROADMAP.md, NOT-ROADMAP.md, and proposal quotas.
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { EXIT_CODES } from "../core/index.mjs";
import { FORBIDDEN_RULES, findUp, corpusMatchesRule, collectTextCorpus } from "../core/not-roadmap.mjs";

/** Valid roadmap milestone citations */
export const VALID_MILESTONES = Object.freeze(["M1", "M2", "M3", "M4", "M5", "M6", "M7"]);

/** Maximum concurrent active proposals permitted */
export const MAX_ACTIVE_PROPOSALS = 3;

/**
 * Validate that a proposal cites a valid roadmap milestone (M1..M7).
 *
 * @param {string} roadmapRef
 * @param {string} startDir
 * @returns {{ ok: boolean, reason?: string, exitCode?: number }}
 */
export function validateRoadmapRef(roadmapRef, startDir) {
  const denied = (reason) => ({ ok: false, reason, exitCode: EXIT_CODES.POLICY_DENIAL });
  if (typeof roadmapRef !== "string" || !roadmapRef.trim()) {
    return denied("proposal must include a roadmap_ref citing Milestones M1 through M7");
  }

  const normalized = roadmapRef.trim().toUpperCase();
  if (!VALID_MILESTONES.includes(normalized)) {
    return denied(`invalid roadmap_ref ${JSON.stringify(roadmapRef)}; must cite one of ${VALID_MILESTONES.join(", ")} from ROADMAP.md`);
  }

  const roadmapPath = findUp(startDir, "ROADMAP.md");
  if (roadmapPath) {
    try {
      const content = readFileSync(roadmapPath, "utf8");
      if (!content.includes(normalized)) {
        return denied(`roadmap_ref ${normalized} not found in ROADMAP.md`);
      }
    } catch {
      // Law 6: a roadmap that exists but cannot be read proves nothing, so the ref stays unconfirmed.
      return denied(`roadmap_ref ${normalized} could not be confirmed against ROADMAP.md`);
    }
  }

  return { ok: true };
}

/**
 * Check text corpus against NOT-ROADMAP.md anti-goals.
 *
 * @param {string | object} input
 * @param {string} startDir
 * @returns {{ ok: boolean, id?: string, reason?: string, violates_law?: string, exitCode?: number }}
 */
export function checkNotRoadmap(input, startDir) {
  const corpus = typeof input === "string" ? input : collectTextCorpus(input);
  const ruleDenial = (rule) => ({
    ok: false,
    id: rule.id,
    reason: rule.reason,
    violates_law: rule.violates_law,
    exitCode: EXIT_CODES.POLICY_DENIAL,
  });

  // 1. Static patterns
  for (const rule of FORBIDDEN_RULES) {
    for (const pat of rule.patterns) {
      if (pat.test(corpus)) {
        return ruleDenial(rule);
      }
    }
  }

  // 2. Dynamic rules from NOT-ROADMAP.md
  const notRoadmapPath = findUp(startDir, "NOT-ROADMAP.md");
  if (notRoadmapPath) {
    try {
      const content = readFileSync(notRoadmapPath, "utf8");
      const jsonMatch = content.match(/```json\r?\n([\s\S]*?)\r?\n```/);
      if (jsonMatch) {
        const dynamicRules = JSON.parse(jsonMatch[1]);
        if (Array.isArray(dynamicRules)) {
          for (const item of dynamicRules) {
            if (corpusMatchesRule(item, corpus)) return ruleDenial(item);
          }
        }
      }
    } catch { /* mp-003-allow: an unreadable rules file contributes no dynamic rules; the static NOT-ROADMAP rules still deny their patterns */ }
  }

  return { ok: true };
}

/**
 * Check that active proposals in <mirqlDir>/proposals do not exceed max ceiling.
 *
 * @param {string} proposalsDir
 * @returns {{ ok: boolean, count: number, reason?: string, exitCode?: number }}
 */
export function checkProposalQuota(proposalsDir) {
  if (!existsSync(proposalsDir)) return { ok: true, count: 0 };

  let activeCount = 0;
  for (const entry of readdirSync(proposalsDir)) {
    if (!entry.endsWith(".json")) continue;
    try {
      const data = JSON.parse(readFileSync(join(proposalsDir, entry), "utf8"));
      const status = data.status || "pending";
      if (status === "pending" || status === "open" || status === "active") {
        activeCount += 1;
      }
    } catch { /* mp-003-allow: an unreadable status entry counts as not active; admission is decided by the signed warrant, not the digest count */ }
  }

  if (activeCount >= MAX_ACTIVE_PROPOSALS) {
    return {
      ok: false,
      count: activeCount,
      reason: `proposal intake ceiling reached: maximum ${MAX_ACTIVE_PROPOSALS} active proposals allowed at a time (found ${activeCount})`,
      exitCode: EXIT_CODES.POLICY_DENIAL,
    };
  }

  return { ok: true, count: activeCount };
}
