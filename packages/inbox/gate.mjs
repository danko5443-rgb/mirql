// packages/inbox/gate.mjs — Intake validation gates: ROADMAP.md, NOT-ROADMAP.md, and proposal quotas.
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { EXIT_CODES } from "../core/index.mjs";

/** Valid roadmap milestone citations */
export const VALID_MILESTONES = Object.freeze(["M1", "M2", "M3", "M4", "M5", "M6", "M7"]);

/** Maximum concurrent active proposals permitted */
export const MAX_ACTIVE_PROPOSALS = 3;

/**
 * Hardcoded negative-space rules from NOT-ROADMAP.md
 */
const FORBIDDEN_RULES = [
  {
    id: "nr-0001",
    reason: "Never auto-approve HUMAN verdicts on timeout",
    violates_law: "Law 6 (Cryptographic Human Sovereignty / Silence Is Never Consent)",
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
    violates_law: "Law 3 (Roles Propose / Tools Author) and Law 8 (Speechless Sandboxes)",
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
    violates_law: "Law 17 (Per-Product Tenant Isolation & Integer-Only JCS)",
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
    violates_law: "Law 1 (Offline Litmus) and Law 8 (Speechless Sandboxes)",
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
    violates_law: "Law 16 (GREEN Must Be Causal)",
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
 * Locate a file by walking up from the start directory.
 * @param {string} startDir
 * @param {string} filename
 * @returns {string | null}
 */
export function findUp(startDir, filename) {
  let curr = resolve(startDir || process.cwd());
  while (true) {
    const candidate = join(curr, filename);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(curr, "..");
    if (parent === curr) break;
    curr = parent;
  }
  return null;
}

/**
 * Validate that a proposal cites a valid roadmap milestone (M1..M7).
 *
 * @param {string} roadmapRef
 * @param {string} startDir
 * @returns {{ ok: boolean, reason?: string, exitCode?: number }}
 */
export function validateRoadmapRef(roadmapRef, startDir) {
  if (typeof roadmapRef !== "string" || !roadmapRef.trim()) {
    return {
      ok: false,
      reason: "proposal must include a roadmap_ref citing Milestones M1 through M7",
      exitCode: EXIT_CODES.POLICY_DENIAL,
    };
  }

  const normalized = roadmapRef.trim().toUpperCase();
  if (!VALID_MILESTONES.includes(normalized)) {
    return {
      ok: false,
      reason: `invalid roadmap_ref ${JSON.stringify(roadmapRef)}; must cite one of ${VALID_MILESTONES.join(", ")} from ROADMAP.md`,
      exitCode: EXIT_CODES.POLICY_DENIAL,
    };
  }

  const roadmapPath = findUp(startDir, "ROADMAP.md");
  if (roadmapPath) {
    try {
      const content = readFileSync(roadmapPath, "utf8");
      if (!content.includes(normalized)) {
        return {
          ok: false,
          reason: `roadmap_ref ${normalized} not found in ROADMAP.md`,
          exitCode: EXIT_CODES.POLICY_DENIAL,
        };
      }
    } catch {}
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
  const corpus = typeof input === "string" ? input : flattenCorpus(input);

  // 1. Static patterns
  for (const rule of FORBIDDEN_RULES) {
    for (const pat of rule.patterns) {
      if (pat.test(corpus)) {
        return {
          ok: false,
          id: rule.id,
          reason: rule.reason,
          violates_law: rule.violates_law,
          exitCode: EXIT_CODES.POLICY_DENIAL,
        };
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
            if (item.id && corpus.toLowerCase().includes(item.id.toLowerCase())) {
              return {
                ok: false,
                id: item.id,
                reason: item.reason,
                violates_law: item.violates_law,
                exitCode: EXIT_CODES.POLICY_DENIAL,
              };
            }
            if (item.reason && corpus.toLowerCase().includes(item.reason.toLowerCase())) {
              return {
                ok: false,
                id: item.id,
                reason: item.reason,
                violates_law: item.violates_law,
                exitCode: EXIT_CODES.POLICY_DENIAL,
              };
            }
            if (Array.isArray(item.surface_delta)) {
              for (const delta of item.surface_delta) {
                if (corpus.includes(delta)) {
                  return {
                    ok: false,
                    id: item.id,
                    reason: item.reason,
                    violates_law: item.violates_law,
                    exitCode: EXIT_CODES.POLICY_DENIAL,
                  };
                }
              }
            }
          }
        }
      }
    } catch {}
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
    } catch {}
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

function flattenCorpus(val) {
  if (val === null || val === undefined) return "";
  if (typeof val === "string") return val;
  if (typeof val === "number" || typeof val === "boolean") return String(val);
  if (Array.isArray(val)) return val.map(flattenCorpus).join(" ");
  if (typeof val === "object") {
    const parts = [];
    for (const [k, v] of Object.entries(val)) {
      parts.push(k, flattenCorpus(v));
    }
    return parts.join(" ");
  }
  return "";
}
