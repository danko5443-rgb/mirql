// packages/core/not-roadmap.mjs — Negative-space rules shared by the inbox and queue gates.
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Hardcoded negative-space rules from NOT-ROADMAP.md
 */
export const FORBIDDEN_RULES = [
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
 * Whether the corpus names a NOT-ROADMAP.md entry by id, reason, or surface delta.
 * @param {{ id?: string, reason?: string, surface_delta?: string[] }} item
 * @param {string} corpus
 * @returns {boolean}
 */
export function corpusMatchesRule(item, corpus) {
  if (item.id && corpus.toLowerCase().includes(item.id.toLowerCase())) return true;
  if (item.reason && corpus.toLowerCase().includes(item.reason.toLowerCase())) return true;
  return Array.isArray(item.surface_delta) && item.surface_delta.some((delta) => corpus.includes(delta));
}

/**
 * Collect all string and key values from a value into one searchable string.
 * @param {unknown} val
 * @returns {string}
 */
export function collectTextCorpus(val) {
  if (val === null || val === undefined) return "";
  if (typeof val === "string") return val;
  if (typeof val === "number" || typeof val === "boolean") return String(val);
  if (Array.isArray(val)) return val.map(collectTextCorpus).join(" ");
  if (typeof val === "object") {
    const parts = [];
    for (const [k, v] of Object.entries(val)) {
      parts.push(k, collectTextCorpus(v));
    }
    return parts.join(" ");
  }
  return "";
}
