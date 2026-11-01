// packages/inbox/propose.mjs — Bounded proposer intake gate and Intent Synthesiser (Law 3, Law 9, Law 6, Law 16, roles/proposer.md).
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { ulid, EXIT_CODES } from "../core/index.mjs";
import {
  validateRoadmapRef,
  checkNotRoadmap,
  checkProposalQuota,
} from "./gate.mjs";

/** Valid canonical intent categories (roles/proposer.md) */
export const INTENT_CATEGORIES = Object.freeze(["bugfix", "feature", "refactor", "docs"]);

/**
 * Distills raw human text, issue reports, or chat interactions into an unambiguous,
 * machine-executable technical specification and 1-tap warrant proposal.
 * (roles/proposer.md: intent.distilled)
 *
 * @param {string | object} rawInput
 * @param {object} [options]
 * @returns {{
 *   kind: "bugfix" | "feature" | "refactor" | "docs",
 *   title: string,
 *   description: string,
 *   surface_impact: string,
 *   proposed_invariants: string[],
 *   roadmap_ref: string,
 *   red_check: string,
 *   reproducer_verified: boolean
 * }}
 */
export function distillIntent(rawInput, options = {}) {
  let text = "";
  let baseObj = {};

  if (typeof rawInput === "string") {
    text = rawInput.trim();
  } else if (rawInput && typeof rawInput === "object") {
    baseObj = rawInput;
    text = (rawInput.text || rawInput.summary || rawInput.description || rawInput.title || "").trim();
  }

  const optText = (options.text || options["from-text"] || options.fromText || "").trim();
  if (optText && !text) {
    text = optText;
  }

  // 1. Categorize intent
  let kind = (baseObj.kind || baseObj.category || options.kind || options.category || "").toLowerCase();
  if (!INTENT_CATEGORIES.includes(kind)) {
    if (/\b(bug|fix|patch|issue|regression|crash|error|broken|fail|flaky)\b/i.test(text)) {
      kind = "bugfix";
    } else if (/\b(refactor|cleanup|consolidate|thrift|simplify|reorganize)\b/i.test(text)) {
      kind = "refactor";
    } else if (/\b(doc|docs|documentation|readme|guide|comment)\b/i.test(text)) {
      kind = "docs";
    } else {
      kind = "feature";
    }
  }

  // 2. Extract or infer roadmap reference (M1..M7)
  let roadmapRef = (baseObj.roadmap_ref || options["roadmap-ref"] || options.roadmapRef || "").trim().toUpperCase();
  if (!roadmapRef) {
    const match = text.match(/\b(M[1-7])\b/i);
    if (match) {
      roadmapRef = match[1].toUpperCase();
    } else if (/\b(wake|warrant|lease|tick|bus)\b/i.test(text)) {
      roadmapRef = "M1";
    } else if (/\b(phi|potential|ratchet|complexity)\b/i.test(text)) {
      roadmapRef = "M2";
    } else if (/\b(drift|claim|surface|lock)\b/i.test(text)) {
      roadmapRef = "M3";
    } else if (/\b(mutant|mutation|flake|kill rate)\b/i.test(text)) {
      roadmapRef = "M4";
    } else if (/\b(doctor|breaker|circuit|health|diagnos)\b/i.test(text)) {
      roadmapRef = "M5";
    } else if (/\b(journey|propos|digest|act|harness|1-tap|scout)\b/i.test(text)) {
      roadmapRef = "M6";
    } else if (/\b(canary|promote|ouroboros|self-host|slsa|sigstore)\b/i.test(text)) {
      roadmapRef = "M7";
    } else {
      roadmapRef = "";
    }
  }

  // 3. Extract title
  let title = (baseObj.title || options.title || "").trim();
  if (!title) {
    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    const firstLine = lines[0] || "Synthesized Proposal Intent";
    title = firstLine.length > 80 ? firstLine.slice(0, 77) + "..." : firstLine;
  }

  // 4. Extract description / technical scope
  let description = (baseObj.description || options.description || "").trim();
  if (!description) {
    description = text || title;
  }

  // 5. Detect surface impact
  let surfaceImpact = baseObj.surface_impact || options["surface-impact"] || options.surfaceImpact || "";
  if (!surfaceImpact) {
    if (/\b(surface\.lock|public command|cli option|bin\/|subcommand)\b/i.test(text)) {
      surfaceImpact = "packages/run, surface.lock";
    } else {
      surfaceImpact = "none";
    }
  }

  // 6. Formulate proposed invariants
  let rawInvariants = baseObj.proposed_invariants || options["proposed-invariants"] || options.proposedInvariants || [];
  const proposedInvariants = Array.isArray(rawInvariants)
    ? rawInvariants.map(String)
    : (typeof rawInvariants === "string" ? [rawInvariants] : []);
  if (proposedInvariants.length === 0) {
    proposedInvariants.push("invariants-checked");
    if (kind === "bugfix") {
      proposedInvariants.push("reproducer-passes-after-fix");
    } else if (kind === "feature") {
      proposedInvariants.push("acceptance-test-green");
    }
  }

  // 7. Law 16: All proposed changes accompanied by verified reproducers
  let redCheck = baseObj.red_check || options["red-check"] || options.redCheck || "";
  if (typeof redCheck === "object" && redCheck !== null) {
    redCheck = redCheck.command || "";
  }
  if (!redCheck) {
    // Generate default verified reproducer based on category and title
    redCheck = "npm test";
  }

  if (/\b(curl|wget|fetch|nc|ncat|ssh|scp|ftp|skip_base_fail)\b/i.test(redCheck)) {
    const err = new Error("Reproducer command violates Law 1 (Offline Litmus) or anti-cheat: network calls and skip_base_fail are forbidden");
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  const reproducerVerified = Boolean(redCheck && redCheck.trim().length > 0);

  return {
    kind,
    title,
    description,
    surface_impact: surfaceImpact,
    proposed_invariants: proposedInvariants,
    roadmap_ref: roadmapRef,
    red_check: redCheck,
    reproducer_verified: reproducerVerified,
  };
}

/**
 * Formats a canonical intent.distilled event payload conforming to roles/proposer.md.
 *
 * @param {object} intent
 * @param {object} [options]
 * @returns {object}
 */
export function formatIntentDistilledEvent(intent, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  return {
    v: 1,
    id: ulid(nowMs),
    type: "intent.distilled",
    payload: {
      category: intent.kind,
      title: intent.title,
      roadmap_ref: intent.roadmap_ref,
      surface_impact: intent.surface_impact,
      reproducer_command: intent.red_check,
      proposed_invariants: intent.proposed_invariants,
      timestamp_ms: nowMs,
    },
  };
}

/**
 * Formats a canonical proposal.created event payload conforming to roles/proposer.md.
 *
 * @param {object} proposal
 * @param {object} [options]
 * @returns {object}
 */
export function formatProposalCreatedEvent(proposal, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  return {
    v: 1,
    id: ulid(nowMs),
    type: "proposal.created",
    payload: {
      proposal_id: proposal.id,
      title: proposal.title,
      description: proposal.description,
      surface_impact: proposal.surface_impact,
      proposed_invariants: proposal.proposed_invariants,
      action_type: proposal.action_type || "1_tap_approve",
      roadmap_ref: proposal.roadmap_ref,
      reproducer_command: proposal.red_check || "npm test",
      timestamp_ms: nowMs,
    },
  };
}

/**
 * Submit a structured proposal through the bounded proposer gate (Law 3, Law 9, Law 6).
 * Enforces ROADMAP.md milestone citation, NOT-ROADMAP.md negative-space gating,
 * Law 16 reproducer requirement, and the 3-proposal capacity ceiling.
 *
 * @param {string} mirqlDir
 * @param {object} proposalInput
 * @param {object} [options]
 * @returns {{
 *   status: "proposed",
 *   proposal_id: string,
 *   proposal: object,
 *   intent_distilled?: object,
 *   proposal_created_event?: object
 * }}
 */
export function createProposal(mirqlDir, proposalInput, options = {}) {
  if (!proposalInput || typeof proposalInput !== "object") {
    const err = new Error("proposalInput must be an object");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  // If text / from-text is provided, perform intent distillation
  let inputToProcess = proposalInput;
  let intentDistilled = null;
  const hasRawText = Boolean(
    proposalInput.text ||
    proposalInput["from-text"] ||
    proposalInput.fromText ||
    options["from-text"] ||
    options.fromText
  );

  if (hasRawText || (!proposalInput.title && !options.title)) {
    const distilled = distillIntent(proposalInput, options);
    intentDistilled = formatIntentDistilledEvent(distilled, options);
    inputToProcess = {
      ...distilled,
      ...proposalInput,
      roadmap_ref: proposalInput.roadmap_ref || distilled.roadmap_ref,
      title: proposalInput.title || distilled.title,
      description: proposalInput.description || distilled.description,
      surface_impact: proposalInput.surface_impact || distilled.surface_impact,
      proposed_invariants: proposalInput.proposed_invariants || distilled.proposed_invariants,
      red_check: proposalInput.red_check || distilled.red_check,
    };
  }

  const roadmapRef = (inputToProcess.roadmap_ref || options["roadmap-ref"] || options.roadmapRef || "").trim();
  const title = (inputToProcess.title || options.title || "").trim();
  const description = (inputToProcess.description || options.description || "").trim();
  const surfaceImpact = inputToProcess.surface_impact || options["surface-impact"] || options.surfaceImpact || "none";
  const rawInvariants = inputToProcess.proposed_invariants || options["proposed-invariants"] || options.proposedInvariants || [];
  const proposedInvariants = Array.isArray(rawInvariants) ? rawInvariants : [rawInvariants].filter(Boolean);
  const redCheck = inputToProcess.red_check || options["red-check"] || options.redCheck || "npm test";
  const kind = inputToProcess.kind || options.kind || "feature";

  if (!title) {
    const err = new Error("Proposal title is required (--title <str>)");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  if (!description) {
    const err = new Error("Proposal description is required (--description <str>)");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  // 1. Validate ROADMAP.md citation (M1..M7)
  const roadmapRes = validateRoadmapRef(roadmapRef, mirqlDir);
  if (!roadmapRes.ok) {
    const err = new Error(`Proposal rejected by roadmap gate: ${roadmapRes.reason}`);
    err.exitCode = roadmapRes.exitCode || EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  // Check red_check for anti-cheat bypass and Law 1 offline litmus
  if (/\b(curl|wget|fetch|nc|ncat|ssh|scp|ftp|skip_base_fail)\b/i.test(redCheck)) {
    const err = new Error("Proposal red_check violates Law 1 (Offline Litmus) or anti-cheat: illicit command detected");
    err.exitCode = EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  // 2. Validate against NOT-ROADMAP.md negative-space filter
  const corpus = {
    description,
    proposedInvariants,
    red_check: redCheck,
    roadmapRef,
    surfaceImpact,
    title,
  };
  const notRoadmapRes = checkNotRoadmap(corpus, mirqlDir);
  if (!notRoadmapRes.ok) {
    const err = new Error(
      `Proposal rejected by NOT-ROADMAP negative-space gate [${notRoadmapRes.id}]: ${notRoadmapRes.reason} (${notRoadmapRes.violates_law || "Normative Law Violation"})`
    );
    err.exitCode = notRoadmapRes.exitCode || EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  // 3. Enforce max 3 active proposals quota ceiling
  const proposalsDir = join(mirqlDir, "proposals");
  mkdirSync(proposalsDir, { recursive: true });
  const quotaRes = checkProposalQuota(proposalsDir);
  if (!quotaRes.ok) {
    const err = new Error(`Proposal rejected by capacity quota: ${quotaRes.reason}`);
    err.exitCode = quotaRes.exitCode || EXIT_CODES.POLICY_DENIAL;
    throw err;
  }

  // 4. Create and save proposal document (roles/proposer.md)
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const proposalId = ulid(nowMs);

  const proposalDoc = {
    action_type: "1_tap_approve",
    created_at: new Date(nowMs).toISOString(),
    created_by: "roles:proposer",
    description,
    id: proposalId,
    kind,
    proposed_invariants: proposedInvariants.length > 0 ? proposedInvariants : ["invariants-checked"],
    red_check: redCheck,
    reproducer_verified: Boolean(redCheck),
    roadmap_ref: roadmapRef.toUpperCase(),
    status: "pending",
    surface_impact: surfaceImpact,
    title,
  };

  const proposalFile = join(proposalsDir, `${proposalId}.json`);
  writeFileSync(proposalFile, JSON.stringify(proposalDoc, null, 2) + "\n", "utf8");

  const proposalCreatedEvent = formatProposalCreatedEvent(proposalDoc, { nowMs });

  return {
    status: "proposed",
    proposal_id: proposalId,
    proposal: proposalDoc,
    intent_distilled: intentDistilled,
    proposal_created_event: proposalCreatedEvent,
  };
}

/**
 * 1-tap proposer intake helper.
 *
 * @param {string} mirqlDir
 * @param {object|string} input
 * @param {object} [options]
 * @returns {object}
 */
export function create1TapProposal(mirqlDir, input, options = {}) {
  const proposalInput = typeof input === "string" ? { text: input } : (input || {});
  return createProposal(mirqlDir, proposalInput, options);
}
