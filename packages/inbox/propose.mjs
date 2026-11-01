// packages/inbox/propose.mjs — Bounded proposer intake gate (Law 3, Law 9, Law 6).
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { ulid, EXIT_CODES } from "../core/index.mjs";
import {
  validateRoadmapRef,
  checkNotRoadmap,
  checkProposalQuota,
} from "./gate.mjs";

/**
 * Submit a structured proposal through the bounded proposer gate.
 * Enforces ROADMAP.md milestone citation, NOT-ROADMAP.md negative-space gating,
 * and the 3-proposal capacity ceiling.
 *
 * @param {string} mirqlDir
 * @param {object} proposalInput
 * @param {object} [options]
 * @returns {{ status: "proposed", proposal_id: string, proposal: object }}
 */
export function createProposal(mirqlDir, proposalInput, options = {}) {
  if (!proposalInput || typeof proposalInput !== "object") {
    const err = new Error("proposalInput must be an object");
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const roadmapRef = (proposalInput.roadmap_ref || options["roadmap-ref"] || options.roadmapRef || "").trim();
  const title = (proposalInput.title || options.title || "").trim();
  const description = (proposalInput.description || options.description || "").trim();
  const surfaceImpact = proposalInput.surface_impact || options["surface-impact"] || "none";
  const rawInvariants = proposalInput.proposed_invariants || options["proposed-invariants"] || [];
  const proposedInvariants = Array.isArray(rawInvariants) ? rawInvariants : [rawInvariants].filter(Boolean);

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

  // 2. Validate against NOT-ROADMAP.md negative-space filter
  const corpus = {
    description,
    proposedInvariants,
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

  // 4. Create and save proposal document
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const proposalId = ulid(nowMs);

  const proposalDoc = {
    action_type: "1_tap_approve",
    created_at: new Date(nowMs).toISOString(),
    created_by: "roles:proposer",
    description,
    id: proposalId,
    proposed_invariants: proposedInvariants.length > 0 ? proposedInvariants : ["invariants-checked"],
    roadmap_ref: roadmapRef.toUpperCase(),
    status: "pending",
    surface_impact: surfaceImpact,
    title,
  };

  const proposalFile = join(proposalsDir, `${proposalId}.json`);
  writeFileSync(proposalFile, JSON.stringify(proposalDoc, null, 2) + "\n", "utf8");

  return {
    status: "proposed",
    proposal_id: proposalId,
    proposal: proposalDoc,
  };
}
