#!/usr/bin/env node
// scripts/ci-phi-warrant.mjs — how much of the owner's Phi warrant is already spent.
//
// Law 13 counts spend across transitions: the sum of max(0, Phi growth), with no
// refund for a decrease. Merged history is the record, so this walks the
// first-parent chain from the warrant's base_sha to the base branch tip. It
// measures with the base copy of the code and reads commits as data only.
//
// Every failure means no allowance, never a broken gate: a PR that does not grow
// Phi has no need of a warrant. Environment contract:
//   PHI_WARRANT   - the signed warrant JSON (repository variable); may be empty
//   BASE_SHA      - base branch tip this run is judged against
//   GITHUB_OUTPUT - (optional) receives `spent=<n>` when the warrant measures
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { readPhiWarrantPin, verifyPhiWarrant } from "../packages/core/phi-warrant.mjs";
import { computeGitTreePhi } from "../packages/run/phi.mjs";
import { isEntrypoint } from "./ci-review-gate.mjs";

const SHA_RE = /^[0-9a-f]{40}$/;
const MAX_COMMITS = 200;
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * @param {{ rootDir: string, repoDir: string, tipSha: string, document: unknown, maxCommits?: number }} input
 *   rootDir holds the base copy's pin; repoDir holds the git history.
 * @returns {{ ok: false, reason: string } | { ok: true, warrant_hash: string, phi_budget: number, phi_spent: number, phi_remaining: number }}
 */
export function measurePhiWarrant({ rootDir, repoDir, tipSha, document, maxCommits = MAX_COMMITS }) {
  if (!document) return { ok: false, reason: "NO_WARRANT" };
  const publicKey = readPhiWarrantPin(rootDir);
  if (!publicKey) return { ok: false, reason: "NO_PIN" };
  const verified = verifyPhiWarrant(document, publicKey);
  if (!verified.ok) return verified;
  if (!SHA_RE.test(tipSha ?? "")) return { ok: false, reason: "BAD_TIP_SHA" };
  const { warrant } = verified;
  try {
    const git = (...args) => execFileSync("git", ["-C", repoDir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    const chain = git("rev-list", "--first-parent", "--reverse", `${warrant.base_sha}..${tipSha}`).split("\n").filter(Boolean);
    // `a..b` alone would also accept a base that is not on the first-parent chain, or one that is newer than the tip.
    const reached = chain.length > 0 ? git("rev-parse", `${chain[0]}^1`) : tipSha;
    if (reached !== warrant.base_sha) return { ok: false, reason: "BASE_NOT_ON_CHAIN" };
    if (chain.length > maxCommits) return { ok: false, reason: "TOO_MANY_COMMITS: sign a new warrant" };
    const total = (sha) => computeGitTreePhi(repoDir, sha).metrics.total;
    let previous = total(warrant.base_sha);
    let spent = 0;
    for (const sha of chain) {
      const current = total(sha);
      spent += Math.max(0, current - previous);
      previous = current;
    }
    return { ok: true, warrant_hash: warrant.hash, phi_budget: warrant.phi_budget, phi_spent: spent, phi_remaining: Math.max(0, warrant.phi_budget - spent) };
  } catch (err) {
    return { ok: false, reason: `MEASURE_FAILED: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export function main(env = process.env, rootDir = ROOT) {
  const result = measurePhiWarrant({ rootDir, repoDir: rootDir, tipSha: env.BASE_SHA, document: env.PHI_WARRANT });
  console.log(JSON.stringify({ tool: "ci-phi-warrant", ...result }));
  if (!result.ok) {
    if (result.reason !== "NO_WARRANT") console.log(`::warning::Phi warrant grants no allowance: ${result.reason.replace(/\s+/g, " ")}`);
    return 0;
  }
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `spent=${result.phi_spent}\n`);
  return 0;
}

if (isEntrypoint(import.meta.url)) {
  process.exit(main());
}
