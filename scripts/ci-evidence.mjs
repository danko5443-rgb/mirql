#!/usr/bin/env node
// scripts/ci-evidence.mjs — honest Notary evidence builder (Laws 4, 6, 7, 16, 17).
//
// Replaces the inline pr-doc synthesis in .github/workflows/mergeproof.yml with
// a committed, testable script. Every field is MEASURED, never assumed:
//   - files / deleted tests come from the authoritative git diff (fail-closed)
//   - proof.suite_pass_base / proof.suite_pass_head mirror the real outcomes of
//     the base-notary and candidate suite steps (Law 7: base-authored evidence)
//   - phi.delta_phi is computed by the base-notary's own computePhi (Law 13)
//   - proof.causal_cycle_completed stays false unless a VERIFIED reproducer
//     artifact is supplied — silence or absence is never a completed cycle
//     (Law 6), and a cycle is never faked (Law 16).
//
// Zero external dependencies. Environment contract (all required except noted):
//   BASE_NOTARY_DIR   - base-notary checkout root (Laws 7 & 9)
//   CANDIDATE_DIR     - candidate PR head checkout root
//   BASE_SHA          - authoritative base tip SHA
//   HEAD_SHA          - authoritative candidate head SHA
//   PR_NUMBER         - integer PR number
//   PR_AUTHOR         - PR author login
//   SUITE_PASS_BASE   - "true"|"1" iff the base suite step concluded success
//   SUITE_PASS_HEAD   - "true"|"1" iff the candidate suite step concluded success
//   PR_DOC_PATH       - (optional) output path, default <CANDIDATE_DIR>/pr-doc.json
//
// Exit codes: 0 evidence written; 1 any measurement failed (fail-closed).

import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** Parses a boolean-ish environment string ("true"/"1", case-insensitive). */
export function parseBoolEnv(value) {
  const v = String(value ?? "").trim().toLowerCase();
  return v === "true" || v === "1";
}

/** Canonical test-file recognizer (same rule as mergeproof evaluator / CI). */
export function isTestFilePath(p) {
  if (typeof p !== "string") return false;
  const norm = p.replaceAll("\\", "/").toLowerCase();
  return (
    norm.startsWith("tests/") ||
    norm.startsWith("test/") ||
    norm.includes(".test.") ||
    norm.includes("_test.")
  );
}

/**
 * Authoritative git diff (Law 7): `git diff --name-status base...head`.
 * Fail-closed: any git failure returns { ok: false } — never an empty guess.
 *
 * @returns {{ ok: boolean, error?: string, files: string[], deletedTests: string[] }}
 */
export function collectDiff(baseSha, headSha, repoDir) {
  if (!baseSha || !headSha || !repoDir) {
    return { ok: false, error: "collectDiff requires baseSha, headSha, repoDir", files: [], deletedTests: [] };
  }
  if (!existsSync(join(repoDir, ".git"))) {
    return { ok: false, error: `Directory ${repoDir} is not a git repository`, files: [], deletedTests: [] };
  }
  const res = spawnSync(
    "git",
    ["diff", "--name-status", `${baseSha}...${headSha}`],
    { cwd: repoDir, encoding: "utf8", timeout: 15000 },
  );
  if (res.status !== 0) {
    const err = (res.stderr || res.stdout || `git exit code ${res.status}`).trim();
    return { ok: false, error: err, files: [], deletedTests: [] };
  }
  const files = [];
  const deletedTests = [];
  for (const line of String(res.stdout || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = line.split("\t");
    const status = parts[0];
    if (status.startsWith("R") && parts.length >= 3) {
      const oldFile = parts[1];
      const newFile = parts[2];
      files.push(newFile);
      if (isTestFilePath(oldFile) && !isTestFilePath(newFile)) {
        deletedTests.push(oldFile);
      }
    } else if (parts.length >= 2) {
      const file = parts[1];
      files.push(file);
      if (status.startsWith("D") && isTestFilePath(file)) {
        deletedTests.push(file);
      }
    }
  }
  return { ok: true, files, deletedTests };
}

/**
 * Composes the PR evidence document from measured inputs (pure function).
 *
 * @param {object} input
 * @param {{ number: number, base_sha: string, head_sha: string, author: string }} input.pr
 * @param {{ files_changed: string[], tests_deleted: string[] }} input.diff
 * @param {{ pass_base: boolean, pass_head: boolean }} input.suite
 * @param {{ delta_phi: number }} input.phi
 * @param {boolean} [input.causalCompleted=false] - only true with a VERIFIED reproducer cycle
 * @returns {object} pr-doc consumable by `mirql m check`
 */
export function buildPrDoc({ pr, diff, suite, phi, causalCompleted = false }) {
  return {
    pr: {
      number: pr.number,
      base_sha: pr.base_sha,
      head_sha: pr.head_sha,
      author: pr.author,
      kind: "pr",
    },
    diff_stat: {
      files_changed: diff.files_changed,
    },
    evidence: {
      tests_deleted: diff.tests_deleted,
    },
    proof: {
      causal_cycle_completed: causalCompleted === true,
      suite_pass_base: suite.pass_base === true,
      suite_pass_head: suite.pass_head === true,
    },
    phi: {
      delta_phi: phi.delta_phi,
    },
  };
}

/**
 * Loads computePhi from the BASE-NOTARY checkout (Law 7: the running version
 * N-1 owns the metric definition; the candidate never measures itself).
 */
async function loadBaseComputePhi(baseDir) {
  const phiPath = join(resolve(baseDir), "packages", "run", "phi.mjs");
  if (!existsSync(phiPath)) {
    throw new Error(`Law 7 fail-closed: base-notary phi engine not found at ${phiPath}`);
  }
  const mod = await import(pathToFileURL(phiPath).href);
  if (typeof mod.computePhi !== "function") {
    throw new Error("Law 7 fail-closed: base-notary phi.mjs does not export computePhi");
  }
  return mod.computePhi;
}

async function main() {
  const required = ["BASE_NOTARY_DIR", "CANDIDATE_DIR", "BASE_SHA", "HEAD_SHA", "PR_NUMBER", "PR_AUTHOR", "SUITE_PASS_BASE", "SUITE_PASS_HEAD"];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length > 0) {
    process.stderr.write(`ci-evidence: missing required env: ${missing.join(", ")}\n`);
    process.exit(1);
  }

  const baseDir = resolve(process.env.BASE_NOTARY_DIR);
  const candidateDir = resolve(process.env.CANDIDATE_DIR);
  const baseSha = process.env.BASE_SHA;
  const headSha = process.env.HEAD_SHA;
  const prNumber = Number.parseInt(process.env.PR_NUMBER, 10);
  if (!Number.isSafeInteger(prNumber) || prNumber <= 0) {
    process.stderr.write(`ci-evidence: PR_NUMBER is not a safe positive integer\n`);
    process.exit(1);
  }

  // 1. Authoritative diff (candidate repo, fail-closed)
  const diff = collectDiff(baseSha, headSha, candidateDir);
  if (!diff.ok) {
    process.stderr.write(`ci-evidence: authoritative git diff failed: ${diff.error}\n`);
    process.exit(1);
  }

  // 2. Law 13: base-authored phi (both sides measured by the SAME N-1 engine)
  let deltaPhi;
  try {
    const computePhi = await loadBaseComputePhi(baseDir);
    const phiBase = computePhi(baseDir);
    const phiHead = computePhi(candidateDir);
    if (!Number.isSafeInteger(phiBase?.total) || !Number.isSafeInteger(phiHead?.total)) {
      throw new Error("base or candidate phi total is not a safe integer");
    }
    deltaPhi = phiHead.total - phiBase.total;
  } catch (err) {
    process.stderr.write(`ci-evidence: base-authored computePhi failed: ${err.message}\n`);
    process.exit(1);
  }

  // 3. Honest suite outcomes (measured by the CI steps, never assumed)
  const prDoc = buildPrDoc({
    pr: { number: prNumber, base_sha: baseSha, head_sha: headSha, author: process.env.PR_AUTHOR },
    diff: { files_changed: diff.files, tests_deleted: diff.deletedTests },
    suite: {
      pass_base: parseBoolEnv(process.env.SUITE_PASS_BASE),
      pass_head: parseBoolEnv(process.env.SUITE_PASS_HEAD),
    },
    phi: { delta_phi: deltaPhi },
    causalCompleted: false, // Law 16: no verified reproducer artifact in this pipeline yet
  });

  const outPath = resolve(process.env.PR_DOC_PATH ?? join(candidateDir, "pr-doc.json"));
  writeFileSync(outPath, JSON.stringify(prDoc), "utf8");
  process.stdout.write(
    `ci-evidence: wrote ${outPath} (suite base=${prDoc.proof.suite_pass_base} head=${prDoc.proof.suite_pass_head} delta_phi=${deltaPhi} causal=false)\n`,
  );
}

// Run only when invoked as a CLI entrypoint, not when imported by tests.
const invokedAsCli =
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedAsCli) {
  main().catch((err) => {
    process.stderr.write(`ci-evidence: ${err?.stack || err?.message || String(err)}\n`);
    process.exit(1);
  });
}
