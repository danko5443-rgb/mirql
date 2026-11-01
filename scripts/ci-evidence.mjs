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
import { existsSync, readFileSync, writeFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

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
 * @param {{ passed: boolean, evidence?: object, reasons?: string[] }} [input.thrift]
 *        - MEASURED thrift test verdict (issue #13). Only ever true when a
 *          real thrift test ran; absent for non-consolidation PRs.
 * @param {object} [input.reproducer] - measured reproducer evidence (see verifyCausalReproducer)
 * @returns {object} pr-doc consumable by `mirql m check`
 */
export function buildPrDoc({ pr, diff, suite, phi, causalCompleted = false, thrift, reproducer }) {
  const phiBlock = { delta_phi: phi.delta_phi };
  if (thrift) {
    phiBlock.thrift_test_passed = thrift.passed === true;
    if (thrift.evidence) phiBlock.thrift_evidence = thrift.evidence;
    if (Array.isArray(thrift.reasons) && thrift.reasons.length > 0) {
      phiBlock.thrift_reasons = thrift.reasons;
    }
  }
  const doc = {
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
    phi: phiBlock,
  };
  if (reproducer) {
    doc.proof.reproducer = reproducer;
  }
  return doc;
}

/**
 * Loads and validates a candidate's `reproducer/manifest.json` (Law 16
 * verified-reproducer contract). The only meaningful causal shape is
 * red-on-base → green-on-head: a reproducer that already passes on base
 * proves nothing, so anything else is rejected fail-closed.
 *
 * Manifest shape:
 *   { "description": "...", "entry": "reproducer/x.mjs",
 *     "expect_base": "fail", "expect_head": "pass" }
 *
 * The entry script is spawned by ci-evidence itself (no shell) TWICE — once
 * against the base-notary checkout and once against the candidate — with
 * process.env.MIRQL_TARGET_ROOT set to the checkout under test. The script
 * must exercise the code under test via that root and exit non-zero when the
 * defect reproduces, zero when it is fixed.
 *
 * @param {string} candidateDir
 * @returns {{ ok: boolean, manifest?: object, error?: string }}
 */
export function loadReproducerManifest(candidateDir) {
  const manifestPath = join(resolve(candidateDir), "reproducer", "manifest.json");
  if (!existsSync(manifestPath)) {
    return { ok: false, error: "no reproducer manifest" };
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (err) {
    return { ok: false, error: `corrupt manifest: ${err.message}` };
  }
  if (typeof manifest.entry !== "string" || !manifest.entry.startsWith("reproducer/")) {
    return { ok: false, error: 'manifest.entry must be a path under reproducer/' };
  }
  if (manifest.entry.includes("..")) {
    return { ok: false, error: "manifest.entry must not escape the candidate root" };
  }
  if (manifest.expect_base !== "fail" || manifest.expect_head !== "pass") {
    return { ok: false, error: 'manifest must declare expect_base:"fail" and expect_head:"pass"' };
  }
  return { ok: true, manifest };
}

/**
 * Runs one reproducer script against a target checkout. Fail-closed: spawn
 * errors and timeouts yield exit_code null and never verify anything.
 *
 * @param {object} options
 * @param {string} options.entryAbs - absolute path to the reproducer script
 * @param {string} options.targetRoot - checkout under test (cwd + MIRQL_TARGET_ROOT)
 * @param {number} [options.timeoutMs=120000]
 * @returns {{ exit_code: number | null, timed_out: boolean, error?: string }}
 */
export function runReproducerScript({ entryAbs, targetRoot, timeoutMs = 120000 }) {
  const res = spawnSync(process.execPath, [entryAbs], {
    cwd: resolve(targetRoot),
    env: { ...process.env, MIRQL_TARGET_ROOT: resolve(targetRoot) },
    timeout: timeoutMs,
    encoding: "utf8",
  });
  if (res.error) {
    return { exit_code: null, timed_out: false, error: res.error.message };
  }
  if (res.signal || !Number.isSafeInteger(res.status)) {
    return { exit_code: null, timed_out: true, error: `terminated by signal ${res.signal ?? "unknown"}` };
  }
  return { exit_code: res.status, timed_out: false };
}

/**
 * Verifies the causal red→green reproducer cycle against the two real
 * checkouts (Law 16: measured, never attested). causal is true ONLY when the
 * base run genuinely exits non-zero AND the head run genuinely exits zero.
 *
 * @param {object} options
 * @param {string} options.candidateDir
 * @param {string} options.baseDir
 * @param {number} [options.timeoutMs=120000]
 * @returns {{ present: boolean, causal: boolean, entry?: string, description?: string,
 *            base_exit_code: number | null, head_exit_code: number | null, error?: string }}
 */
export function verifyCausalReproducer({ candidateDir, baseDir, timeoutMs = 120000 }) {
  const loaded = loadReproducerManifest(candidateDir);
  if (!loaded.ok) {
    return { present: false, causal: false, base_exit_code: null, head_exit_code: null };
  }
  const manifest = loaded.manifest;
  const entryAbs = join(resolve(candidateDir), ...manifest.entry.split("/"));
  if (!existsSync(entryAbs)) {
    return {
      present: true, causal: false, entry: manifest.entry,
      base_exit_code: null, head_exit_code: null,
      error: `entry script not found: ${manifest.entry}`,
    };
  }
  const baseRun = runReproducerScript({ entryAbs, targetRoot: baseDir, timeoutMs });
  const headRun = runReproducerScript({ entryAbs, targetRoot: candidateDir, timeoutMs });
  const causal =
    baseRun.exit_code !== null && baseRun.exit_code !== 0 &&
    headRun.exit_code !== null && headRun.exit_code === 0;
  const error = baseRun.error ?? headRun.error;
  return {
    present: true,
    causal,
    entry: manifest.entry,
    description: typeof manifest.description === "string" ? manifest.description : "",
    base_exit_code: baseRun.exit_code,
    head_exit_code: headRun.exit_code,
    ...(error ? { error } : {}),
  };
}

/**
 * Loads the base-notary phi engine module (Law 7: the running version N-1
 * owns the metric definitions; the candidate never measures itself).
 */
async function loadBasePhiEngine(baseDir) {
  const phiPath = join(resolve(baseDir), "packages", "run", "phi.mjs");
  if (!existsSync(phiPath)) {
    throw new Error(`Law 7 fail-closed: base-notary phi engine not found at ${phiPath}`);
  }
  return import(pathToFileURL(phiPath).href);
}

/** Loads computePhi from the BASE-NOTARY checkout (Law 7). */
export async function loadBaseComputePhi(baseDir) {
  const mod = await loadBasePhiEngine(baseDir);
  if (typeof mod.computePhi !== "function") {
    throw new Error("Law 7 fail-closed: base-notary phi.mjs does not export computePhi");
  }
  return mod.computePhi;
}

/** Loads verifyThrift from the BASE-NOTARY checkout (same Law 7 rationale). */
export async function loadBaseVerifyThrift(baseDir) {
  const mod = await loadBasePhiEngine(baseDir);
  if (typeof mod.verifyThrift !== "function") {
    throw new Error("Law 7 fail-closed: base-notary phi.mjs does not export verifyThrift");
  }
  return mod.verifyThrift;
}

/** Counts all external dependencies across all dependency blocks in a tree's package.json (Law 0, −1 when unmeasurable). */
function countDeps(treeDir) {
  const pkgPath = join(resolve(treeDir), "package.json");
  if (!existsSync(pkgPath)) return 0;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    return (
      Object.keys(pkg.dependencies ?? {}).length +
      Object.keys(pkg.devDependencies ?? {}).length +
      Object.keys(pkg.peerDependencies ?? {}).length +
      Object.keys(pkg.optionalDependencies ?? {}).length
    );
  } catch {
    return -1;
  }
}

/**
 * Law 13 Thrift Test measurement (issue #13), composed from facts the
 * evidence builder has ALREADY measured: base-authored ΔΦ, deleted tests,
 * surface.lock delta, dependency growth. Criteria evaluation is delegated to
 * the BASE notary's own verifyThrift (Law 7: version N-1 owns the rules).
 *
 * @param {object} input
 * @param {number} input.phiBase
 * @param {number} input.phiHead
 * @param {string[]} [input.deletedTests=[]]
 * @param {string[]} [input.filesChanged=[]]
 * @param {number} [input.depsBase=0]
 * @param {number} [input.depsHead=0]
 * @param {Function} input.verifyThriftFn
 * @returns {{ passed: boolean, evidence: object, reasons: string[] }}
 */
export function measureThrift({
  phiBase,
  phiHead,
  deletedTests = [],
  filesChanged = [],
  depsBase = 0,
  depsHead = 0,
  verifyThriftFn,
}) {
  const safeFiles = Array.isArray(filesChanged) ? filesChanged : [];
  const safeDeleted = Array.isArray(deletedTests) ? deletedTests : [];
  const surfacePreserved = !safeFiles.some((f) => {
    const norm = String(f ?? "").replaceAll("\\", "/").replace(/^\.\//, "").trim();
    return norm === "surface.lock";
  });

  if (typeof verifyThriftFn !== "function") {
    return {
      passed: false,
      evidence: { surface_changed: !surfacePreserved, deps_before: depsBase, deps_after: depsHead },
      reasons: ["Law 7 fail-closed: verifyThrift function not provided or not a function"],
    };
  }

  const verdict = verifyThriftFn({
    phiBefore: phiBase,
    phiAfter: phiHead,
    testsPreserved: safeDeleted.length === 0,
    surfacePreserved,
    ...(depsBase >= 0 && depsHead >= 0 ? { depCountBefore: depsBase, depCountAfter: depsHead } : {}),
  });
  // Evidence carries only facts NOT already present elsewhere in the pr-doc
  // (delta_phi and tests_deleted live at top level; criteria internals are
  // pinned by the m2 suite's verifyThrift tests).
  return {
    passed: verdict.ok === true,
    evidence: {
      surface_changed: !surfacePreserved,
      deps_before: depsBase,
      deps_after: depsHead,
    },
    reasons: verdict.reasons ?? [],
  };
}

export async function main(env = process.env) {
  const required = ["BASE_NOTARY_DIR", "CANDIDATE_DIR", "BASE_SHA", "HEAD_SHA", "PR_NUMBER", "PR_AUTHOR", "SUITE_PASS_BASE", "SUITE_PASS_HEAD"];
  const missing = required.filter((k) => !env[k]);
  if (missing.length > 0) {
    process.stderr.write(`ci-evidence: missing required env: ${missing.join(", ")}\n`);
    process.exit(1);
  }

  const baseDir = resolve(env.BASE_NOTARY_DIR);
  const candidateDir = resolve(env.CANDIDATE_DIR);
  const baseSha = env.BASE_SHA;
  const headSha = env.HEAD_SHA;
  const prRaw = String(env.PR_NUMBER || "").trim();
  if (!/^\d+$/.test(prRaw)) {
    process.stderr.write(`ci-evidence: PR_NUMBER is not a safe positive integer\n`);
    process.exit(1);
  }
  const prNumber = Number.parseInt(prRaw, 10);
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
  let phiBaseTotal;
  let phiHeadTotal;
  try {
    const computePhi = await loadBaseComputePhi(baseDir);
    const phiBase = computePhi(baseDir);
    const phiHead = computePhi(candidateDir);
    if (!Number.isSafeInteger(phiBase?.total) || !Number.isSafeInteger(phiHead?.total)) {
      throw new Error("base or candidate phi total is not a safe integer");
    }
    phiBaseTotal = phiBase.total;
    phiHeadTotal = phiHead.total;
    deltaPhi = phiHeadTotal - phiBaseTotal;
  } catch (err) {
    process.stderr.write(`ci-evidence: base-authored computePhi failed: ${err.message}\n`);
    process.exit(1);
  }

  // 2b. Law 13 Thrift Test (issue #13): the evaluator fail-closes
  // THRIFT_TEST_FAILED on consolidation PRs (delta_phi < 0) unless
  // phi.thrift_test_passed === true — so exactly then, MEASURE it from the
  // facts already in hand (diff, deleted tests, both checkouts) with the BASE
  // notary's own verifyThrift criteria (Law 7). Non-consolidations (ΔΦ ≥ 0)
  // never claim a thrift pass.
  let thrift;
  if (deltaPhi < 0) {
    try {
      const verifyThriftFn = await loadBaseVerifyThrift(baseDir);
      thrift = measureThrift({
        phiBase: phiBaseTotal,
        phiHead: phiHeadTotal,
        deletedTests: diff.deletedTests,
        filesChanged: diff.files,
        depsBase: countDeps(baseDir),
        depsHead: countDeps(candidateDir),
        verifyThriftFn,
      });
    } catch (err) {
      thrift = { passed: false, reasons: [`thrift measurement failed: ${err.message}`] };
    }
  }

  // 3. Law 16 verified-reproducer cycle: when the candidate carries a
  // reproducer/manifest.json, run its entry against BOTH real checkouts and
  // measure the red→green cycle. causal is true ONLY on a genuinely observed
  // non-zero-on-base + zero-on-head outcome pair — never attested (Law 6).
  const reproducer = verifyCausalReproducer({ candidateDir, baseDir });

  // 4. Honest suite outcomes (measured by the CI steps, never assumed)
  const prDoc = buildPrDoc({
    pr: { number: prNumber, base_sha: baseSha, head_sha: headSha, author: env.PR_AUTHOR },
    diff: { files_changed: diff.files, tests_deleted: diff.deletedTests },
    suite: {
      pass_base: parseBoolEnv(env.SUITE_PASS_BASE),
      pass_head: parseBoolEnv(env.SUITE_PASS_HEAD),
    },
    phi: { delta_phi: deltaPhi },
    causalCompleted: reproducer.causal,
    thrift,
    ...(reproducer.present ? { reproducer } : {}),
  });

  const outPath = resolve(env.PR_DOC_PATH ?? join(candidateDir, "pr-doc.json"));
  writeFileSync(outPath, JSON.stringify(prDoc), "utf8");
  process.stdout.write(
    `ci-evidence: wrote ${outPath} (suite base=${prDoc.proof.suite_pass_base} head=${prDoc.proof.suite_pass_head} delta_phi=${deltaPhi} causal=${reproducer.causal}${reproducer.present ? ` reproducer_base=${reproducer.base_exit_code} reproducer_head=${reproducer.head_exit_code}` : ""}${thrift ? ` thrift=${prDoc.phi.thrift_test_passed}` : ""})\n`,
  );
}

// Robust CLI invocation check using realpath
function isInvokedAsCli() {
  if (!process.argv[1]) return false;
  try {
    const argv1Real = realpathSync(resolve(process.argv[1]));
    const thisFileReal = realpathSync(fileURLToPath(import.meta.url));
    return argv1Real.toLowerCase() === thisFileReal.toLowerCase();
  } catch {
    return false;
  }
}

if (isInvokedAsCli()) {
  main().catch((err) => {
    process.stderr.write(`ci-evidence: ${err?.stack || err?.message || String(err)}\n`);
    process.exit(1);
  });
}
