#!/usr/bin/env node
// scripts/ci-evidence.mjs — honest Notary evidence builder (Laws 4, 6, 7, 16, 17).
//
// Replaces the inline pr-doc synthesis in .github/workflows/mergeproof.yml with
// a committed, testable script. Every field is MEASURED, never assumed:
//   - files / deleted tests come from the authoritative git diff (fail-closed)
//   - proof.suite_pass_base / proof.suite_pass_head mirror the real outcomes of
//     the base-notary and candidate suite steps (Law 7: base-authored evidence)
//   - sourceCode carries the HEAD-committed content of every changed .mjs file
//     so the notary's MP-002/MP-003 diff-gate scans run on measured evidence
//   - phi.delta_phi is computed by the base-notary's own computePhi (Law 13)
//   - proof.causal_cycle_completed is ALWAYS false in CI: the exit codes of a
//     candidate-supplied script are attestation, not measurement (a script
//     can inspect which tree it runs in and pick its exit code), so no
//     candidate script is ever executed here (Laws 6 & 16). The only accepted
//     causal proof is the measured git-worktree verifier (packages/run).
//     A reproducer manifest, when present, is validated and recorded as DATA.
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
 * @returns {{ ok: boolean, error?: string, files: string[], deletedTests: string[], deletedFiles: string[] }}
 *   deletedFiles lists EVERY deleted or renamed-away path (not just tests) so
 *   source collection knows which changed paths have no content at head.
 */
export function collectDiff(baseSha, headSha, repoDir) {
  if (!baseSha || !headSha || !repoDir) {
    return { ok: false, error: "collectDiff requires baseSha, headSha, repoDir", files: [], deletedTests: [], deletedFiles: [] };
  }
  if (!existsSync(join(repoDir, ".git"))) {
    return { ok: false, error: `Directory ${repoDir} is not a git repository`, files: [], deletedTests: [], deletedFiles: [] };
  }
  const res = spawnSync(
    "git",
    // -z: NUL-separated fields, byte-exact paths. Otherwise git C-quotes
    // any path with a byte >0x7F, a quote, or a backslash, and the later
    // `git show` lookup fails on that legitimate path.
    ["diff", "--name-status", "-z", `${baseSha}...${headSha}`],
    { cwd: repoDir, encoding: "utf8", timeout: 15000 },
  );
  if (res.status !== 0) {
    const err = (res.stderr || res.stdout || `git exit code ${res.status}`).trim();
    return { ok: false, error: err, files: [], deletedTests: [] };
  }
  const files = [];
  const deletedTests = [];
  const deletedFiles = [];
  // -z record shape: `status\0path\0`; renames: `status\0old\0new\0`
  const fields = String(res.stdout || "").split("\0");
  for (let i = 0; i < fields.length; i++) {
    const status = fields[i];
    if (!status) continue;
    const rename = status.startsWith("R") && i + 2 < fields.length;
    if (!rename && i + 1 >= fields.length) continue;
    const oldFile = fields[i + 1];
    i += rename ? 2 : 1;
    files.push(fields[i]);
    if (rename) {
      deletedFiles.push(oldFile);
      if (isTestFilePath(oldFile) && !isTestFilePath(fields[i])) {
        deletedTests.push(oldFile);
      }
    } else if (status.startsWith("D")) {
      deletedFiles.push(fields[i]);
      if (isTestFilePath(fields[i])) {
        deletedTests.push(fields[i]);
      }
    }
  }
  return { ok: true, files, deletedTests, deletedFiles };
}

/**
 * HEAD-committed content of every changed .mjs file, so the base notary's
 * MP-002/MP-003 diff-gate scans run on measured evidence instead of silently
 * skipping (Laws 6 & 7: the scanner is base-authored; this content is data).
 * Content comes from `git show <head>:<path>` — the committed bytes, never the
 * working tree. Deleted paths have no content at head and are skipped; any
 * other read failure fails closed rather than leaving a file unscanned.
 *
 * @param {string[]} files - changed paths (from collectDiff)
 * @param {string[]} deletedFiles - paths with no content at head (from collectDiff)
 * @param {string} headSha
 * @param {string} repoDir - candidate git repository
 * @returns {{ ok: boolean, error?: string, sourceCode: Record<string, string> }}
 */
export function collectSourceCode(files, deletedFiles, headSha, repoDir) {
  if (!headSha || !repoDir) {
    return { ok: false, error: "collectSourceCode requires headSha, repoDir", sourceCode: {} };
  }
  const deleted = new Set(deletedFiles);
  const sourceCode = {};
  for (const file of Array.isArray(files) ? files : []) {
    if (deleted.has(file) || !String(file).endsWith(".mjs")) continue;
    const res = spawnSync("git", ["-C", repoDir, "show", `${headSha}:${file}`], {
      encoding: "utf8",
      timeout: 15000,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.status !== 0) {
      const err = (res.stderr || res.stdout || `git exit code ${res.status}`).trim();
      return { ok: false, error: `reading ${file} at ${headSha.slice(0, 10)}: ${err}`, sourceCode: {} };
    }
    sourceCode[file] = res.stdout;
  }
  return { ok: true, sourceCode };
}

/**
 * Composes the PR evidence document from measured inputs (pure function).
 *
 * @param {object} input
 * @param {{ number: number, base_sha: string, head_sha: string, author: string }} input.pr
 * @param {{ files_changed: string[], tests_deleted: string[] }} input.diff
 * @param {{ pass_base: boolean, pass_head: boolean }} input.suite
 * @param {{ delta_phi: number }} input.phi
 * @param {boolean} [input.causalCompleted=false] - main() NEVER passes true:
 *        causal proof comes only from the measured git-worktree verifier,
 *        never from a candidate reproducer's exit codes
 * @param {{ passed: boolean, evidence?: object, reasons?: string[] }} [input.thrift]
 *        - MEASURED thrift test verdict (issue #13). Only ever true when a
 *          real thrift test ran; absent for non-consolidation PRs.
 * @param {Record<string, string>} [input.sourceCode] - HEAD-committed content of
 *        every changed .mjs file (see collectSourceCode); consumed by the base
 *        notary's MP-002/MP-003 diff-gate scans
 * @param {object} [input.reproducer] - DATA-ONLY manifest record (see
 *        loadReproducerManifest); never a source of causal proof
 * @returns {object} pr-doc consumable by `mirql m check`
 */
export function buildPrDoc({ pr, diff, suite, phi, causalCompleted = false, thrift, sourceCode, reproducer }) {
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
  if (sourceCode && Object.keys(sourceCode).length > 0) {
    doc.sourceCode = sourceCode;
  }
  if (reproducer) {
    doc.proof.reproducer = reproducer;
  }
  return doc;
}

/**
 * Loads and validates a candidate's `reproducer/manifest.json` (Law 16
 * verified-reproducer contract). The manifest is recorded as DATA ONLY —
 * presence and declared entry — never as causal proof: executing a
 * candidate-supplied script would let it inspect which tree it runs in and
 * pick its own exit codes, which is attestation, not measurement. The only
 * accepted causal cycle is the one measured by the git-worktree verifier
 * (packages/run), and it never flows through this builder.
 *
 * Manifest shape (validated, not executed):
 *   { "description": "...", "entry": "reproducer/x.mjs",
 *     "expect_base": "fail", "expect_head": "pass" }
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

  // 2c. Law 6: the HEAD-committed content of every changed .mjs file, so the
  // base notary's MP-002/MP-003 diff-gate scans run on measured evidence
  // instead of silently skipping. Read from the candidate's git objects —
  // never its working tree — and fail-closed: an unreadable file must stop
  // the evidence build, not slip past the scan.
  const sourceInfo = collectSourceCode(diff.files, diff.deletedFiles, headSha, candidateDir);
  if (!sourceInfo.ok) {
    process.stderr.write(`ci-evidence: source collection failed: ${sourceInfo.error}\n`);
    process.exit(1);
  }

  // 3. Law 16: causal proof is NEVER produced in CI. A candidate-supplied
  // reproducer script runs with this job's environment on both checkouts and
  // can inspect which tree it is in before picking its exit code — that is
  // attestation, not measurement — so it is never executed. causalCompleted
  // is therefore always false here; the only accepted causal proof is the
  // measured git-worktree verifier (packages/run). The manifest, when
  // present, is validated and recorded as DATA ONLY.
  const manifestInfo = loadReproducerManifest(candidateDir);
  const reproducer = manifestInfo.ok
    ? {
        present: true,
        causal: false,
        entry: manifestInfo.manifest.entry,
        description:
          typeof manifestInfo.manifest.description === "string"
            ? manifestInfo.manifest.description
            : "",
      }
    : { present: false, causal: false };

  // 4. Honest suite outcomes (measured by the CI jobs, never assumed)
  const prDoc = buildPrDoc({
    pr: { number: prNumber, base_sha: baseSha, head_sha: headSha, author: env.PR_AUTHOR },
    diff: { files_changed: diff.files, tests_deleted: diff.deletedTests },
    suite: {
      pass_base: parseBoolEnv(env.SUITE_PASS_BASE),
      pass_head: parseBoolEnv(env.SUITE_PASS_HEAD),
    },
    phi: { delta_phi: deltaPhi },
    thrift,
    sourceCode: sourceInfo.sourceCode,
    ...(reproducer.present ? { reproducer } : {}),
  });

  const outPath = resolve(env.PR_DOC_PATH ?? join(candidateDir, "pr-doc.json"));
  writeFileSync(outPath, JSON.stringify(prDoc), "utf8");
  process.stdout.write(
    `ci-evidence: wrote ${outPath} (suite base=${prDoc.proof.suite_pass_base} head=${prDoc.proof.suite_pass_head} delta_phi=${deltaPhi} causal=${prDoc.proof.causal_cycle_completed} source_files=${Object.keys(prDoc.sourceCode ?? {}).length}${reproducer.present ? ` reproducer=present-data-only` : ""}${thrift ? ` thrift=${prDoc.phi.thrift_test_passed}` : ""})\n`,
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
