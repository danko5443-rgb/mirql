// packages/run/thrift.mjs — Law 13 Thrift Test producer (issue #13).
//
// verifyThrift() (phi.mjs) evaluates the thrift criteria but nothing ever
// measured its inputs: consolidation PRs were unpassable because no producer
// of phi.thrift_test_passed existed. This module MEASURES everything from a
// real git diff and emits the verdict the mergeproof evaluator consumes:
//
//   1. ΔΦ strictly < 0        — computePhi on both trees (Law 7: inject the
//                               base-authored engine in CI; local default is
//                               this package's own)
//   2. tests preserved        — no test file deleted in base...head
//   3. surface preserved      — surface.lock untouched in base...head
//   4. no dependency growth   — package.json dep+devDep counts compared
//
// Fail-closed: any measurement failure returns thrift_test_passed: false
// with the error — silence is never a passing thrift test (Law 6).

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { computePhi as localComputePhi, verifyThrift } from "./phi.mjs";

function isTestFilePath(p) {
  const norm = String(p ?? "").replaceAll("\\", "/").toLowerCase();
  return (
    norm.startsWith("tests/") ||
    norm.startsWith("test/") ||
    norm.includes(".test.") ||
    norm.includes("_test.")
  );
}

/** Extracts a git tree to a temp dir (git archive | tar). Fail-closed. */
function extractTree(repoDir, ref) {
  const dir = join(
    tmpdir(),
    `mirql-thrift-${process.pid}-${Date.now()}-${String(ref).replace(/[^a-zA-Z0-9._-]/g, "_")}`,
  );
  mkdirSync(dir, { recursive: true });
  const res = spawnSync(`git archive ${ref} | tar -x -C "${dir}"`, {
    cwd: repoDir,
    shell: true,
    encoding: "utf8",
    timeout: 60_000,
  });
  if (res.status !== 0) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
    return { ok: false, error: (res.stderr || `git archive ${ref} failed`).trim() };
  }
  return { ok: true, dir };
}

/** Counts dependencies+devDependencies in a tree's package.json (0 when absent). */
function countDeps(treeDir) {
  const pkgPath = join(treeDir, "package.json");
  if (!existsSync(pkgPath)) return 0;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    return (
      Object.keys(pkg.dependencies ?? {}).length +
      Object.keys(pkg.devDependencies ?? {}).length
    );
  } catch {
    return -1; // malformed package.json: report as unmeasurable, not zero
  }
}

/**
 * Measures the Law 13 Thrift Test for base...head of a git repository.
 *
 * @param {object} options
 * @param {string} options.repoDir - git repository to measure
 * @param {string} options.baseRef - base ref/sha
 * @param {string} [options.headRef] - head ref/sha ("HEAD" default)
 * @param {Function} [options.computePhiFn] - Law 7: base-authored engine override
 * @returns {{
 *   ok: boolean,
 *   thrift_test_passed: boolean,
 *   verdict: string,
 *   delta_phi: number,
 *   reasons: string[],
 *   evidence: {
 *     phi_base: number, phi_head: number, tests_deleted: string[],
 *     surface_changed: boolean, deps_before: number, deps_after: number
 *   },
 *   error?: string
 * }}
 */
export function runThriftTest(options = {}) {
  const { repoDir, baseRef } = options;
  const headRef = options.headRef ?? "HEAD";
  const computePhiFn = typeof options.computePhiFn === "function" ? options.computePhiFn : localComputePhi;

  if (!repoDir || !existsSync(join(repoDir, ".git"))) {
    return fail(0, {}, `${repoDir} is not a git repository`);
  }
  if (!baseRef) {
    return fail(0, {}, "baseRef is required");
  }

  // 1. Authoritative diff facts (fail-closed)
  const diffRes = spawnSync("git", ["diff", "--name-status", `${baseRef}...${headRef}`], {
    cwd: repoDir,
    encoding: "utf8",
    timeout: 30_000,
  });
  if (diffRes.status !== 0) {
    return fail(0, {}, `git diff failed: ${(diffRes.stderr || "").trim()}`);
  }
  const testsDeleted = [];
  for (const line of String(diffRes.stdout || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = line.split("\t");
    const status = parts[0];
    if (status.startsWith("D") && isTestFilePath(parts[1])) testsDeleted.push(parts[1]);
    if (status.startsWith("R") && parts.length >= 3 && isTestFilePath(parts[1]) && !isTestFilePath(parts[2])) {
      testsDeleted.push(parts[1]);
    }
  }

  const surfaceRes = spawnSync("git", ["diff", `${baseRef}...${headRef}`, "--", "surface.lock"], {
    cwd: repoDir,
    encoding: "utf8",
    timeout: 30_000,
  });
  if (surfaceRes.status !== 0) {
    return fail(0, {}, `git diff (surface.lock) failed: ${(surfaceRes.stderr || "").trim()}`);
  }
  const surfaceChanged = String(surfaceRes.stdout || "").trim().length > 0;

  // 2. Phi on both trees (measured, never assumed)
  const baseTree = extractTree(repoDir, baseRef);
  const headTree = extractTree(repoDir, headRef);
  try {
    if (!baseTree.ok || !headTree.ok) {
      const error = !baseTree.ok ? baseTree.error : headTree.error;
      return fail(0, {}, `cannot extract trees: ${error}`);
    }
    let phiBase, phiHead;
    try {
      phiBase = computePhiFn(baseTree.dir);
      phiHead = computePhiFn(headTree.dir);
    } catch (err) {
      return fail(0, {}, `computePhi failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!Number.isSafeInteger(phiBase?.total) || !Number.isSafeInteger(phiHead?.total)) {
      return fail(0, {}, "phi totals are not safe integers");
    }

    const depsBefore = countDeps(baseTree.dir);
    const depsAfter = countDeps(headTree.dir);

    const verdict = verifyThrift({
      phiBefore: phiBase.total,
      phiAfter: phiHead.total,
      testsPreserved: testsDeleted.length === 0,
      surfacePreserved: !surfaceChanged,
      ...(depsBefore >= 0 && depsAfter >= 0 ? { depCountBefore: depsBefore, depCountAfter: depsAfter } : {}),
    });

    return {
      ok: verdict.ok,
      thrift_test_passed: verdict.ok === true,
      verdict: verdict.verdict,
      delta_phi: verdict.delta_phi,
      reasons: verdict.reasons,
      evidence: {
        phi_base: phiBase.total,
        phi_head: phiHead.total,
        tests_deleted: testsDeleted,
        surface_changed: surfaceChanged,
        deps_before: depsBefore,
        deps_after: depsAfter,
      },
    };
  } finally {
    for (const tree of [baseTree, headTree]) {
      if (tree.ok && tree.dir) {
        try {
          rmSync(tree.dir, { recursive: true, force: true });
        } catch {}
      }
    }
  }
}

function fail(deltaPhi, evidencePartial, error) {
  return {
    ok: false,
    thrift_test_passed: false,
    verdict: "reject",
    delta_phi: deltaPhi,
    reasons: [error],
    evidence: {
      phi_base: 0,
      phi_head: 0,
      tests_deleted: [],
      surface_changed: false,
      deps_before: 0,
      deps_after: 0,
      ...evidencePartial,
    },
    error,
  };
}
