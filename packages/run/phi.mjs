// packages/run/phi.mjs — Law 11, Law 13 & Law 17: Complexity Potential PHI and Thrift Engine.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

/**
 * Law 11, 13 & 17 — Complexity Potential Phi (Phi).
 *
 * Computes integer-only complexity metrics for a codebase workspace:
 * - `loc`: lines of code across JS/MJS source files (non-empty).
 * - `export_count`: exported symbols / declarations count.
 * - `cyclomatic`: estimate of decision branching points.
 * - `dep_count`: count of external dependencies in package.json (Law 0).
 * - `dup_blocks`: count of identical repeated code blocks (>= 3 lines).
 * - `debt_markers`: count of debt marker comments.
 * - `max_nesting_depth`: maximum indentation/bracket nesting depth.
 * - `test_gaps`: count of `packages/**` source files not reachable from any
 *   `tests/*.test.mjs` file via the relative-import graph (Law 13 "test gaps":
 *   a module no test can even import is untested code). Scoped to `packages/`
 *   because that is the shipped library surface; `bin/` entrypoints are thin
 *   wrappers exercised end-to-end via process spawn, and `scripts/` is dev
 *   tooling — neither is import-graph coverage debt.
 * - `total`: composite safe-integer score:
 *   loc + 2*export_count + 3*cyclomatic + 10*dep_count + 5*dup_blocks + 4*debt_markers + 2*max_nesting_depth + 6*test_gaps.
 *
 * Every number returned is strictly guaranteed to be a safe integer (Law 17).
 *
 * @param {string} [workspaceDir]
 * @returns {{
 *   loc: number,
 *   export_count: number,
 *   cyclomatic: number,
 *   dep_count: number,
 *   dup_blocks: number,
 *   debt_markers: number,
 *   max_nesting_depth: number,
 *   test_gaps: number,
 *   total: number
 * }}
 */
export function computePhi(workspaceDir = process.cwd()) {
  const root = resolve(workspaceDir);
  const files = collectSourceFiles(root);

  let loc = 0;
  let exportCount = 0;
  let cyclomatic = 0;
  const blockHashes = new Map();
  let dupBlocks = 0;
  let debtMarkers = 0;
  let maxNestingDepth = 0;
  const contentsByFile = new Map();

  for (const file of files) {
    const content = readFileSync(file, "utf8");
    contentsByFile.set(file, content);
    const lines = content.split(/\r?\n/);

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;
      loc++;

      // Count exports
      if (
        line.startsWith("export ") ||
        line.startsWith("export default") ||
        line.startsWith("module.exports")
      ) {
        exportCount++;
      }
    }

    // Cyclomatic approximation: count branching control tokens
    const branchMatches = content.match(
      /\b(if|else if|for|while|case|catch|\?\?|\?:|\&\&|\|\|)\b/g,
    );
    if (branchMatches) {
      cyclomatic += branchMatches.length;
    }

    // Debt markers count (only in code lines, excluding self-referential detector file)
    if (!file.endsWith("phi.mjs")) {
      const debtMatches = content.match(/\b(TODO|FIXME|HACK|XXX)\b/g);
      if (debtMatches) {
        debtMarkers += debtMatches.length;
      }
    }

    // Maximum nesting depth analysis
    let currentDepth = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) continue;
      for (const char of trimmed) {
        if (char === "{" || char === "(" || char === "[") {
          currentDepth++;
          if (currentDepth > maxNestingDepth) {
            maxNestingDepth = currentDepth;
          }
        } else if (char === "}" || char === ")" || char === "]") {
          if (currentDepth > 0) currentDepth--;
        }
      }
    }

    // Duplicate 3-line blocks check
    for (let i = 0; i <= lines.length - 3; i++) {
      const block = lines
        .slice(i, i + 3)
        .map((l) => l.trim())
        .filter(Boolean)
        .join("\n");
      if (block.length > 30) {
        const count = blockHashes.get(block) || 0;
        if (count === 1) {
          dupBlocks++;
        }
        blockHashes.set(block, count + 1);
      }
    }
  }

  // Count external dependencies from package.json if present
  let depCount = 0;
  const pkgPath = join(root, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      depCount += Object.keys(pkg.dependencies || {}).length;
      depCount += Object.keys(pkg.devDependencies || {}).length;
      depCount += Object.keys(pkg.peerDependencies || {}).length;
      depCount += Object.keys(pkg.optionalDependencies || {}).length;
    } catch {
      // ignore parse errors
    }
  }

  // Law 13 "test gaps": package modules unreachable from any test file.
  const testGaps = computeTestGaps(root, files, contentsByFile);

  const total =
    loc +
    exportCount * 2 +
    cyclomatic * 3 +
    depCount * 10 +
    dupBlocks * 5 +
    debtMarkers * 4 +
    maxNestingDepth * 2 +
    testGaps * 6;

  return {
    loc: Math.trunc(loc),
    export_count: Math.trunc(exportCount),
    cyclomatic: Math.trunc(cyclomatic),
    dep_count: Math.trunc(depCount),
    dup_blocks: Math.trunc(dupBlocks),
    debt_markers: Math.trunc(debtMarkers),
    max_nesting_depth: Math.trunc(maxNestingDepth),
    test_gaps: Math.trunc(testGaps),
    total: Math.trunc(total),
  };
}

/**
 * Law 13 test-gap metric: counts `packages/**` source files that no test file
 * reaches via the relative-import graph (direct or transitive). Deterministic,
 * offline (Law 1), and integer-only (Law 17). Workspaces without a `packages/`
 * directory or without `tests/*.test.mjs` files score 0 gaps (metric scoped to
 * the mirql package layout; documented, not silently widened).
 *
 * Weight rationale: an entirely untested module is heavier debt than a TODO
 * marker (4) but lighter than an illicit external dependency (10) — hence 6.
 *
 * @param {string} root
 * @param {string[]} files
 * @param {Map<string, string>} contentsByFile
 * @returns {number}
 */
function computeTestGaps(root, files, contentsByFile) {
  const normalizedRoot = resolve(root);
  const underRoot = (p) => {
    const rel = relative(normalizedRoot, p);
    return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel) ? rel : null;
  };
  const isTestFile = (p) => {
    const rel = underRoot(p);
    return rel !== null && rel.split(sep)[0] === "tests" && /\.test\.(mjs|js)$/.test(rel);
  };
  const isGapCandidate = (p) => {
    const rel = underRoot(p);
    return rel !== null && rel.split(sep)[0] === "packages" && /\.m?js$/.test(rel);
  };

  // Build the relative-import edge list once for every collected file.
  const fileSet = new Set(files);
  const edges = new Map();
  for (const file of files) {
    const content = contentsByFile.get(file) ?? "";
    const specs = extractRelativeSpecifiers(content);
    const targets = [];
    for (const spec of specs) {
      const resolved = resolveSpecifier(dirname(file), spec, fileSet);
      if (resolved) targets.push(resolved);
    }
    edges.set(file, targets);
  }

  // BFS from every test file; mark reached files.
  const reached = new Set();
  const queue = files.filter(isTestFile);
  for (const t of queue) reached.add(t);
  while (queue.length > 0) {
    const current = queue.shift();
    for (const next of edges.get(current) ?? []) {
      if (!reached.has(next)) {
        reached.add(next);
        queue.push(next);
      }
    }
  }

  let gaps = 0;
  for (const file of files) {
    if (isGapCandidate(file) && !reached.has(file)) gaps++;
  }
  return gaps;
}

/** Extracts relative import/export-from, side-effect import, dynamic import(), and require() specifiers. */
function extractRelativeSpecifiers(content) {
  const specs = [];
  // import ... from './x' / export ... from './x' (bounded scan window keeps
  // the match on the same statement even across newlines)
  const staticFrom = /(?:^|[;{}\s])(?:import|export)\s[\s\S]{0,400}?from\s*["'](\.[^"']+)["']/g;
  // bare side-effect import './x' (no from clause)
  const sideEffect = /(?:^|[;{}\s])import\s*["'](\.[^"']+)["']/g;
  // dynamic import('./x') and require('./x')
  const dynamicCall = /\b(?:import|require)\s*\(\s*["'](\.[^"']+)["']\s*\)/g;
  for (const re of [staticFrom, sideEffect, dynamicCall]) {
    let m;
    while ((m = re.exec(content)) !== null) {
      if (!specs.includes(m[1])) specs.push(m[1]);
    }
  }
  return specs;
}

/** Resolves a relative specifier to an existing collected file, or null. */
function resolveSpecifier(fromDir, spec, fileSet) {
  const base = resolve(fromDir, spec);
  const candidates = [
    base,
    `${base}.mjs`,
    `${base}.js`,
    join(base, "index.mjs"),
    join(base, "index.js"),
  ];
  for (const candidate of candidates) {
    if (fileSet.has(candidate)) return candidate;
  }
  return null;
}

/**
 * Law 13 — Verifies non-increasing or strictly decreasing Phi.
 *
 * @param {number} phiBefore
 * @param {number} phiAfter
 * @param {boolean} [strict=false] - If true, requires strictly delta_phi < 0 (consolidator requirement)
 * @returns {{ ok: boolean, delta_phi: number }}
 */
export function checkPhiReduction(phiBefore, phiAfter, strict = false) {
  if (!Number.isSafeInteger(phiBefore) || !Number.isSafeInteger(phiAfter)) {
    throw new TypeError("phi values must be safe integers");
  }
  const deltaPhi = phiAfter - phiBefore;
  const ok = strict ? deltaPhi < 0 : deltaPhi <= 0;
  return { ok, delta_phi: deltaPhi };
}

/**
 * Evaluates Law 13 Monotone Potential gate for PR/patch validation.
 * Fails closed if delta_phi is missing (Law 6).
 *
 * @param {object} options
 * @param {number} [options.phiBefore]
 * @param {number} [options.phiAfter]
 * @param {number} [options.deltaPhi]
 * @param {string} [options.author]
 * @param {string} [options.role]
 * @param {string} [options.kind]
 * @param {number} [options.featureBudget=0]
 * @returns {{
 *   ok: boolean,
 *   verdict: string,
 *   delta_phi?: number,
 *   rule?: string,
 *   violation?: string,
 *   detail?: string
 * }}
 */
export function evaluatePhiGate(options = {}) {
  const phiBase =
    options.phiBefore ??
    options.phi_base ??
    options.phi?.phi_base ??
    options.phi?.phi_before;
  const phiHead =
    options.phiAfter ??
    options.phi_head ??
    options.phi?.phi_head ??
    options.phi?.phi_after;

  let deltaPhi =
    options.deltaPhi ??
    options.delta_phi ??
    options.phi?.delta_phi;

  if (deltaPhi === undefined && phiBase !== undefined && phiHead !== undefined) {
    if (!Number.isSafeInteger(phiBase) || !Number.isSafeInteger(phiHead)) {
      throw new TypeError("phi values must be safe integers");
    }
    deltaPhi = phiHead - phiBase;
  }

  // Law 6: Missing metrics fail closed! Never auto-merge empty/missing delta_phi
  if (deltaPhi === undefined) {
    return {
      ok: false,
      verdict: "reject",
      rule: "LAW_13_PHI_MISSING",
      violation: "MISSING_PHI",
      detail: "Law 13 invariant violation: complexity potential measurement is missing (delta_phi not provided).",
    };
  }

  if (!Number.isSafeInteger(deltaPhi)) {
    throw new TypeError(`deltaPhi must be a safe integer, got ${JSON.stringify(deltaPhi)}`);
  }

  const kind = options.kind ?? options.pr?.kind ?? "";
  const author = options.author ?? options.role ?? options.pr?.author ?? "";
  const isConsolidation =
    kind === "refactor" ||
    kind === "consolidation" ||
    String(author).toLowerCase().includes("consolidator");

  if (isConsolidation && deltaPhi >= 0) {
    return {
      ok: false,
      verdict: "reject",
      delta_phi: deltaPhi,
      rule: "LAW_13_CONSOLIDATOR_PHI",
      violation: "CONSOLIDATOR_PHI_NOT_DECREASED",
      detail: `Law 13 invariant violation: consolidation requires strictly decreasing complexity potential (\u0394\u03a6 must be < 0, got ${deltaPhi}).`,
    };
  }

  const featureBudget = options.featureBudget ?? options.max_delta_phi ?? 0;
  if (!Number.isSafeInteger(featureBudget)) {
    throw new TypeError("featureBudget must be a safe integer");
  }

  if (deltaPhi > featureBudget) {
    return {
      ok: false,
      verdict: "reject",
      delta_phi: deltaPhi,
      rule: "LAW_13_PHI_INCREASE",
      violation: "PHI_INCREASED",
      detail: `Law 13 invariant violation: complexity potential increased beyond budget (\u0394\u03a6 = +${deltaPhi} > ${featureBudget}).`,
    };
  }

  return {
    ok: true,
    verdict: "auto_merge",
    delta_phi: deltaPhi,
  };
}

/**
 * Law 13 Thrift Test: Verifies refactoring candidate meets all thrift criteria.
 *
 * Requirements for Consolidator PRs:
 * 1. Strict potential reduction: delta_phi < 0.
 * 2. Test preservation: zero tests deleted, no weakened assertions.
 * 3. Public API surface intact: surface.lock unchanged unless explicitly approved.
 * 4. Zero redundant external dependency growth.
 *
 * @param {object} options
 * @param {number} options.phiBefore
 * @param {number} options.phiAfter
 * @param {boolean} options.testsPreserved
 * @param {boolean} options.surfacePreserved
 * @param {number} [options.depCountBefore]
 * @param {number} [options.depCountAfter]
 * @returns {{ ok: boolean, verdict: string, reasons: string[], thrift_score: number, delta_phi: number }}
 */
export function verifyThrift(options = {}) {
  const { phiBefore, phiAfter } = options;
  const reasons = [];

  if (!Number.isSafeInteger(phiBefore) || !Number.isSafeInteger(phiAfter)) {
    throw new TypeError("phiBefore and phiAfter must be safe integers");
  }

  // Law 6: fail-closed if required verification assertions are omitted
  if (!("testsPreserved" in options) || !("surfacePreserved" in options)) {
    reasons.push("Law 6 fail-closed: testsPreserved and surfacePreserved must be explicitly asserted");
  } else {
    if (!options.testsPreserved) {
      reasons.push("Test preservation check failed: existing tests deleted or weakened");
    }
    if (!options.surfacePreserved) {
      reasons.push("Public surface preserved check failed: unauthorized modifications to surface");
    }
  }

  if ("depCountBefore" in options && "depCountAfter" in options) {
    if (options.depCountAfter > options.depCountBefore) {
      reasons.push("Redundant dependency detected: external dependency count increased");
    }
  }

  const deltaPhi = phiAfter - phiBefore;
  if (deltaPhi >= 0) {
    reasons.push(`Refactoring did not strictly decrease complexity potential (\u0394\u03a6 = ${deltaPhi} >= 0)`);
  }

  const ok = reasons.length === 0;
  const thriftScore = Math.max(0, -deltaPhi);

  return {
    ok,
    verdict: ok ? "pass" : "reject",
    delta_phi: deltaPhi,
    thrift_score: thriftScore,
    reasons,
  };
}

/** Recursively collect .mjs, .js files, skipping node_modules, .git, .mirql, etc. */
function collectSourceFiles(dir, collected = []) {
  if (!existsSync(dir)) return collected;
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (
        entry.name !== "node_modules" &&
        entry.name !== ".git" &&
        entry.name !== ".mirql" &&
        entry.name !== "coverage"
      ) {
        collectSourceFiles(full, collected);
      }
    } else if (entry.name.endsWith(".mjs") || entry.name.endsWith(".js")) {
      collected.push(full);
    }
  }
  return collected;
}
