// packages/run/phi.mjs — Law 11, Law 13 & Law 17: Complexity Potential PHI and Thrift Engine.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Law 11, 13 & 17 — Complexity Potential Phi (Phi).
 *
 * Computes integer-only complexity metrics for a codebase workspace:
 * - `loc`: lines of code across JS/MJS source files (non-empty).
 * - `export_count`: exported symbols / declarations count.
 * - `cyclomatic`: estimate of decision branching points.
 * - `dep_count`: count of external dependencies in package.json (Law 0).
 * - `dup_blocks`: count of identical repeated code blocks (>= 3 lines).
 * - `debt_markers`: count of debt marker comments (TODO, FIXME, HACK, XXX).
 * - `max_nesting_depth`: maximum indentation/bracket nesting depth.
 * - `total`: composite safe-integer score:
 *   loc + 2*export_count + 3*cyclomatic + 10*dep_count + 5*dup_blocks + 4*debt_markers + 2*max_nesting_depth.
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

  for (const file of files) {
    const content = readFileSync(file, "utf8");
    const lines = content.split(/\r?\n/);
    const nonEmptyLines = lines.filter((l) => l.trim().length > 0);
    loc += nonEmptyLines.length;

    // Export count
    const exportMatches = content.match(
      /\bexport\s+(?:default|const|let|var|function|class|async\s+function|\*|\{)/g,
    );
    if (exportMatches) {
      exportCount += exportMatches.length;
    }

    // Cyclomatic complexity: 1 base per file + branching decision points
    cyclomatic += 1;
    const branchMatches = content.match(
      /\b(if|else\s+if|for|while|catch|case)\b|(?:\&\&|\|\||\?\?|\?(?!\.))/g,
    );
    if (branchMatches) {
      cyclomatic += branchMatches.length;
    }

    // Debt markers count (TODO, FIXME, HACK, XXX)
    const debtMatches = content.match(/\b(TODO|FIXME|HACK|XXX)\b/g);
    if (debtMatches) {
      debtMarkers += debtMatches.length;
    }

    // Maximum nesting depth analysis
    let currentDepth = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
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
        .join("\n");
      if (block.length > 20) {
        const count = blockHashes.get(block) ?? 0;
        if (count === 1) {
          dupBlocks += 1;
        }
        blockHashes.set(block, count + 1);
      }
    }
  }

  // Dependency count from package.json if present
  let depCount = 0;
  const pkgPath = join(root, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      depCount += Object.keys(pkg.dependencies ?? {}).length;
    } catch (err) {
      throw new Error(`Corrupt package.json at ${pkgPath}: ${err.message}`);
    }
  }

  const total =
    loc +
    exportCount * 2 +
    cyclomatic * 3 +
    depCount * 10 +
    dupBlocks * 5 +
    debtMarkers * 4 +
    maxNestingDepth * 2;

  return {
    loc: Math.trunc(loc),
    export_count: Math.trunc(exportCount),
    cyclomatic: Math.trunc(cyclomatic),
    dep_count: Math.trunc(depCount),
    dup_blocks: Math.trunc(dupBlocks),
    debt_markers: Math.trunc(debtMarkers),
    max_nesting_depth: Math.trunc(maxNestingDepth),
    total: Math.trunc(total),
  };
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
 *
 * @param {object} options
 * @param {number} [options.phiBefore]
 * @param {number} [options.phiAfter]
 * @param {number} [options.deltaPhi]
 * @param {string} [options.author]
 * @param {string} [options.role]
 * @returns {{
 *   ok: boolean,
 *   verdict: string,
 *   delta_phi: number,
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

  if (deltaPhi === undefined) {
    return {
      ok: true,
      verdict: "auto_merge",
      delta_phi: 0,
    };
  }

  if (!Number.isSafeInteger(deltaPhi)) {
    throw new TypeError(`deltaPhi must be a safe integer, got ${JSON.stringify(deltaPhi)}`);
  }

  const author = options.author ?? options.role ?? "";
  const isConsolidator = String(author).toLowerCase().includes("consolidator");

  if (deltaPhi > 0) {
    return {
      ok: false,
      verdict: "reject",
      delta_phi: deltaPhi,
      rule: "LAW_13_PHI_INCREASE",
      violation: "PHI_INCREASED",
      detail: `Law 13 invariant violation: complexity potential increased (\u0394\u03a6 = +${deltaPhi} > 0).`,
    };
  }

  if (isConsolidator && deltaPhi >= 0) {
    return {
      ok: false,
      verdict: "reject",
      delta_phi: deltaPhi,
      rule: "LAW_13_CONSOLIDATOR_PHI",
      violation: "CONSOLIDATOR_PHI_NOT_DECREASED",
      detail: `Law 13 invariant violation: consolidator role requires strictly decreasing complexity potential (\u0394\u03a6 must be < 0, got ${deltaPhi}).`,
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
 *
 * @param {object} options
 * @param {number} options.phiBefore
 * @param {number} options.phiAfter
 * @param {boolean} [options.testsPreserved=true]
 * @param {boolean} [options.surfacePreserved=true]
 * @returns {{ ok: boolean, verdict: string, reasons: string[], thrift_score: number }}
 */
export function verifyThrift(options = {}) {
  const { phiBefore, phiAfter, testsPreserved = true, surfacePreserved = true } = options;
  const reasons = [];

  if (!Number.isSafeInteger(phiBefore) || !Number.isSafeInteger(phiAfter)) {
    throw new TypeError("phiBefore and phiAfter must be safe integers");
  }

  const deltaPhi = phiAfter - phiBefore;
  if (deltaPhi >= 0) {
    reasons.push(`Refactoring did not strictly decrease complexity potential (\u0394\u03a6 = ${deltaPhi} >= 0)`);
  }

  if (!testsPreserved) {
    reasons.push("Test preservation check failed: existing tests deleted or weakened");
  }

  if (!surfacePreserved) {
    reasons.push("Public surface preserved check failed: unauthorized modifications to surface");
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
  const entries = readdirSync(dir);

  for (const entry of entries) {
    if (
      entry === "node_modules" ||
      entry === ".git" ||
      entry === ".mirql" ||
      entry === "conformance"
    ) {
      continue;
    }
    const full = join(dir, entry);
    const st = statSync(full);

    if (st.isDirectory()) {
      collectSourceFiles(full, collected);
    } else if (entry.endsWith(".mjs") || entry.endsWith(".js")) {
      collected.push(full);
    }
  }
  return collected;
}
