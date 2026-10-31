import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Law 11 & Law 13 — Complexity Potential Phi (Phi).
 *
 * Computes integer-only complexity metrics for a codebase workspace:
 * - `loc`: lines of code across JS/MJS source files.
 * - `export_count`: exported symbols / declarations count.
 * - `cyclomatic`: estimate of decision branching points.
 * - `dep_count`: count of external dependencies.
 * - `dup_blocks`: count of identical repeated code blocks (>= 3 lines).
 * - `total`: composite safe-integer score.
 *
 * Every number returned is guaranteed to be a safe integer (Law 17).
 *
 * @param {string} [workspaceDir]
 * @returns {{ loc: number, export_count: number, cyclomatic: number, dep_count: number, dup_blocks: number, total: number }}
 */
export function computePhi(workspaceDir = process.cwd()) {
  const root = resolve(workspaceDir);
  const files = collectSourceFiles(root);

  let loc = 0;
  let exportCount = 0;
  let cyclomatic = 0;
  const blockHashes = new Map();
  let dupBlocks = 0;

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
    loc + exportCount * 2 + cyclomatic * 3 + depCount * 10 + dupBlocks * 5;

  return {
    loc: Math.trunc(loc),
    export_count: Math.trunc(exportCount),
    cyclomatic: Math.trunc(cyclomatic),
    dep_count: Math.trunc(depCount),
    dup_blocks: Math.trunc(dupBlocks),
    total: Math.trunc(total),
  };
}

/**
 * Verifies non-increasing or strictly decreasing Phi.
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
