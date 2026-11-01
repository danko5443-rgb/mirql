// packages/run/drift.mjs — Milestone M3: Claim-Check Drift Sentinel & Surface Lock Verification.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { ulid } from "../core/index.mjs";

/**
 * Law 12 & Milestone M3 — Detects architectural divergence, surface drift,
 * convention drift, and dependency creep across the codebase workspace.
 *
 * @param {string} [workspaceDir]
 * @param {object} [options]
 * @param {string} [options.surfaceLockPath] - Optional override for surface.lock
 * @param {string} [options.packageJsonPath] - Optional override for package.json
 * @returns {{
 *   ok: boolean,
 *   drift_detected: boolean,
 *   drift_score_bp: number,
 *   drifts: Array<{
 *     subsystem: string,
 *     drift_type: "surface" | "architecture" | "dependency" | "convention",
 *     drift_score_bp: number,
 *     details: string
 *   }>,
 *   summary: string
 * }}
 */
export function detectDrift(workspaceDir = process.cwd(), options = {}) {
  const root = resolve(workspaceDir);
  const drifts = [];

  // 1. Surface Drift Verification (against surface.lock)
  const surfaceLockPath = options.surfaceLockPath ?? join(root, "surface.lock");
  if (!existsSync(surfaceLockPath)) {
    drifts.push({
      subsystem: "root",
      drift_type: "surface",
      drift_score_bp: 5000,
      details: "Missing normative surface.lock baseline",
    });
  } else {
    try {
      const surfaceLock = JSON.parse(readFileSync(surfaceLockPath, "utf8"));

      // Check required binary entrypoints in bin/
      const binDir = join(root, "bin");
      if (Array.isArray(surfaceLock.bins)) {
        for (const binName of surfaceLock.bins) {
          const expectedFile = join(binDir, `${binName}.mjs`);
          const altFile = join(binDir, binName);
          if (!existsSync(expectedFile) && !existsSync(altFile)) {
            drifts.push({
              subsystem: "bin",
              drift_type: "surface",
              drift_score_bp: 2500,
              details: `Missing public bin entrypoint declared in surface.lock: bin/${binName}.mjs`,
            });
          }
        }
      }

      // Check canonical schema declarations in schemas/
      const schemaDir = join(root, "schemas");
      if (Array.isArray(surfaceLock.schemas)) {
        for (const schemaRef of surfaceLock.schemas) {
          const [kind] = schemaRef.split("/");
          const expectedSchemaFile = join(schemaDir, `${kind}.schema.json`);
          if (!existsSync(expectedSchemaFile)) {
            drifts.push({
              subsystem: "schemas",
              drift_type: "surface",
              drift_score_bp: 2500,
              details: `Missing canonical schema file declared in surface.lock: schemas/${kind}.schema.json`,
            });
          }
        }
      }

      // Check public commands alignment between surface.lock and code
      if (Array.isArray(surfaceLock.commands)) {
        const lockCommandsSet = new Set(surfaceLock.commands);
        const runIndex = join(root, "packages", "run", "index.mjs");
        if (existsSync(runIndex)) {
          const runContent = readFileSync(runIndex, "utf8");
          const subMatch = runContent.match(/export const SUBCOMMANDS = Object\.freeze\(\[([\s\S]*?)\]\);/);
          if (subMatch) {
            const rawSubs = subMatch[1]
              .split(",")
              .map((s) => s.replace(/["'\s]/g, ""))
              .filter(Boolean);
            // Skip help, aliases, or non-canonical shortcuts
            const primarySubs = rawSubs.filter((s) => !["help", "bb"].includes(s));

            for (const sub of primarySubs) {
              const fullCmd = `mirql r ${sub}`;
              if (!lockCommandsSet.has(fullCmd)) {
                drifts.push({
                  subsystem: "packages/run",
                  drift_type: "surface",
                  drift_score_bp: 2500,
                  details: `Uncited public command implemented in code but missing from surface.lock: "${fullCmd}"`,
                });
              }
            }

            for (const lockCmd of surfaceLock.commands) {
              if (lockCmd.startsWith("mirql r ")) {
                const sub = lockCmd.slice("mirql r ".length).trim();
                if (!rawSubs.includes(sub)) {
                  drifts.push({
                    subsystem: "packages/run",
                    drift_type: "surface",
                    drift_score_bp: 2500,
                    details: `Missing public command declared in surface.lock but not found in packages/run SUBCOMMANDS: "${lockCmd}"`,
                  });
                }
              }
            }
          }
        }
      }
    } catch (err) {
      drifts.push({
        subsystem: "surface.lock",
        drift_type: "surface",
        drift_score_bp: 5000,
        details: `Corrupt surface.lock: ${err.message}`,
      });
    }
  }

  // 2. Dependency Creep Check (Law 0: Zero External Dependencies)
  const pkgPath = options.packageJsonPath ?? join(root, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      const depCount = Object.keys(pkg.dependencies ?? {}).length;
      const devDepCount = Object.keys(pkg.devDependencies ?? {}).length;
      const peerDepCount = Object.keys(pkg.peerDependencies ?? {}).length;
      const optDepCount = Object.keys(pkg.optionalDependencies ?? {}).length;
      const bundleDepCount = Object.keys(pkg.bundledDependencies ?? {}).length;

      const totalExternalDeps =
        depCount + devDepCount + peerDepCount + optDepCount + bundleDepCount;

      if (totalExternalDeps > 0) {
        drifts.push({
          subsystem: "package.json",
          drift_type: "dependency",
          drift_score_bp: 5000,
          details: `Law 0 violation: external dependencies detected in package.json (dependencies: ${depCount}, devDependencies: ${devDepCount}, peerDependencies: ${peerDepCount}, optionalDependencies: ${optDepCount})`,
        });
      }
    } catch (err) {
      drifts.push({
        subsystem: "package.json",
        drift_type: "dependency",
        drift_score_bp: 3000,
        details: `Corrupt package.json: ${err.message}`,
      });
    }
  }

  // 3. Architectural Boundary & Import Structure Checks
  const packagesDir = join(root, "packages");
  if (existsSync(packagesDir)) {
    const pkgDirs = readdirSync(packagesDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);

    for (const pkgName of pkgDirs) {
      const currentPkgPath = join(packagesDir, pkgName);
      const mjsFiles = collectMjsFiles(currentPkgPath);

      for (const filePath of mjsFiles) {
        const rawContent = readFileSync(filePath, "utf8");
        // Strip comments to prevent false positives from string examples in comments
        const content = stripComments(rawContent);
        const relPath = filePath.replace(root, "").replace(/^[\\/]/, "");

        // A. Disallow bare specifiers: catch import, re-export, dynamic import, and require
        const specifiers = extractSpecifiers(content);
        for (const spec of specifiers) {
          if (
            !spec.startsWith("node:") &&
            !spec.startsWith("./") &&
            !spec.startsWith("../") &&
            !spec.startsWith("/")
          ) {
            drifts.push({
              subsystem: `packages/${pkgName}`,
              drift_type: "architecture",
              drift_score_bp: 2500,
              details: `Illegal bare specifier "${spec}" imported in ${relPath} (must use node:* or relative paths)`,
            });
          }
        }

        // B. Privilege Separation: unprivileged packages cannot import supervisor private keys or daemons
        const unprivilegedPackages = ["mergeproof", "queue", "inbox", "log"];
        if (unprivilegedPackages.includes(pkgName)) {
          if (
            content.includes("daemons/llm-gateway") ||
            content.includes("packages/run/supervisor") ||
            content.includes("getOrGenerateSupervisorKey") ||
            content.includes("supervisor_key")
          ) {
            drifts.push({
              subsystem: `packages/${pkgName}`,
              drift_type: "architecture",
              drift_score_bp: 4000,
              details: `Law 2 privilege boundary leak: unprivileged ${pkgName} imports privileged supervisor/daemon modules in ${relPath}`,
            });
          }
        }
      }
    }
  }

  // 4. Calculate Composite Basis Points Score
  let totalScoreBp = 0;
  for (const drift of drifts) {
    totalScoreBp += drift.drift_score_bp;
  }
  const clampedScoreBp = Math.min(10000, Math.trunc(totalScoreBp));
  const driftDetected = drifts.length > 0;

  const summary = driftDetected
    ? `Drift detected: ${drifts.length} issue(s) found (severity: ${clampedScoreBp} bp)`
    : "No drift detected: codebase conforms 100% to surface.lock and architecture rules";

  return {
    ok: !driftDetected,
    drift_detected: driftDetected,
    drift_score_bp: clampedScoreBp,
    drifts,
    summary,
  };
}

/**
 * Extracts import/export/require specifiers from JavaScript/MJS source code.
 *
 * @param {string} code - code with comments stripped
 * @returns {string[]}
 */
function extractSpecifiers(code) {
  const specs = [];

  // 1. static import or export specifiers
  const fromMatches = code.matchAll(/(?:import|export)\s+[\s\S]*?\s+from\s+["']([^"']+)["']/g);
  for (const m of fromMatches) {
    specs.push(m[1]);
  }

  // 2. wildcard export specifiers
  const exportAllMatches = code.matchAll(/export\s+\*\s+from\s+["']([^"']+)["']/g);
  for (const m of exportAllMatches) {
    specs.push(m[1]);
  }

  // 3. side-effect import specifiers
  const bareImportMatches = code.matchAll(/import\s+["']([^"']+)["']/g);
  for (const m of bareImportMatches) {
    specs.push(m[1]);
  }

  // 4. dynamic import call specifiers
  const dynamicImportMatches = code.matchAll(/import\s*\(\s*["']([^"']+)["']\s*\)/g);
  for (const m of dynamicImportMatches) {
    specs.push(m[1]);
  }

  // 5. require call specifiers
  const requireMatches = code.matchAll(/require\s*\(\s*["']([^"']+)["']\s*\)/g);
  for (const m of requireMatches) {
    specs.push(m[1]);
  }

  return specs;
}

/** Strips single-line and multi-line comments from JS source */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
}

/**
 * Verifies a formal claim against active repository state.
 *
 * @param {object|string} claimInput
 * @param {string} [workspaceDir]
 * @returns {{ verified: boolean, claim: string, details: string }}
 */
export function verifyClaimCheck(claimInput, workspaceDir = process.cwd()) {
  const root = resolve(workspaceDir);
  const claim = typeof claimInput === "string" ? { type: claimInput } : claimInput;
  const claimType = claim.type || claim.claim || "";

  switch (claimType) {
    case "zero_dependencies": {
      const pkgPath = join(root, "package.json");
      if (!existsSync(pkgPath)) return { verified: false, claim: claimType, details: "Missing package.json" };
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
        const deps = Object.keys(pkg.dependencies ?? {}).length;
        const devDeps = Object.keys(pkg.devDependencies ?? {}).length;
        const peerDeps = Object.keys(pkg.peerDependencies ?? {}).length;
        const optDeps = Object.keys(pkg.optionalDependencies ?? {}).length;
        const total = deps + devDeps + peerDeps + optDeps;
        const verified = total === 0;
        return {
          verified,
          claim: claimType,
          details: verified
            ? "Verified zero external dependencies"
            : `Failed: found ${total} external dependencies (dependencies: ${deps}, devDependencies: ${devDeps}, peerDependencies: ${peerDeps}, optionalDependencies: ${optDeps})`,
        };
      } catch (err) {
        return { verified: false, claim: claimType, details: err.message };
      }
    }

    case "no_surface_drift":
    case "surface_unchanged": {
      const driftRes = detectDrift(root);
      const surfaceDrifts = driftRes.drifts.filter((d) => d.drift_type === "surface");
      const verified = surfaceDrifts.length === 0;
      return {
        verified,
        claim: claimType,
        details: verified
          ? "Verified public surface matches surface.lock"
          : `Failed: ${surfaceDrifts.map((d) => d.details).join("; ")}`,
      };
    }

    case "clean_architecture": {
      const driftRes = detectDrift(root);
      const archDrifts = driftRes.drifts.filter((d) => d.drift_type === "architecture");
      const verified = archDrifts.length === 0;
      return {
        verified,
        claim: claimType,
        details: verified
          ? "Verified clean cross-package architecture and boundaries"
          : `Failed: ${archDrifts.map((d) => d.details).join("; ")}`,
      };
    }

    default: {
      return {
        verified: false,
        claim: claimType,
        details: `Unknown or unverified claim type: "${claimType}"`,
      };
    }
  }
}

/**
 * Formats a canonical drift.detected event payload conforming to roles/scout-drift.md.
 *
 * @param {object} driftResult
 * @param {object} [options]
 * @returns {object}
 */
export function formatDriftEvent(driftResult, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  const primaryDrift = driftResult.drifts?.[0];

  return {
    v: 1,
    id: ulid(nowMs),
    type: "drift.detected",
    subsystem: primaryDrift?.subsystem ?? "codebase",
    payload: {
      drift_type: primaryDrift?.drift_type ?? "surface",
      drift_score_bp: driftResult.drift_score_bp ?? 0,
      details: driftResult.summary ?? "Drift check completed",
      issues_count: driftResult.drifts?.length ?? 0,
      drifts: driftResult.drifts ?? [],
      timestamp_ms: nowMs,
    },
  };
}

/** Recursively collect .mjs files in a directory */
function collectMjsFiles(dir, collected = []) {
  if (!existsSync(dir)) return collected;
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== ".git") {
        collectMjsFiles(full, collected);
      }
    } else if (entry.name.endsWith(".mjs")) {
      collected.push(full);
    }
  }
  return collected;
}
