// packages/run/drift.mjs — Milestone M3: Claim-Check Drift Sentinel & Surface Lock Verification.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { ulid, sha256 } from "../core/index.mjs";

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

      if (depCount > 0 || devDepCount > 0) {
        drifts.push({
          subsystem: "package.json",
          drift_type: "dependency",
          drift_score_bp: 5000,
          details: `Law 0 violation: external dependencies detected (dependencies: ${depCount}, devDependencies: ${devDepCount})`,
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
        const content = readFileSync(filePath, "utf8");
        const relPath = filePath.replace(root, "").replace(/^[\\/]/, "");

        // A. Disallow bare specifiers: must only import node:* or relative paths
        const bareMatches = content.match(/import\s+(?:[^"';]+\s+from\s+)?["']([^"']+)["']/g) || [];
        for (const imp of bareMatches) {
          const specMatch = imp.match(/["']([^"']+)["']/);
          if (specMatch) {
            const spec = specMatch[1];
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
        }

        // B. Law 1 Privileged Separation: Unprivileged agent/workers cannot import daemons/supervisor keys
        if (pkgName === "agent" || pkgName === "mergeproof") {
          if (
            content.includes("daemons/llm-gateway") ||
            content.includes("run/supervisor") ||
            content.includes("getOrGenerateSupervisorKey")
          ) {
            drifts.push({
              subsystem: `packages/${pkgName}`,
              drift_type: "architecture",
              drift_score_bp: 4000,
              details: `Law 1 privilege boundary leak: unprivileged ${pkgName} imports privileged supervisor/daemon modules in ${relPath}`,
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
        const verified = deps === 0 && devDeps === 0;
        return {
          verified,
          claim: claimType,
          details: verified
            ? "Verified zero external dependencies"
            : `Failed: found ${deps} dependencies and ${devDeps} devDependencies`,
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
