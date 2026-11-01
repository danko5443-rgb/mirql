// packages/run/drift.mjs — Milestone M3: Claim-Check Drift Sentinel & Surface Lock Verification.
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
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

  // 3. Architectural Boundary & Import Structure Checks (structural analyzer)
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
        // Structural pass: mask strings/templates/regexes/comments, then pair
        // syntactic import positions with the string literals they reference.
        // This is multiline-safe and immune to specifier-looking text inside
        // strings and comments (which the old per-line regex scan was not).
        const { skeleton, literals } = maskSource(rawContent);
        const relPath = filePath.replace(root, "").replace(/^[\\/]/, "");
        const pkgRel = `packages/${pkgName}`;

        // A. Specifier extraction + classification (bare / coupling / injection)
        const specs = extractSpecifiers(skeleton, literals);
        for (const { spec, kind } of specs) {
          if (kind === "computed") {
            // dynamic import()/require() with a non-literal argument — a
            // runtime dependency-injection vector that cannot be statically
            // audited, so it is rejected outright.
            drifts.push({
              subsystem: pkgRel,
              drift_type: "architecture",
              drift_score_bp: 2500,
              details: `Computed dynamic ${spec} argument in ${relPath} — statically unauditable module injection vector`,
            });
            continue;
          }
          if (kind === "template") {
            drifts.push({
              subsystem: pkgRel,
              drift_type: "architecture",
              drift_score_bp: 2500,
              details: `Template-literal dynamic ${spec} argument in ${relPath} — statically unauditable module injection vector`,
            });
            continue;
          }

          // node:* builtins are always allowed
          if (spec.startsWith("node:")) continue;

          // Bare specifiers are external dependencies — forbidden (Law 0)
          if (!spec.startsWith("./") && !spec.startsWith("../") && !spec.startsWith("/")) {
            drifts.push({
              subsystem: pkgRel,
              drift_type: "architecture",
              drift_score_bp: 2500,
              details: `Illegal bare specifier "${spec}" imported in ${relPath} (must use node:* or relative paths)`,
            });
            continue;
          }

          // Cross-package coupling DAG: a package may import itself and
          // packages/core; reaching into any sibling package is coupling drift.
          const resolved = resolveImportPath(dirname(filePath), spec);
          if (resolved === null) {
            drifts.push({
              subsystem: pkgRel,
              drift_type: "convention",
              drift_score_bp: 1500,
              details: `Unresolvable relative import "${spec}" in ${relPath}`,
            });
            continue;
          }
          const coreDir = join(packagesDir, "core");
          const insideCore = resolved === coreDir || resolved.startsWith(coreDir + "\\") || resolved.startsWith(coreDir + "/");
          const insideSelf = resolved === currentPkgPath || resolved.startsWith(currentPkgPath + "\\") || resolved.startsWith(currentPkgPath + "/");
          if (insideCore || insideSelf) continue;
          drifts.push({
            subsystem: pkgRel,
            drift_type: "architecture",
            drift_score_bp: 3000,
            details: `Cross-package coupling: ${relPath} imports "${spec}" resolving outside ${pkgRel} and packages/core`,
          });
        }

        // B. Privilege Separation: unprivileged packages cannot import supervisor private keys or daemons
        // (checked on the masked skeleton: string/comment mentions do not count)
        const unprivilegedPackages = ["mergeproof", "queue", "inbox", "log"];
        if (unprivilegedPackages.includes(pkgName)) {
          if (
            skeleton.includes("daemons/llm-gateway") ||
            skeleton.includes("packages/run/supervisor") ||
            skeleton.includes("getOrGenerateSupervisorKey") ||
            skeleton.includes("supervisor_key")
          ) {
            drifts.push({
              subsystem: pkgRel,
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
 * Masks string literals, template literals, char literals, regex literals, and
 * comments in JS source so only syntactic code remains. Preserves: length,
 * newlines, and the quote DELIMITERS of string/template literals (so import
 * sites can be paired with their literals by offset). Returns the masked
 * skeleton plus every string/template literal with its start offset and value.
 *
 * @param {string} src
 * @returns {{ skeleton: string, literals: Array<{ start: number, value: string, quote: string }> }}
 */
function maskSource(src) {
  const out = src.split("");
  const literals = [];
  const len = src.length;

  const lastNonspaceOn = (from) => {
    for (let j = from; j >= 0; j--) {
      if (out[j] !== " " && out[j] !== "\t" && out[j] !== "\n" && out[j] !== "\r") return j;
    }
    return -1;
  };

  let i = 0;
  while (i < len) {
    const c = src[i];
    const next = i + 1 < len ? src[i + 1] : "";

    // comments
    if (c === "/" && next === "/") {
      while (i < len && src[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }
    if (c === "/" && next === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < len && !(src[i] === "*" && src[i + 1] === "/")) {
        if (src[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < len) {
        out[i] = " ";
        out[i + 1] = " ";
        i += 2;
      }
      continue;
    }

    // string / template literals (opening delimiter kept for offset pairing)
    if (c === "'" || c === '"' || c === "`") {
      const quote = c;
      const start = i;
      i++;
      let value = "";
      while (i < len) {
        const ch = src[i];
        if (ch === "\\") {
          value += ch + (src[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (ch === quote) break;
        if (quote !== "`" && ch === "\n") break; // unterminated single-line string
        value += ch;
        if (ch !== "\n") out[i] = " ";
        i++;
      }
      if (i < len && src[i] === quote) out[i] = " "; // closing delimiter
      literals.push({ start, value, quote });
      i++;
      continue;
    }

    // regex literal vs division
    if (c === "/") {
      const j = lastNonspaceOn(i - 1);
      const boundary = j < 0 ? "" : src[j];
      const regexPreceder =
        boundary === "" || "(,=:[!&|?{};+-*%<>~^".includes(boundary);
      if (regexPreceder) {
        out[i] = " ";
        i++;
        let inClass = false;
        while (i < len) {
          const ch = src[i];
          if (ch === "\\") {
            out[i] = " ";
            out[i + 1] = " ";
            i += 2;
            continue;
          }
          if (ch === "\n") break; // unterminated regex — bail
          if (ch === "[" && !inClass) inClass = true;
          else if (ch === "]" && inClass) inClass = false;
          else if (ch === "/" && !inClass) {
            out[i] = " ";
            i++;
            while (i < len && /[a-z]/i.test(src[i])) {
              out[i] = " ";
              i++;
            }
            break;
          }
          out[i] = " ";
          i++;
        }
        continue;
      }
    }

    i++;
  }

  return { skeleton: out.join(""), literals };
}

/**
 * Extracts import/export/require specifier USES from a masked skeleton, paired
 * with the string literals at the matching offsets. Multiline-safe; immune to
 * string/comment/regex content. Dynamic calls with computed (non-literal) or
 * template arguments are reported as injection vectors.
 *
 * @param {string} skeleton
 * @param {Array<{ start: number, value: string, quote: string }>} literals
 * @returns {Array<{ spec: string, kind: "static" | "dynamic" | "computed" | "template" }>}
 */
function extractSpecifiers(skeleton, literals) {
  const specs = [];
  const seen = new Set();

  /** literal whose opening delimiter sits at skeleton offset `quotePos` */
  const literalAt = (quotePos) => {
    for (const lit of literals) {
      if (lit.start === quotePos) return lit;
    }
    return null;
  };

  const push = (spec, kind) => {
    const key = `${kind}:${spec}`;
    if (seen.has(key)) return;
    seen.add(key);
    specs.push({ spec, kind });
  };

  // static import/export ... from <lit>  (bounded window keeps the match local)
  const staticFrom = /(?:^|[;{}\s])(?:import|export)\s[\s\S]{0,400}?from\s*["'`]/g;
  // side-effect import <lit>
  const sideEffect = /(?:^|[;{}\s])import\s*["'`]/g;
  for (const re of [staticFrom, sideEffect]) {
    let m;
    while ((m = re.exec(skeleton)) !== null) {
      const quotePos = m.index + m[0].length - 1;
      const lit = literalAt(quotePos);
      if (!lit) continue;
      if (lit.quote === "`") push(lit.value, "template");
      else push(lit.value, "static");
    }
  }

  // dynamic import()/require() with literal, template, or computed argument
  const dynamicCall = /\b(?:import|require)\s*\(/g;
  let m;
  while ((m = dynamicCall.exec(skeleton)) !== null) {
    const callName = m[0].startsWith("import") ? "import" : "require";
    let j = m.index + m[0].length;
    while (j < skeleton.length && /\s/.test(skeleton[j])) j++;
    const ch = skeleton[j];
    if (ch === "`") {
      push(callName, "template");
    } else if (ch === '"' || ch === "'") {
      const lit = literalAt(j);
      if (lit) push(lit.value, "dynamic");
    } else {
      push(callName, "computed");
    }
  }

  return specs;
}

/** Resolves a relative import specifier to an absolute existing path, or null. */
function resolveImportPath(fromDir, spec) {
  const base = resolve(fromDir, spec);
  const candidates = [
    base,
    `${base}.mjs`,
    `${base}.js`,
    join(base, "index.mjs"),
    join(base, "index.js"),
  ];
  for (const candidate of candidates) {
    try {
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      // not a file — try next candidate
    }
  }
  return null;
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
