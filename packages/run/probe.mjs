import { join, resolve, dirname } from "node:path";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { EXIT_CODES } from "../core/index.mjs";
import { computePhi } from "./phi.mjs";
import { runMutationTesting, extractChangedLines } from "./mutant.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";

export const KNOWN_PROBES = Object.freeze([
  "tests",
  "drift",
  "mutants",
  "complexity",
  "surface",
]);

/**
 * Loads probe configuration from policy/probes.toml.
 *
 * @param {string} probeName
 * @param {string} [rootDir=process.cwd()]
 * @returns {Record<string, any> | null}
 */
export function loadProbeConfig(probeName, rootDir = process.cwd()) {
  const tomlPath = join(rootDir, "policy", "probes.toml");
  if (!existsSync(tomlPath)) {
    return null;
  }
  const content = readFileSync(tomlPath, "utf8");
  const sectionHeader = `[probes.${probeName}]`;
  const idx = content.indexOf(sectionHeader);
  if (idx === -1) return null;

  const rest = content.slice(idx + sectionHeader.length);
  const nextSection = rest.search(/\n\s*\[/);
  const sectionText = nextSection !== -1 ? rest.slice(0, nextSection) : rest;

  const config = {};
  for (const line of sectionText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq !== -1) {
      const key = trimmed.slice(0, eq).trim();
      let val = trimmed.slice(eq + 1).trim();
      if (
        (val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))
      ) {
        config[key] = val.slice(1, -1);
      } else if (/^-?\d+$/.test(val)) {
        config[key] = parseInt(val, 10);
      } else {
        config[key] = val;
      }
    }
  }
  return config;
}

/**
 * Lists changed non-test source files in the workspace diff (issue #14):
 * the incremental mutation gate must measure the code a change actually
 * touches, not files picked by hand.
 *
 * @param {string} workspaceDir
 * @param {string} [base="HEAD~1"] - git ref to diff against
 * @returns {{ ok: boolean, files?: string[], error?: string }}
 */
export function deriveChangedSources(workspaceDir, base = "HEAD~1") {
  const gitZ = (args) => {
    const res = spawnSync("git", ["-c", "core.quotePath=false", ...args], {
      cwd: workspaceDir,
      encoding: "utf8",
      timeout: 15000,
    });
    if (res.status !== 0) {
      const err = (res.stderr || res.stdout || `git ${args[0]} exit ${res.status}`).trim();
      return { ok: false, error: `cannot measure diff against ${base}: ${err}` };
    }
    const raw = String(res.stdout || "");
    return { ok: true, items: raw.split("\0").filter(Boolean) };
  };

  const diffRes = gitZ(["diff", "--name-only", "-z", "--diff-filter=ACMRT", base]);
  if (!diffRes.ok) return diffRes;

  const untrackedRes = gitZ(["ls-files", "--others", "-z", "--exclude-standard"]);
  if (!untrackedRes.ok) return untrackedRes;

  const allFiles = [...new Set([...diffRes.items, ...untrackedRes.items])];
  const files = allFiles
    .filter((f) => f.endsWith(".mjs") || f.endsWith(".js"))
    .filter((f) => !f.includes(".test.") && !f.includes("/tests/") && !f.includes("/test/"));

  return { ok: true, files };
}

/**
 * Finds the test files that actually IMPORT the given source (real dependency
 * edges — not name guessing). Scans the workspace's tests/ and test/
 * directories for static and dynamic relative imports resolving to the source.
 *
 * @param {string} workspaceDir
 * @param {string} sourceRel - source path relative to workspaceDir (posix separators)
 * @returns {string[]} absolute paths of importing test files (sorted)
 */
export function findImportingTests(workspaceDir, sourceRel) {
  const sourceAbs = resolve(workspaceDir, sourceRel).toLowerCase();
  const testDirs = ["tests", "test"]
    .map((d) => join(workspaceDir, d))
    .filter((d) => existsSync(d));

  const importers = [];
  for (const testDir of testDirs) {
    let entries;
    try {
      entries = readdirSync(testDir, { recursive: true, withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".mjs")) continue;
      const testAbs = join(entry.parentPath ?? testDir, entry.name);
      let content;
      try {
        content = readFileSync(testAbs, "utf8");
      } catch {
        continue;
      }
      const specifiers = [...content.matchAll(/\bfrom\s*["']([^"']+)["']/g)].map((m) => m[1]);
      for (const dyn of content.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) {
        specifiers.push(dyn[1]);
      }
      for (const spec of specifiers) {
        if (!spec.startsWith(".") && !spec.startsWith("/")) continue;
        const resolvedSpec = resolve(dirname(testAbs), spec).toLowerCase();
        if (resolvedSpec === sourceAbs) {
          importers.push(testAbs);
          break;
        }
      }
    }
  }
  return [...new Set(importers)].sort();
}

/**
 * Law 12 — Declarative 0-Token Probes (mirql r probe).
 *
 * Runs declarative probes, computes real metrics, and records a signed
 * `probe.completed` event in the ledger.
 *
 * @param {object} options
 * @param {string} [options.probe] - probe name ("tests", "surface", "drift", "mutants", "complexity")
 * @param {string} [options.mirqlDir] - ledger directory
 * @param {object} [options.keypair] - Ed25519 keypair for supervisor
 * @param {string} [options.workspaceDir] - working tree directory
 * @returns {{ ok: boolean, probe: object, event: object }}
 */
export function runProbe(options = {}) {
  const mirqlDir =
    options.mirqlDir ?? options.dir ?? join(process.cwd(), ".mirql");
  const probeName = options.probe ?? options.type ?? "tests";
  const workspaceDir = options.workspaceDir ?? process.cwd();

  // Fail closed on unknown probe names with exit code 2 (USAGE_ERROR)
  if (!KNOWN_PROBES.includes(probeName)) {
    const err = new Error(
      `Unknown probe: "${probeName}". Must be one of: ${KNOWN_PROBES.join(", ")}`,
    );
    err.code = "USAGE_ERROR";
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const keypair =
    options.keypair ?? getOrGenerateSupervisorKey(mirqlDir);
  const config = loadProbeConfig(probeName, workspaceDir);

  let probeResult;

  if (probeName === "complexity") {
    const phi = computePhi(workspaceDir);
    const maxCyclomatic =
      Number.isSafeInteger(options.max_cyclomatic)
        ? options.max_cyclomatic
        : config?.max_cyclomatic ?? 15;
    const passed = phi.cyclomatic <= maxCyclomatic;

    probeResult = {
      name: config?.name ?? "ast_cyclomatic_complexity",
      type: "complexity",
      status: passed ? "pass" : "fail",
      passed,
      max_cyclomatic: maxCyclomatic,
      cyclomatic: phi.cyclomatic,
      loc: phi.loc,
      failures: passed ? 0 : 1,
      duration_ms: 15,
    };
  } else if (probeName === "tests") {
    const startedMs = Date.now();
    if (Number.isSafeInteger(options.failures) && Number.isSafeInteger(options.passed)) {
      // Explicit measured results supplied by the caller
      const failures = options.failures;
      const passedCount = options.passed;
      const passed = failures === 0;
      probeResult = {
        name: config?.name ?? "unit_conformance_suite",
        type: "tests",
        status: passed ? "pass" : "fail",
        passed,
        threshold_failures: config?.threshold_failures ?? 0,
        failures,
        passed_count: passedCount,
        duration_ms: Date.now() - startedMs,
      };
    } else if (process.env.NODE_TEST_CONTEXT !== undefined || process.env.NODE_ENV === "test") {
      // Issue #16: never sign a pass that was not measured. Inside a test
      // run (node --test sets NODE_TEST_CONTEXT) we cannot spawn the suite
      // (recursion), so report honestly instead of inventing counts.
      probeResult = {
        name: config?.name ?? "unit_conformance_suite",
        type: "tests",
        status: "not_implemented",
        passed: false,
        threshold_failures: config?.threshold_failures ?? 0,
        failures: 1,
        error: "no measured counts supplied and the suite cannot be spawned from inside a test run",
        duration_ms: Date.now() - startedMs,
      };
    } else {
      // Run the configured suite command and measure the real outcome
      const command = typeof config?.command === "string" && config.command.trim() !== ""
        ? config.command.trim()
        : "npm test";
      const parts = command.split(/\s+/);
      const timeoutMs = Number.isSafeInteger(config?.timeout_ms) ? config.timeout_ms : 600_000;
      let failures = 1;
      let passedCount = null;
      try {
        const res = spawnSync(parts[0], parts.slice(1), {
          cwd: workspaceDir,
          encoding: "utf8",
          timeout: timeoutMs,
        });
        failures = res.status === 0 ? 0 : 1;
        const m = String(res.stdout || "").match(/pass\s+(\d+)/);
        if (m) passedCount = parseInt(m[1], 10);
      } catch {
        failures = 1;
      }
      const passed = failures === 0;
      probeResult = {
        name: config?.name ?? "unit_conformance_suite",
        type: "tests",
        status: passed ? "pass" : "fail",
        passed,
        threshold_failures: config?.threshold_failures ?? 0,
        failures,
        passed_count: passedCount,
        command,
        duration_ms: Date.now() - startedMs,
      };
    }
  } else if (probeName === "surface") {
    if (options.delta !== undefined) {
      const allowed = config?.allowed_delta ?? 0;
      const passed = options.delta <= allowed;
      probeResult = {
        name: config?.name ?? "public_surface_drift",
        type: "surface",
        status: passed ? "pass" : "fail",
        passed,
        allowed_delta: allowed,
        delta: options.delta,
        duration_ms: 10,
      };
    } else {
      // Cannot measure without computed diff
      probeResult = {
        name: config?.name ?? "public_surface_drift",
        type: "surface",
        status: "not_implemented",
        passed: false,
        failures: 1,
        duration_ms: 0,
      };
    }
  } else if (probeName === "mutants") {
    const minKillRateBp = Math.max(8000, config?.min_kill_rate_bp ?? 8000);
    const startedMs = Date.now();

    if (options.source && options.test) {
      // Explicit single-file mode (mirql-run probe --type mutants --source --test)
      try {
        const mutantRes = runMutationTesting({
          sourcePath: options.source ?? options.target,
          testPath: options.test,
          killThresholdBp: minKillRateBp,
        });
        const passed = mutantRes.ok;
        probeResult = {
          name: config?.name ?? "incremental_mutation_density",
          type: "mutants",
          status: passed ? "pass" : "fail",
          passed,
          kill_rate_bp: mutantRes.kill_rate_bp,
          min_kill_rate_bp: minKillRateBp,
          mutants_total: mutantRes.mutants_total,
          mutants_killed: mutantRes.mutants_killed,
          mutants_survived: mutantRes.mutants_survived,
          failures: passed ? 0 : 1,
          duration_ms: Date.now() - startedMs,
          error: mutantRes.error,
        };
      } catch (err) {
        probeResult = {
          name: config?.name ?? "incremental_mutation_density",
          type: "mutants",
          status: "fail",
          passed: false,
          kill_rate_bp: 0,
          min_kill_rate_bp: minKillRateBp,
          failures: 1,
          duration_ms: Date.now() - startedMs,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    } else {
      // Incremental mode (issue #14): the declarative command in probes.toml
      // (`probe --type mutants`, no file arguments) derives targets from the
      // workspace diff and pairs each changed source with the test files that
      // actually import it. Fail closed on unmeasurable or uncovered changes.
      const base = typeof options.base === "string" && options.base.trim() !== ""
        ? options.base.trim()
        : "HEAD~1";
      const diff = deriveChangedSources(workspaceDir, base);
      if (!diff.ok) {
        probeResult = {
          name: config?.name ?? "incremental_mutation_density",
          type: "mutants",
          status: "fail",
          passed: false,
          kill_rate_bp: 0,
          min_kill_rate_bp: minKillRateBp,
          failures: 1,
          duration_ms: Date.now() - startedMs,
          error: diff.error,
        };
      } else if (diff.files.length === 0) {
        probeResult = {
          name: config?.name ?? "incremental_mutation_density",
          type: "mutants",
          status: "pass",
          passed: true,
          kill_rate_bp: 10000,
          min_kill_rate_bp: minKillRateBp,
          mutants_total: 0,
          mutants_killed: 0,
          mutants_survived: 0,
          tested_files: [],
          failures: 0,
          duration_ms: Date.now() - startedMs,
          summary: `No changed source files in diff against ${base}: nothing to mutate`,
        };
      } else {
        const fileResults = [];
        for (const sourceRel of diff.files) {
          const sourceAbs = join(workspaceDir, sourceRel);
          if (!existsSync(sourceAbs)) {
            fileResults.push({ source: sourceRel, ok: false, error: "SOURCE_MISSING" });
            continue;
          }
          const importingTests = findImportingTests(workspaceDir, sourceRel);
          if (importingTests.length === 0) {
            // Changed code with no test importing it cannot prove any kill
            // rate — the M4 invariant is unmet, not unknown.
            fileResults.push({
              source: sourceRel,
              ok: false,
              error: "NO_COVERING_TEST",
            });
            continue;
          }
          try {
            let changedLines;
            try {
              const diffRes = spawnSync("git", ["diff", "-U0", base, "--", sourceRel], {
                cwd: workspaceDir,
                encoding: "utf8",
                timeout: 15000,
              });
              if (diffRes.status === 0 && diffRes.stdout) {
                changedLines = extractChangedLines(diffRes.stdout);
              }
            } catch { /* mp-003-allow: an unreadable diff contributes no changed lines, so the probe runs untargeted instead of skipping */ }

            const res = runMutationTesting({
              sourcePath: sourceAbs,
              testPath: importingTests,
              changedLines: changedLines?.length > 0 ? changedLines : undefined,
              killThresholdBp: minKillRateBp,
            });
            fileResults.push({
              source: sourceRel,
              ok: res.ok,
              kill_rate_bp: res.kill_rate_bp,
              mutants_total: res.mutants_total,
              mutants_killed: res.mutants_killed,
              mutants_survived: res.mutants_survived,
              error: res.error,
            });
          } catch (err) {
            fileResults.push({
              source: sourceRel,
              ok: false,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        const failing = fileResults.filter((f) => !f.ok);
        const measured = fileResults.filter((f) => Number.isSafeInteger(f.kill_rate_bp));
        probeResult = {
          name: config?.name ?? "incremental_mutation_density",
          type: "mutants",
          status: failing.length === 0 ? "pass" : "fail",
          passed: failing.length === 0,
          kill_rate_bp: measured.length > 0 ? Math.min(...measured.map((f) => f.kill_rate_bp)) : 0,
          min_kill_rate_bp: minKillRateBp,
          mutants_total: fileResults.reduce((n, f) => n + (f.mutants_total ?? 0), 0),
          mutants_killed: fileResults.reduce((n, f) => n + (f.mutants_killed ?? 0), 0),
          mutants_survived: fileResults.reduce((n, f) => n + (f.mutants_survived ?? 0), 0),
          tested_files: fileResults,
          failures: failing.length,
          duration_ms: Date.now() - startedMs,
          error: failing.length > 0
            ? `${failing.length} changed file(s) below the kill-rate floor or uncovered: ${failing.map((f) => `${f.source} (${f.error ?? `${f.kill_rate_bp} bp`})`).join(", ")}`
            : undefined,
        };
      }
    }
  } else {
    // Probes that cannot be measured directly report not_implemented
    probeResult = {
      name: config?.name ?? probeName,
      type: probeName,
      status: "not_implemented",
      passed: false,
      failures: 1,
      duration_ms: 0,
    };
  }

  // Record signed probe.completed event
  const nowMs = Number.isSafeInteger(options.nowMs)
    ? options.nowMs
    : Date.now();
  const event = appendSupervisorEvent(
    mirqlDir,
    {
      type: "probe.completed",
      payload: {
        probe: probeResult.name,
        type: probeResult.type,
        status: probeResult.status,
        failures: probeResult.failures ?? 0,
        duration_ms: probeResult.duration_ms,
      },
      nowMs,
    },
    keypair,
  );

  return {
    ok: probeResult.status === "pass" && probeResult.passed !== false,
    probe: probeResult,
    event,
  };
}
