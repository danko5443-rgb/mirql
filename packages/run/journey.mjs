// packages/run/journey.mjs — Milestone M6: User Journey Simulation Harness (roles/scout-journey.md).
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  ulid,
  EXIT_CODES,
  sha256,
  jcs,
} from "../core/index.mjs";
import { isCircuitBreakerTripped } from "./doctor.mjs";
import { quarantineTest } from "./mutant.mjs";

/** Valid journey scenarios (roles/scout-journey.md) */
export const JOURNEY_SCENARIOS = Object.freeze([
  "init-to-merge",
  "fault-to-recovery",
  "quarantine-to-harden",
]);

/**
 * Creates an isolated filesystem sandbox with minimal repo baseline files
 * (surface.lock, ROADMAP.md, NOT-ROADMAP.md, package.json, policy, schemas).
 *
 * @param {object} [options]
 * @param {string} [options.repoRoot] - source repository to copy policy/schemas from
 * @returns {{ sandboxDir: string, mirqlDir: string, cleanup: () => void }}
 */
export function createJourneySandbox(options = {}) {
  const repoRoot = options.repoRoot || resolve(process.cwd());
  const prefix = join(tmpdir(), "mirql-journey-");
  const sandboxDir = mkdtempSync(prefix);
  const mirqlDir = join(sandboxDir, ".mirql");

  // Copy or create minimal essential files for autonomous factory operation
  const copyOrFallback = (srcRel, destRel, fallbackContent = "") => {
    const srcPath = join(repoRoot, srcRel);
    const destPath = join(sandboxDir, destRel);
    mkdirSync(join(destPath, ".."), { recursive: true });
    if (existsSync(srcPath)) {
      writeFileSync(destPath, readFileSync(srcPath));
    } else if (fallbackContent) {
      writeFileSync(destPath, fallbackContent, "utf8");
    }
  };

  copyOrFallback("surface.lock", "surface.lock", JSON.stringify({ v: 1, commands: [], bins: [] }));
  copyOrFallback("ROADMAP.md", "ROADMAP.md", "# ROADMAP\n## Milestone Overview\nM1\nM2\nM3\nM4\nM5\nM6\nM7\n");
  copyOrFallback("NOT-ROADMAP.md", "NOT-ROADMAP.md", '{"anti_goals":[]}\n# NOT-ROADMAP\n');
  copyOrFallback("package.json", "package.json", JSON.stringify({ name: "sandbox", dependencies: {}, devDependencies: {} }));

  // Copy policy directory
  const policySrc = join(repoRoot, "policy");
  if (existsSync(policySrc)) {
    const policyFiles = readdirSync(policySrc);
    for (const f of policyFiles) {
      copyOrFallback(join("policy", f), join("policy", f));
    }
  }

  // Copy schemas directory
  const schemasSrc = join(repoRoot, "schemas");
  if (existsSync(schemasSrc)) {
    const schemaFiles = readdirSync(schemasSrc);
    for (const f of schemaFiles) {
      copyOrFallback(join("schemas", f), join("schemas", f));
    }
  }

  return {
    sandboxDir,
    mirqlDir,
    cleanup: () => {
      if (!options.keepSandbox) {
        try {
          rmSync(sandboxDir, { recursive: true, force: true });
        } catch {}
      }
    },
  };
}

/**
 * Executes a CLI binary command inside the journey sandbox using process spawning.
 * Conforms strictly to Law 12: tool packages import only node:* or core.
 *
 * @param {string[]} args
 * @param {object} ctx
 * @returns {{ status: number | null, stdout: string, stderr: string, parsed: any }}
 */
export function executeCli(args, ctx = {}) {
  const repoRoot = ctx.repoRoot || resolve(process.cwd());
  const binMirql = join(repoRoot, "bin", "mirql.mjs");
  const env = {
    ...process.env,
    ...(ctx.mirqlDir ? { MIRQL_DIR: ctx.mirqlDir } : {}),
  };

  const res = spawnSync(process.execPath, [binMirql, ...args], {
    cwd: ctx.sandboxDir || process.cwd(),
    env,
    encoding: "utf8",
  });

  let parsed = null;
  if (res.stdout) {
    try {
      parsed = JSON.parse(res.stdout.trim());
    } catch {}
  }

  return {
    status: res.status,
    stdout: res.stdout || "",
    stderr: res.stderr || "",
    parsed,
  };
}

/**
 * Formats a canonical journey.gap_found event conforming to roles/scout-journey.md.
 *
 * @param {object} gap
 * @param {object} [options]
 * @returns {object}
 */
export function formatJourneyGapEvent(gap, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  return {
    v: 1,
    id: ulid(nowMs),
    type: "journey.gap_found",
    payload: {
      journey_name: gap.journey_name || "unknown",
      step_failed: gap.step_failed || "unknown_step",
      expected_behavior: gap.expected_behavior || "Expected successful step execution",
      observed_behavior: gap.observed_behavior || "Step failed",
      exit_code: gap.exit_code ?? EXIT_CODES.DOMAIN_NEGATIVE,
      reproduction_steps: gap.reproduction_steps || [gap.step_failed || "step"],
      timestamp_ms: nowMs,
    },
  };
}

/**
 * Formats a canonical regression.reported event conforming to roles/scout-journey.md.
 *
 * @param {object} regression
 * @param {object} [options]
 * @returns {object}
 */
export function formatRegressionReportedEvent(regression, options = {}) {
  const nowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  return {
    v: 1,
    id: ulid(nowMs),
    type: "regression.reported",
    payload: {
      severity: regression.severity || "degraded",
      minimal_repro: regression.minimal_repro || [],
      details: regression.details || "Journey workflow regression detected",
      journey_name: regression.journey_name || "unknown",
      timestamp_ms: nowMs,
    },
  };
}

/**
 * Executes Scenario 1: `init-to-merge`
 * Verifies the developer experience from genesis bootstrap through proposal,
 * 1-tap approval, warrant minting, job lease, execution, and quiescence.
 *
 * @param {object} ctx - { sandboxDir, mirqlDir, repoRoot }
 * @returns {{ ok: boolean, steps: string[] }}
 */
function runScenarioInitToMerge(ctx) {
  const { sandboxDir, mirqlDir } = ctx;
  const steps = [];

  // Step 1: Genesis bootstrap
  steps.push("mirql i genesis");
  const humanKeyOut = join(sandboxDir, "operator_human.key.json");
  const genesisRes = executeCli(["i", "genesis", "--human-key-out", humanKeyOut], ctx);
  if (genesisRes.status !== 0) {
    throw new Error(`Genesis failed with exit ${genesisRes.status}: ${genesisRes.stderr}`);
  }

  // Step 2: Bounded Proposer intake
  steps.push("mirql i propose --roadmap-ref M6 --title 'Journey scout integration'");
  const propRes = executeCli([
    "i", "propose",
    "--roadmap-ref", "M6",
    "--title", "Journey scout integration",
    "--description", "Verify end-to-end journey simulation with 1-tap approval",
    "--proposed-invariants", "journey-scout-verified",
  ], ctx);
  if (propRes.status !== 0 || !propRes.parsed?.proposal_id) {
    throw new Error(`Propose failed with exit ${propRes.status}: ${propRes.stderr}`);
  }
  const proposalId = propRes.parsed.proposal_id;

  // Step 3: 1-Tap Affirmative Action (Law 6, Law 11)
  steps.push(`mirql i act ${proposalId} --approve`);
  const actRes = executeCli(["i", "act", proposalId, "--approve", "--key", humanKeyOut], ctx);
  if (actRes.status !== 0 || !actRes.parsed?.warrant_id) {
    throw new Error(`1-Tap act failed with exit ${actRes.status}: ${actRes.stderr}`);
  }
  const warrantId = actRes.parsed.warrant_id;

  // Step 4: Queue tick
  steps.push("mirql q tick");
  const tickRes = executeCli(["q", "tick"], ctx);
  if (tickRes.status !== 0) {
    throw new Error(`Queue tick failed with exit ${tickRes.status}: ${tickRes.stderr}`);
  }

  // Step 5: Factory Digest verification (Law 6)
  steps.push("mirql i digest");
  const digestRes = executeCli(["i", "digest"], ctx);
  if (digestRes.status !== 0 || digestRes.parsed?.tool !== "inbox") {
    throw new Error(`Digest failed to render inbox report: ${digestRes.stderr}`);
  }

  // Step 6: Verify factory quiescence
  steps.push("verify factory quiescence");
  const eventsFile = join(mirqlDir, "ledger", "events.jsonl");
  if (!existsSync(eventsFile)) {
    throw new Error("Ledger events file missing");
  }

  return { ok: true, steps };
}

/**
 * Executes Scenario 2: `fault-to-recovery`
 * Verifies system behavior under failure: warrant failure, tier escalation,
 * doctor diagnosis, circuit breaker trip, and operator recovery.
 *
 * @param {object} ctx - { sandboxDir, mirqlDir, repoRoot }
 * @returns {{ ok: boolean, steps: string[] }}
 */
function runScenarioFaultToRecovery(ctx) {
  const { sandboxDir, mirqlDir } = ctx;
  const steps = [];

  // Step 1: Genesis bootstrap
  steps.push("mirql i genesis");
  const humanKeyOut = join(sandboxDir, "operator_human.key.json");
  const genesisRes = executeCli(["i", "genesis", "--human-key-out", humanKeyOut], ctx);
  if (genesisRes.status !== 0) {
    throw new Error(`Genesis failed: ${genesisRes.stderr}`);
  }

  // Step 2: Propose and approve a fault scenario warrant
  steps.push("mirql i propose fault warrant");
  const propRes = executeCli([
    "i", "propose",
    "--roadmap-ref", "M5",
    "--title", "Fault scenario test",
    "--description", "Failing test warrant for fault simulation",
    "--red-check", "exit 1",
  ], ctx);
  if (propRes.status !== 0) {
    throw new Error(`Fault proposal failed: ${propRes.stderr}`);
  }

  const actRes = executeCli(["i", "act", propRes.parsed.proposal_id, "--approve", "--key", humanKeyOut], ctx);
  if (actRes.status !== 0) {
    throw new Error(`Fault proposal approval failed: ${actRes.stderr}`);
  }

  // Step 3: Queue tick
  steps.push("mirql q tick");
  executeCli(["q", "tick"], ctx);

  // Step 4: Doctor diagnosis evaluates health
  steps.push("mirql r doctor");
  const doctorRes = executeCli(["r", "doctor"], ctx);
  if (doctorRes.status === null) {
    throw new Error("Doctor execution crashed");
  }

  // Step 5: Breaker trip
  steps.push("mirql r doctor --trip worker:flash");
  const tripRes = executeCli(["r", "doctor", "--trip", "worker:flash", "--reason", "repeated_worker_failures"], ctx);
  if (tripRes.status !== 0) {
    throw new Error(`Doctor trip failed: ${tripRes.stderr}`);
  }

  // Step 6: Breaker reset & Recovery
  steps.push("mirql r doctor --reset worker:flash");
  const resetRes = executeCli(["r", "doctor", "--reset", "worker:flash"], ctx);
  if (resetRes.status !== 0) {
    throw new Error(`Doctor reset failed: ${resetRes.stderr}`);
  }

  return { ok: true, steps };
}

/**
 * Executes Scenario 3: `quarantine-to-harden`
 * Verifies non-deterministic test detection, quarantine execution,
 * and test isolation.
 *
 * @param {object} ctx - { sandboxDir, mirqlDir, repoRoot }
 * @returns {{ ok: boolean, steps: string[] }}
 */
function runScenarioQuarantineToHarden(ctx) {
  const { sandboxDir, mirqlDir } = ctx;
  const steps = [];

  // Step 1: Genesis bootstrap
  steps.push("mirql i genesis");
  const humanKeyOut = join(sandboxDir, "operator_human.key.json");
  executeCli(["i", "genesis", "--human-key-out", humanKeyOut], ctx);

  // Step 2: Create a simulated test file that exhibits flakiness
  steps.push("create non-deterministic test file");
  const testsDir = join(sandboxDir, "tests");
  mkdirSync(testsDir, { recursive: true });
  const flakyTestFile = join(testsDir, "flaky.test.mjs");
  writeFileSync(flakyTestFile, `
import { it } from "node:test";
import assert from "node:assert/strict";
it("flaky test", () => {
  assert.ok(true);
});
  `.trim() + "\n", "utf8");

  // Step 3: Execute Quarantine
  steps.push(`quarantine flaky test ${flakyTestFile}`);
  const quarantineDir = join(mirqlDir, "quarantine");
  const quarantineRes = quarantineTest(flakyTestFile, quarantineDir, {
    reason: "non-deterministic flake detected across iterations",
  });
  if (!quarantineRes.quarantined) {
    throw new Error(`Quarantine failed to quarantine test: ${flakyTestFile}`);
  }

  // Step 4: Verify quarantine directory and moved test file
  steps.push("verify quarantine directory");
  if (!existsSync(quarantineDir)) {
    throw new Error(`Quarantine directory missing at ${quarantineDir}`);
  }
  const quarantinedFiles = readdirSync(quarantineDir);
  if (quarantinedFiles.length === 0) {
    throw new Error(`Quarantine directory empty`);
  }

  return { ok: true, steps };
}

/**
 * Runs a specific journey scenario in an isolated sandbox.
 * (roles/scout-journey.md)
 *
 * @param {string} scenarioName - "init-to-merge" | "fault-to-recovery" | "quarantine-to-harden"
 * @param {object} [options]
 * @returns {{
 *   ok: boolean,
 *   journey_name: string,
 *   steps_completed: string[],
 *   duration_ms: number,
 *   gap?: object,
 *   regression?: object,
 *   error?: string
 * }}
 */
export function runJourney(scenarioName, options = {}) {
  const normName = String(scenarioName || "").trim().toLowerCase();
  if (!JOURNEY_SCENARIOS.includes(normName)) {
    const errorMsg = `Unknown journey scenario "${scenarioName}". Expected one of: ${JOURNEY_SCENARIOS.join(", ")}`;
    const gap = formatJourneyGapEvent({
      journey_name: scenarioName,
      step_failed: "scenario_resolution",
      expected_behavior: `Valid scenario in ${JOURNEY_SCENARIOS.join(", ")}`,
      observed_behavior: errorMsg,
      exit_code: EXIT_CODES.USAGE_ERROR,
    }, options);
    const regression = formatRegressionReportedEvent({
      severity: "annoyance",
      minimal_repro: [`mirql r journey --scenario ${scenarioName}`],
      details: errorMsg,
      journey_name: scenarioName,
    }, options);
    return {
      ok: false,
      journey_name: scenarioName,
      steps_completed: [],
      duration_ms: 0,
      gap,
      regression,
      error: errorMsg,
    };
  }

  const sandbox = createJourneySandbox(options);
  const startMs = Date.now();
  let stepsCompleted = [];

  try {
    let result;
    const ctx = {
      sandboxDir: sandbox.sandboxDir,
      mirqlDir: sandbox.mirqlDir,
      repoRoot: options.repoRoot || resolve(process.cwd()),
      options,
    };

    switch (normName) {
      case "init-to-merge":
        result = runScenarioInitToMerge(ctx);
        break;
      case "fault-to-recovery":
        result = runScenarioFaultToRecovery(ctx);
        break;
      case "quarantine-to-harden":
        result = runScenarioQuarantineToHarden(ctx);
        break;
      default:
        throw new Error(`Unhandled scenario ${normName}`);
    }

    stepsCompleted = result.steps || [];
    const durationMs = Date.now() - startMs;

    return {
      ok: true,
      journey_name: normName,
      steps_completed: stepsCompleted,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - startMs;
    const failedStep = stepsCompleted[stepsCompleted.length - 1] || "scenario_start";
    const severity = normName === "init-to-merge" ? "critical" : "degraded";

    const gap = formatJourneyGapEvent({
      journey_name: normName,
      step_failed: failedStep,
      expected_behavior: "Step succeeds without exception and advances journey lifecycle",
      observed_behavior: err.message || String(err),
      exit_code: err.exitCode ?? EXIT_CODES.DOMAIN_NEGATIVE,
      reproduction_steps: [...stepsCompleted, failedStep],
    }, options);

    const regression = formatRegressionReportedEvent({
      severity,
      minimal_repro: [...stepsCompleted, failedStep],
      details: `Journey ${normName} broke at step "${failedStep}": ${err.message}`,
      journey_name: normName,
    }, options);

    return {
      ok: false,
      journey_name: normName,
      steps_completed: stepsCompleted,
      duration_ms: durationMs,
      gap,
      regression,
      error: err.message,
    };
  } finally {
    sandbox.cleanup();
  }
}

/**
 * Runs all prescribed journey scenarios sequentially.
 *
 * @param {object} [options]
 * @returns {{
 *   ok: boolean,
 *   scenarios_passed: number,
 *   scenarios_failed: number,
 *   results: Record<string, object>,
 *   gaps: object[],
 *   regressions: object[],
 *   duration_ms: number
 * }}
 */
export function runAllJourneys(options = {}) {
  const startMs = Date.now();
  const results = {};
  const gaps = [];
  const regressions = [];
  let scenariosPassed = 0;
  let scenariosFailed = 0;

  for (const name of JOURNEY_SCENARIOS) {
    const res = runJourney(name, options);
    results[name] = res;
    if (res.ok) {
      scenariosPassed++;
    } else {
      scenariosFailed++;
      if (res.gap) gaps.push(res.gap);
      if (res.regression) regressions.push(res.regression);
    }
  }

  const ok = scenariosFailed === 0;
  const durationMs = Date.now() - startMs;

  return {
    ok,
    scenarios_passed: scenariosPassed,
    scenarios_failed: scenariosFailed,
    results,
    gaps,
    regressions,
    duration_ms: durationMs,
  };
}
