// packages/run — attempt supervisor, AST anti-cheat gate, 0-token probe runner,
// and bing-bong multi-agent consensus orchestrator.
import { readFileSync, existsSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import {
  EXIT_CODES,
  jcs,
  LedgerWatcher,
  createLedgerWatcher,
  waitForLedgerEvent,
} from "../core/index.mjs";
import {
  computePhi,
  checkPhiReduction,
  evaluatePhiGate,
  verifyThrift,
} from "./phi.mjs";
import {
  detectDrift,
  verifyClaimCheck,
  formatDriftEvent,
} from "./drift.mjs";
import {
  generateMutants,
  runMutationTesting,
  detectFlakes,
  quarantineTest,
  formatMutantEvent,
  formatKillTestNeededEvent,
  extractChangedLines,
  maskStringsAndComments,
  isValidModuleSyntax,
  MUTATION_OPERATORS,
} from "./mutant.mjs";
import {
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkHumanApprovePaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
  isHumanOnlyPath,
  isHumanApprovePath,
  normalizePath,
  loadPathPolicies,
  loadHumanOnlyPatterns,
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
} from "./anti-cheat.mjs";
import { verifyAttempt } from "./verify.mjs";
import { runAgent, sanitizeAgentEnv, SAFE_ENV_ALLOWLIST } from "./agent.mjs";
import {
  runSupervisor,
  runSupervisorReactive,
  touchHeartbeat,
  startHeartbeatTicker,
} from "./supervisor.mjs";
import { runProbe, KNOWN_PROBES } from "./probe.mjs";
import {
  diagnoseHealth,
  evaluateCircuitBreakers,
  evaluateMacroStateTransition,
  normalizeFailureSignature,
  BreakerStore,
  runDoctor,
  SUBSYSTEMS,
  CIRCUIT_ACTIONS,
  MACRO_STATES,
} from "./doctor.mjs";
import { runBingBong, extractModelFamily } from "./bing-bong.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";
import {
  runJourney,
  runAllJourneys,
  JOURNEY_SCENARIOS,
  formatJourneyGapEvent,
  formatRegressionReportedEvent,
} from "./journey.mjs";

/** Tool name reported by this package. */
export const TOOL = "run";

export const SUBCOMMANDS = Object.freeze([
  "supervisor",
  "agent",
  "verify",
  "probe",
  "bing-bong",
  "bb",
  "phi",
  "drift",
  "mutant",
  "flake",
  "doctor",
  "journey",
  "help",
]);

/**
 * Parses command-line arguments into positional tokens and flag mappings.
 *
 * @param {string[]} argv
 * @returns {{ positional: string[], flags: Record<string, any> }}
 */
function parseArgs(argv) {
  const positional = [];
  const flags = {};

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      if (eq !== -1) {
        flags[arg.slice(2, eq)] = arg.slice(eq + 1);
      } else {
        const name = arg.slice(2);
        if (i + 1 < argv.length && !argv[i + 1].startsWith("-")) {
          flags[name] = argv[++i];
        } else {
          flags[name] = true;
        }
      }
    } else if (arg.startsWith("-") && arg.length > 1) {
      const name = arg.slice(1);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("-")) {
        flags[name] = argv[++i];
      } else {
        flags[name] = true;
      }
    } else {
      positional.push(arg);
    }
  }

  return { positional, flags };
}

function emitLine(text) {
  process.stdout.write(text + "\n");
}

function emitError(errObj) {
  process.stderr.write(jcs(errObj) + "\n");
}

function usageError(reason) {
  emitError({ error: "USAGE_ERROR", reason });
  return EXIT_CODES.USAGE_ERROR;
}

function emitStubContract() {
  process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
  return EXIT_CODES.OK;
}

/**
 * Full CLI dispatch for mirql-run (mirql r <subcommand> / mirql-run <subcommand>).
 *
 * @param {string[]} argv
 * @returns {number | Promise<number>}
 */
export function runCli(argv = []) {
  const { positional, flags } = parseArgs(argv);
  const sub = positional[0];

  if (!sub || sub === "status") {
    return emitStubContract();
  }

  if (sub === "help") {
    emitLine(
      jcs({
        tool: TOOL,
        usage: "mirql r <subcommand> [options]",
        subcommands: {
          supervisor:
            "privileged parent broker: executes agent, verifyAttempt, records Outcome (--epoch <int> threads the leased epoch)",
          agent: "unprivileged worker: strips secrets, enforces policy/paths.yaml",
          verify: "Git causal verifier (--workspace <repo> --base <ref> --head <ref> --reproducer <changed-test> --dir <ledger> --warrant-id <id>); --fixture <path> is conformance only",
          probe: "declarative 0-token probe runner (--probe <name>)",
          "bing-bong": "multi-agent cross-family consensus loop (alias bb)",
          phi: "compute complexity potential phi",
          journey: "simulate end-to-end user journeys (--scenario <name> | all)",
        },
      }),
    );
    return EXIT_CODES.OK;
  }

  switch (sub) {
    case "verify": {
      const fixture = flags.fixture || flags.f;
      // B1: mirql r verify with no inputs must fail with exit 2 (USAGE_ERROR)
      if (!fixture && positional.length <= 1 && !flags.workspace && !flags.reproducer && !flags.base && !flags.head) {
        return usageError("mirql r verify requires --fixture <path> or verification target");
      }

      if (fixture) {
        try {
          const result = verifyAttempt({ fixture });
          if (result.verified) {
            emitLine(jcs(result));
            return EXIT_CODES.OK;
          } else {
            emitError(result);
            if (
              result.rule === "MP-001" ||
              result.rule === "MP-005" ||
              result.verdict === "needs_human"
            ) {
              return EXIT_CODES.POLICY_DENIAL;
            }
            return EXIT_CODES.DOMAIN_NEGATIVE;
          }
        } catch (err) {
          return usageError(err instanceof Error ? err.message : String(err));
        }
      }

      for (const name of ["workspace", "base", "head", "reproducer", "dir", "warrant-id"]) {
        if (flags[name] !== undefined && (typeof flags[name] !== "string" || !flags[name].trim())) {
          return usageError(`--${name} requires a value`);
        }
      }
      // The live command measures Git objects and runs the fixed test pipeline.
      const result = verifyAttempt({
        git: true,
        workspaceDir: flags.workspace ?? process.cwd(),
        baseSha: flags.base,
        headSha: flags.head,
        reproducerFile: flags.reproducer,
        mirqlDir: flags.dir,
        warrantId: flags["warrant-id"],
      });
      emitLine(jcs(result));
      if (result.verified) return EXIT_CODES.OK;
      return result.verdict === "needs_human" ? EXIT_CODES.POLICY_DENIAL : EXIT_CODES.DOMAIN_NEGATIVE;
    }

    case "supervisor": {
      try {
        // Daemon mode composes queue leasing with the reactive loop; packages
        // must not cross-import, so the wiring lives in bin/mirql.mjs.
        if (flags.daemon !== undefined) {
          return usageError("--daemon is composed by the mirql router (it wires the queue); run: mirql r supervisor --daemon");
        }
        // H1: `--epoch <int>` threads the leased configuration epoch (Law 5
        // fencing) into the Outcome and the signed attempt.outcome event.
        let epoch;
        if (flags.epoch !== undefined) {
          epoch = Number.parseInt(String(flags.epoch), 10);
          if (!Number.isSafeInteger(epoch) || epoch < 0) {
            return usageError(`invalid --epoch value ${JSON.stringify(flags.epoch)}: expected a non-negative safe integer`);
          }
        }

        const res = runSupervisor({
          dir: flags.dir,
          workspaceDir: flags.workspace ?? process.cwd(),
          warrant: flags.warrant || flags.w,
          warrantId: flags.warrantId ?? flags["warrant-id"],
          builderCommand: flags.command,
          epoch,
        });

        if (res && typeof res.then === "function") {
          return res.then((asyncRes) => {
            emitLine(jcs(asyncRes));
            return asyncRes.verified ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
          });
        }

        emitLine(jcs(res));
        // Exit code reflects the result: 0 on auto_merge/pass, 1 on fail/reject (B3)
        return res.verified ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
      } catch (err) {
        emitError({
          error: err.code ?? "USAGE_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        return err.exitCode ?? EXIT_CODES.USAGE_ERROR;
      }
    }

    case "agent": {
      try {
        const res = runAgent({
          command: flags.command,
          cwd: flags.workspace ?? process.cwd(),
        });
        emitLine(jcs(res));
        return res.exitCode;
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    case "probe": {
      try {
        const res = runProbe({
          probe: flags.probe ?? flags.type ?? "tests",
          dir: flags.dir,
          workspaceDir: flags.workspace ?? process.cwd(),
          source: flags.source,
          test: flags.test,
          base: flags.base,
        });
        emitLine(jcs(res));
        return res.ok ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    case "bing-bong":
    case "bb": {
      const warrant = flags.warrant || flags.w;
      if (!warrant) {
        return usageError("missing required --warrant <path|json> argument");
      }

      const rounds = flags.rounds ? parseInt(flags.rounds, 10) : 3;

      let panel = undefined;
      const panelArg = flags.panel || flags.p;
      if (panelArg) {
        if (typeof panelArg === "string" && existsSync(panelArg)) {
          try {
            const panelData = JSON.parse(readFileSync(panelArg, "utf8"));
            panel = panelData.panel ?? panelData;
          } catch (err) {
            return usageError(`Corrupt panel file at ${panelArg}: ${err.message}`);
          }
        } else if (typeof panelArg === "string") {
          panel = panelArg.split(",").map((s) => s.trim());
        }
      }

      try {
        const res = runBingBong({
          warrant,
          rounds,
          panel,
          dir: flags.dir,
        });

        if (res && typeof res.then === "function") {
          return res.then((asyncRes) => {
            if (asyncRes.status === "CONVERGED") {
              emitLine(jcs(asyncRes));
              return EXIT_CODES.OK;
            } else {
              emitError(asyncRes);
              return EXIT_CODES.NEEDS_HUMAN;
            }
          });
        }

        if (res.status === "CONVERGED") {
          emitLine(jcs(res));
          return EXIT_CODES.OK;
        } else {
          emitError(res);
          return EXIT_CODES.NEEDS_HUMAN;
        }
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    case "phi": {
      const res = computePhi(flags.dir ?? process.cwd());
      emitLine(jcs(res));
      return EXIT_CODES.OK;
    }

    case "drift": {
      const res = detectDrift(flags.dir ?? process.cwd());
      emitLine(jcs(res));
      return res.ok ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
    }

    case "mutant": {
      try {
        const sourcePath = flags.source ?? positional[1];
        const testPath = flags.test ?? positional[2];
        if (!sourcePath) {
          return usageError("missing required --source <path>");
        }
        if (!testPath) {
          return usageError("missing required --test <path>");
        }

        let killThresholdBp = 8000;
        if (flags.threshold !== undefined) {
          const th = parseInt(flags.threshold, 10);
          if (!Number.isSafeInteger(th) || th < 8000 || th > 10000) {
            return usageError("threshold must be an integer between 8000 and 10000 bp (8000 bp floor)");
          }
          killThresholdBp = th;
        }

        let maxMutants = 20;
        if (flags["max-mutants"] !== undefined) {
          const mm = parseInt(flags["max-mutants"], 10);
          if (!Number.isSafeInteger(mm) || mm <= 0) {
            return usageError("max-mutants must be a positive safe integer (> 0)");
          }
          maxMutants = mm;
        }

        let changedLines = null;
        if (flags["changed-lines"]) {
          changedLines = new Set();
          const parts = String(flags["changed-lines"]).split(",");
          for (const part of parts) {
            if (part.includes("-")) {
              const [s, e] = part.split("-").map((n) => parseInt(n.trim(), 10));
              if (Number.isSafeInteger(s) && Number.isSafeInteger(e)) {
                for (let i = s; i <= e; i++) changedLines.add(i);
              }
            } else {
              const n = parseInt(part.trim(), 10);
              if (Number.isSafeInteger(n)) changedLines.add(n);
            }
          }
        } else if (flags.base || flags.diff) {
          const base = typeof flags.base === "string" ? flags.base : "HEAD~1";
          const diffRes = spawnSync("git", ["diff", "-U0", base, "--", sourcePath], {
            encoding: "utf8",
            timeout: 10000,
          });
          if (diffRes.status === 0 && diffRes.stdout) {
            changedLines = extractChangedLines(diffRes.stdout);
          }
        }

        const res = runMutationTesting({
          sourcePath,
          testPath,
          killThresholdBp,
          maxMutants,
          changedLines,
        });
        emitLine(jcs(res));
        return res.ok ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    case "flake": {
      try {
        const testPath = flags.test ?? positional[1];
        if (!testPath) {
          return usageError("missing required --test <path>");
        }
        const iterations = flags.iterations ? parseInt(flags.iterations, 10) : 5;
        if (!Number.isSafeInteger(iterations) || iterations <= 0) {
          return usageError("iterations must be a positive safe integer");
        }

        const res = detectFlakes(testPath, { iterations });
        if (res.flaky && flags.quarantine) {
          const qRes = quarantineTest(testPath, flags.quarantine);
          res.quarantine = qRes;
        }
        emitLine(jcs(res));
        return res.flaky ? EXIT_CODES.DOMAIN_NEGATIVE : EXIT_CODES.OK;
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    case "doctor": {
      try {
        const workspaceDir = flags.workspace ? resolve(flags.workspace) : process.cwd();
        const mirqlDir = flags.ledger
          ? resolve(flags.ledger)
          : flags.dir
            ? resolve(flags.dir)
            : resolve(workspaceDir, ".mirql");

        if (flags.trip !== undefined) {
          if (
            typeof flags.trip !== "string" ||
            flags.trip.trim() === "" ||
            !SUBSYSTEMS.includes(flags.trip) ||
            flags.trip === "all" ||
            flags.trip === "lifeguard"
          ) {
            return usageError(`invalid subsystem to trip: ${JSON.stringify(flags.trip)}; must be one of: ${SUBSYSTEMS.filter((s) => s !== "all" && s !== "lifeguard").join(", ")}`);
          }
        }

        if (flags.reset !== undefined) {
          if (
            typeof flags.reset !== "string" ||
            flags.reset.trim() === "" ||
            (!SUBSYSTEMS.includes(flags.reset) && flags.reset !== "all") ||
            flags.reset === "lifeguard"
          ) {
            return usageError(`invalid subsystem to reset: ${JSON.stringify(flags.reset)}; must be one of: ${SUBSYSTEMS.filter((s) => s !== "lifeguard").join(", ")}`);
          }
        }

        let cooldownMs;
        if (flags.cooldown !== undefined) {
          const rawCd = String(flags.cooldown).trim();
          if (!/^\d+$/.test(rawCd)) {
            return usageError(`cooldown must be a non-negative integer ms, got ${JSON.stringify(flags.cooldown)}`);
          }
          const cd = parseInt(rawCd, 10);
          if (!Number.isSafeInteger(cd) || cd < 0) {
            return usageError("cooldown exceeds safe integer range");
          }
          cooldownMs = cd;
        }

        const res = runDoctor({
          mirqlDir,
          workspaceDir,
          trip: flags.trip,
          reset: flags.reset,
          cooldown_ms: cooldownMs,
          autoQuarantine: Boolean(flags["auto-quarantine"] || flags.quarantine),
          runProbes: Boolean(flags.probes),
        });

        if (flags.trip || flags.reset) {
          if (flags.format === "text") {
            process.stdout.write(`=== mirql Doctor Action: ${res.action.toUpperCase()} ===\n`);
            process.stdout.write(`Target: ${res.target}\n`);
            process.stdout.write(`Status: SUCCESS\n`);
          } else {
            emitLine(jcs(res));
          }
          return EXIT_CODES.OK;
        }

        if (flags.format === "text") {
          process.stdout.write("=== mirql Doctor Health Report ===\n");
          process.stdout.write(`Healthy: ${res.healthy ? "YES" : "NO"}\n`);
          if (res.triage) {
            process.stdout.write(`Signature: ${res.triage.failure_signature}\n`);
            process.stdout.write(`Root Cause: ${res.triage.root_cause_analysis}\n`);
            process.stdout.write(`Remediation: ${res.triage.recommended_remediation}\n`);
          }
          if (res.breaker) {
            process.stdout.write(`Circuit Breaker: [${res.breaker.target_subsystem}] -> ${res.breaker.action} (${res.breaker.reason})\n`);
          }
        } else {
          emitLine(jcs(res));
        }

        return res.healthy ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    case "journey": {
      const scenario = flags.scenario || flags.s || positional[1];
      const repoRoot = flags.repoRoot || flags.root || process.cwd();
      const keepSandbox = Boolean(flags.keepSandbox || flags["keep-sandbox"]);

      try {
        let result;
        if (scenario && scenario !== "all") {
          result = runJourney(scenario, { repoRoot, keepSandbox });
        } else {
          result = runAllJourneys({ repoRoot, keepSandbox });
        }

        if (flags.json) {
          process.stdout.write(JSON.stringify(result) + "\n");
        } else {
          process.stdout.write(JSON.stringify(result, null, 2) + "\n");
        }

        return result.ok ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
      } catch (err) {
        return usageError(err instanceof Error ? err.message : String(err));
      }
    }

    default: {
      return usageError(`unknown subcommand ${JSON.stringify(sub)}; expected one of ${SUBCOMMANDS.join(", ")}`);
    }
  }
}

/**
 * Law 14 daemon composition: wraps runSupervisorReactive with launcher
 * lifecycle (pid + heartbeat), optional drain-and-exit (maxSteps, for cron
 * style drains and tests) and signal shutdown. Cross-package wiring — queue
 * leasing, warrant documents — is injected by the bin composition root;
 * packages never cross-import (structure gate).
 *
 * @param {object} options
 * @param {string} [options.dir] ledger dir (default .mirql)
 * @param {string} [options.workspaceDir] workspace for supervised runs
 * @param {string} [options.builderCommand] sandboxed builder command
 * @param {Function} [options.leaseJob] injected queue lease callback
 * @param {Function} [options.getWarrant] injected warrant document resolver
 * @param {number} [options.maxSteps] stop after N executed steps (drain mode)
 * @param {boolean} [options.handleSignals=true] install SIGINT/SIGTERM shutdown
 * @returns {Promise<{watcher: object, getStepsExecuted: () => number, close: () => void, stop: () => void, done: Promise<void>}>}
 */
export async function startFactoryDaemon(options = {}) {
  const mirqlDir = resolve(options.dir ?? options.mirqlDir ?? join(process.cwd(), ".mirql"));
  const stateDir = join(mirqlDir, "state");
  mkdirSync(stateDir, { recursive: true });
  // The watcher silently no-ops when the ledger directory does not exist,
  // which would leave an idle daemon that exits 0 the moment nothing else
  // keeps the event loop alive (P1 from the Codex review).
  mkdirSync(join(mirqlDir, "ledger"), { recursive: true });
  const heartbeatPath = join(stateDir, "heartbeat");
  const pidPath = join(stateDir, "launcher.pid");
  const touch = (file, body) => { try { writeFileSync(file, body, "utf8"); } catch { /* mp-003-allow: a heartbeat or pid write failure is caught by the lifeguard's staleness check, not by crashing the launcher */ } };
  touch(heartbeatPath, `${Date.now()}\n`);
  touch(pidPath, `${process.pid}\n`);
  const ticker = setInterval(() => touch(heartbeatPath, `${Date.now()}\n`), options.heartbeatMs ?? 2000);
  ticker.unref();

  const daemon = await runSupervisorReactive({
    ...options,
    mirqlDir,
    initialRun: false,
    // the daemon owns launcher.pid for its whole lifetime; per-step
    // supervisors must not unlink it between events.
    skipPidFile: true,
  });

  let stopped = false;
  let resolveDone;
  const done = new Promise((res) => { resolveDone = res; });
  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(ticker);
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    try { daemon.close(); } catch { /* mp-003-allow: the launcher is already stopping; a failed close leaves the socket to the OS */ }
    try { if (existsSync(pidPath)) unlinkSync(pidPath); } catch { /* mp-003-allow: a pid file that cannot be unlinked during stop reads as stale at next launch, which rewrites it */ }
    resolveDone();
  };

  // Drain mode resolves the reactive loop's own done promise; mirror it here
  // so the launcher lifecycle (pid + heartbeat ticker) shuts down with it.
  daemon.done.then(stop).catch(() => { /* mp-003-allow: stop is idempotent; a rejected done only means the reactive loop already stopped itself */ });
  if (options.handleSignals !== false) {
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  }
  if (options.initialRun ?? true) await daemon.start();
  return { watcher: daemon.watcher, getStepsExecuted: daemon.getStepsExecuted, getLastStep: daemon.getLastStep, close: daemon.close, stop, done };
}

/**
 * Primary CLI entrypoint imported by bin/mirql-run.mjs and bin/mirql.mjs.
 *
 * @param {string[]} argv
 * @returns {number | Promise<number>} process exit code
 */
export function main(argv = []) {
  const first = argv[0];
  if (
    argv.length === 0 ||
    first === "--help" ||
    first === "-h" ||
    first === "status"
  ) {
    return emitStubContract();
  }

  // Preserve W1 stub contract for bare `mirql r bing-bong` / `mirql r bb` with no args
  if (argv.length === 1 && (first === "bing-bong" || first === "bb")) {
    return emitStubContract();
  }

  const result = runCli(argv);
  if (result && typeof result.then === "function") {
    return result
      .then((code) => {
        const exitCode = typeof code === "number" ? code : EXIT_CODES.OK;
        process.exitCode = exitCode;
        return exitCode;
      })
      .catch((err) => {
        emitError({
          error: "INTERNAL_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        process.exitCode = 1;
        return 1;
      });
  }

  return typeof result === "number" ? result : EXIT_CODES.OK;
}

export default main;

// Re-export core capabilities
export {
  computePhi,
  checkPhiReduction,
  evaluatePhiGate,
  verifyThrift,
  detectDrift,
  verifyClaimCheck,
  formatDriftEvent,
  generateMutants,
  runMutationTesting,
  detectFlakes,
  quarantineTest,
  formatMutantEvent,
  formatKillTestNeededEvent,
  extractChangedLines,
  maskStringsAndComments,
  isValidModuleSyntax,
  MUTATION_OPERATORS,
  verifyAttempt,
  runSupervisor,
  runSupervisorReactive,
  runAgent,
  sanitizeAgentEnv,
  SAFE_ENV_ALLOWLIST,
  runProbe,
  KNOWN_PROBES,
  runBingBong,
  extractModelFamily,
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkHumanApprovePaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
  isHumanOnlyPath,
  isHumanApprovePath,
  normalizePath,
  loadPathPolicies,
  loadHumanOnlyPatterns,
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
  appendSupervisorEvent,
  getOrGenerateSupervisorKey,
  touchHeartbeat,
  startHeartbeatTicker,
  LedgerWatcher,
  createLedgerWatcher,
  waitForLedgerEvent,
  diagnoseHealth,
  evaluateCircuitBreakers,
  evaluateMacroStateTransition,
  normalizeFailureSignature,
  BreakerStore,
  runDoctor,
  SUBSYSTEMS,
  CIRCUIT_ACTIONS,
  MACRO_STATES,
  runJourney,
  runAllJourneys,
  JOURNEY_SCENARIOS,
  formatJourneyGapEvent,
  formatRegressionReportedEvent,
};
