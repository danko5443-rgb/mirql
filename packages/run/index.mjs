// packages/run — attempt supervisor, AST anti-cheat gate, 0-token probe runner,
// and bing-bong multi-agent consensus orchestrator.
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { EXIT_CODES, jcs } from "../core/index.mjs";
import { computePhi, checkPhiReduction } from "./phi.mjs";
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
import { runSupervisor, touchHeartbeat } from "./supervisor.mjs";
import { runProbe, KNOWN_PROBES } from "./probe.mjs";
import { runBingBong, extractModelFamily } from "./bing-bong.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";

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
          verify: "triple-execution Red-Green-ReRed verifier & anti-cheat gate (--fixture <path>)",
          probe: "declarative 0-token probe runner (--probe <name>)",
          "bing-bong": "multi-agent cross-family consensus loop (alias bb)",
          phi: "compute complexity potential phi",
        },
      }),
    );
    return EXIT_CODES.OK;
  }

  switch (sub) {
    case "verify": {
      const fixture = flags.fixture || flags.f;
      // B1: mirql r verify with no inputs must fail with exit 2 (USAGE_ERROR)
      if (!fixture && positional.length <= 1 && !flags.workspace && !flags.reproducer) {
        emitError({
          error: "USAGE_ERROR",
          reason: "mirql r verify requires --fixture <path> or verification target",
        });
        return EXIT_CODES.USAGE_ERROR;
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
          emitError({
            error: "USAGE_ERROR",
            reason: err instanceof Error ? err.message : String(err),
          });
          return EXIT_CODES.USAGE_ERROR;
        }
      }

      // Live verification without fixture
      const result = verifyAttempt({
        workspaceDir: flags.workspace ?? process.cwd(),
      });
      emitLine(jcs(result));
      return result.verified ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
    }

    case "supervisor": {
      try {
        // H1: `--epoch <int>` threads the leased configuration epoch (Law 5
        // fencing) into the Outcome and the signed attempt.outcome event.
        let epoch;
        if (flags.epoch !== undefined) {
          epoch = Number.parseInt(String(flags.epoch), 10);
          if (!Number.isSafeInteger(epoch) || epoch < 0) {
            emitError({
              error: "USAGE_ERROR",
              reason: `invalid --epoch value ${JSON.stringify(flags.epoch)}: expected a non-negative safe integer`,
            });
            return EXIT_CODES.USAGE_ERROR;
          }
        }

        const res = runSupervisor({
          dir: flags.dir,
          workspaceDir: flags.workspace ?? process.cwd(),
          warrant: flags.warrant || flags.w,
          warrantId: flags.warrantId ?? flags["warrant-id"],
          fixture: flags.fixture,
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
          error: "USAGE_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        return EXIT_CODES.USAGE_ERROR;
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
        emitError({
          error: "USAGE_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        return EXIT_CODES.USAGE_ERROR;
      }
    }

    case "probe": {
      try {
        const res = runProbe({
          probe: flags.probe ?? flags.type ?? "tests",
          dir: flags.dir,
          workspaceDir: flags.workspace ?? process.cwd(),
        });
        emitLine(jcs(res));
        return res.ok ? EXIT_CODES.OK : EXIT_CODES.DOMAIN_NEGATIVE;
      } catch (err) {
        emitError({
          error: "USAGE_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        return EXIT_CODES.USAGE_ERROR;
      }
    }

    case "bing-bong":
    case "bb": {
      const warrant = flags.warrant || flags.w;
      if (!warrant) {
        emitError({
          error: "USAGE_ERROR",
          reason: "missing required --warrant <path|json> argument",
        });
        return EXIT_CODES.USAGE_ERROR;
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
            emitError({
              error: "USAGE_ERROR",
              reason: `Corrupt panel file at ${panelArg}: ${err.message}`,
            });
            return EXIT_CODES.USAGE_ERROR;
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
        emitError({
          error: "USAGE_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        return EXIT_CODES.USAGE_ERROR;
      }
    }

    case "phi": {
      const res = computePhi(flags.dir ?? process.cwd());
      emitLine(jcs(res));
      return EXIT_CODES.OK;
    }

    default: {
      emitError({
        error: "USAGE_ERROR",
        reason: `unknown subcommand ${JSON.stringify(sub)}; expected one of ${SUBCOMMANDS.join(", ")}`,
      });
      return EXIT_CODES.USAGE_ERROR;
    }
  }
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
    result
      .then((code) => {
        if (typeof code === "number") {
          process.exitCode = code;
        }
      })
      .catch((err) => {
        emitError({
          error: "INTERNAL_ERROR",
          reason: err instanceof Error ? err.message : String(err),
        });
        process.exitCode = 1;
      });
    return EXIT_CODES.OK;
  }

  return typeof result === "number" ? result : EXIT_CODES.OK;
}

export default main;

// Re-export core capabilities
export {
  computePhi,
  checkPhiReduction,
  verifyAttempt,
  runSupervisor,
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
};
