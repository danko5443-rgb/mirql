#!/usr/bin/env node
// bin/mirql — top-level CLI router for the mirql factory.
//
//   mirql <tool|alias> [command] [options]
//   mirql --help | --version
//
// Tools: mergeproof (m) · inbox (i) · run (r) · queue (q) · log (l)
// All output is JSON on stdout; errors are JSON on stderr.
import { readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { EXIT_CODES } from "../packages/core/index.mjs";
import { main as mergeproofMain } from "../packages/mergeproof/index.mjs";
import { main as runMain, startFactoryDaemon } from "../packages/run/index.mjs";
import { main as queueMain, leaseNextJob } from "../packages/queue/index.mjs";
import { main as logMain } from "../packages/log/index.mjs";
import { main as inboxMain } from "../packages/inbox/index.mjs";

const PKG = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

/**
 * Tool registry. Every tool now owns a package entrypoint; `main` receives
 * the arguments after the tool token and keeps the W1 stub contract itself
 * for bare `--help` / no-args / `status` calls.
 */
const ROUTES = Object.freeze({
  mergeproof: { name: "mergeproof", alias: "m", main: mergeproofMain },
  inbox: { name: "inbox", alias: "i", main: inboxMain },
  run: { name: "run", alias: "r", main: runMain },
  queue: { name: "queue", alias: "q", main: queueMain },
  log: { name: "log", alias: "l", main: logMain },
});

/**
 * Router entrypoint.
 * @param {string[]} argv - arguments after the program name
 * @returns {number} process exit code (see EXIT_CODES)
 */
export function main(argv = []) {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    emit(helpPayload());
    return EXIT_CODES.OK;
  }
  if (argv[0] === "--version" || argv[0] === "-v") {
    emit({ tool: "mirql", version: PKG.version });
    return EXIT_CODES.OK;
  }

  const route = resolveRoute(argv[0]);
  if (!route) {
    process.stderr.write(
      JSON.stringify({
        tool: "mirql",
        error: "unknown_tool",
        requested: argv[0],
        hint: "run `mirql --help` for the tool list",
      }) + "\n",
    );
    return EXIT_CODES.USAGE_ERROR;
  }

  const rest = argv.slice(1);
  // Daemon mode is composed here: the router is the one place that already
  // sees every package, so it hands queue leasing to the reactive supervisor
  // loop (packages never cross-import — structure gate).
  if (route.name === "run" && rest[0] === "supervisor" &&
      rest.some((arg) => arg === "--daemon" || arg.startsWith("--daemon="))) {
    return runFactoryDaemonMode(rest);
  }
  if (route.main) return route.main(rest);

  // Defensive fallback for tools without a package main (none today).
  emit({ tool: route.name, status: "stub" });
  return EXIT_CODES.OK;
}

/** @param {string} token @returns {{ name: string, alias: string, main: ((argv: string[]) => number) | null } | null} */
function resolveRoute(token) {
  if (Object.prototype.hasOwnProperty.call(ROUTES, token)) return ROUTES[token];
  return Object.values(ROUTES).find((route) => route.alias === token) ?? null;
}

/**
 * `mirql r supervisor --daemon` — the 24/7 factory loop. Wires the reactive
 * supervisor to the queue (the only legal composition point) and keeps the
 * process alive until stopped; `--max-steps N` drains N steps then exits.
 *
 * @param {string[]} argv - arguments after the `supervisor` token
 * @returns {Promise<number>} process exit code
 */
async function runFactoryDaemonMode(argv) {
  let options;
  try {
    options = parseDaemonFlags(argv);
  } catch (err) {
    process.stderr.write(JSON.stringify({ error: "USAGE_ERROR", reason: err.message }) + "\n");
    return EXIT_CODES.USAGE_ERROR;
  }
  const { dir, workspace, command, maxSteps, initialRun } = options;
  const repoRoot = resolve(workspace);

  try {
    const daemon = await startFactoryDaemon({
      dir,
      workspaceDir: workspace,
      builderCommand: command,
      maxSteps,
      initialRun,
      leaseJob: (ledgerDir) => leaseNextJob(ledgerDir, { repoRoot }),
      getWarrant: (id) => JSON.parse(readFileSync(join(dir, "warrants", `${id}.json`), "utf8")),
    });

    daemon.watcher.on("step", (step) => {
      process.stdout.write(JSON.stringify(step) + "\n");
    });
    daemon.watcher.on("error", (err) => {
      process.stderr.write(JSON.stringify({ error: "DAEMON_WATCHER", reason: err?.message }) + "\n");
    });

    await daemon.done;
    // The initial drain runs before listeners attach; report the final step
    // (when any) here. Live steps after startup stream above.
    const lastStep = daemon.getLastStep();
    if (lastStep !== null && lastStep !== undefined) {
      process.stdout.write(JSON.stringify({
        daemon_summary: true,
        steps: daemon.getStepsExecuted(),
        last_step: lastStep,
      }) + "\n");
    }
    return EXIT_CODES.OK;
  } catch (err) {
    process.stderr.write(JSON.stringify({
      error: err?.code ?? "DAEMON_FAILED",
      reason: err?.message,
    }) + "\n");
    return err?.exitCode ?? EXIT_CODES.USAGE_ERROR;
  }
}

/**
 * Strict daemon flag parsing (Law 6: an ambiguous flag is a refusal, never a
 * silent default that leaves a 24/7 process running with unintended settings).
 *
 * @param {string[]} argv - arguments after the `supervisor` token
 * @returns {{ dir: string, workspace: string, command?: string, maxSteps?: number, initialRun: boolean }}
 */
export function parseDaemonFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const eq = arg.indexOf("=");
    if (eq !== -1) flags[arg.slice(2, eq)] = arg.slice(eq + 1);
    else if (arg === "--daemon" || arg === "--no-initial-run") flags[arg.slice(2)] = true;
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("-")) flags[arg.slice(2)] = argv[++i];
    else flags[arg.slice(2)] = true;
  }
  if (flags.daemon !== true && flags.daemon !== "true") {
    throw new Error("--daemon takes no value");
  }
  for (const name of ["dir", "workspace", "command"]) {
    if (flags[name] !== undefined && (typeof flags[name] !== "string" || !flags[name].trim())) {
      throw new Error(`--${name} requires a value`);
    }
  }
  let maxSteps;
  if (flags["max-steps"] !== undefined) {
    const raw = String(flags["max-steps"]);
    maxSteps = /^[1-9]\d*$/.test(raw) ? Number(raw) : NaN;
    if (!Number.isSafeInteger(maxSteps)) throw new Error("--max-steps must be a positive integer");
  }
  const initialRunFlag = flags["initial-run"];
  if (initialRunFlag !== undefined && ![true, "true", "false"].includes(initialRunFlag)) {
    throw new Error("--initial-run must be true or false");
  }
  if (flags["no-initial-run"] !== undefined && flags["no-initial-run"] !== true) {
    throw new Error("--no-initial-run takes no value");
  }
  if (flags["no-initial-run"] === true && initialRunFlag !== undefined && initialRunFlag !== "false") {
    throw new Error("--initial-run and --no-initial-run conflict");
  }
  const initialRun = flags["no-initial-run"] !== true && initialRunFlag !== "false";
  return {
    dir: flags.dir ?? join(process.cwd(), ".mirql"),
    workspace: flags.workspace ?? process.cwd(),
    command: flags.command,
    maxSteps,
    initialRun,
  };
}

/** @returns {{ tool: string, version: string, usage: string, tools: Array<object> }} */
function helpPayload() {
  return {
    tool: "mirql",
    version: PKG.version,
    usage: "mirql <tool|alias> [command] [options]",
    tools: Object.values(ROUTES).map((route) => ({
      name: route.name,
      alias: route.alias,
      status: "stub",
    })),
  };
}

/** @param {unknown} payload @returns {void} */
function emit(payload) {
  process.stdout.write(JSON.stringify(payload) + "\n");
}

function resolveArgv1(entry) {
  try {
    return realpathSync(entry);
  } catch {
    return resolve(entry);
  }
}

// Run only when invoked directly (not when imported by tests or other tools).
// Handles both synchronous number results and asynchronous Promises from
// main() — assigning a Promise to process.exitCode crashes Node v24 with
// ERR_INVALID_ARG_TYPE, so thenables are settled explicitly.
if (process.argv[1] && import.meta.url === pathToFileURL(resolveArgv1(process.argv[1])).href) {
  const result = main(process.argv.slice(2));
  if (result && typeof result.then === "function") {
    result
      .then((code) => {
        if (typeof code === "number") process.exitCode = code;
      })
      .catch((err) => {
        process.stderr.write(JSON.stringify({ error: err?.message || String(err) }) + "\n");
        process.exitCode = 1;
      });
  } else if (typeof result === "number") {
    process.exitCode = result;
  }
}
