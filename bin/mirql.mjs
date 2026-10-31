#!/usr/bin/env node
// bin/mirql — top-level CLI router for the mirql factory.
//
//   mirql <tool|alias> [command] [options]
//   mirql --help | --version
//
// Tools: mergeproof (m) · inbox (i) · run (r) · queue (q) · log (l)
// All output is JSON on stdout; errors are JSON on stderr.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { EXIT_CODES } from "../packages/core/index.mjs";
import { main as runMain } from "../packages/run/index.mjs";
import { main as queueMain } from "../packages/queue/index.mjs";
import { main as logMain } from "../packages/log/index.mjs";
import { main as inboxMain } from "../packages/inbox/index.mjs";

const PKG = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

/**
 * Tool registry. `mergeproof` has no package in W1 (W2 lands it) — the router
 * serves its stub contract itself.
 */
const ROUTES = Object.freeze({
  mergeproof: { name: "mergeproof", alias: "m", main: null },
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
  if (route.main) return route.main(rest);

  // mergeproof until W2 ships its package.
  emit({ tool: route.name, status: "stub" });
  return EXIT_CODES.OK;
}

/** @param {string} token @returns {{ name: string, alias: string, main: ((argv: string[]) => number) | null } | null} */
function resolveRoute(token) {
  if (Object.prototype.hasOwnProperty.call(ROUTES, token)) return ROUTES[token];
  return Object.values(ROUTES).find((route) => route.alias === token) ?? null;
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

// Run only when invoked directly (not when imported by tests or other tools).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
