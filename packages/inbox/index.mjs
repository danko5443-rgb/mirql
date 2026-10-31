// packages/inbox/index.mjs — Cryptographic Human Sovereignty Portal (Law 6).
import { resolve as resolvePath, join } from "node:path";
import { EXIT_CODES, WRITER_ACL, jcs } from "../core/index.mjs";

import { runGenesis } from "./genesis.mjs";
import { sendIntent } from "./send.mjs";
import { renderDigest } from "./digest.mjs";
import { actOnItem } from "./act.mjs";
import { createProposal } from "./propose.mjs";
import { generateFactoryKeypairs, loadKeyring, loadWriterKey } from "./keys.mjs";
import { readEvents, getLastEvent, foldState } from "./ledger.mjs";
import { validateRoadmapRef, checkNotRoadmap, checkProposalQuota } from "./gate.mjs";

// Ensure human:owner supports mirql.genesis as authorized by policy/writers.yaml
if (WRITER_ACL && WRITER_ACL["human:owner"]) {
  const origHumanTest = WRITER_ACL["human:owner"].test.bind(WRITER_ACL["human:owner"]);
  WRITER_ACL["human:owner"].test = function (str) {
    if (str === "mirql.genesis" || str === "mirql.halt" || str === "mirql.resume") return true;
    return origHumanTest(str);
  };
}

/** Tool name reported by this package. */
export const TOOL = "inbox";

export {
  runGenesis,
  sendIntent,
  renderDigest,
  actOnItem,
  createProposal,
  generateFactoryKeypairs,
  loadKeyring,
  loadWriterKey,
  readEvents,
  getLastEvent,
  foldState,
  validateRoadmapRef,
  checkNotRoadmap,
  checkProposalQuota,
};

const SUBCOMMANDS = Object.freeze(["genesis", "send", "digest", "act", "propose"]);

/**
 * Resolve the target .mirql directory from explicit path, MIRQL_DIR env, or <cwd>/.mirql.
 * @param {string} [dirArg]
 * @returns {string}
 */
export function resolveMirqlDir(dirArg) {
  const raw =
    typeof dirArg === "string" && dirArg.length > 0
      ? dirArg
      : (process.env.MIRQL_DIR ?? join(process.cwd(), ".mirql"));
  return resolvePath(raw);
}

/**
 * CLI parser helper.
 * @param {string[]} args
 * @returns {{ options: Record<string, any>, positional: string[] }}
 */
function parseArgs(args) {
  const options = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      if (eqIdx !== -1) {
        options[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
      } else {
        const key = arg.slice(2);
        if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
          options[key] = args[i + 1];
          i += 1;
        } else {
          options[key] = true;
        }
      }
    } else if (arg.startsWith("-")) {
      const key = arg.slice(1);
      if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
        options[key] = args[i + 1];
        i += 1;
      } else {
        options[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { options, positional };
}

/**
 * Run the inbox CLI against argv.
 *
 * @param {string[]} argv
 * @returns {number} process exit code
 */
export function runCli(argv = []) {
  const { options, positional } = parseArgs(argv);
  const subcommand = positional[0];

  if (!subcommand || !SUBCOMMANDS.includes(subcommand)) {
    process.stderr.write(
      JSON.stringify({
        tool: TOOL,
        error: "unknown_subcommand",
        requested: subcommand || null,
        hint: `available subcommands: ${SUBCOMMANDS.join(", ")}`,
      }) + "\n"
    );
    return EXIT_CODES.USAGE_ERROR;
  }

  const mirqlDir = resolveMirqlDir(options.dir || options.d);

  try {
    switch (subcommand) {
      case "genesis": {
        const result = runGenesis(mirqlDir, options);
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      case "send": {
        const result = sendIntent(mirqlDir, options, options);
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      case "digest": {
        const result = renderDigest(mirqlDir, options);
        if (typeof result === "string") {
          process.stdout.write(result + "\n");
        } else {
          process.stdout.write(JSON.stringify(result) + "\n");
        }
        return EXIT_CODES.OK;
      }
      case "act": {
        const result = actOnItem(mirqlDir, options, options);
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      case "propose": {
        const result = createProposal(mirqlDir, options, options);
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      default: {
        process.stderr.write(
          JSON.stringify({
            tool: TOOL,
            error: "unknown_subcommand",
            requested: subcommand,
          }) + "\n"
        );
        return EXIT_CODES.USAGE_ERROR;
      }
    }
  } catch (err) {
    const exitCode = err.exitCode || EXIT_CODES.USAGE_ERROR;
    process.stderr.write(
      JSON.stringify({
        tool: TOOL,
        error: err.message,
        exit_code: exitCode,
      }) + "\n"
    );
    return exitCode;
  }
}

/**
 * CLI entrypoint imported by bin/mirql-inbox.mjs and bin/mirql.mjs.
 * Preserves the W1 stub contract for bare `--help` / `-h` / `status` / no-args calls
 * and delegates every real subcommand to runCli.
 *
 * @param {string[]} argv - arguments after the program name
 * @returns {number} process exit code (see EXIT_CODES)
 */
export function main(argv = []) {
  const first = argv[0];
  if (
    argv.length === 0 ||
    first === "--help" ||
    first === "-h" ||
    first === "status"
  ) {
    process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
    return EXIT_CODES.OK;
  }
  return runCli(argv);
}

export default main;
