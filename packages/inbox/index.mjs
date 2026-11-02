import { approveMerge } from "./merge-approval.mjs";
export { approveMerge };
// packages/inbox/index.mjs — Cryptographic Human Sovereignty Portal (Law 6, Milestone M6).
import { resolve as resolvePath, join } from "node:path";
import { enrollKey } from "../core/keyring.mjs";
import { EXIT_CODES, WRITER_ACL } from "../core/index.mjs";

import { runGenesis } from "./genesis.mjs";
import { sendIntent } from "./send.mjs";
import { renderDigest, formatMicroUsd } from "./digest.mjs";
import { actOnItem } from "./act.mjs";
import {
  createProposal,
  create1TapProposal,
  distillIntent,
  executeReproducer,
  formatIntentDistilledEvent,
  formatProposalCreatedEvent,
  INTENT_CATEGORIES,
} from "./propose.mjs";
import {
  generateFactoryKeypairs,
  loadKeyring,
  loadWriterKey,
  requireHumanKey,
  authenticateHumanWriter,
  resolveHumanKeyPath,
  keyringEntry,
  derivePublicParts,
  FACTORY_WRITERS,
  CANONICAL_WRITERS,
  HUMAN_WRITER_NS,
  HUMAN_KEY_FILENAME,
} from "./keys.mjs";
import {
  readEvents,
  getLastEvent,
  foldState,
  requireGenesisLedger,
} from "./ledger.mjs";
import { validateRoadmapRef, checkNotRoadmap, checkProposalQuota } from "./gate.mjs";

/** Tool name reported by this package. */
export const TOOL = "inbox";

export {
  runGenesis,
  sendIntent,
  renderDigest,
  formatMicroUsd,
  actOnItem,
  createProposal,
  create1TapProposal,
  distillIntent,
  executeReproducer,
  formatIntentDistilledEvent,
  formatProposalCreatedEvent,
  INTENT_CATEGORIES,
  generateFactoryKeypairs,
  loadKeyring,
  loadWriterKey,
  requireHumanKey,
  authenticateHumanWriter,
  resolveHumanKeyPath,
  keyringEntry,
  derivePublicParts,
  readEvents,
  getLastEvent,
  foldState,
  requireGenesisLedger,
  validateRoadmapRef,
  checkNotRoadmap,
  checkProposalQuota,
};

export { FACTORY_WRITERS, CANONICAL_WRITERS, HUMAN_WRITER_NS, HUMAN_KEY_FILENAME };

const SUBCOMMANDS = Object.freeze(["genesis", "send", "digest", "act", "propose", "enroll-key", "approve-merge"]);

// Law 3 note: WRITER_ACL is imported so this module fails fast if the frozen
// ACL table is ever absent — but it is NEVER mutated here. The canonical
// grants live in packages/core/acl.mjs, reconciled with policy/writers.yaml.
void WRITER_ACL;

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

const BOOLEAN_FLAGS = new Set([
  "approve",
  "reject",
  "kill",
  "resume",
  "help",
  "version",
  "all",
  "initialize",
]);

/**
 * CLI parser helper. Kebab-case flags (--signing-key, --target-id,
 * --idempotency-key, --human-key-out, ...) populate BOTH the kebab-case and
 * the camelCase option keys so every call site can use either form.
 *
 * @param {string[]} args
 * @returns {{ options: Record<string, any>, positional: string[] }}
 */
function parseArgs(args) {
  const options = {};
  const positional = [];
  function setOpt(key, val) {
    options[key] = val;
    const camelKey = key.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
    options[camelKey] = val;
  }
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    // Base64url public keys can start with one or two hyphens.
    if (positional[0] === "enroll-key" && positional.length === 2 &&
        /^[A-Za-z0-9_-]{43}$/.test(arg)) {
      positional.push(arg);
      continue;
    }
    if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      if (eqIdx !== -1) {
        setOpt(arg.slice(2, eqIdx), arg.slice(eqIdx + 1));
      } else {
        const key = arg.slice(2);
        if (BOOLEAN_FLAGS.has(key)) {
          setOpt(key, true);
        } else if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
          setOpt(key, args[i + 1]);
          i += 1;
        } else {
          setOpt(key, true);
        }
      }
    } else if (arg.startsWith("-")) {
      const key = arg.slice(1);
      if (BOOLEAN_FLAGS.has(key)) {
        setOpt(key, true);
      } else if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
        setOpt(key, args[i + 1]);
        i += 1;
      } else {
        setOpt(key, true);
      }
    } else {
      positional.push(arg);
    }
  }
  return { options, positional };
}

/** @returns {number} exit code */
function emitUsage() {
  process.stdout.write(
    JSON.stringify({
      tool: TOOL,
      usage: "mirql-inbox <subcommand> [options]  (or: mirql i <subcommand>)",
      dir: "--dir <path> | MIRQL_DIR | <cwd>/.mirql",
      subcommands: {
        genesis:
          "bootstrap .mirql/, provision factory keys, sign mirql.genesis; --human-key-out <path> (default: <trustRoot>/human_owner.key.private.json, mode 0600)",
        "approve-merge": "sign exact Git commit/tree/path approval; --warrant-id <ULID> --workspace <repo> --base <ref> --head <ref> --key <human-key>",
        "enroll-key": "enroll a public key for a writer namespace; requires --key <human-private-key>",
        send:
          "submit human intent & mint a warrant; REQUIRES --key <path> or MIRQL_HUMAN_KEY (outside .mirql)",
        digest: "keyless read-only factory digest; --format markdown|json",
        act: "signed human decision; REQUIRES --key; --decision approve|reject|kill|resume --target-id <ULID>",
        propose: "bounded proposer intake (--roadmap-ref M1..M7 --title --description)",
      },
      exit_codes: EXIT_CODES,
    }) + "\n"
  );
  return EXIT_CODES.OK;
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
    if (subcommand === "help") return emitUsage();
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
      case "enroll-key": {
        const owner = requireHumanKey(mirqlDir, options);
        const result = enrollKey(mirqlDir, positional[1], positional[2], owner, { initialize: options.initialize === true });
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      case "genesis": {
        const result = runGenesis(mirqlDir, options);
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      case "approve-merge": {
        const result = approveMerge(mirqlDir, {
          ...options, workspaceDir: options.workspace ?? process.cwd(),
          warrantId: options.warrantId ?? options["warrant-id"],
        });
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
        const actInput = { ...options };
        if (options.approve === true) {
          actInput.decision = "approve";
        } else if (options.reject === true) {
          actInput.decision = "reject";
        } else if (options.kill === true) {
          actInput.decision = "kill";
        } else if (options.resume === true) {
          actInput.decision = "resume";
        }
        const remainingPositional = positional.slice(1);
        if (!actInput.target_id && !actInput["target-id"] && !actInput.targetId && remainingPositional[0]) {
          actInput.target_id = remainingPositional[0];
          actInput["target-id"] = remainingPositional[0];
        }
        const result = actOnItem(mirqlDir, actInput, actInput);
        process.stdout.write(JSON.stringify(result) + "\n");
        return EXIT_CODES.OK;
      }
      case "propose": {
        const propInput = { ...options };
        const remainingPositional = positional.slice(1);
        if (!propInput.text && !propInput["from-text"] && remainingPositional.length > 0) {
          propInput.text = remainingPositional.join(" ");
        }
        const result = createProposal(mirqlDir, propInput, propInput);
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
    const exitCode = typeof err.exitCode === "number" ? err.exitCode : EXIT_CODES.USAGE_ERROR;
    const payload = {
      tool: TOOL,
      error: err.errorCode || err.message,
      exit_code: exitCode,
    };
    if (err.hint) payload.hint = err.hint;
    if (err.message && err.message !== err.errorCode) payload.reason = err.message;
    process.stderr.write(JSON.stringify(payload) + "\n");
    return exitCode;
  }
}

/**
 * CLI entrypoint imported by bin/mirql-inbox.mjs and bin/mirql.mjs.
 * Preserves the W1 stub contract for bare `--help` / `-h` / `status` / no-args
 * calls and delegates every real subcommand to runCli. Thenable/Promise
 * return values from runCli are settled to a numeric exit code so bin
 * wrappers can assign `process.exitCode` without ERR_INVALID_ARG_TYPE.
 *
 * @param {string[]} argv - arguments after the program name
 * @returns {number | Promise<number>} process exit code (see EXIT_CODES)
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
  const result = runCli(argv);
  if (result !== null && typeof result === "object" && typeof result.then === "function") {
    return result
      .then((code) => (typeof code === "number" ? code : EXIT_CODES.USAGE_ERROR))
      .catch((err) => {
        process.stderr.write(
          JSON.stringify({ tool: TOOL, error: err?.message || String(err) }) + "\n"
        );
        return typeof err?.exitCode === "number" ? err.exitCode : EXIT_CODES.USAGE_ERROR;
      });
  }
  return typeof result === "number" ? result : EXIT_CODES.USAGE_ERROR;
}

export default main;
