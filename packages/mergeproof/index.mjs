// packages/mergeproof/index.mjs — the mechanical merge gate (Law 10: Ship
// Invariants Not Features; Law 7: the notary sits outside the blast radius).
//
// CLI contract:
//   mirql m check [--pr <path|json>] [--base <sha>] [--head <sha>]
//                 [--dir <mirqlDir>] [--key <notaryKeyPath>] [--sign]
//
// - `--pr` accepts a fixture file path or inline JSON; without it the PR
//   document is read from stdin.
// - `--base` asserts the authoritative target tip SHA (MP-004 STALE_BASE on
//   mismatch); `--head` asserts the actual head SHA the same way.
// - `--sign` signs the verdict with the notary key and appends the
//   verdict.issued / verdict.rejected / verdict.needs_human event to
//   <mirqlDir>/ledger/events.jsonl (writer ns `notary:mergeproof`).
// - Output is pure JCS JSON on stdout; exit codes are the canonical
//   EXIT_CODES (0 auto_merge, 1 reject/needs_human, 2 usage error).
//
// Bare invocation, `--help`, `-h`, and `status` keep the W1 stub contract:
//   { "tool": "mergeproof", "status": "stub" }
import { existsSync, readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { EXIT_CODES, jcs } from "../core/index.mjs";
import { evaluatePullRequest, TOOL } from "./evaluator.mjs";
import { signAndAppendVerdict } from "./notary.mjs";

export { TOOL };

export const SUBCOMMANDS = Object.freeze(["check"]);

/**
 * Resolve the active `.mirql` directory: explicit argument wins, then the
 * MIRQL_DIR environment variable, then `<cwd>/.mirql`.
 *
 * @param {string | undefined | null} mirqlDir
 * @returns {string} absolute path
 */
function resolveMirqlDir(mirqlDir) {
  const raw =
    typeof mirqlDir === "string" && mirqlDir.length > 0
      ? mirqlDir
      : (process.env.MIRQL_DIR ?? resolvePath(process.cwd(), ".mirql"));
  return resolvePath(raw);
}

/**
 * Parse argv into positionals and flags (supports `--flag value` and
 * `--flag=value`; boolean flags and value-flags followed by another flag
 * never consume a value).
 *
 * @param {string[]} argv
 * @returns {{ positional: string[], flags: Record<string, string | boolean> }}
 */
function parseArgs(argv) {
  const BOOL_FLAGS = new Set(["sign", "help"]);
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
        if (
          !BOOL_FLAGS.has(name) &&
          i + 1 < argv.length &&
          !argv[i + 1].startsWith("-")
        ) {
          flags[name] = argv[++i];
        } else {
          flags[name] = true;
        }
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

/**
 * Read all of stdin synchronously (pipe or redirect); empty when stdin is a
 * TTY or unreadable, so interactive misuse fails fast instead of hanging.
 *
 * @returns {string}
 */
function readStdinSync() {
  try {
    if (process.stdin.isTTY) return "";
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/**
 * Load the PR document from `--pr <path | inline JSON>` or stdin.
 *
 * @param {Record<string, string | boolean>} flags
 * @returns {object} parsed PR document
 * @throws Error (USAGE_ERROR) on missing or malformed input
 */
function loadPrDocument(flags) {
  const raw = flags.pr ?? flags.fixture;
  let text = null;
  let origin = "--pr";

  if (typeof raw === "string" && raw.length > 0) {
    const trimmed = raw.trimStart();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      text = raw; // inline JSON document
    } else {
      const abs = resolvePath(raw);
      if (!existsSync(abs)) {
        throw usageError(`--pr file not found: ${raw}`);
      }
      try {
        text = readFileSync(abs, "utf8");
      } catch (err) {
        throw usageError(
          `--pr file is not readable: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  } else {
    origin = "stdin";
    text = readStdinSync();
    if (text.trim().length === 0) {
      throw usageError(
        "no PR input: pass --pr <path|json> or pipe a PR document on stdin",
      );
    }
  }

  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw usageError(
      `${origin} does not contain valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw usageError(`${origin} must contain a JSON object PR document`);
  }
  return doc;
}

/**
 * USAGE_ERROR-carrying error for the CLI boundary.
 *
 * @param {string} message
 * @returns {Error & { code: "USAGE_ERROR" }}
 */
function usageError(message) {
  const err = new Error(message);
  err.code = "USAGE_ERROR";
  return err;
}

/** @param {string} text @returns {void} */
function emitLine(text) {
  process.stdout.write(text + "\n");
}

/** The W1-pinned stub contract (bare invocation, --help, -h, status). */
function emitStubContract() {
  process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
  return EXIT_CODES.OK;
}

/** @returns {number} exit code */
function emitUsage() {
  emitLine(
    jcs({
      tool: TOOL,
      usage: "mirql-mergeproof <subcommand> [options]  (or: mirql m <subcommand>)",
      subcommands: {
        check:
          "evaluate a PR against MP-000..MP-005 + Law 13; --pr <path|json> or stdin; --base <sha> asserts the target tip; --head <sha> asserts the head; --sign appends the signed verdict to the ledger (--dir, --key <notaryKeyPath>)",
      },
      exit_codes: {
        OK: "0 auto_merge",
        DOMAIN_NEGATIVE: "1 reject / needs_human",
        USAGE_ERROR: "2 bad arguments or malformed input",
      },
    }),
  );
  return EXIT_CODES.OK;
}

/**
 * `check` subcommand: evaluate (and optionally sign) one PR document.
 *
 * @param {Record<string, string | boolean>} flags
 * @returns {number} exit code
 */
function cliCheck(flags) {
  const prDoc = loadPrDocument(flags);
  try {
    jcs(prDoc);
  } catch (err) {
    throw usageError(
      `PR document violates Law 17 (integer-only canonical JSON): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const options = {};

  if (typeof flags.base === "string" && flags.base.length > 0) {
    options.targetTipSha = flags.base;
  }
  if (typeof flags.head === "string" && flags.head.length > 0) {
    options.expectedHeadSha = flags.head;
  }
  // Law 3 & 6: Affirmative human sign-off cannot be claimed via raw CLI flag.
  // It must come from an external verified signed event or verified programmatic caller.

  const verdict = evaluatePullRequest(prDoc, options);

  const out = {
    tool: TOOL,
    command: "check",
    ok: verdict.ok,
    verdict: verdict.verdict,
    rule: verdict.rule,
    violation: verdict.violation,
    detail: verdict.detail,
    job_id: typeof prDoc.job_id === "string" ? prDoc.job_id : null,
    warrant_id: typeof prDoc.warrant_id === "string" ? prDoc.warrant_id : null,
    pr: prDoc.pr ?? null,
    delta_phi:
      Number.isSafeInteger(prDoc.phi?.delta_phi) ? prDoc.phi.delta_phi : null,
    checks: verdict.checks,
  };
  if (Array.isArray(verdict.flags) && verdict.flags.length > 0) {
    out.flags = verdict.flags;
  }

  if (flags.sign === true) {
    const mirqlDir = resolveMirqlDir(
      typeof flags.dir === "string" ? flags.dir : undefined,
    );
    const signOptions = {};
    if (typeof flags.key === "string" && flags.key.length > 0) {
      signOptions.keyPath = flags.key;
    }
    const result = signAndAppendVerdict(mirqlDir, out, signOptions);
    out.ledger = {
      dir: mirqlDir,
      status: result.status,
      type: result.type,
      seq: result.seq,
      hash: result.hash,
      event_id: result.event.id,
      writer: result.event.writer,
    };
  }

  emitLine(jcs(out));
  return verdict.verdict === "auto_merge"
    ? EXIT_CODES.OK
    : EXIT_CODES.DOMAIN_NEGATIVE;
}

/**
 * Full CLI dispatch (mirql m <subcommand>). JSON results on stdout; JSON
 * errors on stderr; exit codes are the canonical EXIT_CODES.
 *
 * @param {string[]} argv arguments after the tool name
 * @returns {number} process exit code
 */
export function runCli(argv = []) {
  try {
    const { positional, flags } = parseArgs(argv);
    const sub = positional[0];
    if (sub === undefined || sub === "status") return emitStubContract();
    if (flags.help === true || sub === "help") return emitUsage();

    switch (sub) {
      case "check":
        return cliCheck(flags);
      default:
        process.stderr.write(
          jcs({
            tool: TOOL,
            error: "USAGE_ERROR",
            reason: `unknown subcommand ${JSON.stringify(sub)}; expected one of ${SUBCOMMANDS.join(", ")}`,
          }) + "\n",
        );
        return EXIT_CODES.USAGE_ERROR;
    }
  } catch (err) {
    if (err instanceof Error && (err.code === "USAGE_ERROR" || err.name === "NotaryError")) {
      const notary = err.name === "NotaryError";
      process.stderr.write(
        jcs({
          tool: TOOL,
          error: notary ? err.code : "USAGE_ERROR",
          reason: err.message,
        }) + "\n",
      );
      return notary ? err.exitCode : EXIT_CODES.USAGE_ERROR;
    }
    throw err;
  }
}

/**
 * CLI entrypoint imported by bin/mirql.mjs. Preserves the W1 stub contract
 * for bare `--help` / `-h` / `status` / no-args calls and delegates every
 * real subcommand to runCli.
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
    return emitStubContract();
  }
  return runCli(argv);
}

export default main;
