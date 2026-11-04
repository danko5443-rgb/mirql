// packages/run/coverage-driver.mjs — out-of-band coverage collector for the git verifier.
//
// The verifier spawns this script with spawnSync and reads exactly one JSON
// line from stdout: {exitCode, signal, timedOut, stdout, stderr, coverage}.
//
// Why a separate process: green-on-head coverage must be measured where the
// candidate cannot reach. NODE_V8_COVERAGE output files (or any other file or
// environment channel) can be forged by the code under test, so this driver
// starts the reproducer under `--inspect-brk` and collects coverage over the
// Node inspector WebSocket instead. NODE_V8_COVERAGE is never set and coverage
// is never read from disk; if no coverage comes back the caller fails closed.
// Each entry carries the hash of its script's real source (bindScriptSources).
//
// `--test` is deliberately NOT used: it forks one child process per test file,
// and those children escape this inspector session, so nothing would be
// measured. The reproducer file is executed directly; --test-reporter=tap
// keeps the same TAP/exit-code contract the verifier applies elsewhere.
//
// Accepted trade-off: a reproducer that does its real work inside a subprocess
// it spawns itself is not measured here, so its changed lines read as
// unexecuted and the attempt is rejected (REPRODUCER_IRRELEVANT or
// UNCOVERED_CHANGE) or, under a non-surgical warrant, held for human review.
// Failing closed on unmeasured work is the safe direction.
//
// The reproducer timeout is enforced here by killing the child.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { constants as osConstants } from "node:os";

const fileArg = process.argv[2];
const cwdArg = process.argv[3];
const timeoutMs = Number(process.argv[4]);
const reproducerTimeoutMs =
  Number.isSafeInteger(timeoutMs) && timeoutMs > 0 ? timeoutMs : 30000;

function report(result) {
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}

if (typeof fileArg !== "string" || !fileArg || typeof cwdArg !== "string" || !cwdArg) {
  report({ exitCode: null, signal: null, timedOut: false, stdout: "", stderr: "usage: coverage-driver.mjs <file> <cwd> [timeoutMs]", coverage: null });
}

// The global WebSocket client exists from Node 22; without it nothing is measured.
if (typeof WebSocket !== "function") {
  report({ exitCode: null, signal: null, timedOut: false, stdout: "", stderr: "coverage-driver.mjs requires Node >= 22 (global WebSocket)", coverage: null });
}

const child = spawn(
  process.execPath,
  ["--inspect-brk=127.0.0.1:0", "--test-reporter=tap", resolve(cwdArg, fileArg)],
  { cwd: cwdArg, stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
);

let stdout = "";
let stderr = "";
let ws = null;
let messageId = 0;
let coverage = null;
let timedOut = false;
const pending = new Map();

const send = (method, params = {}) =>
  new Promise((resolvePromise) => {
    const id = ++messageId;
    pending.set(id, resolvePromise);
    ws.send(JSON.stringify({ id, method, params }));
  });

// A script chooses its own reported URL (a sourceURL directive, vm's filename
// option), so the URL proves nothing. Hash what V8 actually compiled; the
// verifier compares it to the commit's blob. An unavailable source leaves the
// entry without a hash, which never counts as coverage.
async function bindScriptSources(result) {
  for (const entry of Array.isArray(result?.result) ? result.result : []) {
    if (typeof entry.url !== "string" || !entry.url.startsWith("file:")) continue;
    const script = await send("Debugger.getScriptSource", { scriptId: entry.scriptId });
    if (typeof script?.scriptSource === "string") {
      entry.sourceHash = createHash("sha256").update(script.scriptSource).digest("hex");
    }
  }
}

const timeout = setTimeout(() => {
  timedOut = true;
  child.kill();
}, reproducerTimeoutMs);

child.stdout.on("data", (chunk) => { stdout += chunk; });
child.stderr.on("data", (chunk) => {
  stderr += chunk;
  const address = /ws:\/\/\S+/.exec(stderr);
  if (address && ws === null) {
    ws = new WebSocket(address[0]);
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.id && pending.has(message.id)) {
        pending.get(message.id)(message.result ?? message.error);
        pending.delete(message.id);
      }
    };
    ws.onopen = async () => {
      await send("Profiler.enable");
      await send("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
      await send("Runtime.enable");
      // Sources are retrievable only for scripts compiled while the debugger was
      // on. Pauses stay off, so `debugger;` in the candidate cannot stall the run.
      await send("Debugger.enable");
      await send("Debugger.setSkipAllPauses", { skip: true });
      send("Runtime.runIfWaitingForDebugger");
    };
  }
  // The child finished its work and is only held alive by this session.
  if (/Waiting for the debugger to disconnect/.test(stderr) && coverage === null) {
    coverage = "pending";
    send("Profiler.takePreciseCoverage").then(async (result) => {
      await bindScriptSources(result);
      coverage = result;
      ws.close();
    });
  }
});

child.on("exit", (code, signal) => {
  clearTimeout(timeout);
  // Coverage entries that are not workspace files never participate in checks.
  const entries = Array.isArray(coverage?.result)
    ? coverage.result.filter((entry) => typeof entry.url === "string" && entry.url.startsWith("file:"))
    : null;
  report({
    exitCode: signal ? 128 + (osConstants.signals[signal] ?? 1) : code,
    signal: signal ?? null,
    timedOut,
    stdout,
    stderr,
    coverage: entries,
  });
});
