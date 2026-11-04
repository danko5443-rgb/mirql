// tests/phase5-6-completion.test.mjs — Phase 5 (sandbox isolation & gating,
// Law 8) and Phase 6 (canonical ledger primitives, O(1) head sidecar, MP-003
// self-check, docs/STATUS.md).
//
// Every test runs against an isolated temporary HOME/USERPROFILE and
// MIRQL_TRUST_ROOT so the real ~/.mirql-trust is never touched.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { git } from "./helpers/git.mjs";
import { provisionTestTrust, saveTestKeyring } from "./helpers/keyring.mjs";

import { EXIT_CODES, checkSwallowedExceptions, generateEd25519Keypair } from "../packages/core/index.mjs";
import {
  GENESIS_PREV_HASH,
  readLedgerHeadSidecar,
  verifyChainBeforeAppend,
} from "../packages/core/ledger-verify.mjs";
import { runAgent, buildContainerArgs } from "../packages/run/agent.mjs";
import { verifyAttempt } from "../packages/run/verify.mjs";
import { appendEvent } from "../packages/log/index.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "../packages/run/ledger.mjs";
import { appendLedgerEventRaw } from "../packages/queue/ledger.mjs";
import { foldQueueState } from "../packages/core/index.mjs";
import { signAndAppendVerdict } from "../packages/mergeproof/notary.mjs";
import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

// ---------------------------------------------------------------------------
// Isolated environment (never touch the real ~/.mirql-trust)
// ---------------------------------------------------------------------------

let envRoot;
const savedEnv = {};

before(() => {
  envRoot = mkdtempSync(join(tmpdir(), "mirql-phase56-env-"));
  for (const key of ["MIRQL_TRUST_ROOT", "HOME", "USERPROFILE"]) {
    savedEnv[key] = process.env[key];
  }
  process.env.MIRQL_TRUST_ROOT = join(envRoot, "trust");
  process.env.HOME = envRoot;
  process.env.USERPROFILE = envRoot;
});

after(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(envRoot, { recursive: true, force: true });
});

/** A git workspace with one commit, mirroring tests/worker-postrun.test.mjs. */
function makeWorkspace(parent) {
  const workspace = join(parent, "workspace");
  mkdirSync(join(workspace, "policy"), { recursive: true });
  git(workspace, "init", "-q");
  git(workspace, "config", "user.name", "test");
  git(workspace, "config", "user.email", "test@mirql.local");
  git(workspace, "config", "core.autocrlf", "false");
  writeFileSync(join(workspace, "policy", "guard.json"), "base\n");
  writeFileSync(join(workspace, "code.mjs"), "export const value=1;\n");
  git(workspace, "add", "-A");
  git(workspace, "commit", "-q", "-m", "base");
  // Ledger state must never be staged into a container.
  mkdirSync(join(workspace, ".mirql"), { recursive: true });
  writeFileSync(join(workspace, ".mirql", "secret.txt"), "ledger internals\n");
  return workspace;
}

// ---------------------------------------------------------------------------
// Phase 5 — sandbox isolation & gating (Law 8)
// ---------------------------------------------------------------------------

test("runAgent defaults to sandbox: \"none\" and reports it on the result", () => {
  const res = runAgent({ modifiedFiles: [] });
  assert.equal(res.ok, true);
  assert.equal(res.sandbox, "none");
});

test("buildContainerArgs produces the hardened Law 8 argument vector", () => {
  const args = buildContainerArgs({
    runtime: "docker",
    image: "img:1",
    workdir: "C:\\stage",
    command: "true",
    env: { FOO: "bar" },
  });
  assert.equal(args[0], "run");
  assert.equal(args[1], "--rm");
  const networkIndex = args.indexOf("--network");
  assert.equal(args[networkIndex + 1], "none");
  assert.ok(args.includes("--read-only"));
  const capIndex = args.indexOf("--cap-drop");
  assert.equal(args[capIndex + 1], "ALL");
  const secIndex = args.indexOf("--security-opt");
  assert.equal(args[secIndex + 1], "no-new-privileges:true");
  const userIndex = args.indexOf("--user");
  assert.equal(args[userIndex + 1], "65534:65534");
  const vIndex = args.indexOf("-v");
  assert.equal(args[vIndex + 1], "C:\\stage:/workspace:rw");
  const wIndex = args.indexOf("-w");
  assert.equal(args[wIndex + 1], "/workspace");
  const envIndex = args.indexOf("--env");
  assert.equal(args[envIndex + 1], "FOO=bar");
  assert.equal(args[args.indexOf("FOO=bar") + 1], "img:1");
  assert.equal(args[args.indexOf("img:1") + 1], "sh");
  assert.equal(args[args.indexOf("img:1") + 2], "-c");
  assert.equal(args.at(-1), "true");
});

test("runAgent({ sandbox: \"docker\" }) stages the workspace isolated and syncs container edits back", () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-docker-"));
  try {
    const workspace = makeWorkspace(parent);
    const binDir = join(parent, "mock-bin");
    mkdirSync(binDir, { recursive: true });
    const argsFile = join(parent, "mock-args.json");

    // A mock `docker` executable: records its argv, proves the staging
    // directory excludes .mirql, and edits a file "inside the container".
    const mockSrc = join(binDir, "docker-mock.mjs");
    writeFileSync(mockSrc, [
      'import { writeFileSync, readdirSync, statSync } from "node:fs";',
      'import { join, relative } from "node:path";',
      'const args = process.argv.slice(2);',
      'const vIndex = args.indexOf("-v");',
      'const mount = vIndex !== -1 ? args[vIndex + 1] : null;',
      'const staged = mount ? mount.slice(0, mount.lastIndexOf(":/workspace")) : null;',
      'const walk = (dir, base = dir, acc = []) => {',
      '  for (const entry of readdirSync(dir)) {',
      '    const full = join(dir, entry);',
      '    if (statSync(full).isDirectory()) walk(full, base, acc);',
      '    else acc.push(relative(base, full).replace(/\\\\/g, "/"));',
      '  }',
      '  return acc;',
      '};',
      'const stagedFiles = staged ? walk(staged).sort() : [];',
      'if (staged) writeFileSync(join(staged, "container-edit.txt"), "edited inside the sandbox\\n");',
      'writeFileSync(process.env.MIRQL_MOCK_OUT, JSON.stringify({ args, stagedFiles }, null, 2) + "\\n");',
      'process.exit(0);',
    ].join("\n"));
    if (process.platform === "win32") {
      writeFileSync(join(binDir, "docker.cmd"), `@node "${mockSrc}" %*\r\n`);
    } else {
      writeFileSync(join(binDir, "docker"), `#!/bin/sh\nexec node "${mockSrc}" "$@"\n`);
      chmodSync(join(binDir, "docker"), 0o755);
    }

    const res = runAgent({
      sandbox: "docker",
      image: "mirql-agent-mock:latest",
      cwd: workspace,
      command: "true",
      env: {
        PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}`,
        MIRQL_MOCK_OUT: argsFile,
      },
      allowedEnv: ["MIRQL_MOCK_OUT"],
    });

    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.sandbox, "docker");

    const report = JSON.parse(readFileSync(argsFile, "utf8"));
    // Hardened flags reached the runtime.
    assert.equal(report.args[report.args.indexOf("--network") + 1], "none");
    assert.ok(report.args.includes("--read-only"));
    assert.equal(report.args[report.args.indexOf("--cap-drop") + 1], "ALL");
    assert.equal(report.args[report.args.indexOf("--security-opt") + 1], "no-new-privileges:true");
    assert.equal(report.args[report.args.indexOf("--user") + 1], "65534:65534");
    assert.ok(report.args.includes("mirql-agent-mock:latest"));
    // The staged workspace contains working files but never .mirql.
    assert.ok(report.stagedFiles.includes("code.mjs"));
    assert.ok(report.stagedFiles.some((f) => f.startsWith("policy/")));
    assert.ok(!report.stagedFiles.some((f) => f.startsWith(".mirql")));
    // The container's edit was synced back into the real workspace.
    assert.equal(
      readFileSync(join(workspace, "container-edit.txt"), "utf8"),
      "edited inside the sandbox\n",
    );
    assert.ok(res.changedFiles.includes("container-edit.txt"));
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("runAgent fails closed with SANDBOX_UNAVAILABLE when the runtime binary is missing", () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-missing-"));
  try {
    const workspace = makeWorkspace(parent);
    const emptyBin = join(parent, "empty-bin");
    mkdirSync(emptyBin, { recursive: true });
    const res = runAgent({
      sandbox: "podman", // no mock, no real podman on PATH
      cwd: workspace,
      command: "true",
      env: { PATH: emptyBin },
    });
    assert.equal(res.ok, false);
    assert.equal(res.exitCode, EXIT_CODES.POLICY_DENIAL);
    assert.equal(res.violation, "SANDBOX_UNAVAILABLE");
    assert.equal(res.rule, "MP-001");
    assert.equal(res.sandbox, "podman");
    assert.ok(Array.isArray(res.strippedEnv));
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

const RUN_CHECK_STEPS = {
  red_on_base: { exitCode: 1 },
  green_on_head: { exitCode: 0 },
  re_red_on_revert: { exitCode: 1 },
};
const runCheck = ({ stage }) => RUN_CHECK_STEPS[stage];

test("verifyAttempt: sandbox \"none\" and requireSandbox never yield auto_merge (Law 8)", () => {
  // Control: without sandbox options the measured cycle still auto-merges.
  const control = verifyAttempt({ runCheck });
  assert.equal(control.verdict, "auto_merge");
  assert.equal(control.verified, true);

  const none = verifyAttempt({ runCheck, sandbox: "none" });
  assert.equal(none.verdict, "needs_human");
  assert.equal(none.rule, "UNSANDBOXED_EXECUTION");
  assert.equal(none.violation, "SANDBOX_NONE");
  assert.equal(none.verified, false);
  assert.match(none.detail, /sandbox: "none"/);

  const required = verifyAttempt({ runCheck, requireSandbox: true });
  assert.equal(required.verdict, "needs_human");
  assert.equal(required.rule, "UNSANDBOXED_EXECUTION");

  // A container runtime satisfies the requirement.
  const sandboxed = verifyAttempt({ runCheck, sandbox: "docker" });
  assert.equal(sandboxed.verdict, "auto_merge");
});

test("evaluatePullRequest caps passing verdicts at needs_human under sandbox \"none\"", () => {
  const goodDoc = {
    pr: { kind: "feature", author: "builder" },
    diff_stat: { files_changed: ["src/a.mjs"] },
    phi: { delta_phi: 0 },
    proof: { causal_cycle_completed: true },
  };
  const control = evaluatePullRequest(goodDoc, { rootDir: ROOT });
  assert.equal(control.verdict, "conformance_pass");

  const viaDoc = evaluatePullRequest({ ...goodDoc, sandbox: "none" }, { rootDir: ROOT });
  assert.equal(viaDoc.verdict, "needs_human");
  assert.equal(viaDoc.rule, "UNSANDBOXED_EXECUTION");
  assert.equal(viaDoc.violation, "SANDBOX_NONE");
  assert.ok(viaDoc.flags.includes("UNSANDBOXED_EXECUTION"));

  const viaEvidence = evaluatePullRequest(
    { ...goodDoc, evidence: { sandbox: "none" } },
    { rootDir: ROOT },
  );
  assert.equal(viaEvidence.verdict, "needs_human");
  assert.equal(viaEvidence.rule, "UNSANDBOXED_EXECUTION");
});

// ---------------------------------------------------------------------------
// Phase 6.1 & 6.2 — O(1) verified head sidecar & pre-append verification
// ---------------------------------------------------------------------------

test("appendEvent (log) writes and updates the head.json sidecar", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-head-log-"));
  try {
    const kp = generateEd25519Keypair();
    const first = appendEvent(
      dir,
      { type: "mirql.genesis", writer: "human:owner", payload: { macro_state: "run" } },
      { signingKey: kp.privateKey, nowMs: 1000 },
    );
    assert.equal(first.status, "appended");
    assert.ok(existsSync(join(dir, "ledger", "head.json")));
    let head = readLedgerHeadSidecar(dir);
    assert.equal(head.valid, true);
    assert.equal(head.seq, 1);
    assert.equal(head.hash, first.hash);

    const second = appendEvent(
      dir,
      {
        type: "mirql.genesis",
        writer: "human:owner",
        idempotency_key: "genesis-2",
        payload: { macro_state: "run" },
      },
      { signingKey: kp.privateKey, nowMs: 2000 },
    );
    assert.equal(second.status, "appended");
    head = readLedgerHeadSidecar(dir);
    assert.equal(head.valid, true);
    assert.equal(head.seq, 2);
    assert.equal(head.hash, second.hash);
    assert.equal(typeof head.lastEvent.sig, "string");
    assert.ok(head.lastEvent.sig.length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("appendSupervisorEvent (run) writes the sidecar and verifies the chain before appending", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-head-run-"));
  try {
    provisionTestTrust(dir);
    const kp = getOrGenerateSupervisorKey(dir);
    const ev = appendSupervisorEvent(
      dir,
      { type: "probe.completed", payload: { probe: "unit", status: "pass", duration_ms: 10 }, nowMs: 1000 },
      kp,
    );
    const head = readLedgerHeadSidecar(dir);
    assert.equal(head.valid, true);
    assert.equal(head.seq, 1);
    assert.equal(head.hash, ev.hash);
    assert.equal(head.lastEvent.sig, ev.sig);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("appendLedgerEventRaw (queue) writes the head.json sidecar", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-head-queue-"));
  try {
    provisionTestTrust(dir);
    const kp = generateEd25519Keypair();
    saveTestKeyring(dir, { "notary:mergeproof": kp.publicKey });
    const ev = appendLedgerEventRaw(
      dir,
      { type: "verdict.accepted", payload: { job_id: "job-1", status: "accepted" }, nowMs: 1000 },
      { ...kp, writer: { ns: "notary:mergeproof" } },
      foldQueueState(dir),
    );
    const head = readLedgerHeadSidecar(dir);
    assert.equal(head.valid, true);
    assert.equal(head.seq, 1);
    assert.equal(head.hash, ev.hash);
    assert.equal(head.lastEvent.sig, ev.sig);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("signAndAppendVerdict (mergeproof notary) writes the head.json sidecar", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-head-notary-"));
  try {
    provisionTestTrust(dir);
    const result = signAndAppendVerdict(dir, {
      verdict: "auto_merge",
      rule: "MP-000",
      violation: null,
      job_id: "job-n-1",
      warrant_id: "w-1",
      pr: {
        number: 7,
        kind: "feature",
        head_sha: "a".repeat(40),
        base_sha: "b".repeat(40),
      },
      delta_phi: 0,
    });
    assert.equal(result.status, "appended");
    const head = readLedgerHeadSidecar(dir);
    assert.equal(head.valid, true);
    assert.equal(head.seq, 1);
    assert.equal(head.hash, result.hash);
    assert.equal(head.lastEvent.sig, result.event.sig);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readLedgerHeadSidecar fails closed on a tampered or out-of-sync head.json", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-head-tamper-"));
  try {
    const kp = generateEd25519Keypair();
    appendEvent(
      dir,
      { type: "mirql.genesis", writer: "human:owner", payload: { macro_state: "run" } },
      { signingKey: kp.privateKey, nowMs: 1000 },
    );
    appendEvent(
      dir,
      {
        type: "mirql.genesis",
        writer: "human:owner",
        idempotency_key: "genesis-2",
        payload: { macro_state: "run" },
      },
      { signingKey: kp.privateKey, nowMs: 2000 },
    );
    assert.equal(readLedgerHeadSidecar(dir).valid, true);

    const headPath = join(dir, "ledger", "head.json");

    // Tampered seq: out of sync with events.jsonl.
    const head = JSON.parse(readFileSync(headPath, "utf8"));
    writeFileSync(headPath, JSON.stringify({ ...head, seq: 9 }) + "\n");
    assert.equal(readLedgerHeadSidecar(dir).valid, false);

    // Stale head: restored head no longer matches the (longer) events file.
    writeFileSync(headPath, JSON.stringify(head) + "\n");
    appendEvent(
      dir,
      {
        type: "mirql.genesis",
        writer: "human:owner",
        idempotency_key: "genesis-3",
        payload: { macro_state: "run" },
      },
      { signingKey: kp.privateKey, nowMs: 3000 },
    );
    // The append itself rebuilt the sidecar, so it is valid again.
    const fresh = readLedgerHeadSidecar(dir);
    assert.equal(fresh.valid, true);
    assert.equal(fresh.seq, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verifyChainBeforeAppend returns the genesis anchor for an empty ledger", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-chain-empty-"));
  try {
    const chain = verifyChainBeforeAppend(dir);
    assert.equal(chain.seq, 0);
    assert.equal(chain.prevHash, GENESIS_PREV_HASH);
    assert.equal(chain.lastEvent, null);
    assert.deepEqual(chain.events, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a corrupted hash chain fails closed before appending even when head.json is deleted", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-chain-corrupt-"));
  try {
    provisionTestTrust(dir);
    const kp = getOrGenerateSupervisorKey(dir);
    appendSupervisorEvent(
      dir,
      { type: "probe.completed", payload: { probe: "unit", status: "pass", duration_ms: 10 }, nowMs: 1000 },
      kp,
    );
    appendSupervisorEvent(
      dir,
      {
        type: "probe.completed",
        idempotency_key: "probe-2",
        payload: { probe: "unit", status: "pass", duration_ms: 11 },
        nowMs: 2000,
      },
      kp,
    );

    const eventsPath = join(dir, "ledger", "events.jsonl");
    const lines = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean);

    // prev_hash corruption on the second event, sidecar deleted.
    const first = JSON.parse(lines[0]);
    const second = JSON.parse(lines[1]);
    second.prev_hash = GENESIS_PREV_HASH; // forged linkage
    rmSync(join(dir, "ledger", "head.json"), { force: true });
    writeFileSync(eventsPath, [lines[0], JSON.stringify(second)].join("\n") + "\n");
    void first;

    assert.throws(
      () =>
        appendSupervisorEvent(
          dir,
          {
            type: "probe.completed",
            idempotency_key: "probe-3",
            payload: { probe: "unit", status: "pass", duration_ms: 12 },
            nowMs: 3000,
          },
          kp,
        ),
      (error) => error.code === "INTEGRITY_VIOLATION",
    );
    // Nothing was appended: the ledger still has exactly two events.
    const after = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean);
    assert.equal(after.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a sequence gap fails closed before appending even when head.json is deleted", () => {
  const dir = mkdtempSync(join(tmpdir(), "mirql-chain-gap-"));
  try {
    provisionTestTrust(dir);
    const kp = getOrGenerateSupervisorKey(dir);
    appendSupervisorEvent(
      dir,
      { type: "probe.completed", payload: { probe: "unit", status: "pass", duration_ms: 10 }, nowMs: 1000 },
      kp,
    );
    appendSupervisorEvent(
      dir,
      {
        type: "probe.completed",
        idempotency_key: "probe-2",
        payload: { probe: "unit", status: "pass", duration_ms: 11 },
        nowMs: 2000,
      },
      kp,
    );

    const eventsPath = join(dir, "ledger", "events.jsonl");
    const lines = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean);
    // Delete the first line: the remaining tail has seq 2 at position 1.
    rmSync(join(dir, "ledger", "head.json"), { force: true });
    writeFileSync(eventsPath, lines.slice(1).join("\n") + "\n");

    assert.throws(
      () =>
        appendSupervisorEvent(
          dir,
          {
            type: "probe.completed",
            idempotency_key: "probe-3",
            payload: { probe: "unit", status: "pass", duration_ms: 12 },
            nowMs: 3000,
          },
          kp,
        ),
      (error) => error.code === "INTEGRITY_VIOLATION",
    );
    const after = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean);
    assert.equal(after.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Phase 6.4 & 6.7 — MP-003 self-check & docs/STATUS.md
// ---------------------------------------------------------------------------

const MP003_FILES = [
  "packages/run/agent.mjs",
  "packages/run/verify.mjs",
  "packages/mergeproof/evaluator.mjs",
  "packages/core/ledger-verify.mjs",
  "packages/core/anti-cheat.mjs",
  "packages/log/index.mjs",
  "packages/run/ledger.mjs",
  "packages/queue/ledger.mjs",
  "packages/mergeproof/notary.mjs",
];

test("MP-003: every file touched by Phase 5-6 has zero swallowed exceptions", () => {
  for (const rel of MP003_FILES) {
    const source = readFileSync(join(ROOT, rel), "utf8");
    const result = checkSwallowedExceptions(source, rel);
    assert.deepEqual(
      result.violations,
      [],
      `${rel} must not swallow exceptions (MP-003): ${JSON.stringify(result.violations, null, 2)}`,
    );
    assert.equal(result.ok, true, rel);
  }
});

test("docs/STATUS.md exists and documents Laws 1-17 and all five tools", () => {
  const statusPath = join(ROOT, "docs", "STATUS.md");
  assert.ok(existsSync(statusPath), "docs/STATUS.md must exist");
  const text = readFileSync(statusPath, "utf8");
  for (let law = 1; law <= 17; law += 1) {
    assert.ok(text.includes(`Law ${law}`), `docs/STATUS.md must document Law ${law}`);
  }
  for (const tool of ["mergeproof", "inbox", "run", "queue", "log"]) {
    assert.ok(text.includes(tool), `docs/STATUS.md must document the ${tool} tool`);
  }
});
