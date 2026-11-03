// tests/factory-daemon.test.mjs — the 24/7 loop composition (M1 reactive
// daemon exposed through `r supervisor --daemon`). Unit coverage injects the
// queue like the bin composition root does; the e2e test spawns the real bin.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { ulid, sha256 } from "../packages/core/index.mjs";
import { leaseNextJob, submitWarrant } from "../packages/queue/index.mjs";
import { startFactoryDaemon } from "../packages/run/index.mjs";
import { authorizeTestWarrant } from "./helpers/warrant.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

function makeValidWarrant(overrides = {}) {
  const nowMs = Date.now();
  return {
    v: 1,
    id: ulid(nowMs),
    class: "bugfix",
    semantic_fingerprint: sha256(`daemon intent ${Math.random()}`),
    anchors: ["ROADMAP.md"],
    evidence: { issue_id: "ISSUE-DAEMON-001", reproducer_test: "tests/m1-repro.test.mjs" },
    red_check: { exit_code: 1, stdout: "", stderr: "Expected failure on base" },
    scope: { paths: ["packages/core/watcher.mjs"], max_files: 5, max_loc_delta: 200 },
    budget_micro_usd: 1_500_000,
    created_by: "human:owner",
    ...overrides,
  };
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`timeout after ${ms}ms: ${label}`)), ms).unref()),
  ]);
}

describe("factory daemon (r supervisor --daemon)", () => {
  let tmp, ledger, workspace;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "mirql-daemon-"));
    ledger = join(tmp, "ledger");
    workspace = join(tmp, "workspace");
    mkdirSync(workspace, { recursive: true });
    process.env.MIRQL_TRUST_ROOT = join(tmp, "trust");
  });

  afterEach(() => {
    try { rmSync(tmp, { recursive: true, force: true }); } catch {}
    delete process.env.MIRQL_TRUST_ROOT;
  });

  it("shutdown handlers cover the initial lease and are removed on stop", async () => {
    const before = process.listenerCount("SIGTERM");
    let checked = false;
    const daemon = await startFactoryDaemon({
      dir: ledger,
      leaseJob: async () => {
        assert.equal(process.listenerCount("SIGTERM"), before + 1);
        checked = true;
        process.emit("SIGTERM");
        return { ok: false, status: "empty" };
      },
    });
    try {
      assert.equal(checked, true);
      await withTimeout(daemon.done, 1000, "shutdown during startup");
      assert.equal(existsSync(join(ledger, "state", "launcher.pid")), false);
      assert.equal(process.listenerCount("SIGTERM"), before);
    } finally { daemon.stop(); }
  });

  it("the router honors the target workspace's zero daily budget", async () => {
    mkdirSync(join(workspace, "policy"));
    writeFileSync(join(workspace, "policy", "mirql.json"), JSON.stringify({ daily_budget_micro_usd: 0 }));
    const warrant = authorizeTestWarrant(ledger, makeValidWarrant());
    submitWarrant(ledger, warrant, { repoRoot: ROOT });
    const child = spawn(process.execPath, [join(ROOT, "bin", "mirql.mjs"), "r", "supervisor",
      "--daemon", "--max-steps", "1", "--dir", ledger, "--workspace", workspace],
      { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env } });
    let stderr = "";
    child.stderr.on("data", c => { stderr += c; });
    try {
      await new Promise(resolve => setTimeout(resolve, 2000));
      assert.equal(child.exitCode, null, stderr);
      const events = readFileSync(join(ledger, "ledger", "events.jsonl"), "utf8");
      assert.equal(events.includes('"job.leased"'), false, events);
      assert.equal(events.includes('"attempt.outcome"'), false, events);
    } finally {
      child.kill();
      if (child.exitCode === null) await new Promise(resolve => child.once("exit", resolve));
    }
  });

  it("unit: drains one leased job via injected queue wiring and stops at maxSteps", async () => {
    const warrant = authorizeTestWarrant(ledger, makeValidWarrant());
    submitWarrant(ledger, warrant, { repoRoot: ROOT });

    const daemon = await startFactoryDaemon({
      dir: ledger,
      workspaceDir: workspace,
      builderCommand: "node -e 0",
      maxSteps: 1,
      handleSignals: false,
      heartbeatMs: 50,
      leaseJob: (dir2) => leaseNextJob(dir2, { repoRoot: ROOT }),
      getWarrant: (id) => JSON.parse(readFileSync(join(ledger, "warrants", `${id}.json`), "utf8")),
    });

    await withTimeout(daemon.done, 30_000, "daemon did not drain the leased job");
    assert.equal(daemon.getStepsExecuted() >= 1, true);
    // launcher lifecycle: pid removed on stop, heartbeat written by the daemon
    assert.equal(existsSync(join(ledger, "state", "launcher.pid")), false);
    assert.equal(existsSync(join(ledger, "state", "heartbeat")), true);
    daemon.stop();
  });

  it("e2e: fresh ledger dir is created and an idle daemon stays alive on it", async () => {
    // Regression (Codex P1): a --dir without ledger/ used to leave the
    // watcher unattached, so the daemon exited 0 immediately.
    const freshLedger = join(tmp, "fresh-ledger");
    const child = spawn(process.execPath, [
      join(ROOT, "bin", "mirql.mjs"), "r", "supervisor",
      "--daemon", "--dir", freshLedger, "--workspace", workspace,
    ], {
      stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, MIRQL_TRUST_ROOT: join(tmp, "trust") },
    });
    let stderr = "";
    child.stderr.on("data", (c) => { stderr += c; });
    try {
      await withTimeout(
        new Promise((res, rej) => {
          child.on("exit", (code) => rej(new Error(`daemon exited early with ${code}; stderr: ${stderr}`)));
          setTimeout(res, 3000);
        }),
        10_000,
        "aliveness probe",
      );
      assert.equal(existsSync(join(freshLedger, "ledger")), true, "ledger dir not created");
      assert.equal(existsSync(join(freshLedger, "state", "launcher.pid")), true);
    } finally {
      child.kill();
    }
  });

  it("e2e: bin composition drains a submitted job, prints the step, exits 0", async () => {
    const warrant = authorizeTestWarrant(ledger, makeValidWarrant());
    submitWarrant(ledger, warrant, { repoRoot: ROOT });

    const child = spawn(process.execPath, [
      join(ROOT, "bin", "mirql.mjs"), "r", "supervisor",
      "--daemon", "--max-steps", "1",
      "--dir", ledger, "--workspace", workspace,
      "--command", "node -e 0",
    ], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, MIRQL_TRUST_ROOT: join(tmp, "trust") },
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => { stdout += c; });
    child.stderr.on("data", (c) => { stderr += c; });

    const code = await withTimeout(new Promise((res) => child.on("exit", res)), 60_000, "bin daemon did not exit");
    assert.equal(code, 0, `daemon exited ${code}; stderr: ${stderr}`);
    assert.match(stdout, /"job_id"/);
    // The supervisor outcome reached the ledger the daemon was watching.
    const events = readFileSync(join(ledger, "ledger", "events.jsonl"), "utf8").trim().split(/\r?\n/);
    assert.ok(events.some((line) => line.includes("attempt.outcome")), "no attempt.outcome appended");
  });
});
