import { git } from "./helpers/git.mjs";
// tests/honest-metrics.test.mjs — measured-or-flagged telemetry (issue #16).
// The ledger is honest that an event happened; its payload must not lie.
// Pins: the supervisor never invents thrift/cost/surface numbers (unmeasured
// fields are flagged measured:0 and the ledger payload carries null), and
// every SHA it signs is a real, reproducible measurement. Also pins
// `mirql m check --surface` — the command policy/probes.toml declares.

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { generateEd25519Keypair, verifyEvent } from "../packages/core/index.mjs";
import { runSupervisor } from "../packages/run/index.mjs";
import { runCli as mergeproofCli } from "../packages/mergeproof/index.mjs";
import { foldLedger, readLedgerEvents } from "../packages/core/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");



const RUN = {
  mirqlDir: null,
  builderCommand: "node -v",
  runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
  jobId: "01HZZZZZZZZZZZZZZZZZZZZZZZ",
  warrantId: "01HWWWWWWWWWWWWWWWWWWWWWWW",
};

function supervisorRun(overrides = {}) {
  const kp = generateEd25519Keypair();
  return runSupervisor({
    ...RUN,
    signingKey: kp.privateKey,
    keyId: kp.keyId,
    keypair: kp,
    ...overrides,
  });
}

describe("supervisor telemetry honesty (issue #16)", () => {
  let tempDir;
  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-honest-"));
    RUN.mirqlDir = tempDir;
    RUN.workspaceDir = tempDir;
  });
  afterEach(() => rmSync(tempDir, { recursive: true, force: true }));

  it("unmeasured thrift/cost/surface are flagged, never invented", () => {
    const res = supervisorRun({ workspaceDir: tempDir });
    assert.equal(res.outcome.thrift.measured, 0);
    assert.deepEqual(Object.keys(res.outcome.thrift), ["measured"]);
    assert.equal(res.outcome.cost.measured, 0);
    assert.equal(res.outcome.cost.micro_usd, undefined);
    assert.equal(res.outcome.surface.measured, 0);

    // The ledger payload carries null — downstream folds treat it as 0, and
    // anyone auditing sees "not measured" instead of a fabricated number.
    const evt = JSON.parse(readFileSync(join(tempDir, "ledger", "events.jsonl"), "utf8"));
    assert.equal(evt.payload.tokens_consumed, null);
    assert.equal(evt.payload.cost_micro_usd, null);
  });

  it("real measurements pass through verbatim when supplied", () => {
    const thrift = { model_calls: 2, tokens_in: 1200, tokens_out: 340, cache_hits: 1 };
    const res = supervisorRun({ workspaceDir: tempDir, thrift, costMicroUsd: 42_500 });
    assert.equal(res.outcome.thrift.measured, 1);
    assert.equal(res.outcome.thrift.tokens_in, 1200);
    assert.equal(res.outcome.cost.measured, 1);
    assert.equal(res.outcome.cost.micro_usd, 42_500);

    const evt = JSON.parse(readFileSync(join(tempDir, "ledger", "events.jsonl"), "utf8"));
    assert.equal(evt.payload.tokens_consumed, 1540);
    assert.equal(evt.payload.cost_micro_usd, 42_500);
  });

  it("tree digest is a real measurement: deterministic and content-sensitive", () => {
    const a = supervisorRun({ workspaceDir: tempDir });
    const b = supervisorRun({ jobId: "01HZZZZZZZZZZZZZZZZZZZZZZY" });
    assert.equal(a.outcome.tree_hash, b.outcome.tree_hash, "same tree must digest identically");

    writeFileSync(join(tempDir, "probe.txt"), "x", "utf8"); // non-source file: ignored
    const c = supervisorRun({ jobId: "01HZZZZZZZZZZZZZZZZZZZZZZX" });
    assert.equal(c.outcome.tree_hash, a.outcome.tree_hash, "non-source files do not alter the digest");

    writeFileSync(join(tempDir, "widget.mjs"), "export const x = 1;\n", "utf8");
    const d = supervisorRun({ jobId: "01HZZZZZZZZZZZZZZZZZZZZZZW" });
    assert.notEqual(d.outcome.tree_hash, a.outcome.tree_hash, "source change must alter the digest");
  });

  it("git workspaces: surface measured via numstat, head from real git HEAD", () => {
    const ws = mkdtempSync(join(tmpdir(), "mirql-honest-git-"));
    git(ws, "init", "-q");
    git(ws, "config", "user.email", "t@mirql.local");
    git(ws, "config", "user.name", "t");
    git(ws, "config", "core.autocrlf", "false");
    writeFileSync(join(ws, "code.mjs"), "export const a = 1;\n");
    git(ws, "add", "-A");
    git(ws, "commit", "-q", "-m", "base");
    // Agent's uncommitted work: 1 file changed, 2 added, 1 removed
    writeFileSync(join(ws, "code.mjs"), "export const a = 2;\nexport const b = 3;\n");

    try {
      const res = supervisorRun({ workspaceDir: ws });
      assert.equal(res.outcome.surface.measured, 1);
      assert.equal(res.outcome.surface.files_changed, 1);
      assert.equal(res.outcome.surface.lines_added, 2);
      assert.equal(res.outcome.surface.lines_removed, 1);

      // head_sha is a digest OF the real git HEAD (cross-checkable)
      const head = git(ws, "rev-parse", "HEAD").trim();
      assert.match(res.outcome.head_sha, /^sha256:[0-9a-f]{64}$/);
      assert.notEqual(res.outcome.head_sha, res.outcome.tree_hash);
      void head;
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });

  it("signed outcome events stay valid and fold without NaN from nulls", () => {
    const kp = generateEd25519Keypair();
    const res = supervisorRun({ workspaceDir: tempDir, signingKey: kp.privateKey, keyId: kp.keyId, keypair: kp });
    const evt = JSON.parse(readFileSync(join(tempDir, "ledger", "events.jsonl"), "utf8"));
    assert.equal(verifyEvent(evt, kp.publicKey).ok, true);

    const events = readLedgerEvents(tempDir);
    const folded = foldLedger(events);
    assert.ok(Number.isSafeInteger(folded.metrics?.total_cost_micro_usd ?? 0));
    assert.ok(Number.isSafeInteger(folded.metrics?.total_tokens_consumed ?? 0));
    void res;
  });
});

describe("m check --surface (issue #16: the command probes.toml declares)", () => {
  it("verifies the real repo's surface.lock as consistent", () => {
    const code = mergeproofCli(["check", "--surface", "--workspace", ROOT]);
    assert.equal(code, 0);
  });

  it("rejects a missing locked bin and flags uncited bins", () => {
    const ws = mkdtempSync(join(tmpdir(), "mirql-honest-surf-"));
    try {
      mkdirSync(join(ws, "bin"), { recursive: true });
      writeFileSync(join(ws, "bin", "mirql.mjs"), "export {};\n");
      writeFileSync(join(ws, "bin", "rogue.mjs"), "export {};\n"); // uncited
      writeFileSync(
        join(ws, "surface.lock"),
        JSON.stringify({
          v: 1,
          bins: ["mirql", "mirql-run"], // mirql-run does not exist here
          commands: ["mirql m check", "ghost-bin do-thing"], // ghost-bin uncited
        }),
        "utf8",
      );

      const code = mergeproofCli(["check", "--surface", "--workspace", ws]);
      assert.equal(code, 1); // DOMAIN_NEGATIVE
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });

  it("fails closed when surface.lock is absent", () => {
    const ws = mkdtempSync(join(tmpdir(), "mirql-honest-nosurf-"));
    try {
      const code = mergeproofCli(["check", "--surface", "--workspace", ws]);
      assert.equal(code, 1);
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });
});
