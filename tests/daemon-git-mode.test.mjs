// tests/daemon-git-mode.test.mjs — the daemon accepting and refusing real work.
//
// Every scenario drives the real CLI (genesis, send, submit, daemon, digest)
// against a throwaway repository. HOME is isolated and no real key is touched.

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { runSupervisor } from "../packages/run/supervisor.mjs";
import { FIX, REPRODUCER, WRITE_FIX, initBugRepo } from "./helpers/bug-repo.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BIN = join(ROOT, "bin", "mirql.mjs");
const BLOAT = Array.from({ length: 60 }, (_, i) => `export function extra${i}(x) {\n  if (x > ${i}) return x;\n  return ${i};\n}\n`).join("");

const HEADER = `import { existsSync, mkdirSync, writeFileSync } from "node:fs";\nimport { execSync } from "node:child_process";\n`;

const ENV_KEYS = ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "MIRQL_TRUST_ROOT", "MIRQL_HUMAN_KEY", "MIRQL_HUMAN_PASSPHRASE", "MIRQL_ALLOW_PLAINTEXT_OWNER_KEY", "MIRQL_SUITE_TIMEOUT_MS"];
const savedEnv = {};
let sandbox;
let counter = 0;

before(() => {
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  sandbox = mkdtempSync(join(tmpdir(), "mirql-daemon-git-"));
  process.env.HOME = sandbox;
  process.env.USERPROFILE = sandbox;
  // Throwaway ledgers only: the verifier otherwise refuses a plaintext owner key.
  process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY = "1";
});

after(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

function git(cwd, ...args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}

function mirql(args, cwd) {
  return spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: "utf8", timeout: 300_000, windowsHide: true });
}

function json(result) {
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

/** A repository holding a real bug, plus a genesis-anchored ledger beside it. */
function project() {
  const root = join(sandbox, `p${++counter}`);
  const workspace = join(root, "workspace");
  const mirqlDir = join(root, "ledger");
  const key = join(root, "operator", "owner.key.json");
  mkdirSync(join(root, "operator"), { recursive: true });
  const base = initBugRepo(workspace);
  json(mirql(["i", "genesis", "--dir", mirqlDir, "--human-key-out", key], root));
  return { root, workspace, mirqlDir, key, base };
}

function issue(p, { budget = 10000, reproducer = REPRODUCER } = {}) {
  const sent = json(mirql([
    "i", "send", "--dir", p.mirqlDir, "--key", p.key, "--kind", "bug", "--title", "Fix add",
    "--scope", "src/**,tests/**", "--phi-budget", String(budget),
    ...(reproducer ? ["--reproducer", reproducer] : []),
  ], p.root));
  const file = join(p.mirqlDir, "warrants", `${sent.warrant_id}.json`);
  json(mirql(["q", "submit", "--dir", p.mirqlDir, "--file", file], ROOT));
  return sent.warrant_id;
}

function worker(p, name, body) {
  const path = join(p.root, `${name}.mjs`).replaceAll("\\", "/");
  writeFileSync(path, HEADER + body);
  return `node "${path}"`;
}

function daemon(p, command) {
  const result = mirql(["r", "supervisor", "--daemon", "--max-steps", "1", "--dir", p.mirqlDir, "--workspace", p.workspace, "--command", command], ROOT);
  assert.equal(result.status, 0, `daemon: ${result.stderr}\n${result.stdout}`);
  return result;
}

function outcomes(p) {
  return readFileSync(join(p.mirqlDir, "ledger", "events.jsonl"), "utf8").trim().split(/\r?\n/)
    .map((line) => JSON.parse(line)).filter((event) => event.type === "attempt.outcome").map((event) => event.payload);
}

function digestRules(p) {
  return json(mirql(["i", "digest", "--dir", p.mirqlDir], ROOT)).recent_outcomes.map((outcome) => outcome.rule);
}

function assertWorkspaceUntouched(p) {
  assert.equal(git(p.workspace, "rev-parse", "HEAD"), p.base);
  assert.equal(git(p.workspace, "status", "--porcelain", "--ignored"), "");
  assert.equal(git(p.workspace, "worktree", "list", "--porcelain").match(/^worktree /gm).length, 1, "attempt checkout left behind");
}

describe("daemon verification in Git mode", () => {
  it("an honest fix reaches auto_merge on a commit the host authored", () => {
    const p = project();
    issue(p);
    daemon(p, worker(p, "honest", WRITE_FIX));

    const [outcome] = outcomes(p);
    assert.equal(outcome.verdict, "auto_merge", JSON.stringify(outcome));
    assert.equal(outcome.rule, "MP-000");
    assert.equal(outcome.base_commit, p.base);
    assert.notEqual(outcome.candidate_commit, p.base);
    assert.notEqual(outcome.head_commit, undefined);
    assert.equal(git(p.workspace, "rev-parse", `${outcome.candidate_commit}^`), p.base);
    assert.equal(git(p.workspace, "log", "-1", "--format=%an", outcome.candidate_commit), "mirql-supervisor");
    assert.equal(git(p.workspace, "show", `${outcome.candidate_commit}:src/app.mjs`), FIX.trim());
    assert.equal(git(p.workspace, "rev-parse", `refs/mirql/attempts/${outcome.candidate_commit}`), outcome.candidate_commit);
    assert.deepEqual(digestRules(p), ["MP-000"]);
    assertWorkspaceUntouched(p);
  });

  it("a budget-1 bloat worker is rejected and its candidate unpinned", () => {
    const p = project();
    issue(p, { budget: 1 });
    daemon(p, worker(p, "bloat", `${WRITE_FIX}\nwriteFileSync("src/bloat.mjs", ${JSON.stringify(BLOAT)});\n`));

    const [outcome] = outcomes(p);
    assert.equal(outcome.verdict, "reject");
    assert.equal(outcome.rule, "LAW_13_PHI_INCREASE");
    assert.ok(outcome.phi_after > outcome.phi_before);
    const digest = mirql(["i", "digest", "--dir", p.mirqlDir, "--format", "markdown"], ROOT);
    assert.match(digest.stdout, /`reject` `LAW_13_PHI_INCREASE`/);
    assert.equal(git(p.workspace, "for-each-ref", "refs/mirql/attempts"), "");
    assertWorkspaceUntouched(p);
  });

  it("a retry starts from a clean base", () => {
    const p = project();
    issue(p);
    const failing = worker(p, "failing", `
writeFileSync("src/app.mjs", "// half done\\n");
writeFileSync("left-behind.mjs", "export {};\\n");
writeFileSync("cache.ignored", "stale\\n");
process.exit(7);
`);
    daemon(p, failing);
    assertWorkspaceUntouched(p);

    const retry = worker(p, "retry", `
import { readFileSync } from "node:fs";
if (existsSync("left-behind.mjs") || existsSync("cache.ignored")) process.exit(21);
if (readFileSync("src/app.mjs", "utf8").includes("half done")) process.exit(22);
if (execSync("git rev-parse HEAD", { encoding: "utf8" }).trim() !== ${JSON.stringify(p.base)}) process.exit(23);
${WRITE_FIX}
`);
    daemon(p, retry);

    const [first, second] = outcomes(p);
    assert.equal(first.verdict, "reject");
    assert.equal(first.rule, "WORKER_FAILED");
    assert.equal(second.rule, "MP-000", JSON.stringify(second));
    assert.equal(second.verdict, "auto_merge");
    assert.equal(git(p.workspace, "show", "--name-only", "--format=", second.candidate_commit).includes("left-behind"), false);
    assert.deepEqual(digestRules(p), ["WORKER_FAILED", "MP-000"]);
    assertWorkspaceUntouched(p);
  });

  it("fails closed before the worker when the warrant names no reproducer", () => {
    const p = project();
    issue(p, { reproducer: null });
    const sentinel = join(p.root, "worker-ran").replaceAll("\\", "/");
    daemon(p, worker(p, "unwanted", `writeFileSync(${JSON.stringify(sentinel)}, "1");\n`));

    assert.equal(outcomes(p)[0].rule, "NO_REPRODUCER_DECLARED");
    assert.equal(existsSync(sentinel), false, "the worker must not run");
  });

  it("refuses a reproducer path that leaves the repository", () => {
    const p = project();
    for (const bad of ["../outside.test.mjs", "/abs.test.mjs", "C:/abs.test.mjs", "tests\\repro.test.mjs"]) {
      const result = mirql(["i", "send", "--dir", p.mirqlDir, "--key", p.key, "--title", "x", "--reproducer", bad], p.root);
      assert.notEqual(result.status, 0, bad);
    }
  });

  it("does not stage output after the worker changed the Git configuration", () => {
    const p = project();
    issue(p);
    const marker = join(p.root, "filter-ran").replaceAll("\\", "/");
    daemon(p, worker(p, "tamper", `
execSync(${JSON.stringify(`git config filter.pwn.clean "node -e \\"require('fs').writeFileSync('${marker}','1')\\""`)});
writeFileSync(".gitattributes", "*.mjs filter=pwn\\n");
${WRITE_FIX}
`));

    assert.equal(outcomes(p)[0].rule, "WORKER_TAMPERED_GIT");
    assert.equal(existsSync(marker), false, "the host must not run a filter the worker planted");
  });

  it("a library caller's runCheck and verifyOptions cannot skip the signed budget", () => {
    const p = project();
    const warrantId = issue(p, { budget: 1 });
    const stub = () => ({ verified: true, verdict: "auto_merge", passed: true, rule: "MP-000" });
    const result = runSupervisor({
      mirqlDir: p.mirqlDir,
      workspaceDir: p.workspace,
      warrantId,
      noHeartbeatTicker: true,
      skipPidFile: true,
      builderCommand: worker(p, "library-bloat", `${WRITE_FIX}\nwriteFileSync("src/bloat.mjs", ${JSON.stringify(BLOAT)});\n`),
      runCheck: stub,
      verifyOptions: { runCheck: stub, fixture: true },
      fixture: true,
    });
    assert.equal(result.verdict, "reject");
    assert.equal(result.rule, "LAW_13_PHI_INCREASE");
  });
});
