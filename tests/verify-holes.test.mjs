// tests/verify-holes.test.mjs — regression tests for attacks that once reached auto_merge.
//
// Every scenario runs the real git-mode verifier against a throwaway repository
// and a really signed warrant. HOME is isolated; no real key is ever touched.

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { verifyAttempt } from "../packages/run/verify.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { sendIntent } from "../packages/inbox/send.mjs";
import { approveMerge } from "../packages/inbox/merge-approval.mjs";
import { protectOwnerKey } from "../packages/inbox/keys.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POLICY = readFileSync(join(ROOT, "policy", "paths.yaml"), "utf8");

const BASE = {
  "package.json": JSON.stringify({ type: "module", scripts: { test: "node --test tests/*.test.mjs" } }),
  "policy/paths.yaml": POLICY,
  "src/app.mjs": "export function add(a, b) {\n  return a - b;\n}\n",
  "src/auth.mjs": "export function allowed(user) {\n  return user === 'admin';\n}\n",
  "tests/auth.test.mjs": "import test from 'node:test';\nimport assert from 'node:assert';\nimport { allowed } from '../src/auth.mjs';\ntest('guests are refused', () => assert.equal(allowed('guest'), false));\n",
};
const FIX = "export function add(a, b) {\n  return a + b;\n}\n";
const TEST = "import test from 'node:test';\nimport assert from 'node:assert';\nimport { add } from '../src/app.mjs';\ntest('adds', () => assert.equal(add(2, 2), 4));\n";
const GREP_TEST = "import test from 'node:test';\nimport assert from 'node:assert';\nimport { readFileSync } from 'node:fs';\ntest('marker', () => assert.ok(readFileSync('src/app.mjs', 'utf8').includes('a + b')));\n";
const FORGE_TEST = GREP_TEST + `import { writeFileSync as w } from 'node:fs';
import { join as j, resolve as res } from 'node:path';
import { pathToFileURL as u } from 'node:url';
if (process.env.NODE_V8_COVERAGE) {
  const f = res('src/app.mjs');
  const n = readFileSync(f, 'utf8').length;
  w(j(process.env.NODE_V8_COVERAGE, 'forged.json'), JSON.stringify({ result: [{ url: u(f).href, functions: [{ ranges: [{ startOffset: 0, endOffset: n, count: 1 }] }] }] }));
}
`;
const BACKDOOR = FIX + "export function debug(cmd) {\n  return import('node:child_process').then((c) => c.execSync(cmd));\n}\n";
const OPEN_AUTH = "export function allowed(user) {\n  return true;\n}\n";

const savedEnv = {};
const ENV_KEYS = ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "MIRQL_TRUST_ROOT", "MIRQL_HUMAN_KEY", "MIRQL_HUMAN_PASSPHRASE", "MIRQL_ALLOW_PLAINTEXT_OWNER_KEY", "MIRQL_SUITE_TIMEOUT_MS"];
let sandbox;
let mirqlDir;
let owner;

function git(repo, ...args) {
  const res = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
  if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  return res.stdout.trim();
}

function write(repo, files) {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), content);
  }
}

function repoWith(head, base = BASE) {
  const repo = mkdtempSync(join(sandbox, "repo-"));
  git(repo, "init", "-q", "-b", "main");
  git(repo, "config", "user.email", "holes@example.test");
  git(repo, "config", "user.name", "holes");
  git(repo, "config", "core.autocrlf", "false");
  write(repo, base);
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "base");
  const baseSha = git(repo, "rev-parse", "HEAD");
  write(repo, head);
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "head");
  return { repo, baseSha, headSha: git(repo, "rev-parse", "HEAD") };
}

function warrant(kind = "feature", scope = ["**"]) {
  return sendIntent(mirqlDir, { title: "Verifier regression grant", kind, phi_budget: 10000, scope }, { key: owner.human_key_path }).warrant_id;
}

function verify(target, warrantId, extra = {}) {
  return verifyAttempt({
    git: true, workspaceDir: target.repo, baseSha: target.baseSha, headSha: target.headSha,
    reproducerFile: "tests/repro.test.mjs", mirqlDir, warrantId, ...extra,
  });
}

function approve(target, warrantId) {
  approveMerge(mirqlDir, {
    key: owner.human_key_path, warrantId, repoDir: target.repo, workspaceDir: target.repo,
    baseSha: target.baseSha, headSha: target.headSha,
  });
}

function assertHeld(result, verdict, rule) {
  assert.equal(result.verdict, verdict, JSON.stringify(result));
  assert.equal(result.rule, rule, JSON.stringify(result));
  assert.equal(result.verified, false);
}

before(() => {
  for (const key of ENV_KEYS) { savedEnv[key] = process.env[key]; delete process.env[key]; }
  sandbox = mkdtempSync(join(tmpdir(), "mirql-holes-home-"));
  process.env.HOME = sandbox;
  process.env.USERPROFILE = sandbox;
  process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY = "1";
  mkdirSync(join(sandbox, "authority"));
  mirqlDir = join(sandbox, "authority", ".mirql");
  owner = runGenesis(mirqlDir);
});

after(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  rmSync(sandbox, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
});

describe("controls", () => {
  it("S0: an honest fix with a causal test still auto-merges", async () => {
    const result = await verify(repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": TEST }), warrant());
    assert.equal(result.verdict, "auto_merge", JSON.stringify(result));
    assert.equal(result.rule, "MP-000");
    assert.equal(result.verified, true);
  });

  it("S1: a test that only greps the source is rejected", async () => {
    assertHeld(await verify(repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": GREP_TEST }), warrant()),
      "reject", "REPRODUCER_IRRELEVANT");
  });
});

describe("attacks", () => {
  it("S2: a forged V8 coverage file proves nothing", async () => {
    assertHeld(await verify(repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": FORGE_TEST }), warrant()),
      "reject", "REPRODUCER_IRRELEVANT");
  });

  it("S3: skipping a guarding test is held", async () => {
    const target = repoWith({
      "src/app.mjs": FIX, "tests/repro.test.mjs": TEST, "src/auth.mjs": OPEN_AUTH,
      "tests/auth.test.mjs": BASE["tests/auth.test.mjs"].replace("test('guests", "test.skip('guests"),
    });
    assertHeld(await verify(target, warrant()), "needs_human", "TEST_WEAKENED");
  });

  it("S3b: rewriting a guarding test's assertion fails against the base test", async () => {
    const target = repoWith({
      "src/app.mjs": FIX, "tests/repro.test.mjs": TEST, "src/auth.mjs": OPEN_AUTH,
      "tests/auth.test.mjs": BASE["tests/auth.test.mjs"].replace("false", "true"),
    });
    assertHeld(await verify(target, warrant()), "needs_human", "TEST_WEAKENED");
  });

  it("S4: a never-executed backdoor beside the fix is held", async () => {
    const result = await verify(repoWith({ "src/app.mjs": BACKDOOR, "tests/repro.test.mjs": TEST }), warrant());
    assertHeld(result, "needs_human", "UNCOVERED_CHANGE");
    assert.match(result.detail, /src\/app\.mjs: line\(s\) .*5/);
  });

  it("A1: under a surgical warrant an unneeded change is rejected", async () => {
    const target = repoWith({
      "src/app.mjs": FIX, "tests/repro.test.mjs": TEST, "src/auth.mjs": OPEN_AUTH,
      "tests/auth.test.mjs": BASE["tests/auth.test.mjs"].replace("test('guests", "test.skip('guests"),
    });
    assertHeld(await verify(target, warrant("bug")), "reject", "UNNECESSARY_CHANGE");
  });

  it("A2: under a surgical warrant the backdoor is rejected", async () => {
    assertHeld(await verify(repoWith({ "src/app.mjs": BACKDOOR, "tests/repro.test.mjs": TEST }), warrant("bug")),
      "reject", "UNCOVERED_CHANGE");
  });

  it("unneeded files on a non-surgical warrant are held", async () => {
    const target = repoWith({
      "src/app.mjs": FIX, "tests/repro.test.mjs": TEST, "src/auth.mjs": "export function allowed(user) {\n  return user === 'admin' || user === 'root';\n}\n",
    });
    assertHeld(await verify(target, warrant()), "needs_human", "UNPROVEN_CHANGE");
  });

  it("B: a change outside the signed scope is rejected before candidate code runs", async () => {
    const marker = join(sandbox, "scope-ran.txt");
    const test = `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'ran');\n` + TEST;
    const target = repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": test });
    assertHeld(await verify(target, warrant("feature", ["docs/**"])), "reject", "OUT_OF_SCOPE");
    assert.equal(existsSync(marker), false, "candidate code ran before the scope gate");
  });

  it("C1: candidate code sees a disposable home that is removed afterwards", async () => {
    const seen = join(sandbox, "seen-home.txt");
    const test = `import { writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
writeFileSync(join(homedir(), 'holes-marker.txt'), 'x');
writeFileSync(${JSON.stringify(seen)}, homedir());
` + TEST;
    const result = await verify(repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": test }), warrant());
    assert.equal(result.verdict, "auto_merge", JSON.stringify(result));
    const candidateHome = readFileSync(seen, "utf8");
    assert.notEqual(resolve(candidateHome), resolve(sandbox));
    assert.equal(existsSync(join(sandbox, "holes-marker.txt")), false, "marker reached the invoking home");
    assert.equal(existsSync(candidateHome), false, "disposable home was not removed");
  });

  it("D: the full suite has its own limit, not the 30s reproducer cap", async () => {
    const slow = { ...BASE, "tests/slow.test.mjs": "import test from 'node:test';\ntest('slow', async () => { await new Promise((r) => setTimeout(r, 2000)); });\n" };
    const head = { "src/app.mjs": FIX, "tests/repro.test.mjs": TEST };
    const passing = await verify(repoWith(head, slow), warrant(), { suiteTimeoutMs: 120000 });
    assert.equal(passing.verdict, "auto_merge", JSON.stringify(passing));
    const tooShort = await verify(repoWith(head, slow), warrant(), { suiteTimeoutMs: 500 });
    assert.equal(tooShort.verdict, "reject", JSON.stringify(tooShort));
    assert.equal(tooShort.checks?.full_suite?.passed, false, JSON.stringify(tooShort));
  });
});

describe("owner approval", () => {
  it("clears a held result on a non-surgical warrant", async () => {
    const target = repoWith({ "src/app.mjs": BACKDOOR, "tests/repro.test.mjs": TEST });
    const id = warrant();
    assertHeld(await verify(target, id), "needs_human", "UNCOVERED_CHANGE");
    approve(target, id);
    const result = await verify(target, id);
    assert.equal(result.verdict, "auto_merge", JSON.stringify(result));
    assert.equal(typeof result.proof.human_approval_hash, "string");
  });

  it("never clears a reject", async () => {
    const surgical = repoWith({ "src/app.mjs": BACKDOOR, "tests/repro.test.mjs": TEST });
    const surgicalId = warrant("bug");
    approve(surgical, surgicalId);
    assertHeld(await verify(surgical, surgicalId), "reject", "UNCOVERED_CHANGE");

    const outOfScope = repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": TEST });
    const scopedId = warrant("feature", ["docs/**"]);
    approve(outOfScope, scopedId);
    assertHeld(await verify(outOfScope, scopedId), "reject", "OUT_OF_SCOPE");
  });
});

describe("owner key preflight", () => {
  it("refuses to run candidate code beside a plaintext owner key, and proceeds once it is encrypted", async () => {
    const marker = join(sandbox, "preflight-ran.txt");
    const test = `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'ran');\n` + TEST;
    const target = repoWith({ "src/app.mjs": FIX, "tests/repro.test.mjs": test });
    const id = warrant();
    delete process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY;
    try {
      assertHeld(await verify(target, id), "needs_human", "OWNER_KEY_UNPROTECTED");
      assert.equal(existsSync(marker), false, "candidate code ran beside a plaintext key");

      const protectedKey = protectOwnerKey(mirqlDir, { passphrase: "holes-test-passphrase-1234" });
      assert.equal(protectedKey.status, "protected");
      const result = await verify(target, id);
      assert.notEqual(result.rule, "OWNER_KEY_UNPROTECTED", JSON.stringify(result));
      assert.equal(existsSync(marker), true);
    } finally {
      process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY = "1";
    }
  });
});
