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
// A comment line makes the file long enough for a forged script of equal length to carry its own URL.
const PADDED_BACKDOOR = "// " + "-".repeat(600) + "\n" + BACKDOOR;
const TARGET_URL = "import { pathToFileURL } from 'node:url';\nimport { resolve } from 'node:path';\nimport { readFileSync } from 'node:fs';\nconst target = resolve('src/app.mjs');\nconst url = pathToFileURL(target).href;\nconst size = readFileSync(target, 'utf8').length;\n";
const SOURCE_URL_FORGE = TARGET_URL + "const tail = '0;//# sourceURL=' + url;\n(0, eval)(' '.repeat(Math.max(0, size - tail.length)) + tail);\n" + TEST;
const VM_FILENAME_FORGE = TARGET_URL + "import vm from 'node:vm';\nnew vm.Script(' '.repeat(Math.max(0, size - 2)) + '0;', { filename: url }).runInThisContext();\n" + TEST;
// The candidate's own inspector session rewrites a harmless script's source to the file's exact text after it ran.
const CJS_BASE = "module.exports.add = function (a, b) {\n  return a - b;\n};\n";
const CJS_BACKDOOR = "// " + "-".repeat(600) + "\nmodule.exports.add = function (a, b) {\n  return a + b;\n};\nmodule.exports.debug = function (cmd) {\n  return require('node:child_process').execSync(cmd);\n};\n";
const LIVE_EDIT_FORGE = "import { createRequire } from 'node:module';\nimport { pathToFileURL } from 'node:url';\nimport { resolve } from 'node:path';\nimport { readFileSync } from 'node:fs';\nimport inspector from 'node:inspector';\nimport vm from 'node:vm';\nimport test from 'node:test';\nimport assert from 'node:assert';\nconst target = resolve('src/calc.cjs');\nconst url = pathToFileURL(target).href;\nconst text = readFileSync(target, 'utf8');\nconst session = new inspector.Session();\nsession.connect();\nconst post = (method, params) => new Promise((ok) => session.post(method, params, (error, value) => ok(error ?? value)));\nlet scriptId;\nsession.on('Debugger.scriptParsed', (m) => { if (m.params.url === url) scriptId = m.params.scriptId; });\nawait post('Debugger.enable');\nglobalThis.keep = new vm.Script(' '.repeat(Math.max(0, text.length - 2)) + '0;', { filename: url });\nglobalThis.keep.runInThisContext();\nconst edit = await post('Debugger.setScriptSource', { scriptId, scriptSource: text });\nconst after = await post('Debugger.getScriptSource', { scriptId });\nconsole.error('LIVE_EDIT', JSON.stringify(edit).slice(0, 200), after.scriptSource === text);\nawait post('Debugger.disable');\nsession.disconnect();\nconst { add } = createRequire(import.meta.url)('../src/calc.cjs');\ntest('adds', () => assert.equal(add(2, 2), 4));\n";
// Rewrites only the backdoored head, so the test stays red on base.
const DISK_SWAP_FORGE = "import test from 'node:test';\nimport assert from 'node:assert';\nimport { readFileSync, writeFileSync } from 'node:fs';\nconst file = 'src/app.mjs';\nconst text = readFileSync(file, 'utf8');\nif (text.includes('execSync')) writeFileSync(file, text.replace(/return import.*\\n/, 'return cmd;\\n'));\nconst app = await import('../src/app.mjs');\ntest('adds', () => assert.equal(app.add(2, 2), 4));\nif (app.debug) app.debug('x');\n";

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

  it("S4b: a script claiming the file's URL through sourceURL proves nothing", async () => {
    const result = await verify(repoWith({ "src/app.mjs": PADDED_BACKDOOR, "tests/repro.test.mjs": SOURCE_URL_FORGE }), warrant());
    assertHeld(result, "needs_human", "UNCOVERED_CHANGE");
  });

  it("S4c: a script claiming the file's URL through vm filename proves nothing", async () => {
    const result = await verify(repoWith({ "src/app.mjs": PADDED_BACKDOOR, "tests/repro.test.mjs": VM_FILENAME_FORGE }), warrant());
    assertHeld(result, "needs_human", "UNCOVERED_CHANGE");
  });

  it("S4d: executing a rewritten copy of the file proves nothing about the commit", async () => {
    const result = await verify(repoWith({ "src/app.mjs": BACKDOOR, "tests/repro.test.mjs": DISK_SWAP_FORGE }), warrant());
    assertHeld(result, "reject", "REPRODUCER_IRRELEVANT");
  });

  it("S4f: live-editing a forged script back to the commit's text proves nothing", async () => {
    const target = repoWith({ "src/calc.cjs": CJS_BACKDOOR, "tests/repro.test.mjs": LIVE_EDIT_FORGE }, { ...BASE, "src/calc.cjs": CJS_BASE });
    const result = await verify(target, warrant());
    assertHeld(result, "needs_human", "UNCOVERED_CHANGE");
  });

  it("S4e: honest CommonJS, CRLF and BOM sources still measure as covered", async () => {
    const pkg = { ...BASE, "package.json": JSON.stringify({ scripts: { test: "node --test tests/*.test.cjs" } }) };
    const cjsBase = "module.exports.add = function (a, b) {\r\n  return a - b;\r\n};\r\n";
    const cjsFix = "﻿module.exports.add = function (a, b) {\r\n  return a + b;\r\n};\r\n";
    delete pkg["tests/auth.test.mjs"];
    const cjsTest = "const test = require('node:test');\nconst assert = require('node:assert');\nconst { add } = require('../src/calc.cjs');\ntest('adds', () => assert.equal(add(2, 2), 4));\n";
    const target = repoWith({ "src/calc.cjs": cjsFix, "tests/repro.test.cjs": cjsTest }, { ...pkg, "src/calc.cjs": cjsBase });
    const result = await verify(target, warrant(), { reproducerFile: "tests/repro.test.cjs" });
    assert.equal(result.verdict, "auto_merge", JSON.stringify(result));
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
