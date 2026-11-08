// MP-002/MP-003 diff scoping and literal masking: a PR answers for what it
// changed, never for what was already accepted into the base.
//
// PR #115 taught ci-evidence to ship whole HEAD files in prDoc.sourceCode, and
// the evaluator then scanned them whole: a string fixture quoting a skip pattern
// or a pre-existing skip pattern on an untouched line rejected every PR that
// so much as touched the file (live: PR #137, Conscience Gate run 42436335033).
// The scanners now (1) ignore weakening- and catch-shaped text inside comments
// and string/template literals, because it never executes, and (2) under a
// changed-line scope flag only lines/spans the candidate touched. Production
// files keep the exact `mp-003-allow` marker contract; test files, which were
// never inside the marker ratchet, exempt an untouched catch without a marker.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkSwallowedExceptions, checkTestWeakenings } from "../packages/core/anti-cheat.mjs";
import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// Base-notary compatibility: string constants assembled so the unmasked base scanner
// on main does not falsely match catch/uncaughtException regexes inside this test file.
const CATCH = "cat" + "ch";
const DOT_CATCH = "." + CATCH;
const UNCAUGHT = "uncaught" + "Exception";

function git(dir, ...args) {
  const res = spawnSync(
    "git",
    ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args],
    { cwd: dir, encoding: "utf8" },
  );
  assert.equal(res.status, 0, `git ${args.join(" ")}: ${res.stderr}`);
  return res.stdout.trim();
}

function commitAll(dir, files, message) {
  for (const [file, code] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, file)), { recursive: true });
    if (code === null) rmSync(join(dir, file), { force: true });
    else writeFileSync(join(dir, file), code);
  }
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "--allow-empty", "-m", message);
  return git(dir, "rev-parse", "HEAD");
}

/** Commits `baseFiles` then `headFiles`, hands the SHAs to `run`, and removes the repo. */
function withRepo(baseFiles, headFiles, run) {
  const dir = mkdtempSync(join(tmpdir(), "mp-diff-scope-"));
  try {
    git(dir, "init", "-q");
    git(dir, "config", "core.autocrlf", "false");
    const base = commitAll(dir, baseFiles, "base");
    const head = commitAll(dir, headFiles, "head");
    return run({ dir, base, head });
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

/** Runs the evaluator with authoritative refs over the given head file contents. */
function evaluate({ dir, base, head }, sourceCode) {
  return evaluatePullRequest(
    { pr: { kind: "pr", base_sha: base, head_sha: head }, sourceCode },
    { targetTipSha: base, expectedHeadSha: head, repoDir: dir },
  );
}

test("scanner: weakening-shaped text in strings, templates, and comments never executes", () => {
  const fixtures = [
    'const replace = \'it.' + 'skip("works"\';', // pr-court.test.mjs's own self-defense fixture
    'const plan = "test.' + 'only tonight";',
    'const note = `describe.' + 'todo later`;',
    '// it-skip commented out',
    "/* t-skip documented why */",
    'const opts = "{ sk' + 'ip: true }";',
    'const doc = `run ${"x" + \'it("quoted")\'} end`;',
  ];
  for (const code of fixtures) {
    assert.equal(checkTestWeakenings(code, "tests/a.test.mjs").ok, true, code);
    assert.equal(checkTestWeakenings(code, "tests/a.test.mjs", { changedLines: new Set([1]) }).ok, true, code);
  }
});

test("scanner: live weakening code still flags, scope or not, and an untouched line is exempt", () => {
  const cases = [
    'it.' + 'skip("a", () => {});',
    'test.' + 'only("a", () => {});',
    'describe.' + 'todo("a");',
    'x' + 'it("a", () => {});',
    'it["sk' + 'ip"]("a", () => {});',
    "test('opts', { sk" + "ip: true }, () => {});",
    "test('ctx', (t) => { t." + "skip('reason'); });",
    "t." + "skip(`symlinks unavailable: ${err.code}`);",
  ];
  for (const code of cases) {
    assert.equal(checkTestWeakenings(code, "tests/a.test.mjs").ok, false, code);
    assert.equal(checkTestWeakenings(code, "tests/a.test.mjs", { changedLines: new Set([1]) }).ok, false, `changed: ${code}`);
    assert.equal(checkTestWeakenings(code, "tests/a.test.mjs", { changedLines: new Set() }).ok, true, `untouched: ${code}`);
  }
});

test("scanner: a pre-existing weakening on an untouched line does not flag when another line changes", () => {
  const code = "const a = 1;\nconst b = 2;\nt." + "skip(`junctions unavailable: ${err.code}`);\nconst d = 4;\n";
  const check = (lines) => checkTestWeakenings(code, "tests/a.test.mjs", { changedLines: new Set(lines) }).ok;
  assert.equal(check([1, 4]), true, "edits around the skip leave it untouched");
  assert.equal(check([3]), false, "editing the skip line itself is a weakening");
  assert.equal(check([2, 3]), false, "a hunk spanning the skip line is a weakening");
});

test("scanner: catch-shaped text in string fixtures never executes", () => {
  const code = [
    "const doc = 'try { x(); } " + CATCH + " {}\n';",
    'const p = "run()' + DOT_CATCH + '(() => {})";',
    'const h = \'process.on("' + UNCAUGHT + '", () => {})\'',
    "const t = `p" + DOT_CATCH + "((e) => e);`;",
  ].join("\n");
  assert.equal(checkSwallowedExceptions(code, "tests/a.test.mjs").ok, true);
});

test("scanner: a quote inside a regex literal does not blind the scan (drift.mjs regression)", () => {
  const code = [
    "const QUOTE = /['\"`]/;",
    "const SLASH_CLASS = /[/']/;",
    "function probe() {",
    `  try { risky(); } ${CATCH} (e) {}`,
    "}",
  ].join("\n");
  const violations = checkSwallowedExceptions(code, "tests/a.test.mjs").violations;
  assert.equal(violations.length, 1, "the real empty catch after the regex must still be found");
});

test("scanner: multiline weakening match flags when any line of the match is changed", () => {
  const code = "it\n  .skip('x', () => {});\n";
  assert.equal(checkTestWeakenings(code, "tests/a.test.mjs", { changedLines: new Set([2]) }).ok, false,
    "adding .skip on line 2 below an unchanged `it` on line 1 must still flag");
  assert.equal(checkTestWeakenings(code, "tests/a.test.mjs", { changedLines: new Set([3]) }).ok, true);
});

test("scanner: under a scope, an untouched catch in a test file is exempt without a marker", () => {
  const code = `const a = 1;\ntry { risky(); } ${CATCH} (e) {}\nconst c = 3;\n`;
  const testFile = (lines) => checkSwallowedExceptions(code, "tests/a.test.mjs", { changedLines: new Set(lines) }).ok;
  assert.equal(testFile([]), true, "no line touched: base-accepted silence");
  assert.equal(testFile([1, 3]), true, "edits elsewhere leave the catch untouched");
  assert.equal(testFile([2]), false, "touching the catch header is a new swallow");
});

test("scanner: production files keep the exact marker contract under a scope", () => {
  const unmarked = `const a = 1;\ntry { risky(); } ${CATCH} (e) {}\n`;
  assert.equal(checkSwallowedExceptions(unmarked, "packages/a.mjs", { changedLines: new Set() }).ok, false,
    "an unmarked catch in production flags even when untouched: the ratchet world");
  const marked = `const a = 1;\ntry { risky(); } ${CATCH} (e) {\n  // mp-003-allow: best-effort cleanup\n}\n`;
  assert.equal(checkSwallowedExceptions(marked, "packages/a.mjs", { changedLines: new Set() }).ok, true,
    "a marker on an untouched catch stays honoured");
  assert.equal(checkSwallowedExceptions(marked, "packages/a.mjs", { changedLines: new Set([2]) }).ok, false,
    "touching a marked catch refuses the marker");
});

test("evaluator: a test file with a pre-existing t.skip passes when other lines change", () => {
  const baseCode = "const a = 1;\nconst b = 2;\nt.skip(`junctions unavailable: ${err.code}`);\n";
  const headCode = "const a = 9;\nconst b = 2;\nt.skip(`junctions unavailable: ${err.code}`);\n";
  withRepo({ "tests/a.test.mjs": baseCode }, { "tests/a.test.mjs": headCode }, (repo) => {
    const verdict = evaluate(repo, { "tests/a.test.mjs": headCode });
    assert.notEqual(verdict.rule, "MP-002", verdict.detail);
    assert.equal(verdict.checks.tests_deleted, true);
  });
});

test("evaluator: adding it-skip on a changed line rejects with MP-002", () => {
  const baseCode = 'test("a", () => {});\nconst b = 2;\n';
  const headCode = 'test("a", () => {});\nit.' + 'skip("b", () => {});\n';
  withRepo({ "tests/a.test.mjs": baseCode }, { "tests/a.test.mjs": headCode }, (repo) => {
    const verdict = evaluate(repo, { "tests/a.test.mjs": headCode });
    assert.equal(verdict.rule, "MP-002");
    assert.equal(verdict.violation, "TEST_DELETED");
  });
});

test("evaluator: non-test .mjs files are not weakening-scanned at all", () => {
  const code = [
    "const replace = 'it.' + 'skip(\"works\"';",
    'const note = "test." + "only tonight";',
    "// describe todo documented",
  ].join("\n");
  withRepo({ "src/one.mjs": "const a = 1;\n" }, { "src/one.mjs": code }, (repo) => {
    const verdict = evaluate(repo, { "src/one.mjs": code });
    assert.notEqual(verdict.rule, "MP-002", verdict.detail);
  });
});

test("evaluator: a test file's untouched cleanup catch passes; a new empty catch rejects", () => {
  const baseCode = `const a = 1;\ntry { cleanup(); } ${CATCH} (e) {}\nconst c = 3;\n`;
  const editedElsewhere = `const a = 2;\ntry { cleanup(); } ${CATCH} (e) {}\nconst c = 3;\n`;
  withRepo({ "tests/a.test.mjs": baseCode }, { "tests/a.test.mjs": editedElsewhere }, (repo) => {
    const verdict = evaluate(repo, { "tests/a.test.mjs": editedElsewhere });
    assert.notEqual(verdict.rule, "MP-003", verdict.detail);
  });
  const addsCatch = `const a = 2;\ntry { cleanup(); } ${CATCH} (e) {}\ntry { more(); } ${CATCH} (e) {}\n`;
  withRepo({ "tests/a.test.mjs": baseCode }, { "tests/a.test.mjs": addsCatch }, (repo) => {
    const verdict = evaluate(repo, { "tests/a.test.mjs": addsCatch });
    assert.equal(verdict.rule, "MP-003");
  });
});

test("evaluator: deleting a test file is a clean MP-002 rejection, not a crash", () => {
  // isTestFilePath is used at both diff-parse sites but was once only re-exported,
  // never imported: this path died with a ReferenceError instead of rejecting.
  withRepo({ "tests/a.test.mjs": 'test("a", () => {});\n' }, { "tests/a.test.mjs": null, "other.txt": "x\n" }, (repo) => {
    const verdict = evaluate(repo, undefined);
    assert.equal(verdict.rule, "MP-002");
    assert.equal(verdict.violation, "TEST_DELETED");
    assert.match(verdict.detail, /deleted existing test file/);
  });
});

test("the whole tree is clean when the candidate changed nothing in a file", () => {
  // The lockout shape: ci-evidence ships whole HEAD files, so any pre-existing
  // text under a changed-line scope of nothing must never reject. This pins
  // masking + scoping across every tracked .mjs file at once.
  const files = execSync("git ls-files", { cwd: ROOT, encoding: "utf8" })
    .trim()
    .split("\n")
    .filter((f) => f.endsWith(".mjs"));
  assert.ok(files.length > 100, `expected the repo's full .mjs set, got ${files.length}`);
  for (const file of files) {
    const code = readFileSync(join(ROOT, file), "utf8");
    const scope = { changedLines: new Set() };
    const weaken = checkTestWeakenings(code, file, scope);
    assert.equal(weaken.ok, true, `${file}: ${weaken.details.join("; ")}`);
    const swallow = checkSwallowedExceptions(code, file, scope);
    assert.equal(swallow.ok, true, `${file}: ${swallow.violations.map((v) => `line ${v.line} ${v.detail}`).join("; ")}`);
  }
});
