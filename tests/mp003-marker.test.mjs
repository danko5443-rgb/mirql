// MP-003 exemption marker: changed code cannot approve its own silence.
//
// `// mp-003-allow: <reason>` lives in the source being scanned, so a marker
// only counts where the candidate did not touch the catch. The base it is
// compared against must be the authoritative --base/--head pair, never a value
// from the PR document.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkSwallowedExceptions } from "../packages/core/anti-cheat.mjs";
import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MARKED_CATCH = "try { risky(); } catch (e) {\n  // mp-003-allow: best-effort cleanup\n}\n";

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
    writeFileSync(join(dir, file), code);
  }
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "--allow-empty", "-m", message);
  return git(dir, "rev-parse", "HEAD");
}

/** Commits `baseFiles` then `headFiles`, hands the SHAs to `run`, and removes the repo. */
function withRepo(baseFiles, headFiles, run) {
  const dir = mkdtempSync(join(tmpdir(), "mp003-marker-"));
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

test("scanner: a marker alone exempts nothing unless the caller vouches for the lines", () => {
  for (const source of [
    MARKED_CATCH,
    "run().catch(() => {\n  // mp-003-allow: best-effort\n});\n",
    "run().catch((e) => { /* mp-003-allow: best-effort */ });\n",
  ]) {
    assert.equal(checkSwallowedExceptions(source, "a.js").ok, false, `no scope: ${source}`);
    assert.equal(
      checkSwallowedExceptions(source, "a.js", { changedLines: new Set() }).ok,
      true,
      `untouched: ${source}`,
    );
    assert.equal(
      checkSwallowedExceptions(source, "a.js", { changedLines: new Set([1]) }).ok,
      false,
      `changed: ${source}`,
    );
  }
});

test("scanner: a change anywhere in the catch counts, a change elsewhere does not", () => {
  const source = `const a = 1;\n${MARKED_CATCH}const b = 2;\n`;
  const check = (lines) => checkSwallowedExceptions(source, "a.js", { changedLines: new Set(lines) }).ok;
  assert.equal(check([1, 5]), true, "lines outside the catch leave the marker honoured");
  assert.equal(check([2]), false, "catch header line");
  assert.equal(check([3]), false, "marker line");
  assert.equal(check([4]), false, "closing brace line");
});

test("scanner: a refused marker says why", () => {
  const { violations } = checkSwallowedExceptions(MARKED_CATCH, "a.js", { changedLines: new Set([2]) });
  assert.match(violations[0].detail, /mp-003-allow/);
});

test("evaluator: a candidate cannot add an empty catch with its own marker", () => {
  const code = `export const a = 1;\n${MARKED_CATCH}`;
  withRepo({ "src/a.js": "export const a = 1;\n" }, { "src/a.js": code }, (repo) => {
    const verdict = evaluate(repo, { "src/a.js": code });
    assert.equal(verdict.rule, "MP-003");
    assert.equal(verdict.violation, "ANTI_CHEAT_VIOLATION");
    assert.equal(verdict.verdict, "reject");
    assert.match(verdict.detail, /mp-003-allow/, "the rejection must name the refused marker");
  });
});

test("evaluator: a new file cannot carry its own marker", () => {
  withRepo({ "src/a.js": "export const a = 1;\n" }, { "src/new.js": MARKED_CATCH }, (repo) => {
    assert.equal(evaluate(repo, { "src/new.js": MARKED_CATCH }).rule, "MP-003");
  });
});

test("evaluator: a marker already in the base stays honoured when other lines change", () => {
  const baseCode = `export const a = 1;\n\n${MARKED_CATCH}`;
  const headCode = `export const a = 2;\n\n${MARKED_CATCH}`;
  withRepo({ "src/a.js": baseCode }, { "src/a.js": headCode }, (repo) => {
    const verdict = evaluate(repo, { "src/a.js": headCode });
    assert.notEqual(verdict.rule, "MP-003", verdict.detail);
    assert.equal(verdict.checks.anti_cheat, true);
  });
});

test("evaluator: copying a base marker onto a second catch does not exempt the copy", () => {
  const headCode = `${MARKED_CATCH}${MARKED_CATCH}`;
  withRepo({ "src/a.js": MARKED_CATCH }, { "src/a.js": headCode }, (repo) => {
    assert.equal(evaluate(repo, { "src/a.js": headCode }).rule, "MP-003");
  });
});

test("evaluator: a new catch wrapped around an old marker comment is not exempt", () => {
  const marker = "// mp-003-allow: stray comment\n";
  const headCode = `try { risky(); } catch (e) {\n${marker}}\n`;
  withRepo({ "src/a.js": marker }, { "src/a.js": headCode }, (repo) => {
    assert.equal(evaluate(repo, { "src/a.js": headCode }).rule, "MP-003");
  });
});

test("evaluator: deleting a handler so a catch reaches an old marker is not exempt", () => {
  const baseCode =
    "try { risky(); } catch (e) {\n  throw e;\n}\nfunction f() {\n  // mp-003-allow: stray comment\n}\n";
  const headCode = "try { risky(); } catch (e) {\n  // mp-003-allow: stray comment\n}\n";
  withRepo({ "src/a.js": baseCode }, { "src/a.js": headCode }, (repo) => {
    assert.equal(evaluate(repo, { "src/a.js": headCode }).rule, "MP-003");
  });
});

test("evaluator: a candidate .gitattributes cannot hide its lines from the diff", () => {
  const code = `export const a = 1;\n${MARKED_CATCH}`;
  const headFiles = { ".gitattributes": "*.js binary\n", "src/a.js": code };
  withRepo({ "src/a.js": "export const a = 1;\n" }, headFiles, (repo) => {
    assert.equal(evaluate(repo, { "src/a.js": code }).rule, "MP-003");
  });
});

test("evaluator: supplied source that is not the head blob gets no exemption", () => {
  const baseCode = `export const a = 1;\n${MARKED_CATCH}`;
  // Same line count and untouched in git, but the reviewed head never contained this text.
  const forged = `export const a = 1;\ntry { other(); } catch (e) {\n  // mp-003-allow: forged\n}\n`;
  withRepo({ "src/a.js": baseCode }, { "other.txt": "x\n" }, (repo) => {
    assert.equal(evaluate(repo, { "src/a.js": forged }).rule, "MP-003");
  });
});

test("evaluator: CRLF in supplied source does not cost a base marker its exemption", () => {
  const baseCode = `export const a = 1;\n${MARKED_CATCH}`;
  withRepo({ "src/a.js": baseCode }, { "other.txt": "x\n" }, (repo) => {
    const verdict = evaluate(repo, { "src/a.js": baseCode.replace(/\n/g, "\r\n") });
    assert.equal(verdict.checks.anti_cheat, true, verdict.detail);
  });
});

test("evaluator: PR-document SHAs cannot vouch for a marker", () => {
  // Claiming base == head would make the diff empty and every line look untouched.
  withRepo({ "src/a.js": MARKED_CATCH }, { "other.txt": "x\n" }, ({ dir, head }) => {
    const verdict = evaluatePullRequest(
      { pr: { kind: "pr", base_sha: head, head_sha: head }, sourceCode: { "src/a.js": MARKED_CATCH } },
      { repoDir: dir },
    );
    assert.equal(verdict.rule, "MP-003");
  });
});

test("evaluator: a bare source string has no file to compare, so no exemption", () => {
  withRepo({ "src/a.js": MARKED_CATCH }, { "other.txt": "x\n" }, (repo) => {
    assert.equal(evaluate(repo, MARKED_CATCH).rule, "MP-003");
  });
});

test("the markers shipped on main stay honoured once they are in the base", () => {
  const files = ["packages/inbox/ledger.mjs", "packages/run/agent.mjs", "packages/run/verify.mjs"];
  const sources = Object.fromEntries(
    files.map((file) => [file, readFileSync(join(ROOT, file), "utf8").replace(/\r\n/g, "\n")]),
  );
  for (const [file, code] of Object.entries(sources)) {
    assert.match(code, /mp-003-allow:/, `${file} should still carry a marker`);
  }
  withRepo(sources, { "other.txt": "x\n" }, (repo) => {
    const verdict = evaluate(repo, sources);
    assert.equal(verdict.checks.anti_cheat, true, verdict.detail);
  });
});
