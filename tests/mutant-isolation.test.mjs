import { provisionTestTrust } from "./helpers/keyring.mjs";
import { git } from "./helpers/git.mjs";
// tests/mutant-isolation.test.mjs — sandboxed mutation + incremental kill gate
// (issue #14). Two contracts:
//   1. The mutation engine NEVER writes the real workspace — mutants live in a
//      temp sandbox copy; proven here by running with the real files made
//      read-only (any real-tree write would fail the whole run).
//   2. The declarative mutants probe derives targets from the workspace diff
//      and pairs them with tests by REAL import edges — the 8000 bp floor is
//      enforced without hand-picked files, fail-closed when uncovered.

import { describe, it } from "node:test";
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
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { runMutationTesting } from "../packages/run/mutant.mjs";
import { runProbe, deriveChangedSources, findImportingTests } from "../packages/run/probe.mjs";



function makeWorkspace() {
  const ws = mkdtempSync(join(tmpdir(), "mirql-mutant-iso-"));
  git(ws, "init", "-q");
  mkdirSync(join(ws, "src"), { recursive: true });
  mkdirSync(join(ws, "tests"), { recursive: true });
  return ws;
}

const ADD_SOURCE = "export function add(a, b) { return a + b; }\n";
const ADD_TEST = `import test from "node:test";
import assert from "node:assert/strict";
import { add } from "../src/add.mjs";
test("add", () => { assert.equal(add(2, 3), 5); });
`;

describe("mutation engine isolation (issue #14, part 1)", () => {
  it("never writes the real workspace: succeeds with read-only source and test", () => {
    const ws = makeWorkspace();
    const src = join(ws, "src", "add.mjs");
    const test = join(ws, "tests", "add.test.mjs");
    writeFileSync(src, ADD_SOURCE, "utf8");
    writeFileSync(test, ADD_TEST, "utf8");
    // Make the REAL tree unwritable: any attempt to mutate in place would
    // throw EPERM and fail the run — the sandbox path must sail through.
    chmodSync(src, 0o444);
    chmodSync(test, 0o444);
    try {
      const res = runMutationTesting({ sourcePath: src, testPath: test });
      assert.equal(res.ok, true, `${res.summary ?? res.error}`);
      assert.equal(res.kill_rate_bp, 10000);
      assert.ok(res.mutants_killed > 0, "engine must really have run mutants");
      assert.equal(readFileSync(src, "utf8"), ADD_SOURCE, "real source byte-identical");
      assert.equal(readFileSync(test, "utf8"), ADD_TEST, "real test byte-identical");
    } finally {
      chmodSync(src, 0o666);
      chmodSync(test, 0o666);
      rmSync(ws, { recursive: true, force: true });
    }
  });

  it("creates no backup artifacts in the real tree", () => {
    const ws = makeWorkspace();
    const src = join(ws, "src", "add.mjs");
    const test = join(ws, "tests", "add.test.mjs");
    writeFileSync(src, ADD_SOURCE, "utf8");
    writeFileSync(test, ADD_TEST, "utf8");
    try {
      runMutationTesting({ sourcePath: src, testPath: test });
      assert.equal(existsSync(`${src}.mutant-bak`), false, "no .mutant-bak may be created");
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });

  it("custom testRunner path writes nothing at all (read-only source)", () => {
    const ws = makeWorkspace();
    const src = join(ws, "src", "add.mjs");
    writeFileSync(src, ADD_SOURCE, "utf8");
    chmodSync(src, 0o444);
    try {
      const res = runMutationTesting({
        sourcePath: src,
        testPath: "unused.test.mjs",
        testRunner: (mutant) => (mutant.isBaseline ? true : false),
      });
      assert.equal(res.ok, true);
      assert.equal(res.kill_rate_bp, 10000);
      assert.equal(readFileSync(src, "utf8"), ADD_SOURCE);
    } finally {
      chmodSync(src, 0o666);
      rmSync(ws, { recursive: true, force: true });
    }
  });

  it("fails closed with SANDBOX_UNAVAILABLE when no bounded workspace root exists", () => {
    const wsA = mkdtempSync(join(tmpdir(), "mirql-mutant-iso-a-"));
    const wsB = mkdtempSync(join(tmpdir(), "mirql-mutant-iso-b-"));
    try {
      const src = join(wsA, "add.mjs");
      const test = join(wsB, "add.test.mjs");
      writeFileSync(src, ADD_SOURCE, "utf8");
      writeFileSync(test, "export {};\n", "utf8");
      const res = runMutationTesting({ sourcePath: src, testPath: test });
      assert.equal(res.ok, false);
      assert.equal(res.error, "SANDBOX_UNAVAILABLE");
      assert.equal(readFileSync(src, "utf8"), ADD_SOURCE, "source untouched");
    } finally {
      rmSync(wsA, { recursive: true, force: true });
      rmSync(wsB, { recursive: true, force: true });
    }
  });

  it("accepts multiple covering test files (union of importers kills)", () => {
    const ws = makeWorkspace();
    const src = join(ws, "src", "add.mjs");
    writeFileSync(src, ADD_SOURCE, "utf8");
    writeFileSync(join(ws, "tests", "add-a.test.mjs"), ADD_TEST, "utf8");
    writeFileSync(
      join(ws, "tests", "add-b.test.mjs"),
      ADD_TEST.replace('"add"', '"add again"'),
      "utf8",
    );
    try {
      const res = runMutationTesting({
        sourcePath: src,
        testPath: [join(ws, "tests", "add-a.test.mjs"), join(ws, "tests", "add-b.test.mjs")],
      });
      assert.equal(res.ok, true, res.summary);
      assert.equal(res.kill_rate_bp, 10000);
      assert.equal(readFileSync(src, "utf8"), ADD_SOURCE);
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });
});

describe("incremental mutants probe — the wired 8000 bp gate (issue #14, part 2)", () => {
  function makeRepo() {
    const ws = mkdtempSync(join(tmpdir(), "mirql-mutant-probe-"));
    git(ws, "init", "-q");
    git(ws, "config", "user.email", "test@mirql.local");
    git(ws, "config", "user.name", "mirql-test");
    git(ws, "config", "core.autocrlf", "false");
    mkdirSync(join(ws, "packages", "run"), { recursive: true });
    mkdirSync(join(ws, "tests"), { recursive: true });
    writeFileSync(join(ws, "packages", "run", "calc.mjs"), ADD_SOURCE, "utf8");
    writeFileSync(
      join(ws, "tests", "calc.test.mjs"),
      ADD_TEST.replace("../src/add.mjs", "../packages/run/calc.mjs"),
      "utf8",
    );
    git(ws, "add", "-A");
    git(ws, "commit", "-q", "-m", "base");
    // HEAD changes calc.mjs: this is the incremental diff the probe must target
    writeFileSync(
      join(ws, "packages", "run", "calc.mjs"),
      `${ADD_SOURCE}export function sub(a, b) { return a - b; }\n`,
      "utf8",
    );
    writeFileSync(
      join(ws, "tests", "calc.test.mjs"),
      `import test from "node:test";
import assert from "node:assert/strict";
import { add, sub } from "../packages/run/calc.mjs";
test("add", () => { assert.equal(add(2, 3), 5); });
test("sub", () => { assert.equal(sub(5, 2), 3); });
`,
      "utf8",
    );
    git(ws, "add", "-A");
    git(ws, "commit", "-q", "-m", "head");
    return ws;
  }

  it("derives changed sources from the diff and pairs them via real import edges", () => {
    const ws = makeRepo();
    const controlDir = mkdtempSync(join(tmpdir(), "mirql-mutant-probe-ctl-"));
    provisionTestTrust(join(controlDir, ".mirql"));
    try {
      const importers = findImportingTests(ws, "packages/run/calc.mjs");
      assert.deepEqual(
        importers.map((p) => p.slice(ws.length + 1)),
        [join("tests", "calc.test.mjs")],
      );

      const res = runProbe({
        probe: "mutants",
        workspaceDir: ws,
        mirqlDir: join(controlDir, ".mirql"),
        base: "HEAD~1",
      });
      assert.equal(res.ok, true, JSON.stringify(res.probe));
      assert.equal(res.probe.status, "pass");
      assert.equal(res.probe.tested_files.length, 1);
      assert.equal(res.probe.tested_files[0].source, "packages/run/calc.mjs");
      assert.ok(res.probe.tested_files[0].kill_rate_bp >= 8000);
      assert.ok(res.probe.duration_ms > 0, "duration must be measured, not hardcoded");
      // Real tree untouched
      assert.match(
        readFileSync(join(ws, "packages", "run", "calc.mjs"), "utf8"),
        /return a - b;/,
      );
    } finally {
      rmSync(ws, { recursive: true, force: true });
      rmSync(controlDir, { recursive: true, force: true });
    }
  });

  it("fails closed when a changed source has NO importing test (M4 invariant unmet)", () => {
    const ws = mkdtempSync(join(tmpdir(), "mirql-mutant-lonely-"));
    git(ws, "init", "-q");
    git(ws, "config", "user.email", "test@mirql.local");
    git(ws, "config", "user.name", "mirql-test");
    git(ws, "config", "core.autocrlf", "false");
    mkdirSync(join(ws, "packages", "run"), { recursive: true });
    writeFileSync(join(ws, "packages", "run", "lonely.mjs"), ADD_SOURCE, "utf8");
    git(ws, "add", "-A");
    git(ws, "commit", "-q", "-m", "base");
    writeFileSync(join(ws, "packages", "run", "lonely.mjs"), `${ADD_SOURCE}// changed\n`, "utf8");
    git(ws, "add", "-A");
    git(ws, "commit", "-q", "-m", "head");
    const controlDir = mkdtempSync(join(tmpdir(), "mirql-mutant-lonely-ctl-"));
    provisionTestTrust(join(controlDir, ".mirql"));
    try {
      const res = runProbe({
        probe: "mutants",
        workspaceDir: ws,
        mirqlDir: join(controlDir, ".mirql"),
        base: "HEAD~1",
      });
      assert.equal(res.ok, false);
      assert.equal(res.probe.status, "fail");
      assert.equal(res.probe.tested_files[0].source, "packages/run/lonely.mjs");
      assert.equal(res.probe.tested_files[0].error, "NO_COVERING_TEST");
    } finally {
      rmSync(ws, { recursive: true, force: true });
      rmSync(controlDir, { recursive: true, force: true });
    }
  });

  it("derivation fails closed outside a git repository", () => {
    const notARepo = mkdtempSync(join(tmpdir(), "mirql-mutant-norepo-"));
    try {
      const res = deriveChangedSources(notARepo, "HEAD~1");
      assert.equal(res.ok, false);
    } finally {
      rmSync(notARepo, { recursive: true, force: true });
    }
  });

  it(".gitignore excludes mutation backup artifacts", () => {
    const gitignore = readFileSync(join(process.cwd(), ".gitignore"), "utf8");
    assert.match(gitignore, /\*\.mutant-bak/);
  });
  it("deriveChangedSources picks up untracked files (Law 6 fail-closed diff surface)", () => {
    const ws = makeWorkspace();
    try {
      git(ws, "config", "user.email", "test@test.local");
      git(ws, "config", "user.name", "Tester");
      const dummy = join(ws, "src", "dummy.mjs");
      writeFileSync(dummy, "export const x = 1;\n", "utf8");
      git(ws, "add", "-A");
      git(ws, "commit", "-q", "-m", "initial");

      const untracked = join(ws, "src", "untracked.mjs");
      writeFileSync(untracked, "export const y = 2;\n", "utf8");

      const res = deriveChangedSources(ws, "HEAD");
      assert.equal(res.ok, true);
      assert.ok(res.files.some((f) => f.includes("untracked.mjs")), "untracked source must be included");
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });

});
