import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { git } from "./helpers/git.mjs";
import { runAgent } from "../packages/run/agent.mjs";

let policyRoot, workspace;
beforeEach(() => {
  policyRoot = mkdtempSync(join(tmpdir(), "mirql-worker-diff-"));
  workspace = join(policyRoot, "workspace");
  mkdirSync(join(workspace, "policy"), { recursive: true });
  git(workspace, "init", "-q");
  git(workspace, "config", "user.name", "test");
  git(workspace, "config", "user.email", "test@mirql.local");
  git(workspace, "config", "core.autocrlf", "false");
  writeFileSync(join(workspace, "policy", "guard.json"), "base\n");
  writeFileSync(join(workspace, "code.mjs"), "export const value=1;\n");
  git(workspace, "add", "-A");
  git(workspace, "commit", "-q", "-m", "base");
});
afterEach(() => rmSync(policyRoot, { recursive: true, force: true }));

function worker(source, options = {}) {
  const script = join(policyRoot, "worker.mjs");
  writeFileSync(script, source);
  return runAgent({ cwd: workspace, command: `"${process.execPath}" "${script}"`, ...options });
}

function denied(result, path = "policy/guard.json") {
  assert.equal(result.ok, false);
  assert.equal(result.exitCode, 4);
  assert.equal(result.violation, "TOUCH_HUMAN_ONLY");
  assert.equal(result.workerExitCode, 0);
  assert.ok(result.forbidden.includes(path));
}

test("a worker cannot omit a protected edit from its claimed file list", () => {
  const result = worker(`import {writeFileSync} from "node:fs";writeFileSync("policy/guard.json","changed");console.log("worker output");`, { modifiedFiles: [] });
  denied(result);
  assert.match(result.stdout, /worker output/);
});

test("ordinary source edits pass and preserve worker diagnostics", () => {
  const result = worker('import {writeFileSync} from "node:fs";writeFileSync("code.mjs","export const value=2;\\n");console.log("ok");');
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(result.changedFiles.includes("code.mjs"));
  assert.match(result.stdout, /ok/);
});

test("ignored untracked protected files are still checked", () => {
  const result = worker('import {writeFileSync,mkdirSync} from "node:fs";writeFileSync(".gitignore",".github/\\n");mkdirSync(".github/workflows",{recursive:true});writeFileSync(".github/workflows/hidden.yml","changed");');
  denied(result, ".github/workflows/hidden.yml");
});

test("protected deletions are measured", () => {
  denied(worker('import {unlinkSync} from "node:fs";unlinkSync("policy/guard.json");'));
});

test("renaming a protected file retains its original protected path", () => {
  denied(worker('import {renameSync} from "node:fs";renameSync("policy/guard.json","moved.json");'));
});

test("committed edits cannot hide behind a clean worker index", () => {
  denied(worker('import {writeFileSync} from "node:fs";import {execFileSync} from "node:child_process";writeFileSync("policy/guard.json","changed");execFileSync("git",["add","-A"]);execFileSync("git",["commit","-qm","worker"]);'));
});

test("staged protected edits are checked even when final file bytes match base", () => {
  denied(worker('import {writeFileSync} from "node:fs";import {execFileSync} from "node:child_process";writeFileSync("policy/guard.json","changed");execFileSync("git",["add","policy/guard.json"]);writeFileSync("policy/guard.json","base\\n");'));
});

test("assume-unchanged flags cannot hide protected edits", () => {
  denied(worker('import {writeFileSync} from "node:fs";import {execFileSync} from "node:child_process";execFileSync("git",["update-index","--assume-unchanged","policy/guard.json"]);writeFileSync("policy/guard.json","changed");'));
});

test("worker clean filters cannot conceal changed physical bytes", () => {
  denied(worker('import {writeFileSync} from "node:fs";import {execFileSync} from "node:child_process";writeFileSync(".gitattributes","policy/* filter=hide\\n");execFileSync("git",["config","filter.hide.clean","echo base"]);writeFileSync("policy/guard.json","changed");'));
});

test("a missing Git baseline refuses dispatch", () => {
  const result = worker('console.log("should not execute");', { cwd: policyRoot });
  assert.equal(result.ok, false);
  assert.equal(result.exitCode, 4);
  assert.equal(result.violation, "WORKSPACE_UNVERIFIED");
  assert.equal(result.stdout, undefined);
});

test("post-run Git failure refuses success while retaining output", () => {
  const result = worker('import {writeFileSync} from "node:fs";writeFileSync(".git/HEAD","invalid");console.log("worker finished");');
  assert.equal(result.ok, false);
  assert.equal(result.exitCode, 4);
  assert.equal(result.workerExitCode, 0);
  assert.equal(result.violation, "WORKSPACE_UNVERIFIED");
  assert.match(result.stdout, /worker finished/);
});


test("newline-containing file names remain intact during measurement", { skip: process.platform === "win32" }, () => {
  const path = "policy/line\nbreak.json";
  const result = worker('import {writeFileSync} from "node:fs";writeFileSync(' + JSON.stringify(path) + ',"changed");');
  denied(result, path);
});
