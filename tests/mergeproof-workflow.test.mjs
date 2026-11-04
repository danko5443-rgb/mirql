// tests/mergeproof-workflow.test.mjs — textual pins on the CI merge gate.
//
// The workflow file .github/workflows/mergeproof.yml IS the security
// boundary: it runs from the base branch via pull_request_target, it is the
// only thing allowed to hold the token, and it must never execute candidate
// files. These tests parse the YAML as plain text (zero dependencies) so a
// regression in any of those invariants fails locally instead of in review.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wf = readFileSync(join(ROOT, ".github", "workflows", "mergeproof.yml"), "utf8");

const JOBS = ["candidate-tests", "base-suite", "notary"];

/** The text of one job block, from its `  <id>:` line to the next job or top-level key. */
function jobBlock(id) {
  const start = wf.match(new RegExp(`^ {2}${id}:\\s*$`, "m"));
  assert.ok(start, `job '${id}' must exist in the workflow`);
  const after = wf.slice(start.index + start[0].length);
  const end = after.search(/^ {2}\S|^\S/m);
  return end === -1 ? after : after.slice(0, end);
}

/** The step blocks (6-space `- ` items) of a job block. */
function stepsOf(block) {
  const chunks = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^ {6}- /.test(line)) chunks.push([line]);
    else if (chunks.length > 0) chunks[chunks.length - 1].push(line);
  }
  return chunks.map((c) => c.join("\n"));
}

/** The shell script text of every `run:` key in a job block. */
function runScripts(block) {
  const scripts = [];
  let current = null;
  for (const line of block.split(/\r?\n/)) {
    if (/^ {8}run:/.test(line)) {
      current = [line.replace(/^ {8}run:\s*/, "")];
      scripts.push(current);
    } else if (current !== null) {
      if (/^\s*$/.test(line) || /^ {10}\S/.test(line)) current.push(line);
      else current = null;
    }
  }
  return scripts.map((l) => l.join("\n"));
}

describe("mergeproof workflow: self-gate-proof structure", () => {
  it("all three jobs exist (guard against vacuous passes below)", () => {
    for (const id of JOBS) jobBlock(id);
  });

  it("triggers only on pull_request_target, so a PR cannot rewrite its own gate", () => {
    // pull_request / pull_request_review would run the PR's own copy of this
    // file; pull_request_target always runs the base branch's copy. The
    // literal `pull_request:` must not match `pull_request_target:`.
    assert.match(wf, /^ {2}pull_request_target:\s*$/m);
    assert.doesNotMatch(wf, /^\s*pull_request:\s*$/m);
    assert.doesNotMatch(wf, /^\s*pull_request_review:\s*$/m);
    assert.match(wf, /types:\s*\[opened,\s*synchronize,\s*reopened,\s*ready_for_review,\s*labeled\]/);
    // The workflow must document that a review does not re-trigger the check.
    assert.match(wf, /does NOT re-trigger this check/);
  });

  it("every actions/checkout keeps persist-credentials: false (no token in any .git/config)", () => {
    let checkouts = 0;
    for (const id of JOBS) {
      for (const step of stepsOf(jobBlock(id))) {
        if (/uses:\s*actions\/checkout@/.test(step)) {
          checkouts += 1;
          assert.match(
            step,
            /persist-credentials:\s*false/,
            `${id}: every checkout must set persist-credentials: false`,
          );
        }
      }
    }
    assert.ok(checkouts >= 5, `expected at least 5 checkouts, found ${checkouts}`);
  });

  it("candidate-tests and base-suite hold contents: read and nothing else", () => {
    // contents: read is the minimum: checkout of a private repository fails
    // without it, which would make both suite results permanently false.
    for (const id of ["candidate-tests", "base-suite"]) {
      assert.match(jobBlock(id), /^ {4}permissions:\n {6}contents: read\n {4}runs-on:/m, id);
    }
    assert.match(wf, /^permissions: \{\}$/m, "workflow default must grant nothing");
    assert.doesNotMatch(wf, /:\s*write\s*$/m, "no job may hold a write permission");
    assert.doesNotMatch(wf, /secrets\./, "no job may reference a secret");
  });

  it("never uses actions/cache or a cache: key", () => {
    assert.doesNotMatch(wf, /uses:\s*actions\/cache/);
    assert.doesNotMatch(wf, /^\s*cache:/m);
  });

  it("keeps the conscience gate job name exactly stable (branch protection targets it)", () => {
    assert.match(jobBlock("notary"), /^ {4}name: Mergeproof Conscience Gate$/m);
  });

  it("the notary job never executes candidate files", () => {
    const block = jobBlock("notary");
    // No step may cd into the candidate tree.
    assert.doesNotMatch(block, /^ {8}working-directory:\s*candidate\s*$/m);
    // No shell command may run a file under candidate/ (or any npm command).
    for (const script of runScripts(block)) {
      assert.doesNotMatch(script, /\bnode\s+\S*candidate\//, "node must never run a file under candidate/");
      assert.doesNotMatch(script, /\bnpm\b/, "npm must never run in the notary job");
    }
    // Every node script the notary runs is a base-notary file, or the base
    // bin/mirql.mjs with the working directory pinned to the base tree.
    for (const step of stepsOf(block)) {
      for (const m of step.matchAll(/\bnode\s+([^\s"']+\.mjs)\b/g)) {
        const path = m[1];
        if (path.startsWith("base-notary/")) continue;
        if (path === "bin/mirql.mjs") {
          assert.match(step, /^ {8}working-directory:\s*base-notary\s*$/m,
            "bin/mirql.mjs may only run with the base tree as cwd (base policy)");
          continue;
        }
        assert.fail(`notary runs a script outside base-notary: ${path}`);
      }
    }
    // And no bootstrap fallback to candidate copies anywhere in the file.
    assert.doesNotMatch(wf, /node candidate\//);
    assert.doesNotMatch(wf, /candidate\/scripts/);
  });

  it("the notary runs after both measurement jobs whatever their result", () => {
    const block = jobBlock("notary");
    assert.match(block, /^ {4}needs:\s*\[candidate-tests,\s*base-suite\]\s*$/m);
    assert.match(block, /^ {4}if:\s*always\(\)\s*$/m);
  });

  it("the notary holds read-only permissions only", () => {
    const block = jobBlock("notary");
    assert.match(block, /^ {6}contents:\s*read\s*$/m);
    assert.match(block, /^ {6}pull-requests:\s*read\s*$/m);
    assert.doesNotMatch(block, /:\s*write\s*$/m);
  });

  it("suite outcomes are measured job results, never steps of the notary VM", () => {
    assert.match(wf, /SUITE_PASS_BASE:\s*\$\{\{ needs\.base-suite\.result == 'success' \}\}/);
    assert.match(wf, /SUITE_PASS_HEAD:\s*\$\{\{ needs\.candidate-tests\.result == 'success' \}\}/);
  });

  it("needs_human/conformance_pass pass only with an AI approver; everything else fails", () => {
    const step = stepsOf(jobBlock("notary")).find((s) => /Evaluate Mergeproof/.test(s));
    assert.ok(step, "evaluate step must exist");
    assert.match(step, /needs_human\|conformance_pass\)/);
    assert.match(step, /if \[ -n "\$AI_APPROVER" \]/);
    assert.match(step, /::error::mergeproof verdict: \$verdict requires review/);
    assert.match(step, /exit 1/);
  });
});
