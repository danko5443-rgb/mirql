// tests/mergeproof-workflow.test.mjs — textual pins on the CI merge gate.
//
// The workflow file .github/workflows/mergeproof.yml IS the security
// boundary: it runs from the base branch via pull_request_target, it is the
// only thing allowed to hold the token, and it must never execute candidate
// files. Those run in .github/workflows/mergeproof-candidate.yml, on
// pull_request. These tests parse the YAML as plain text (zero dependencies) so
// a regression in any of those invariants fails locally instead of in review.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Normalized because Git for Windows checks this file out with CRLF by default.
const readWorkflow = (name) => readFileSync(join(ROOT, ".github", "workflows", name), "utf8").replace(/\r\n/g, "\n");
const wf = readWorkflow("mergeproof.yml");
const candidateWf = readWorkflow("mergeproof-candidate.yml");

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
    assert.ok(checkouts >= 4, `expected at least 4 checkouts, found ${checkouts}`);
  });

  it("the measurement jobs hold only the read permissions they need", () => {
    // contents: read is the minimum: checkout of a private repository fails
    // without it, which would make both suite results permanently false.
    // actions: read is what lets candidate-tests list the candidate suite's runs.
    assert.match(jobBlock("base-suite"), /^ {4}permissions:\n {6}contents: read\n {4}runs-on:/m);
    assert.match(jobBlock("candidate-tests"), /^ {4}permissions:\n {6}contents: read\n {6}actions: read\n {4}runs-on:/m);
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

  it("no job in this base-context workflow runs candidate code", () => {
    assert.doesNotMatch(wf, /^ {8}working-directory:\s*candidate\s*$/m);
    assert.doesNotMatch(wf, /MIRQL_TEST_ROOT/);
    // The only checkout of the PR head is the notary's, as data.
    for (const id of ["candidate-tests", "base-suite"]) {
      assert.doesNotMatch(jobBlock(id), /pull_request\.head\.sha \}\}\n\s+persist-credentials/, id);
      assert.doesNotMatch(jobBlock(id), /path: candidate/, id);
    }
  });

  it("candidate-tests only reads the candidate suite's result, from the base copy of the script", () => {
    const block = jobBlock("candidate-tests");
    assert.deepEqual(runScripts(block).map((s) => s.trim()), ["node base-notary/scripts/ci-candidate-result.mjs"]);
    assert.match(block, /^ {10}HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \}\}$/m);
    assert.match(block, /^ {4}timeout-minutes: \d+$/m, "a poller must not run for the 6-hour default");
    // The job name is what scripts/pr-court.mjs looks the suite result up by.
    assert.match(block, /^ {4}name: Candidate Tests \(advisory\)$/m);
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

  it("needs_human/conformance_pass pass only with an owner sign-off or AI approver; everything else fails", () => {
    const step = stepsOf(jobBlock("notary")).find((s) => /Evaluate Mergeproof/.test(s));
    assert.ok(step, "evaluate step must exist");
    assert.match(step, /needs_human\|conformance_pass\)/);
    assert.match(step, /REVIEWER="\$\{OWNER_SIGNOFF:-\$AI_APPROVER\}"/);
    assert.match(step, /if \[ -n "\$REVIEWER" \]/);
    assert.match(step, /::error::mergeproof verdict: \$verdict requires review/);
    assert.match(step, /exit 1/);
  });

  it("owner sign-off comes from the base copy of the script, checked against the repo owner and head", () => {
    const step = stepsOf(jobBlock("notary")).find((s) => /Find Owner Sign-off/.test(s));
    assert.ok(step, "owner sign-off step must exist");
    assert.match(step, /node base-notary\/scripts\/ci-owner-signoff\.mjs/);
    assert.match(step, /REPO_OWNER: \$\{\{ github\.repository_owner \}\}/);
    assert.match(step, /HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
    const evaluate = stepsOf(jobBlock("notary")).find((s) => /Evaluate Mergeproof/.test(s));
    assert.match(evaluate, /OWNER_SIGNOFF: \$\{\{ steps\.owner_signoff\.outputs\.owner \}\}/);
    assert.match(evaluate, /if \[ -n "\$OWNER_SIGNOFF" \]; then\s+reviewer_args\+=\(--owner-signoff "\$OWNER_SIGNOFF"\)/);
    assert.doesNotMatch(evaluate, /--owner-signoff "\$(REVIEWER|AI_APPROVER)"/);
  });
});

describe("mergeproof candidate workflow: PR code stays out of the base context", () => {
  it("triggers only on pull_request, never in the base-branch context", () => {
    assert.match(candidateWf, /^ {2}pull_request:\n {4}types: \[opened, synchronize, reopened, ready_for_review\]$/m);
    assert.doesNotMatch(candidateWf, /^\s*pull_request_target:/m);
    assert.doesNotMatch(candidateWf, /^\s*workflow_run:/m);
    assert.doesNotMatch(candidateWf, /^\s*issue_comment:/m);
  });

  it("the file the reader looks up is this one, on this event", () => {
    const reader = readFileSync(join(ROOT, "scripts", "ci-candidate-result.mjs"), "utf8");
    assert.match(reader, /const WORKFLOW_FILE = "mergeproof-candidate\.yml";/);
    assert.match(reader, /r\?\.event === "pull_request"/);
  });

  it("holds contents: read and nothing else: no write, no secret, no token, no cache", () => {
    assert.match(candidateWf, /^permissions:\n {2}contents: read\n\n/m);
    assert.doesNotMatch(candidateWf, /:\s*write\s*$/m);
    assert.doesNotMatch(candidateWf, /secrets\./);
    assert.doesNotMatch(candidateWf, /github\.token/);
    assert.doesNotMatch(candidateWf, /uses:\s*actions\/cache/);
    assert.doesNotMatch(candidateWf, /^\s*cache:/m);
    assert.doesNotMatch(candidateWf, /upload-artifact/);
  });

  it("every checkout keeps persist-credentials: false", () => {
    const checkouts = candidateWf.split(/^ {6}- /m).filter((s) => /uses:\s*actions\/checkout@/.test(s));
    assert.equal(checkouts.length, 2);
    for (const step of checkouts) assert.match(step, /persist-credentials:\s*false/);
  });

  it("the base notary's runner judges the candidate tree (Law 7)", () => {
    assert.match(candidateWf, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}\n\s+persist-credentials: false\n\s+path: candidate/);
    assert.match(candidateWf, /ref: \$\{\{ github\.event\.pull_request\.base\.sha \}\}\n\s+persist-credentials: false\n\s+path: base-notary/);
    assert.match(candidateWf, /working-directory: candidate\n\s+run: MIRQL_TEST_ROOT="\$PWD" node \.\.\/base-notary\/scripts\/run-tests\.mjs/);
    assert.doesNotMatch(candidateWf, /node candidate\//);
  });

  it("is bounded, so the reader's wait can outlast it", () => {
    const [, suite] = candidateWf.match(/^ {4}timeout-minutes: (\d+)$/m) ?? [];
    assert.equal(Number(suite), 15);
    const [, reader] = jobBlock("candidate-tests").match(/^ {4}timeout-minutes: (\d+)$/m) ?? [];
    assert.ok(Number(reader) > 20, "the reader's job must outlast its own 20-minute wait");
  });
});
