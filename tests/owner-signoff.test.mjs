// Owner sign-off on a PR head: the `reviewed:<sha>` label, its CI lookup, and
// the evaluator cap it relies on (needs_human at best, other rules still run).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";
import { findOwnerSignoff, main, parseEvents, signoffLabel } from "../scripts/ci-owner-signoff.mjs";
import { run } from "../scripts/owner-signoff.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HEAD = "a".repeat(40);
const OLD = "b".repeat(40);
const CTX = { owner: "ahmed-3m", headSha: HEAD };

let nextId = 1;
function event(type, { sha = HEAD, login = "ahmed-3m", userType = "User", name } = {}) {
  return {
    id: nextId++,
    event: type,
    actor: { login, type: userType },
    label: { name: name ?? `reviewed:${sha}` },
  };
}

describe("owner sign-off: findOwnerSignoff", () => {
  it("accepts the owner's label on the exact head commit, whatever the login's case", () => {
    assert.equal(findOwnerSignoff([event("labeled")], CTX), "ahmed-3m");
    assert.equal(findOwnerSignoff([event("labeled", { login: "Ahmed-3M" })], CTX), "Ahmed-3M");
  });

  it("a push voids it: a label naming an older commit does not count", () => {
    assert.equal(findOwnerSignoff([event("labeled", { sha: OLD })], CTX), null);
  });

  it("ignores anyone but the owner, and bots using the owner's name", () => {
    assert.equal(findOwnerSignoff([event("labeled", { login: "someone-else" })], CTX), null);
    assert.equal(findOwnerSignoff([event("labeled", { userType: "Bot" })], CTX), null);
  });

  it("ignores other labels, short SHAs and non-label events", () => {
    assert.equal(findOwnerSignoff([event("labeled", { name: "reviewed" })], CTX), null);
    assert.equal(findOwnerSignoff([event("labeled", { name: `reviewed:${HEAD.slice(0, 7)}` })], CTX), null);
    assert.equal(findOwnerSignoff([{ id: 1, event: "commented", actor: { login: "ahmed-3m", type: "User" } }], CTX), null);
  });

  it("removing the label voids it, and only the owner can restore it", () => {
    assert.equal(findOwnerSignoff([event("labeled"), event("unlabeled")], CTX), null);
    assert.equal(findOwnerSignoff([event("labeled"), event("unlabeled"), event("labeled")], CTX), "ahmed-3m");
    assert.equal(
      findOwnerSignoff([event("labeled"), event("unlabeled"), event("labeled", { login: "someone-else" })], CTX),
      null,
    );
    assert.equal(findOwnerSignoff([event("labeled"), event("unlabeled", { login: "someone-else" })], CTX), null);
  });

  it("orders events by id, not by the order the API returned them", () => {
    const labeled = event("labeled");
    const removed = event("unlabeled");
    assert.equal(findOwnerSignoff([removed, labeled], CTX), null);
  });

  it("fails closed on missing or malformed context", () => {
    assert.equal(findOwnerSignoff(null, CTX), null);
    assert.equal(findOwnerSignoff([event("labeled")], { owner: "", headSha: HEAD }), null);
    assert.equal(findOwnerSignoff([event("labeled")], { owner: "ahmed-3m", headSha: "abc" }), null);
    assert.throws(() => signoffLabel("abc"), /full 40-character/);
  });
});

describe("owner sign-off: main", () => {
  it("writes the owner output only for a real sign-off and fails closed on bad input", () => {
    const dir = mkdtempSync(join(tmpdir(), "mirql-signoff-"));
    try {
      const eventsPath = join(dir, "events.jsonl");
      const outPath = join(dir, "out.txt");
      const env = { EVENTS_PATH: eventsPath, HEAD_SHA: HEAD, REPO_OWNER: "ahmed-3m", GITHUB_OUTPUT: outPath };

      writeFileSync(eventsPath, `${JSON.stringify(event("labeled"))}\n\n`);
      writeFileSync(outPath, "");
      assert.equal(main(env), 0);
      assert.equal(readFileSync(outPath, "utf8"), "owner=ahmed-3m\n");

      writeFileSync(eventsPath, `${JSON.stringify(event("labeled", { sha: OLD }))}\n`);
      writeFileSync(outPath, "");
      assert.equal(main(env), 0);
      assert.equal(readFileSync(outPath, "utf8"), "");

      writeFileSync(eventsPath, "not json\n");
      assert.equal(main(env), 1, "unreadable events fail closed");
      assert.equal(main({ ...env, EVENTS_PATH: join(dir, "missing") }), 1, "missing file fails closed");
      for (const name of ["EVENTS_PATH", "HEAD_SHA", "REPO_OWNER"]) {
        assert.equal(main({ ...env, [name]: undefined }), 1, `${name} is required`);
      }
      assert.deepEqual(parseEvents("\n"), []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("owner sign-off: evaluator cap", () => {
  const doc = (overrides = {}) => ({
    schema: "outcome/v1",
    pr: { number: 1, author: "ahmed-3m", kind: "bugfix" },
    diff_stat: { files_changed: ["policy/paths.yaml"] },
    proof: { causal_cycle_completed: true },
    evidence: { forbidden_paths_touched: [], tests_deleted: [] },
    anti_cheat: { violations_count: 0, flags: [] },
    phi: { phi_base: 10, phi_head: 9, delta_phi: -1 },
    surface: { uncited_commands: [], delta_count: 0 },
    ...overrides,
  });

  it("clears MP-001 to needs_human, never auto_merge", () => {
    const res = evaluatePullRequest(doc(), { rootDir: ROOT, humanOnlyReviewer: "ahmed-3m" });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.human_only_reviewer, "ahmed-3m");
  });

  it("does not stop the other rules from rejecting", () => {
    const res = evaluatePullRequest(
      doc({ evidence: { forbidden_paths_touched: [], tests_deleted: ["tests/feature.test.mjs"] } }),
      { rootDir: ROOT, humanOnlyReviewer: "ahmed-3m" },
    );
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "TEST_DELETED");
  });

  it("does not clear a change to reviewer config or agent instructions", () => {
    const res = evaluatePullRequest(
      doc({ diff_stat: { files_changed: ["AGENTS.md"] } }),
      { rootDir: ROOT, humanOnlyReviewer: "ahmed-3m" },
    );
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "TOUCH_HUMAN_ONLY");
  });
});

describe("owner sign-off: Phi growth (Law 13)", () => {
  const grow = (overrides = {}) => ({
    schema: "outcome/v1",
    pr: { number: 1, author: "ahmed-3m", kind: "bugfix" },
    diff_stat: { files_changed: ["packages/run/journey.mjs"] },
    proof: { causal_cycle_completed: true },
    evidence: { forbidden_paths_touched: [], tests_deleted: [] },
    anti_cheat: { violations_count: 0, flags: [] },
    phi: { phi_base: 10, phi_head: 51, delta_phi: 41 },
    surface: { uncited_commands: [], delta_count: 0 },
    ...overrides,
  });
  const check = (d, opts = {}) => evaluatePullRequest(d, { rootDir: ROOT, ...opts });
  const signed = { ownerSignoff: "ahmed-3m" };

  it("stays rejected with no sign-off and with only an AI approval", () => {
    for (const opts of [{}, { humanOnlyReviewer: "coderabbitai[bot]" }]) {
      const res = check(grow(), opts);
      assert.equal(res.verdict, "reject");
      assert.equal(res.violation, "PHI_INCREASE");
    }
  });

  it("clears to needs_human with the owner's sign-off, never better", () => {
    const res = check(grow(), signed);
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.rule, "LAW_13");
    assert.equal(res.violation, "PHI_INCREASE");
    assert.equal(res.owner_signoff, "ahmed-3m");
    assert.equal(res.checks.phi, false);
  });

  it("still reports humanOnly paths when a signed-off PR also touches them", () => {
    const res = check(grow({ diff_stat: { files_changed: ["policy/paths.yaml"] } }), { ...signed, humanOnlyReviewer: "ahmed-3m" });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.rule, "LAW_13");
    assert.deepEqual(res.forbidden_paths, ["policy/paths.yaml"]);
  });

  it("still applies the proof rules", () => {
    const suite = check(grow({ proof: { suite_pass_base: true, suite_pass_head: true } }), signed);
    assert.equal(suite.verdict, "needs_human");
    assert.equal(suite.rule, "LAW_16");
    assert.match(suite.detail, /\+41/);
    const none = check(grow({ proof: {} }), signed);
    assert.equal(none.verdict, "reject");
    assert.equal(none.violation, "MISSING_PROOF");
  });

  it("does not excuse a refactor that grows Phi", () => {
    const res = check(grow({ pr: { number: 1, author: "ahmed-3m", kind: "refactor" } }), signed);
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "PHI_INCREASE");
  });

  it("does not excuse a deleted test, reviewer config or a malformed login", () => {
    const deleted = check(grow({ evidence: { forbidden_paths_touched: [], tests_deleted: ["tests/a.test.mjs"] } }), signed);
    assert.equal(deleted.violation, "TEST_DELETED");
    const config = check(grow({ diff_stat: { files_changed: ["AGENTS.md"] } }), { ...signed, humanOnlyReviewer: "ahmed-3m" });
    assert.equal(config.verdict, "reject");
    assert.equal(check(grow(), { ownerSignoff: "--output=x" }).verdict, "reject");
  });

  it("m check --owner-signoff reaches the evaluator and never exits 0", () => {
    const res = spawnSync(
      process.execPath,
      [join(ROOT, "bin", "mirql.mjs"), "m", "check", "--pr", JSON.stringify(grow()), "--owner-signoff", "ahmed-3m"],
      { cwd: ROOT, encoding: "utf8" },
    );
    assert.equal(JSON.parse(res.stdout.trim().split(/\r?\n/).pop()).verdict, "needs_human");
    assert.notEqual(res.status, 0);
  });
});

describe("owner sign-off: helper command", () => {
  function harness(answer) {
    const calls = [];
    const logs = [];
    const runGh = (args) => {
      calls.push(args);
      return args[0] === "pr"
        ? JSON.stringify({ headRefOid: HEAD, title: "A fix", files: [{ path: "scripts/x.mjs" }] })
        : "";
    };
    return { calls, logs, deps: { runGh, ask: async () => answer, isTty: true, log: (l) => logs.push(l) } };
  }

  it("shows the head commit and files, then adds the label after a typed yes", async () => {
    const h = harness("yes");
    assert.equal(await run(["67"], h.deps), 0);
    assert.ok(h.logs.includes(`Head commit: ${HEAD}`));
    assert.ok(h.logs.includes("  scripts/x.mjs"));
    assert.deepEqual(h.calls[1].slice(0, 3), ["label", "create", `reviewed:${HEAD}`]);
    assert.deepEqual(h.calls[2], ["api", "--method", "POST", "repos/{owner}/{repo}/issues/67/labels", "-f", `labels[]=reviewed:${HEAD}`]);
  });

  it("adds nothing without a typed yes", async () => {
    for (const answer of ["", "n", "y"]) {
      const h = harness(answer);
      assert.equal(await run(["67"], h.deps), 1);
      assert.equal(h.calls.length, 1, "only the read happened");
    }
  });

  it("refuses without a terminal, and on a bad PR number, before calling gh", async () => {
    const noTty = harness("yes");
    assert.equal(await run(["67"], { ...noTty.deps, isTty: false }), 2);
    assert.equal(noTty.calls.length, 0);
    for (const argv of [[], ["abc"], ["67", "68"], ["-1"]]) {
      const h = harness("yes");
      assert.equal(await run(argv, h.deps), 2);
      assert.equal(h.calls.length, 0);
    }
  });
});
