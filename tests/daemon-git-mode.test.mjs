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

/** A filter script that leaves a marker, so a test can tell whether Git ran it. */
function plantedFilter(p) {
  const marker = join(p.root, "filter-ran").replaceAll("\\", "/");
  const script = join(p.root, "filter.mjs").replaceAll("\\", "/");
  writeFileSync(script, `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(marker)}, "1");
process.stdin.pipe(process.stdout);
`);
  return { marker, command: `node '${script}'` };
}

/** A hook body that leaves a marker, so a test can tell whether Git ran it. */
function plantedHook(p) {
  const marker = join(p.root, "hook-ran").replaceAll("\\", "/");
  return { marker, body: `#!/bin/sh\necho 1 > "${marker}"\n` };
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

  it("the planted filter does run under plain Git, so the tests below are not vacuous", () => {
    const p = project();
    const { marker, command } = plantedFilter(p);
    const repo = join(p.root, "control");
    git(p.root, "init", "-q", repo);
    git(repo, "config", "filter.pwn.clean", command);
    writeFileSync(join(repo, ".gitattributes"), "*.mjs filter=pwn\n");
    writeFileSync(join(repo, "a.mjs"), "export {};\n");
    git(repo, "add", "-A");
    assert.equal(existsSync(marker), true);
  });

  it("a filter in the worker's own Git store never runs in the host", () => {
    const p = project();
    issue(p);
    const before = readFileSync(join(p.workspace, ".git", "config"));
    const { marker, command } = plantedFilter(p);
    daemon(p, worker(p, "own-store", `
execSync(${JSON.stringify(`git config filter.pwn.clean "${command}"`)});
mkdirSync(".git/info", { recursive: true });
writeFileSync(".git/info/attributes", "*.mjs filter=pwn\\n");
writeFileSync("src/.gitattributes", "*.mjs filter=pwn\\n");
${WRITE_FIX}
`));

    const [outcome] = outcomes(p);
    // Staged and verified without the filter; the stray attributes file is what the verifier refuses.
    assert.equal(outcome.rule, "UNNECESSARY_CHANGE", JSON.stringify(outcome));
    assert.equal(git(p.workspace, "show", `${outcome.candidate_commit}:src/app.mjs`), FIX.trim());
    assert.equal(existsSync(marker), false, "the host must not run a filter the worker planted");
    assert.deepEqual(readFileSync(join(p.workspace, ".git", "config")), before);
    assertWorkspaceUntouched(p);
  });

  it("a smudge filter planted by one attempt does not reach the retry", () => {
    const p = project();
    issue(p);
    const { marker, command } = plantedFilter(p);
    daemon(p, worker(p, "smudge", `
execSync(${JSON.stringify(`git config filter.pwn.smudge "${command}"`)});
mkdirSync(".git/info", { recursive: true });
writeFileSync(".git/info/attributes", "* filter=pwn\\n");
process.exit(7);
`));
    daemon(p, worker(p, "after-smudge", WRITE_FIX));

    const [first, second] = outcomes(p);
    assert.equal(first.rule, "WORKER_FAILED");
    assert.equal(second.rule, "MP-000", JSON.stringify(second));
    assert.equal(existsSync(marker), false, "the host must not run a filter the worker planted");
  });

  it("the planted hook does run under plain Git, so the tests below are not vacuous", () => {
    const p = project();
    const { marker, body } = plantedHook(p);
    const hook = join(p.workspace, ".git", "hooks", "post-index-change");
    mkdirSync(dirname(hook), { recursive: true });
    writeFileSync(hook, body, { mode: 0o755 });
    git(p.workspace, "read-tree", "HEAD");
    assert.equal(existsSync(marker), true);
  });

  it("a hook in the worker's own Git store never runs in the host", () => {
    const p = project();
    issue(p);
    const { marker, body } = plantedHook(p);
    daemon(p, worker(p, "own-hook", `
mkdirSync(".git/hooks", { recursive: true });
writeFileSync(".git/hooks/post-index-change", ${JSON.stringify(body)}, { mode: 0o755 });
${WRITE_FIX}
`));

    assert.equal(outcomes(p)[0].rule, "MP-000", JSON.stringify(outcomes(p)[0]));
    assert.equal(existsSync(marker), false, "the host must not run a hook the worker planted");
    assertWorkspaceUntouched(p);
  });

  it("a hooks directory the worker configures never runs in the host", () => {
    const p = project();
    issue(p);
    const { marker, body } = plantedHook(p);
    const hooks = join(p.root, "planted-hooks").replaceAll("\\", "/");
    mkdirSync(hooks);
    writeFileSync(join(hooks, "post-index-change"), body, { mode: 0o755 });
    daemon(p, worker(p, "hooks-path", `
execSync(${JSON.stringify(`git config core.hooksPath "${hooks}"`)});
${WRITE_FIX}
`));

    assert.equal(outcomes(p)[0].rule, "MP-000", JSON.stringify(outcomes(p)[0]));
    assert.equal(existsSync(marker), false, "the host must not run a hook the worker configured");
    assertWorkspaceUntouched(p);
  });

  it("a promisor remote the worker configures never runs in the host", () => {
    const p = project();
    issue(p);
    const marker = join(p.root, "uploadpack-ran").replaceAll("\\", "/");
    const script = join(p.root, "uploadpack.mjs").replaceAll("\\", "/");
    writeFileSync(script, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "1");\nprocess.exit(1);\n`);
    // A commit whose tree is missing makes Git fetch it from the promisor remote.
    daemon(p, worker(p, "promisor", `
import { chmodSync, rmSync } from "node:fs";
${WRITE_FIX}
const run = (command) => execSync(command, { encoding: "utf8" }).trim();
run("git add -A");
run('git -c user.name=w -c user.email=w@mirql.local commit -qm worker');
const tree = run('git rev-parse "HEAD^{tree}"');
const object = ".git/objects/" + tree.slice(0, 2) + "/" + tree.slice(2);
chmodSync(object, 0o644);
rmSync(object);
run("git config core.repositoryformatversion 1");
run("git config extensions.partialClone evil");
run("git config remote.evil.promisor true");
run("git config remote.evil.url .");
run(${JSON.stringify(`git config remote.evil.uploadpack "node '${script}'"`)});
`));

    assert.notEqual(outcomes(p)[0].verdict, "auto_merge", JSON.stringify(outcomes(p)[0]));
    assert.equal(existsSync(marker), false, "the host must not run a command the worker configured");
    assertWorkspaceUntouched(p);
  });

  it("refuses and undoes a write to the workspace's Git files by absolute path", () => {
    const p = project();
    issue(p);
    const gitDir = join(p.workspace, ".git");
    const before = readFileSync(join(gitDir, "config"));
    const { marker, command } = plantedFilter(p);
    const hook = join(gitDir, "hooks", "post-checkout");
    const attributes = join(gitDir, "info", "attributes");
    const hadAttributes = existsSync(attributes);
    daemon(p, worker(p, "cross-path", `
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(join(gitDir, "config"))}, ${JSON.stringify(`[filter "pwn"]\n\tsmudge = ${command}\n\tclean = ${command}\n`)});
mkdirSync(${JSON.stringify(dirname(attributes))}, { recursive: true });
writeFileSync(${JSON.stringify(attributes)}, "* filter=pwn\\n");
mkdirSync(${JSON.stringify(dirname(hook))}, { recursive: true });
writeFileSync(${JSON.stringify(hook)}, "#!/bin/sh\\nexit 0\\n");
${WRITE_FIX}
`));

    assert.equal(outcomes(p)[0].rule, "WORKER_TAMPERED_GIT");
    assert.deepEqual(readFileSync(join(gitDir, "config")), before);
    assert.equal(existsSync(hook), false);
    assert.equal(existsSync(attributes), hadAttributes);
    assert.equal(existsSync(marker), false, "the host must not run a filter the worker planted");
    assert.equal(git(p.workspace, "for-each-ref", "refs/mirql/attempts"), "");
    assertWorkspaceUntouched(p);
  });

  it("refuses and undoes a write to a configuration file the workspace includes", () => {
    const p = project();
    issue(p);
    const included = join(p.root, "included.gitconfig").replaceAll("\\", "/");
    const original = "[user]\n\tname = operator\n";
    writeFileSync(included, original);
    git(p.workspace, "config", "include.path", included);
    const { marker, command } = plantedFilter(p);
    daemon(p, worker(p, "included", `
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(included)}, ${JSON.stringify(`[filter "pwn"]\n\tclean = ${command}\n`)});
writeFileSync("src/.gitattributes", "*.mjs filter=pwn\\n");
${WRITE_FIX}
`));

    assert.equal(outcomes(p)[0].rule, "WORKER_TAMPERED_GIT");
    assert.equal(readFileSync(included, "utf8"), original);
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
