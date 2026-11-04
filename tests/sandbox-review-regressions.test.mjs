// tests/sandbox-review-regressions.test.mjs — PR 69 review findings: staged
// workspace access for the container UID, symlink traversal and lost deletions
// during workspace sync, git-mode verification under a sandbox request, and
// ledger appends over corrupted history.
//
// HOME, USERPROFILE and MIRQL_TRUST_ROOT are isolated: the real ~/.mirql-trust
// is never touched.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { git } from "./helpers/git.mjs";
import { provisionTestTrust } from "./helpers/keyring.mjs";

import { checkSwallowedExceptions, sha256 } from "../packages/core/index.mjs";
import { readLedgerHeadSidecar } from "../packages/core/ledger-verify.mjs";
import { EXIT_CODES } from "../packages/core/index.mjs";
import { runAgent } from "../packages/run/agent.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "../packages/run/ledger.mjs";
import { verifyAttempt } from "../packages/run/verify.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { sendIntent } from "../packages/inbox/send.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENV_KEYS = ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "MIRQL_TRUST_ROOT", "MIRQL_HUMAN_KEY", "MIRQL_HUMAN_PASSPHRASE", "MIRQL_ALLOW_PLAINTEXT_OWNER_KEY", "MIRQL_SUITE_TIMEOUT_MS"];
const savedEnv = {};
let envRoot;

before(() => {
  envRoot = mkdtempSync(join(tmpdir(), "mirql-sandbox-review-"));
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  process.env.HOME = envRoot;
  process.env.USERPROFILE = envRoot;
  process.env.MIRQL_TRUST_ROOT = join(envRoot, "trust");
  process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY = "1";
});

after(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(envRoot, { recursive: true, force: true });
});

function makeWorkspace(parent) {
  const workspace = join(parent, "workspace");
  mkdirSync(join(workspace, "policy"), { recursive: true });
  mkdirSync(join(workspace, "src", "nested"), { recursive: true });
  git(workspace, "init", "-q");
  git(workspace, "config", "user.name", "test");
  git(workspace, "config", "user.email", "test@mirql.local");
  git(workspace, "config", "core.autocrlf", "false");
  writeFileSync(join(workspace, ".gitignore"), "ignored.txt\n");
  writeFileSync(join(workspace, "policy", "guard.json"), "base\n");
  writeFileSync(join(workspace, "code.mjs"), "export const value=1;\n");
  writeFileSync(join(workspace, "old-name.mjs"), "export const renamed=true;\n");
  writeFileSync(join(workspace, "src", "nested", "only.mjs"), "export const only=1;\n");
  git(workspace, "add", "-A");
  git(workspace, "commit", "-q", "-m", "base");
  writeFileSync(join(workspace, "ignored.txt"), "host only\n");
  mkdirSync(join(workspace, ".mirql"), { recursive: true });
  writeFileSync(join(workspace, ".mirql", "secret.txt"), "ledger internals\n");
  return workspace;
}

/** A mock `docker` that runs `body` as a module with its cwd in the staged workspace. */
function installMockDocker(parent, body) {
  const binDir = join(parent, "mock-bin");
  mkdirSync(binDir, { recursive: true });
  const mockSrc = join(binDir, "docker-mock.mjs");
  writeFileSync(mockSrc, [
    'import * as fs from "node:fs";',
    'import { dirname, join } from "node:path";',
    'const args = process.argv.slice(2);',
    'const mount = args[args.indexOf("-v") + 1];',
    'const staged = mount.slice(0, mount.lastIndexOf(":/workspace"));',
    'process.chdir(staged);',
    'const report = (value) => fs.writeFileSync(process.env.MIRQL_MOCK_OUT, JSON.stringify(value));',
    'void dirname; void join; void report;',
    body,
    'process.exit(0);',
  ].join("\n"));
  if (process.platform === "win32") {
    writeFileSync(join(binDir, "docker.cmd"), `@node "${mockSrc}" %*\r\n`);
  } else {
    writeFileSync(join(binDir, "docker"), `#!/bin/sh\nexec node "${mockSrc}" "$@"\n`);
    chmodSync(join(binDir, "docker"), 0o755);
  }
  return binDir;
}

function runInMock(parent, workspace, body, extra = {}) {
  const out = join(parent, "mock-out.json");
  const binDir = installMockDocker(parent, body);
  const result = runAgent({
    sandbox: "docker", image: "mirql-agent-mock:latest", cwd: workspace, command: "true",
    env: { PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}`, MIRQL_MOCK_OUT: out },
    allowedEnv: ["MIRQL_MOCK_OUT"], ...extra,
  });
  return { result, reportFile: out };
}

function withParent(fn) {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-review-"));
  try {
    return fn(parent);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
}

function canSymlink() {
  return withParent((parent) => {
    try {
      symlinkSync("target", join(parent, "probe"));
      return true;
    } catch (error) {
      if (error.code === "EPERM" || error.code === "EACCES") return false;
      throw error;
    }
  });
}

const SYMLINKS = canSymlink();
const SKIP_SYMLINKS = SYMLINKS ? false : "this user cannot create symlinks";
const SKIP_POSIX = process.platform === "win32" ? "POSIX file modes only" : false;

// ---------------------------------------------------------------------------
// Finding 1: the staged workspace must be usable by container UID 65534
// ---------------------------------------------------------------------------

test("the mounted workspace is open to the container UID while its parent stays private", { skip: SKIP_POSIX }, () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  chmodSync(join(workspace, "code.mjs"), 0o640);
  const before = statSync(join(workspace, "code.mjs")).mode & 0o777;
  const { result, reportFile } = runInMock(parent, workspace, `
    const mode = (p) => fs.statSync(p).mode & 0o777;
    report({ cwd: process.cwd(), command: args.at(-1), root: mode("."), parent: mode(".."), dir: mode("src/nested"), file: mode("code.mjs") });
  `);
  assert.equal(result.ok, true, JSON.stringify(result));
  const seen = JSON.parse(readFileSync(reportFile, "utf8"));
  assert.equal(seen.root, 0o777, "mount point must be traversable by UID 65534");
  assert.equal(seen.dir, 0o777, "staged directories must be writable by UID 65534");
  assert.equal(seen.file & 0o666, 0o666, "staged files must be writable by UID 65534");
  assert.equal(seen.parent, 0o700, "other host users must not reach the opened staging tree");
  assert.equal(seen.command, "umask 000; true", "container output must stay readable and removable by the host user");
  // Opening the staged copy must not change the real workspace or fake a change.
  assert.equal(statSync(join(workspace, "code.mjs")).mode & 0o777, before);
  // The measurer always lists untracked host files; only those may appear here.
  assert.deepEqual(result.changedFiles, [".mirql/secret.txt", "ignored.txt"]);
}));

const REAL_MOUNT_PROBE = process.platform === "linux" && process.getuid?.() === 0 &&
  spawnSync("unshare", ["--mount", "sh", "-c", "mount --bind /tmp /mnt && command -v setpriv"], { encoding: "utf8" }).status === 0;

test("real UID 65534 through a real bind mount can read, edit and create files", { skip: REAL_MOUNT_PROBE ? false : "needs Linux root with unshare and setpriv" }, () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  chmodSync(join(workspace, "code.mjs"), 0o640);
  const binDir = join(parent, "bind-bin");
  mkdirSync(binDir);
  // Models the runtime's bind mount: host parent modes do not apply past the mount point.
  writeFileSync(join(binDir, "docker"), [
    "#!/bin/sh",
    'while [ $# -gt 1 ]; do [ "$1" = "-v" ] && m="$2"; shift; done',
    'exec unshare --mount sh -c \'mount --bind "$1" /mnt && cd /mnt && exec setpriv --reuid=65534 --regid=65534 --clear-groups sh -c "$2"\' sh "${m%:/workspace:rw}" "$1"',
    "",
  ].join("\n"));
  chmodSync(join(binDir, "docker"), 0o755);
  const result = runAgent({
    sandbox: "docker", image: "unused", cwd: workspace,
    command: "cat code.mjs > copy.txt && echo edited >> code.mjs && mkdir made && echo new > made/new.txt && rm old-name.mjs && id -u > uid.txt",
    env: { PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}` },
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(readFileSync(join(workspace, "uid.txt"), "utf8").trim(), "65534");
  assert.equal(readFileSync(join(workspace, "copy.txt"), "utf8"), "export const value=1;\n");
  assert.match(readFileSync(join(workspace, "code.mjs"), "utf8"), /edited/);
  assert.equal(readFileSync(join(workspace, "made", "new.txt"), "utf8"), "new\n");
  assert.equal(existsSync(join(workspace, "old-name.mjs")), false);
  assert.equal(statSync(join(workspace, "code.mjs")).mode & 0o777, 0o640);
}));

// ---------------------------------------------------------------------------
// Finding 2: sync must never follow worker-created symlinks
// ---------------------------------------------------------------------------

function assertEscapeDenied(result) {
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.exitCode, EXIT_CODES.POLICY_DENIAL);
  assert.equal(result.rule, "MP-001");
  assert.equal(result.violation, "WORKSPACE_ESCAPE");
}

test("a worker directory symlink to a host path is refused and nothing is copied or applied", { skip: SKIP_SYMLINKS }, () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const outside = join(parent, "host-secrets");
  mkdirSync(outside);
  writeFileSync(join(outside, "secret.txt"), "host secret\n");
  const { result } = runInMock(parent, workspace, `
    fs.symlinkSync(${JSON.stringify(outside)}, "loot", "dir");
    fs.writeFileSync("code.mjs", "export const value=2;\\n");
  `);
  assertEscapeDenied(result);
  assert.equal(existsSync(join(workspace, "loot")), false, "the symlink target must not be copied into the workspace");
  assert.equal(readFileSync(join(workspace, "code.mjs"), "utf8"), "export const value=1;\n", "a refused sync applies nothing");
}));

test("a worker file symlink, a relative escape and a link into .git are each refused", { skip: SKIP_SYMLINKS }, () => {
  const cases = {
    absolute: (outside) => `fs.symlinkSync(${JSON.stringify(join(outside, "secret.txt"))}, "leak.txt");`,
    relative: () => 'fs.symlinkSync("../../outside.txt", "leak.txt");',
    protected: () => 'fs.mkdirSync(".git/hooks", { recursive: true }); fs.symlinkSync(".git/hooks", "leak.txt");',
    chained: (outside) => `fs.symlinkSync(${JSON.stringify(outside)}, "a", "dir"); fs.symlinkSync("a", "leak.txt", "dir");`,
  };
  for (const [name, body] of Object.entries(cases)) {
    withParent((parent) => {
      const workspace = makeWorkspace(parent);
      const outside = join(parent, "host-secrets");
      mkdirSync(outside);
      writeFileSync(join(outside, "secret.txt"), "host secret\n");
      const { result } = runInMock(parent, workspace, body(outside));
      assert.equal(result.violation, "WORKSPACE_ESCAPE", `${name}: ${JSON.stringify(result)}`);
      assert.equal(existsSync(join(workspace, "leak.txt")), false, name);
    });
  }
});

test("a worker write never passes through a host symlink that was not staged", { skip: SKIP_SYMLINKS }, () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const outside = join(parent, "host-data");
  mkdirSync(outside);
  writeFileSync(join(workspace, ".gitignore"), "ignored.txt\ndata\n");
  git(workspace, "add", "-A");
  git(workspace, "commit", "-q", "-m", "ignore data");
  symlinkSync(outside, join(workspace, "data"), "dir");
  const { result } = runInMock(parent, workspace, 'fs.mkdirSync("data"); fs.writeFileSync("data/planted.txt", "x");');
  assertEscapeDenied(result);
  assert.equal(existsSync(join(outside, "planted.txt")), false);
  assert.equal(lstatSync(join(workspace, "data")).isSymbolicLink(), true);
}));

test("a safe relative link syncs, and a committed link stays verbatim", { skip: SKIP_SYMLINKS }, () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  symlinkSync("code.mjs", join(workspace, "committed-link"));
  git(workspace, "add", "-A");
  git(workspace, "commit", "-q", "-m", "link");
  const { result, reportFile } = runInMock(parent, workspace, `
    report({ staged: fs.readlinkSync("committed-link") });
    fs.symlinkSync("code.mjs", "fresh-link");
  `);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(JSON.parse(readFileSync(reportFile, "utf8")).staged, "code.mjs", "a staged link must not be rewritten to a host path");
  assert.equal(readlinkSync(join(workspace, "committed-link")), "code.mjs");
  assert.equal(readlinkSync(join(workspace, "fresh-link")), "code.mjs");
}));

test("a worker FIFO is refused rather than read on the host", { skip: process.platform === "win32" ? "no FIFOs" : false }, () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const { result } = runInMock(parent, workspace, 'import("node:child_process").then(({ execSync }) => { execSync("mkfifo pipe"); process.exit(0); }); await new Promise(() => {});');
  assertEscapeDenied(result);
  assert.equal(existsSync(join(workspace, "pipe")), false);
}));

// ---------------------------------------------------------------------------
// Finding 5: deletions and renames must reach the workspace and the gate
// ---------------------------------------------------------------------------

test("worker deletions and renames sync back, are measured, and spare unstaged host files", () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const { result } = runInMock(parent, workspace, `
    fs.rmSync("src/nested/only.mjs");
    fs.rmdirSync("src/nested");
    fs.renameSync("old-name.mjs", "new-name.mjs");
  `);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(existsSync(join(workspace, "src", "nested", "only.mjs")), false, "deleted file must leave the workspace");
  assert.equal(existsSync(join(workspace, "src")), false, "directories emptied by the worker are pruned");
  assert.equal(existsSync(join(workspace, "old-name.mjs")), false, "renamed-from path must leave the workspace");
  assert.equal(readFileSync(join(workspace, "new-name.mjs"), "utf8"), "export const renamed=true;\n");
  for (const path of ["src/nested/only.mjs", "old-name.mjs", "new-name.mjs"]) assert.ok(result.changedFiles.includes(path), path);
  // Never staged, so absence from the staging copy is not a deletion.
  assert.equal(readFileSync(join(workspace, "ignored.txt"), "utf8"), "host only\n");
  assert.equal(readFileSync(join(workspace, ".mirql", "secret.txt"), "utf8"), "ledger internals\n");
  assert.ok(existsSync(join(workspace, ".git", "HEAD")));
}));

test("a worker deleting a human-only path is caught by the MP-001 gate", () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const { result } = runInMock(parent, workspace, 'fs.rmSync("policy/guard.json");');
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.violation, "TOUCH_HUMAN_ONLY");
  assert.ok(result.forbidden.includes("policy/guard.json"), JSON.stringify(result));
}));

test("a worker write to .git in any spelling never reaches the host", () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const headBefore = readFileSync(join(workspace, ".git", "HEAD"), "utf8");
  const { result } = runInMock(parent, workspace, `
    fs.mkdirSync(".git", { recursive: true });
    fs.writeFileSync(".git/HEAD", "planted\\n");
    fs.mkdirSync(".mirql", { recursive: true });
    fs.writeFileSync(".mirql/secret.txt", "planted\\n");
  `);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(readFileSync(join(workspace, ".git", "HEAD"), "utf8"), headBefore);
  assert.equal(readFileSync(join(workspace, ".mirql", "secret.txt"), "utf8"), "ledger internals\n");
}));

test("a worker cannot plant node_modules on the host, where host tooling would run it", () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  mkdirSync(join(workspace, "node_modules", "dep"), { recursive: true });
  writeFileSync(join(workspace, "node_modules", "dep", "index.js"), "host dep\n");
  const { result } = runInMock(parent, workspace, `
    fs.mkdirSync("node_modules/dep", { recursive: true });
    fs.writeFileSync("node_modules/dep/index.js", "planted\\n");
    fs.mkdirSync("node_modules/.bin", { recursive: true });
    fs.writeFileSync("node_modules/.bin/tool", "planted\\n");
    fs.writeFileSync("kept.txt", "kept\\n");
  `);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(readFileSync(join(workspace, "node_modules", "dep", "index.js"), "utf8"), "host dep\n");
  assert.equal(existsSync(join(workspace, "node_modules", ".bin")), false);
  assert.equal(readFileSync(join(workspace, "kept.txt"), "utf8"), "kept\n");
}));

test("a worker overwriting an ignored host file it never saw is refused and nothing is applied", () => withParent((parent) => {
  const workspace = makeWorkspace(parent);
  const { result } = runInMock(parent, workspace, `
    fs.writeFileSync("ignored.txt", "planted\\n");
    fs.writeFileSync("code.mjs", "edited\\n");
  `);
  assert.equal(result.ok, false);
  assert.equal(result.violation, "WORKSPACE_ESCAPE");
  assert.equal(result.exitCode, EXIT_CODES.POLICY_DENIAL);
  assert.equal(readFileSync(join(workspace, "ignored.txt"), "utf8"), "host only\n");
  assert.notEqual(readFileSync(join(workspace, "code.mjs"), "utf8"), "edited\n");
}));

// ---------------------------------------------------------------------------
// Finding 3: git-mode verification has no container runner, so a sandbox
// request must refuse before any candidate code runs on the host
// ---------------------------------------------------------------------------

const BASE_FILES = {
  "package.json": JSON.stringify({ type: "module", scripts: { test: "node --test tests/*.test.mjs" } }),
  "policy/paths.yaml": readFileSync(join(ROOT, "policy", "paths.yaml"), "utf8"),
  "src/app.mjs": "export function add(a, b) {\n  return a - b;\n}\n",
};
const FIX = "export function add(a, b) {\n  return a + b;\n}\n";

function verifyTarget(sandboxRoot, marker) {
  const repo = mkdtempSync(join(sandboxRoot, "repo-"));
  const write = (files) => {
    for (const [path, content] of Object.entries(files)) {
      mkdirSync(dirname(join(repo, path)), { recursive: true });
      writeFileSync(join(repo, path), content);
    }
  };
  git(repo, "init", "-q", "-b", "main");
  git(repo, "config", "user.email", "review@example.test");
  git(repo, "config", "user.name", "review");
  git(repo, "config", "core.autocrlf", "false");
  write(BASE_FILES);
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "base");
  const baseSha = git(repo, "rev-parse", "HEAD").trim();
  write({
    "src/app.mjs": FIX,
    "tests/repro.test.mjs": [
      "import test from 'node:test';",
      "import assert from 'node:assert';",
      "import { writeFileSync } from 'node:fs';",
      "import { add } from '../src/app.mjs';",
      `writeFileSync(${JSON.stringify(marker)}, 'candidate ran on the host');`,
      "test('adds', () => assert.equal(add(2, 2), 4));",
      "",
    ].join("\n"),
  });
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "head");
  return { repo, baseSha, headSha: git(repo, "rev-parse", "HEAD").trim() };
}

test("git-mode verification refuses a sandbox request before running candidate code", () => withParent((parent) => {
  const mirqlDir = join(parent, "authority", ".mirql");
  const owner = runGenesis(mirqlDir);
  const warrantId = () => sendIntent(mirqlDir, { title: "Sandbox request grant", kind: "feature", phi_budget: 10000, scope: ["**"] }, { key: owner.human_key_path }).warrant_id;
  const attempt = (marker, extra) => {
    const target = verifyTarget(parent, marker);
    return verifyAttempt({ git: true, workspaceDir: target.repo, baseSha: target.baseSha, headSha: target.headSha,
      reproducerFile: "tests/repro.test.mjs", mirqlDir, warrantId: warrantId(), ...extra });
  };

  // Control: the fixture really does verify, and really does run on the host.
  const controlMarker = join(parent, "control-marker");
  const control = attempt(controlMarker, {});
  assert.equal(control.verdict, "auto_merge", JSON.stringify(control));
  assert.equal(existsSync(controlMarker), true, "control run must execute candidate code");

  for (const extra of [
    { requireSandbox: true, sandbox: "docker" },
    { requireSandbox: true, sandbox: "podman" },
    { sandbox: "docker" },
    { requireSandbox: true },
  ]) {
    const label = JSON.stringify(extra);
    const marker = join(parent, `marker-${Object.values(extra).join("-")}-${Object.keys(extra).length}`);
    const result = attempt(marker, extra);
    assert.notEqual(result.verdict, "auto_merge", `${label}: ${JSON.stringify(result)}`);
    assert.equal(result.verified, false, label);
    assert.equal(result.verdict, "needs_human", `${label}: ${JSON.stringify(result)}`);
    assert.equal(result.rule, "UNSANDBOXED_EXECUTION", label);
    assert.equal(result.violation, "SANDBOX_NONE", label);
    assert.match(result.detail, /No candidate code was executed/, label);
    assert.equal(existsSync(marker), false, `${label}: candidate code ran on the host`);
  }
}));

// ---------------------------------------------------------------------------
// Finding 4: head.json must not let an append proceed over corrupted history
// ---------------------------------------------------------------------------

function ledgerWithTwoEvents(parent) {
  const mirqlDir = join(parent, ".mirql");
  mkdirSync(join(mirqlDir, "ledger"), { recursive: true });
  provisionTestTrust(mirqlDir);
  const kp = getOrGenerateSupervisorKey(mirqlDir);
  const append = (seq) => appendSupervisorEvent(mirqlDir, {
    type: "probe.completed", idempotency_key: `review-${seq}`,
    payload: { probe: "unit", status: "pass", duration_ms: 10 }, nowMs: 1700000000000 + seq * 1000,
  }, kp);
  append(1);
  append(2);
  return { mirqlDir, file: join(mirqlDir, "ledger", "events.jsonl"), append };
}

function assertAppendRefused(ledger, tamper) {
  const lines = readFileSync(ledger.file, "utf8").trim().split("\n");
  lines[0] = tamper(lines[0]);
  const tampered = lines.join("\n") + "\n";
  writeFileSync(ledger.file, tampered);
  // Whoever can edit the ledger can also recompute the unkeyed digest in head.json.
  const headFile = join(ledger.mirqlDir, "ledger", "head.json");
  writeFileSync(headFile, JSON.stringify({ ...JSON.parse(readFileSync(headFile, "utf8")), events_sha256: sha256(tampered) }));
  // The precondition of the finding: the sidecar alone still reports a valid head.
  assert.equal(readLedgerHeadSidecar(ledger.mirqlDir).valid, true);
  const before = readFileSync(ledger.file, "utf8");
  assert.throws(() => ledger.append(3), (error) => error.code === "INTEGRITY_VIOLATION");
  assert.equal(readFileSync(ledger.file, "utf8"), before, "nothing may be appended over corrupted history");
}

test("append refuses when an earlier ledger line is not JSON, despite a valid head.json", () => withParent((parent) => {
  assertAppendRefused(ledgerWithTwoEvents(parent), () => "{ this is not json");
}));

test("append refuses when an earlier ledger line was edited, despite a valid head.json", () => withParent((parent) => {
  assertAppendRefused(ledgerWithTwoEvents(parent), (line) => {
    const event = JSON.parse(line);
    event.payload.status = "fail";
    return JSON.stringify(event);
  });
}));

test("appends still chain normally over intact history", () => withParent((parent) => {
  const ledger = ledgerWithTwoEvents(parent);
  const third = ledger.append(3);
  assert.equal(third.seq, 3);
  assert.equal(readLedgerHeadSidecar(ledger.mirqlDir).seq, 3);
}));

// ---------------------------------------------------------------------------
// MP-003 self-check for the sync code
// ---------------------------------------------------------------------------

test("sandbox workspace code has no swallowed exceptions (MP-003)", () => {
  for (const file of ["packages/run/agent.mjs", "packages/run/agent-workspace.mjs"]) {
    assert.deepEqual(checkSwallowedExceptions(readFileSync(join(ROOT, file), "utf8"), file).violations, [], file);
  }
});
