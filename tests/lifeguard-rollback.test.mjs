// tests/lifeguard-rollback.test.mjs — quarantine-first rollback (Law 14, issue #11).
// Pins the contract that executeRollback NEVER silently destroys uncommitted
// work: everything `git reset --hard` + `git clean -fd` would remove is first
// copied to a quarantine directory, and a quarantine failure aborts the
// destructive rollback unless the operator explicitly allowed data loss.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import {
  LifeguardWatchdog,
  executeRollback,
  listDestructiblePaths,
} from "../packages/daemons/index.mjs";

function git(repoDir, ...args) {
  const res = spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 15000 });
  assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

/** Creates a real git repo with a base commit and returns { dir, baseSha }. */
function makeRepo(dirty = false) {
  const repo = mkdtempSync(join(tmpdir(), "mirql-lgrb-"));
  git(repo, "init", "-q");
  git(repo, "config", "user.email", "test@mirql.local");
  git(repo, "config", "user.name", "mirql-test");
  // Byte-exact fixture: no CRLF rewriting, quarantines must be byte-identical
  git(repo, "config", "core.autocrlf", "false");
  writeFileSync(join(repo, ".gitignore"), "scratch/\n.mirql/\n");
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "app.mjs"), "export const version = 1;\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "base");
  const baseSha = git(repo, "rev-parse", "HEAD").trim();

  if (dirty) {
    // Concurrent agent's uncommitted work: modified tracked, untracked, nested untracked
    writeFileSync(join(repo, "src", "app.mjs"), "export const version = 2; // agent WIP\n");
    writeFileSync(join(repo, "notes-draft.md"), "agent WIP notes\n");
    mkdirSync(join(repo, "agent", "deep"), { recursive: true });
    writeFileSync(join(repo, "agent", "deep", "wip.mjs"), "export const wip = true;\n");
  }
  // Ignored scratch file: git clean -fd must never touch it, quarantine must not copy it
  mkdirSync(join(repo, "scratch"), { recursive: true });
  writeFileSync(join(repo, "scratch", "local.txt"), "ignored but precious\n");

  return { repo, baseSha };
}

describe("lifeguard rollback: quarantine-first data safety (issue #11)", () => {
  it("listDestructiblePaths enumerates exactly what reset+clean would destroy", () => {
    const { repo } = makeRepo(true);
    try {
      const res = listDestructiblePaths(repo);
      assert.equal(res.ok, true, res.error);
      assert.deepEqual(res.paths, ["agent/deep/wip.mjs", "notes-draft.md", "src/app.mjs"]);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("listDestructiblePaths is empty on a clean worktree and fails closed off-repo", () => {
    const { repo } = makeRepo(false);
    const notARepo = mkdtempSync(join(tmpdir(), "mirql-lgrb-clean-"));
    try {
      assert.deepEqual(listDestructiblePaths(repo).paths, []);
      // Not a repository: `git ls-files` fails → must return ok:false, never guess.
      const bad = listDestructiblePaths(notARepo);
      assert.equal(bad.ok, false);
    } finally {
      rmSync(repo, { recursive: true, force: true });
      rmSync(notARepo, { recursive: true, force: true });
    }
  });

  it("rollback quarantines and recovers all uncommitted work, ignores .gitignored files", () => {
    const { repo, baseSha } = makeRepo(true);
    try {
      const res = executeRollback(repo, baseSha);
      assert.equal(res.ok, true, res.error);

      // Authoritative state restored
      assert.equal(readFileSync(join(repo, "src", "app.mjs"), "utf8"), "export const version = 1;\n");
      assert.equal(existsSync(join(repo, "notes-draft.md")), false);
      assert.equal(existsSync(join(repo, "agent")), false);

      // Ignored file untouched (clean -fd must not remove it)
      assert.equal(readFileSync(join(repo, "scratch", "local.txt"), "utf8"), "ignored but precious\n");

      // Quarantine holds the destroyed work, byte-identical
      const q = res.quarantine;
      assert.ok(q, "quarantine metadata must be reported");
      assert.equal(q.copied.length, 3);
      assert.equal(q.skipped.length, 0);
      assert.equal(readFileSync(join(q.dir, "src", "app.mjs"), "utf8"), "export const version = 2; // agent WIP\n");
      assert.equal(readFileSync(join(q.dir, "notes-draft.md"), "utf8"), "agent WIP notes\n");
      assert.equal(readFileSync(join(q.dir, "agent", "deep", "wip.mjs"), "utf8"), "export const wip = true;\n");
      // Quarantine lives under .mirql/quarantine/ (survives the clean)
      assert.ok(q.dir.includes(join(".mirql", "quarantine")), q.dir);
      assert.match(res.output, /Quarantined 3 file\(s\)/);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("clean worktree rollback succeeds without creating a quarantine", () => {
    const { repo, baseSha } = makeRepo(false);
    try {
      const res = executeRollback(repo, baseSha);
      assert.equal(res.ok, true, res.error);
      assert.equal(res.quarantine, null);
      assert.equal(existsSync(join(repo, ".mirql", "quarantine")), false);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("quarantine failure ABORTS the rollback and leaves the worktree untouched", () => {
    const { repo, baseSha } = makeRepo(true);
    try {
      // Block the quarantine root with a regular file → mkdir/copy must fail
      writeFileSync(join(repo, "blocker"), "not a dir");
      const res = executeRollback(repo, baseSha, { quarantineRoot: join(repo, "blocker") });
      assert.equal(res.ok, false);
      assert.match(res.error, /Quarantine failed, refusing destructive rollback/);

      // Worktree untouched: agent WIP still present and dirty
      assert.equal(readFileSync(join(repo, "src", "app.mjs"), "utf8"), "export const version = 2; // agent WIP\n");
      assert.equal(existsSync(join(repo, "notes-draft.md")), true);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("allowDataLoss overrides a failed quarantine (explicit operator decision)", () => {
    const { repo, baseSha } = makeRepo(true);
    try {
      writeFileSync(join(repo, "blocker"), "not a dir");
      const res = executeRollback(repo, baseSha, {
        quarantineRoot: join(repo, "blocker"),
        allowDataLoss: true,
      });
      assert.equal(res.ok, true, res.error);
      // Destructive rollback proceeded: base content restored
      assert.equal(readFileSync(join(repo, "src", "app.mjs"), "utf8"), "export const version = 1;\n");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("refuses to roll back when the dirty worktree cannot even be measured", () => {
    const notARepo = mkdtempSync(join(tmpdir(), "mirql-lgrb-norepo-"));
    try {
      const res = executeRollback(notARepo, "a".repeat(40));
      assert.equal(res.ok, false);
      assert.match(res.error, /not a git repository/);
    } finally {
      rmSync(notARepo, { recursive: true, force: true });
    }
  });

  it("LifeguardWatchdog trip runs the quarantine-first rollback (integration)", () => {
    const { repo, baseSha } = makeRepo(true);
    const controlDir = mkdtempSync(join(tmpdir(), "mirql-lgrb-ctl-"));
    try {
      // Operator files live OUTSIDE the repo (same convention as disarm files)
      const baseFile = join(controlDir, "base_sha");
      writeFileSync(baseFile, baseSha, "utf8");
      const watchdog = new LifeguardWatchdog({
        repoDir: repo,
        baseShaFile: baseFile,
        timeoutMs: 1000,
        startTimeMs: Date.now() - 2000, // already expired
      });
      const res = watchdog.check();
      assert.equal(res.tripped, true);
      assert.equal(res.rollback.ok, true, res.rollback?.error);
      assert.equal(res.rollback.quarantine.copied.length, 3);
      assert.equal(readFileSync(join(res.rollback.quarantine.dir, "notes-draft.md"), "utf8"), "agent WIP notes\n");
    } finally {
      rmSync(repo, { recursive: true, force: true });
      rmSync(controlDir, { recursive: true, force: true });
    }
  });
});
