import { git } from "./helpers/git.mjs";
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

  it("quarantines non-ASCII and special filenames without C-quote loss (B1)", () => {
    const { repo, baseSha } = makeRepo(false);
    try {
      const nonAsciiName = "caf\u00e9-uni-\u7b46\u8a18.txt";
      writeFileSync(join(repo, nonAsciiName), "precious unicode notes\n", "utf8");

      const destructible = listDestructiblePaths(repo, baseSha);
      assert.equal(destructible.ok, true, destructible.error);
      assert.ok(destructible.paths.includes(nonAsciiName), `Expected ${nonAsciiName} in destructible paths`);

      const res = executeRollback(repo, baseSha);
      assert.equal(res.ok, true, res.error);
      assert.equal(existsSync(join(repo, nonAsciiName)), false);

      const q = res.quarantine;
      assert.ok(q, "quarantine metadata must exist");
      assert.ok(q.copied.includes(nonAsciiName), "non-ASCII file must be copied to quarantine");
      assert.equal(readFileSync(join(q.dir, nonAsciiName), "utf8"), "precious unicode notes\n");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("quarantines staged modifications and staged new files (B2)", () => {
    const { repo, baseSha } = makeRepo(false);
    try {
      writeFileSync(join(repo, "src", "app.mjs"), "export const version = 42; // staged mod\n");
      git(repo, "add", "src/app.mjs");

      writeFileSync(join(repo, "staged-new.txt"), "staged new content\n");
      git(repo, "add", "staged-new.txt");

      const destructible = listDestructiblePaths(repo, baseSha);
      assert.equal(destructible.ok, true, destructible.error);
      assert.ok(destructible.paths.includes("src/app.mjs"));
      assert.ok(destructible.paths.includes("staged-new.txt"));

      const res = executeRollback(repo, baseSha);
      assert.equal(res.ok, true, res.error);

      assert.equal(readFileSync(join(repo, "src", "app.mjs"), "utf8"), "export const version = 1;\n");
      assert.equal(existsSync(join(repo, "staged-new.txt")), false);

      const q = res.quarantine;
      assert.ok(q, "quarantine metadata must exist");
      assert.ok(q.copied.includes("src/app.mjs"));
      assert.ok(q.copied.includes("staged-new.txt"));
      assert.equal(readFileSync(join(q.dir, "src", "app.mjs"), "utf8"), "export const version = 42; // staged mod\n");
      assert.equal(readFileSync(join(q.dir, "staged-new.txt"), "utf8"), "staged new content\n");

      const diffPatchPath = join(q.dir, "staged-worktree.diff");
      assert.equal(existsSync(diffPatchPath), true);
      const diffContent = readFileSync(diffPatchPath, "utf8");
      assert.match(diffContent, /diff --git a\/src\/app\.mjs/);
      assert.match(diffContent, /diff --git a\/staged-new\.txt/);
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("safely handles untracked directories and nested files (M1)", () => {
    const { repo, baseSha } = makeRepo(false);
    try {
      const nestedDir = join(repo, "nested-pkg");
      mkdirSync(nestedDir, { recursive: true });
      writeFileSync(join(nestedDir, "inner.txt"), "inner content\n");

      const res = executeRollback(repo, baseSha);
      assert.equal(res.ok, true, res.error);
      assert.equal(existsSync(nestedDir), false);

      const q = res.quarantine;
      assert.ok(q, "quarantine metadata must exist");
      assert.ok(q.copied.includes("nested-pkg/inner.txt"));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("preserves prior quarantine directory when rolling back again with custom root (M3)", () => {
    const { repo, baseSha } = makeRepo(false);
    try {
      const customRoot = join(repo, "custom-quarantine");

      writeFileSync(join(repo, "file1.txt"), "content 1\n");
      const res1 = executeRollback(repo, baseSha, { quarantineRoot: customRoot });
      assert.equal(res1.ok, true, res1.error);
      assert.equal(existsSync(res1.quarantine.dir), true);
      assert.equal(readFileSync(join(res1.quarantine.dir, "file1.txt"), "utf8"), "content 1\n");

      writeFileSync(join(repo, "file2.txt"), "content 2\n");
      const res2 = executeRollback(repo, baseSha, { quarantineRoot: customRoot });
      assert.equal(res2.ok, true, res2.error);
      assert.equal(existsSync(res2.quarantine.dir), true);
      assert.equal(readFileSync(join(res2.quarantine.dir, "file2.txt"), "utf8"), "content 2\n");

      assert.equal(existsSync(res1.quarantine.dir), true, "First quarantine directory must survive second rollback");
      assert.equal(readFileSync(join(res1.quarantine.dir, "file1.txt"), "utf8"), "content 1\n");
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  it("refuses to roll back when repo measurement fails closed on corrupted git repo (m4)", () => {
    const corruptRepo = mkdtempSync(join(tmpdir(), "mirql-lgrb-corrupt-"));
    mkdirSync(join(corruptRepo, ".git"));
    try {
      const res = executeRollback(corruptRepo, "a".repeat(40));
      assert.equal(res.ok, false);
      assert.match(res.error, /Refusing rollback — cannot measure dirty worktree/);
    } finally {
      rmSync(corruptRepo, { recursive: true, force: true });
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
