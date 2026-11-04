// packages/run/supervisor-attempt.mjs — host-side Git authority for one attempt.
//
// Law 3 (Roles Propose / Tools Author): the worker only leaves files behind.
// This module, running in the supervisor, gives the worker a disposable
// checkout of the base commit and authors the commit from what it finds there.
// The operator's checkout is never reset, cleaned or moved, so every attempt,
// including a retry, starts from the base commit with no leftovers, ignored
// files included.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const HOST_GIT = [
  "--no-replace-objects", "--no-pager",
  "-c", "core.fsmonitor=false",
  "-c", "core.sparseCheckout=false",
  "-c", `core.hooksPath=${devNull}`,
];
const HOST_IDENTITY = {
  GIT_AUTHOR_NAME: "mirql-supervisor", GIT_AUTHOR_EMAIL: "supervisor@mirql.local",
  GIT_COMMITTER_NAME: "mirql-supervisor", GIT_COMMITTER_EMAIL: "supervisor@mirql.local",
};

function hostEnv(extra = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !/^GIT_/i.test(key)) env[key] = value;
  }
  return { ...env, ...extra };
}

function git(args, { cwd, env = hostEnv(), timeout = 120_000 }) {
  const result = spawnSync("git", [...HOST_GIT, ...args], {
    cwd, env, encoding: "utf8", timeout, maxBuffer: 64 * 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.signal || result.status !== 0) {
    throw new Error(result.error?.message || result.stderr?.trim() || `git ${args[0]} failed`);
  }
  return result.stdout;
}

/** Explicit Git paths, so a rewritten `.git` file in the checkout is never followed. */
function attemptGit(attempt) {
  return ["--git-dir", attempt.gitDir, "--work-tree", attempt.attemptDir];
}

/**
 * Creates the disposable checkout for one attempt. Fails closed, without
 * throwing, unless the workspace is the root of a Git repository with a commit.
 *
 * @param {string} workspaceDir
 * @returns {{ ok: true, attempt: object } | { ok: false, rule: string, detail: string }}
 */
export function prepareAttempt(workspaceDir) {
  let baseSha;
  try {
    const [inside, cdup] = git(["rev-parse", "--is-inside-work-tree", "--show-cdup"], { cwd: workspaceDir }).split(/\r?\n/);
    if (inside !== "true" || cdup) {
      return { ok: false, rule: "WORKSPACE_UNVERIFIED", detail: "The workspace must be the root of a Git repository" };
    }
    baseSha = git(["rev-parse", "--verify", "HEAD^{commit}"], { cwd: workspaceDir }).trim();
  } catch (error) {
    return { ok: false, rule: "WORKSPACE_UNVERIFIED", detail: error.message };
  }
  const root = mkdtempSync(join(tmpdir(), "mirql-attempt-"));
  const attemptDir = join(root, "tree");
  try {
    git(["worktree", "add", "--detach", "--quiet", attemptDir, baseSha], { cwd: workspaceDir });
    const gitDir = git(["rev-parse", "--absolute-git-dir"], { cwd: attemptDir }).trim();
    const commonDir = resolve(attemptDir, git(["rev-parse", "--git-common-dir"], { cwd: attemptDir }).trim());
    return { ok: true, attempt: Object.freeze({ workspaceDir, root, attemptDir, gitDir, commonDir, baseSha }) };
  } catch (error) {
    rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    return { ok: false, rule: "WORKSPACE_UNVERIFIED", detail: error.message };
  }
}

/**
 * Digest of the files that decide what host Git commands execute. Without OS
 * isolation a worker can write to them, for example to add a clean filter that
 * would run when the supervisor stages its output.
 */
export function gitAuthorityDigest(attempt) {
  const hash = createHash("sha256");
  const paths = [join(attempt.commonDir, "config"), join(attempt.gitDir, "config.worktree"), join(attempt.gitDir, "commondir")];
  for (const path of paths) {
    let content = "<missing>";
    try {
      content = readFileSync(path);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    hash.update(path).update("\0").update(content).update("\0");
  }
  return hash.digest("hex");
}

/**
 * Hashes the worker's files into a tree through a fresh index, so index flags
 * and HEAD moves left by the worker have no effect on what gets recorded.
 *
 * @returns {string} tree id
 */
export function snapshotWorkerTree(attempt) {
  const scratch = mkdtempSync(join(tmpdir(), "mirql-attempt-index-"));
  try {
    const options = { cwd: attempt.attemptDir, env: hostEnv({ GIT_INDEX_FILE: join(scratch, "index") }) };
    const prefix = attemptGit(attempt);
    git([...prefix, "read-tree", attempt.baseSha], options);
    git([...prefix, "add", "-A", "--", "."], options);
    return git([...prefix, "write-tree"], options).trim();
  } finally {
    rmSync(scratch, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

/** Real change surface between the base commit and a tree. */
export function measureTreeSurface(attempt, tree) {
  const output = git(["diff", "--numstat", "--no-ext-diff", "--no-textconv", "--no-renames", attempt.baseSha, tree],
    { cwd: attempt.workspaceDir });
  const surface = { files_changed: 0, lines_added: 0, lines_removed: 0 };
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [added, removed] = line.split("\t");
    surface.files_changed += 1;
    if (/^\d+$/.test(added)) surface.lines_added += Number(added);
    if (/^\d+$/.test(removed)) surface.lines_removed += Number(removed);
  }
  return surface;
}

export function treeMatchesBase(attempt, tree) {
  return git(["rev-parse", `${attempt.baseSha}^{tree}`], { cwd: attempt.workspaceDir }).trim() === tree;
}

/**
 * Authors the candidate commit on top of the base and pins it, so the verifier
 * and an operator can still reach it after the checkout is gone.
 *
 * @returns {string} commit id
 */
export function authorCandidate(attempt, tree, { jobId, warrantId }) {
  const options = { cwd: attempt.workspaceDir, env: hostEnv(HOST_IDENTITY) };
  const message = `mirql attempt ${jobId ?? "unleased"} for warrant ${warrantId}`;
  const head = git(["commit-tree", tree, "-p", attempt.baseSha, "-m", message], options).trim();
  git(["update-ref", `refs/mirql/attempts/${head}`, head], options);
  return head;
}

/** Drops the pin on a candidate that was not accepted, so rejected work can be collected. */
export function releaseCandidate(attempt, head) {
  try {
    git(["update-ref", "-d", `refs/mirql/attempts/${head}`], { cwd: attempt.workspaceDir });
  } catch (error) {
    if (process.env.MIRQL_DEBUG) process.stderr.write(`[mirql-supervisor] candidate release: ${error.message}\n`);
  }
}

/** Removes the checkout. A leftover temp directory is never worth failing an attempt over. */
export function disposeAttempt(attempt) {
  const steps = [
    () => git(["worktree", "remove", "--force", "--force", attempt.attemptDir], { cwd: attempt.workspaceDir }),
    () => rmSync(attempt.root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }),
    () => git(["worktree", "prune"], { cwd: attempt.workspaceDir }),
  ];
  for (const step of steps) {
    try {
      step();
    } catch (error) {
      if (process.env.MIRQL_DEBUG) process.stderr.write(`[mirql-supervisor] attempt cleanup: ${error.message}\n`);
    }
  }
}
