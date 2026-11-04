// packages/run/supervisor-attempt.mjs — host-side Git authority for one attempt.
//
// Law 3 (Roles Propose / Tools Author): the worker only leaves files behind.
// This module, running in the supervisor, gives the worker a private clone of
// the base commit and authors the commit from what it finds there. The
// operator's checkout is never reset, cleaned or moved, so every attempt,
// including a retry, starts from the base commit with no leftovers, ignored
// files included.
//
// The worker's Git store is its own and dies with the attempt, so nothing it
// configures there survives into a retry. Its output is staged through a store
// created after it exits, with no configuration in reach, so no filter it
// planted can run in the supervisor.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";

import { configFreeEnv, hostEnv } from "./worker-diff.mjs";

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

function git(args, { cwd, env = hostEnv(), timeout = 120_000 }) {
  const result = spawnSync("git", [...HOST_GIT, ...args], {
    cwd, env, encoding: "utf8", timeout, maxBuffer: 64 * 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.signal || result.status !== 0) {
    throw new Error(result.error?.message || result.stderr?.trim() || `git ${args[0]} failed`);
  }
  return result.stdout;
}

/**
 * Creates the private clone for one attempt. Fails closed, without throwing,
 * unless the workspace is the root of a Git repository with a commit. The
 * files are written without the workspace's configuration, so its filters and
 * hooks do not run here.
 *
 * @param {string} workspaceDir
 * @returns {{ ok: true, attempt: object } | { ok: false, rule: string, detail: string }}
 */
export function prepareAttempt(workspaceDir) {
  let baseSha, gitDir, commonDir, objectFormat;
  try {
    const [inside, cdup] = git(["rev-parse", "--is-inside-work-tree", "--show-cdup"], { cwd: workspaceDir }).split(/\r?\n/);
    if (inside !== "true" || cdup) {
      return { ok: false, rule: "WORKSPACE_UNVERIFIED", detail: "The workspace must be the root of a Git repository" };
    }
    baseSha = git(["rev-parse", "--verify", "HEAD^{commit}"], { cwd: workspaceDir }).trim();
    gitDir = git(["rev-parse", "--absolute-git-dir"], { cwd: workspaceDir }).trim();
    commonDir = resolve(workspaceDir, git(["rev-parse", "--git-common-dir"], { cwd: workspaceDir }).trim());
    objectFormat = git(["rev-parse", "--show-object-format"], { cwd: workspaceDir }).trim();
  } catch (error) {
    return { ok: false, rule: "WORKSPACE_UNVERIFIED", detail: error.message };
  }
  const root = mkdtempSync(join(tmpdir(), "mirql-attempt-"));
  const attemptDir = join(root, "tree");
  try {
    const env = configFreeEnv();
    git(["init", "--quiet", "--template=", `--object-format=${objectFormat}`, attemptDir], { cwd: root, env });
    git(["config", "core.autocrlf", "false"], { cwd: attemptDir, env });
    // Only this step keeps the global configuration, which holds safe.directory.
    // The fetched path is not stored, so the clone has no remote to the workspace.
    git(["fetch", "--quiet", "--no-tags", resolve(workspaceDir), baseSha], { cwd: attemptDir });
    git(["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", baseSha], { cwd: attemptDir, env });
    return { ok: true, attempt: Object.freeze({ workspaceDir, root, attemptDir, gitDir, commonDir, objectFormat, baseSha }) };
  } catch (error) {
    rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    return { ok: false, rule: "WORKSPACE_UNVERIFIED", detail: error.message };
  }
}

function readOrNull(path) {
  try {
    return readFileSync(path);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "EISDIR") return null;
    throw error;
  }
}

function includedConfigFiles(attempt) {
  try {
    const tokens = git(["config", "--local", "--includes", "--list", "--show-origin", "--name-only", "-z"],
      { cwd: attempt.workspaceDir }).split("\0");
    return tokens.filter((token) => token.startsWith("file:")).map((token) => resolve(attempt.workspaceDir, token.slice(5)));
  } catch {
    return []; // A configuration Git cannot read differs from the captured bytes anyway.
  }
}

function hookFiles(attempt) {
  const hooks = join(attempt.commonDir, "hooks");
  try {
    return readdirSync(hooks, { withFileTypes: true })
      .filter((entry) => entry.isFile() || entry.isSymbolicLink())
      .map((entry) => join(hooks, entry.name));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

/**
 * Bytes of the workspace files that decide what its Git executes. The worker
 * has no Git route to them, but without OS isolation it can still write there
 * by absolute path, and the verifier and any later attempt run Git in the
 * workspace. This is a best-effort guard, not a boundary: it cannot see the
 * operator's global configuration or anything else outside the repository.
 *
 * @returns {Map<string, Buffer|null>}
 */
export function captureGitAuthority(attempt) {
  const paths = new Set([
    join(attempt.commonDir, "config"),
    join(attempt.commonDir, "config.worktree"),
    join(attempt.gitDir, "config.worktree"),
    join(attempt.commonDir, "info", "attributes"),
    ...hookFiles(attempt),
    ...includedConfigFiles(attempt),
  ]);
  return new Map([...paths].map((path) => [path, readOrNull(path)]));
}

/** @returns {boolean} whether those files differ from what was captured. */
export function gitAuthorityChanged(attempt, captured) {
  const paths = new Set([...captured.keys(), ...captureGitAuthority(attempt).keys()]);
  return [...paths].some((path) => {
    const before = captured.get(path) ?? null;
    const now = readOrNull(path);
    return before === null || now === null ? before !== now : !before.equals(now);
  });
}

/**
 * Puts the captured bytes back, so neither the verifier nor a retry runs under
 * what the worker planted. New hooks are removed. A file named only by a new
 * include is left alone, since restoring the configuration drops the include
 * and the file may not be the supervisor's to delete.
 */
export function restoreGitAuthority(attempt, captured) {
  for (const path of hookFiles(attempt)) {
    if (!captured.has(path)) rmSync(path, { force: true });
  }
  for (const [path, bytes] of captured) {
    if (bytes === null) {
      rmSync(path, { force: true });
    } else {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, bytes);
    }
  }
}

/**
 * Hashes the worker's files into a tree. The Git directory is created here,
 * after the worker has exited, and no configuration applies to it, so a filter
 * named by the worker's attributes has no definition and nothing runs. Only the
 * objects go to the workspace's store.
 *
 * @returns {string} tree id
 */
export function snapshotWorkerTree(attempt) {
  const scratch = mkdtempSync(join(tmpdir(), "mirql-attempt-index-"));
  try {
    const store = join(scratch, "store");
    git(["init", "--quiet", "--bare", "--template=", `--object-format=${attempt.objectFormat}`, store],
      { cwd: scratch, env: configFreeEnv() });
    const options = {
      cwd: attempt.attemptDir,
      env: configFreeEnv({ GIT_INDEX_FILE: join(scratch, "index"), GIT_OBJECT_DIRECTORY: join(attempt.commonDir, "objects") }),
    };
    const prefix = ["--git-dir", store, "--work-tree", attempt.attemptDir];
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
 * and an operator can still reach it after the clone is gone.
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

/** Removes the clone. A leftover temp directory is never worth failing an attempt over. */
export function disposeAttempt(attempt) {
  try {
    rmSync(attempt.root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  } catch (error) {
    if (process.env.MIRQL_DEBUG) process.stderr.write(`[mirql-supervisor] attempt cleanup: ${error.message}\n`);
  }
}
