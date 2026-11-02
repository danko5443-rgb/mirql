import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";

const WIN_LOCK_PATTERNS = [
  "Permission denied",
  "unable to write file",
  "failed to write commit object",
  "another git process seems to be running",
  "index.lock",
  "cannot lock ref",
];

const MAX_ATTEMPTS = 5;
const BASE_WAIT_MS = 50;
const SLEEP_BUF = new Int32Array(new SharedArrayBuffer(4));

/** Zero-CPU synchronous sleep using Atomics.wait on a shared buffer (Law 17 safe integer ms). */
function syncSleep(ms) {
  const safeMs = Math.max(1, Math.floor(ms));
  Atomics.wait(SLEEP_BUF, 0, 0, safeMs);
}

function isTransientWinLock(res) {
  if (process.platform !== "win32") return false;
  // If spawn itself errored (e.g. ENOENT) or process received an external signal, don't retry as transient lock
  if (res.error && res.error.code !== "EBUSY" && res.error.code !== "EPERM") return false;
  const err = (res.stderr ?? "") + (res.error?.message ?? "");
  return WIN_LOCK_PATTERNS.some((pattern) => err.includes(pattern));
}

/**
 * Spawns git synchronously with timeout and robust Windows transient lock retries.
 * 
 * @param {string} repoDir Working directory for the git invocation.
 * @param  {...string} args Git CLI arguments.
 * @returns {string} Standard output of git on exit code 0.
 */
export function git(repoDir, ...args) {
  let res;
  const env = {
    ...process.env,
    GIT_OPTIONAL_LOCKS: "0",
  };

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    res = spawnSync("git", args, {
      cwd: repoDir,
      encoding: "utf8",
      timeout: 15000,
      env,
    });

    if (res.status === 0) {
      return res.stdout;
    }

    // If a retried commit command hit a transient lock during write but the commit landed:
    if (
      attempt > 1 &&
      args[0] === "commit" &&
      res.status === 1 &&
      (res.stdout?.includes("nothing to commit") || res.stderr?.includes("nothing to commit"))
    ) {
      return res.stdout;
    }

    if (attempt === MAX_ATTEMPTS || !isTransientWinLock(res)) {
      break;
    }

    // Exponential backoff with integer jitter: 50ms, 100ms, 200ms, 400ms + random jitter up to 25ms
    const jitter = Math.floor(Math.random() * 25);
    const waitMs = BASE_WAIT_MS * (1 << (attempt - 1)) + jitter;
    syncSleep(waitMs);
  }

  assert.strictEqual(
    res.status,
    0,
    `git ${args.join(" ")} failed (status=${res.status}, signal=${res.signal ?? "none"}, ` +
      `error=${res.error?.message ?? "none"}): ${res.stderr ?? ""}`
  );
  return res.stdout;
}


/** A real committed baseline for worker-execution fixtures. */
export function initEmptyRepo(repoDir) {
  git(repoDir, "init", "-q");
  git(repoDir, "config", "user.email", "test@mirql.local");
  git(repoDir, "config", "user.name", "test");
  git(repoDir, "config", "core.autocrlf", "false");
  git(repoDir, "commit", "--allow-empty", "-q", "-m", "fixture base");
}
