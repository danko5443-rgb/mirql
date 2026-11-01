import {
  openSync,
  closeSync,
  unlinkSync,
  statSync,
  fstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  linkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

/** Age beyond which a lock whose holder is dead may be broken. */
export const STALE_LOCK_AGE_MS = 15000;

/**
 * Check if a process ID is currently alive on the host.
 * @param {number} pid
 * @returns {boolean}
 */
function isPidAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // ESRCH means process does not exist; EPERM means exists but not permitted to signal (still alive)
    return err.code === "EPERM";
  }
}

/**
 * Read and parse the metadata recorded in a lock file descriptor.
 * @param {number} fd
 * @returns {{ pid?: number, ts?: number, nonce?: string } | null}
 */
function readLockMeta(fd) {
  try {
    const raw = readFileSync(fd, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed;
  } catch {}
  return null;
}

/**
 * Pure staleness decision for a lock's metadata and stats (Law 5 spirit:
 * silence is never consent — an unverifiable lock is only broken when its
 * holder is provably dead AND the lock is provably old).
 *
 * @param {{ pid?: number }} meta
 * @param {{ mtimeMs: number }} st
 * @param {number} [nowMs]
 * @returns {boolean} true when the lock may be broken
 */
export function shouldBreakStaleLock(meta, st, nowMs = Date.now()) {
  if (!st || !Number.isFinite(st.mtimeMs)) return false;
  const ageMs = nowMs - st.mtimeMs;
  if (ageMs <= STALE_LOCK_AGE_MS) return false;
  const holderPid = Number.isSafeInteger(meta?.pid) ? meta.pid : null;
  // No recorded pid OR a dead pid: unverifiable holder, old lock → breakable
  return !holderPid || !isPidAlive(holderPid);
}

/**
 * Atomically claim the stale lock by RENAMING it out of the way (issue #12).
 *
 * Rename is atomic: exactly one contender can move a given lock file off the
 * lock path — the losing contender's rename hits ENOENT. After claiming, the
 * claimed file's nonce is re-verified against `expectedNonce` (the nonce the
 * breaker inspected when deciding the lock was stale). If they differ, the
 * breaker grabbed a NEWER lock that replaced the stale one after inspection —
 * it is restored (link, which refuses to clobber an existing path), never
 * destroyed. This closes the unlink TOCTOU where a second stale-breaker
 * removed the first breaker's freshly acquired lock and admitted two writers.
 *
 * @param {string} lockPath
 * @param {string} expectedNonce - nonce of the lock that was inspected as stale
 * @returns {{ claimed: boolean, gone?: boolean, displaced?: boolean, restored?: boolean }}
 */
export function claimStaleLock(lockPath, expectedNonce) {
  const claimPath = `${lockPath}.claimed-${process.pid}-${Date.now()}`;
  try {
    renameSync(lockPath, claimPath);
  } catch {
    // Someone else broke the stale lock first (ENOENT) — retry acquisition.
    return { claimed: false, gone: true };
  }

  // Verify we claimed the exact file we inspected as stale.
  let claimedNonce = null;
  try {
    const raw = readFileSync(claimPath, "utf8");
    claimedNonce = JSON.parse(raw)?.nonce ?? null;
  } catch {}
  if (claimedNonce !== null && claimedNonce === expectedNonce) {
    try {
      unlinkSync(claimPath);
    } catch {}
    return { claimed: true };
  }

  // We displaced a newer lock. Restore it without clobbering: linkSync fails
  // with EEXIST if a new lock already (re)occupied the path — then the
  // displaced file is left in place, still identifying its holder by content.
  let restored = false;
  try {
    linkSync(claimPath, lockPath);
    restored = true;
    try {
      unlinkSync(claimPath);
    } catch {}
  } catch {}
  return { claimed: false, displaced: true, restored };
}

/**
 * Acquire exclusive lockfile with retry/backoff.
 * Writes { pid, ts, nonce } into the lockfile; the nonce makes every
 * acquisition unique so stale-breaking can verify file identity (see
 * claimStaleLock).
 *
 * @param {string} lockPath
 * @param {number} [timeoutMs]
 * @returns {number} file descriptor
 */
export function acquireLock(lockPath, timeoutMs = 10000) {
  const start = Date.now();
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));

  while (true) {
    const nonce = randomUUID();
    try {
      const fd = openSync(lockPath, "wx");
      try {
        const metadata = JSON.stringify({ pid: process.pid, ts: Date.now(), nonce });
        writeFileSync(fd, metadata, "utf8");
      } catch {}

      // Verify that OUR acquisition is what the lock path now holds
      try {
        const raw = readFileSync(lockPath, "utf8");
        const parsed = JSON.parse(raw);
        if (parsed.pid !== process.pid || parsed.nonce !== nonce) {
          try { closeSync(fd); } catch {}
          continue;
        }
      } catch {}

      return fd;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;

      const elapsed = Date.now() - start;
      if (elapsed > timeoutMs) {
        // Stale-breaking under verification: snapshot the CURRENT lock via an
        // open fd (immune to path replacement), decide staleness on that exact
        // file, then atomically claim it by nonce (never blind-unlink).
        let inspectedNonce = null;
        let breakable = false;
        try {
          const staleFd = openSync(lockPath, "r");
          try {
            const meta = readLockMeta(staleFd);
            const st = fstatSync(staleFd);
            inspectedNonce = typeof meta?.nonce === "string" ? meta.nonce : null;
            breakable = shouldBreakStaleLock(meta, st);
          } finally {
            try { closeSync(staleFd); } catch {}
          }
        } catch {}

        if (breakable) {
          claimStaleLock(lockPath, inspectedNonce);
          continue;
        }

        throw new Error(`Timeout acquiring ledger lockfile at ${lockPath}`);
      }

      Atomics.wait(sleepBuf, 0, 0, 15);
    }
  }
}

/**
 * Release exclusive lockfile, verifying process ownership before unlinking.
 * @param {number} fd
 * @param {string} lockPath
 */
export function releaseLock(fd, lockPath) {
  try {
    if (fd !== null) closeSync(fd);
  } catch {}
  try {
    const raw = readFileSync(lockPath, "utf8");
    const meta = JSON.parse(raw);
    if (meta && meta.pid === process.pid) {
      unlinkSync(lockPath);
    }
  } catch {
    // If lockfile is missing or already unlinked, safe no-op
  }
}

/**
 * Execute a function within the exclusive ledger lockfile.
 * @template T
 * @param {string} mirqlDir
 * @param {() => T} fn
 * @param {number} [timeoutMs]
 * @returns {T}
 */
export function withLedgerLock(mirqlDir, fn, timeoutMs = 10000) {
  const lockPath = join(mirqlDir, "ledger.lock");
  mkdirSync(mirqlDir, { recursive: true });
  const fd = acquireLock(lockPath, timeoutMs);
  try {
    return fn();
  } finally {
    releaseLock(fd, lockPath);
  }
}
