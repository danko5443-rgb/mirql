import {
  openSync,
  closeSync,
  unlinkSync,
  statSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

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
 * Acquire exclusive lockfile with retry/backoff.
 * Writes { pid, ts } into the lockfile for stale detection with liveness checks.
 *
 * @param {string} lockPath
 * @param {number} [timeoutMs]
 * @returns {number} file descriptor
 */
export function acquireLock(lockPath, timeoutMs = 10000) {
  const start = Date.now();
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));

  while (true) {
    try {
      const fd = openSync(lockPath, "wx");
      try {
        const metadata = JSON.stringify({ pid: process.pid, ts: Date.now() });
        writeFileSync(fd, metadata, "utf8");
      } catch {}

      // Verify that our PID was successfully recorded
      try {
        const raw = readFileSync(lockPath, "utf8");
        const parsed = JSON.parse(raw);
        if (parsed.pid !== process.pid) {
          try { closeSync(fd); } catch {}
          continue;
        }
      } catch {}

      return fd;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;

      const elapsed = Date.now() - start;
      if (elapsed > timeoutMs) {
        // Attempt intelligent stale-breaking: check age AND process liveness
        try {
          const st = statSync(lockPath);
          const ageMs = Date.now() - st.mtimeMs;
          if (ageMs > 15000) {
            let holderPid = null;
            try {
              const raw = readFileSync(lockPath, "utf8");
              const parsed = JSON.parse(raw);
              if (Number.isSafeInteger(parsed.pid)) {
                holderPid = parsed.pid;
              }
            } catch {}

            // If holder PID is dead or absent, safely break stale lock
            if (!holderPid || !isPidAlive(holderPid)) {
              try {
                unlinkSync(lockPath);
              } catch {}
              continue;
            }
          }
        } catch {}

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
