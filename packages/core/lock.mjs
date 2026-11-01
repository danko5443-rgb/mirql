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
  existsSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

/** Age beyond which a lock whose holder is dead may be broken. */
export const STALE_LOCK_AGE_MS = 15000;

/** Active nonces per held lock descriptor (M2 protection against cross-thread/recycled PID unlinks). */
const activeNonces = new Map();

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
 * Read and parse the metadata recorded in a lock file descriptor or file path.
 * @param {number|string} target
 * @returns {{ pid?: number, ts?: number, nonce?: string } | null}
 */
function readLockMeta(target) {
  try {
    const raw = readFileSync(target, "utf8");
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
 * Check whether a previously acquired lock is still affirmatively held
 * at lockPath (detects displacement by racing breaker or external rename).
 *
 * @param {number} fd
 * @param {string} lockPath
 * @returns {boolean}
 */
export function isLockHeld(fd, lockPath) {
  if (typeof fd !== "number" || fd < 0) return false;
  const expectedNonce = activeNonces.get(fd);
  try {
    const fdStat = fstatSync(fd);
    const pathStat = statSync(lockPath);
    // Inode must match the opened descriptor
    if (fdStat.ino !== pathStat.ino) return false;
    // Nonce must match what this acquisition wrote
    if (expectedNonce) {
      const meta = readLockMeta(lockPath);
      if (!meta || meta.pid !== process.pid || meta.nonce !== expectedNonce) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Atomically claim the stale lock by RENAMING it out of the way (issue #12).
 *
 * Rename is atomic: exactly one contender can move a given lock file off the
 * lock path — the losing contender's rename hits ENOENT. After claiming, the
 * claimed file's nonce is re-verified against `expectedNonce`.
 *
 * If `expectedNonce` matches (or if expectedNonce was null and the claimed file
 * is verified still stale / empty / legacy), the claim succeeds and the claimed
 * file is removed.
 *
 * If a newer lock was displaced (nonce mismatch), it attempts safe restoration
 * without clobbering.
 *
 * @param {string} lockPath
 * @param {string|null} expectedNonce - nonce of the lock that was inspected as stale
 * @returns {{ claimed: boolean, gone?: boolean, displaced?: boolean, restored?: boolean }}
 */
export function claimStaleLock(lockPath, expectedNonce) {
  const claimPath = `${lockPath}.claimed-${process.pid}-${Date.now()}`;
  try {
    renameSync(lockPath, claimPath);
  } catch (err) {
    if (err && (err.code === "ENOENT" || err.code === "EBUSY")) {
      return { claimed: false, gone: true };
    }
    return { claimed: false, gone: true };
  }

  // Inspect the claimed file to verify identity
  let claimedMeta = null;
  let claimedStat = null;
  try {
    claimedMeta = readLockMeta(claimPath);
    claimedStat = statSync(claimPath);
  } catch {}

  const claimedNonce = typeof claimedMeta?.nonce === "string" ? claimedMeta.nonce : null;

  // Case 1: Exact nonce match with inspected stale lock
  if (claimedNonce !== null && claimedNonce === expectedNonce) {
    try {
      unlinkSync(claimPath);
    } catch {}
    return { claimed: true };
  }

  // Case 2 (B1 fix): Inspected lock had no nonce (empty file, corrupt JSON, or legacy lock).
  // If the claimed file also has no nonce AND is still provably stale/empty, complete the break!
  if (expectedNonce === null && claimedNonce === null) {
    if (shouldBreakStaleLock(claimedMeta, claimedStat)) {
      try {
        unlinkSync(claimPath);
      } catch {}
      return { claimed: true };
    }
  }

  // Case 3 (Displaced newer lock): We grabbed a newer lock that replaced the stale one.
  // Restore it safely without clobbering:
  let restored = false;
  try {
    linkSync(claimPath, lockPath);
    restored = true;
    try {
      unlinkSync(claimPath);
    } catch {}
  } catch {
    // If linkSync fails (e.g. non-NTFS or EEXIST), try rename if lockPath is free
    if (!existsSync(lockPath)) {
      try {
        renameSync(claimPath, lockPath);
        restored = true;
      } catch {}
    }
  }
  return { claimed: false, displaced: true, restored };
}

/**
 * Acquire exclusive lockfile with retry/backoff.
 * Writes { pid, ts, nonce } into the lockfile; the nonce makes every
 * acquisition unique so stale-breaking can verify file identity.
 *
 * Fail-closed (B3): Write errors immediately abort and clean up.
 * Verification failure never falls through to return fd.
 * Hard deadline (M3): Bounded execution prevents unbounded spinning.
 *
 * @param {string} lockPath
 * @param {number} [timeoutMs]
 * @returns {number} file descriptor
 */
export function acquireLock(lockPath, timeoutMs = 10000) {
  const start = Date.now();
  const hardDeadline = start + timeoutMs * 2 + 5000;
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));

  while (true) {
    if (Date.now() > hardDeadline) {
      throw new Error(`Timeout acquiring ledger lockfile at ${lockPath}`);
    }

    const nonce = randomUUID();
    try {
      const fd = openSync(lockPath, "wx");
      try {
        const metadata = JSON.stringify({ pid: process.pid, ts: Date.now(), nonce });
        writeFileSync(fd, metadata, "utf8");
      } catch (writeErr) {
        // B3: Fail-closed on metadata write failure (never leave empty lockfile)
        try { closeSync(fd); } catch {}
        try { unlinkSync(lockPath); } catch {}
        throw writeErr;
      }

      // Verify that OUR acquisition is what the lock path now holds (fail-closed)
      let verified = false;
      try {
        const raw = readFileSync(lockPath, "utf8");
        const parsed = JSON.parse(raw);
        if (parsed.pid === process.pid && parsed.nonce === nonce) {
          verified = true;
        }
      } catch {}

      if (!verified) {
        try { closeSync(fd); } catch {}
        continue;
      }

      activeNonces.set(fd, nonce);
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
 * Release exclusive lockfile, verifying process ownership and acquisition nonce before unlinking.
 * @param {number} fd
 * @param {string} lockPath
 */
export function releaseLock(fd, lockPath) {
  const expectedNonce = activeNonces.get(fd);
  activeNonces.delete(fd);
  try {
    if (typeof fd === "number" && fd >= 0) closeSync(fd);
  } catch {}
  try {
    const raw = readFileSync(lockPath, "utf8");
    const meta = JSON.parse(raw);
    if (meta && meta.pid === process.pid) {
      // M2: Only unlink if nonce matches our acquisition (or if unknown legacy)
      if (!expectedNonce || meta.nonce === expectedNonce) {
        unlinkSync(lockPath);
      }
    }
  } catch {
    // If lockfile is missing or already unlinked, safe no-op
  }
}

/**
 * Execute a function within the exclusive ledger lockfile.
 * Fail-closed (B2): Verifies lock was not displaced during critical section.
 *
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
    const result = fn();
    if (!isLockHeld(fd, lockPath)) {
      throw new Error(`Ledger lock was displaced during execution at ${lockPath}`);
    }
    return result;
  } finally {
    releaseLock(fd, lockPath);
  }
}
