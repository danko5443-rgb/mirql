// tests/lock-toctou.test.mjs — verified stale-breaking (issue #12).
// Pins the contract that a stale-breaker can NEVER unlink a lock it did not
// inspect: the break is an atomic rename-claim verified by nonce, so a second
// breaker racing the first cannot destroy the first's freshly acquired lock
// (the two-writers TOCTOU).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  acquireLock,
  claimStaleLock,
  releaseLock,
  shouldBreakStaleLock,
  withLedgerLock,
} from "../packages/core/lock.mjs";

/** A PID that is dead on every supported host (same convention as topology tests). */
const DEAD_PID = 999999;

function tmp() {
  return mkdtempSync(join(tmpdir(), "mirql-lock-toctou-"));
}

function writeLock(lockPath, meta, backdateMs = 0) {
  writeFileSync(lockPath, JSON.stringify(meta), "utf8");
  if (backdateMs > 0) {
    const past = new Date(Date.now() - backdateMs);
    utimesSync(lockPath, past, past);
  }
}

describe("ledger lock: verified stale-breaking (issue #12)", () => {
  it("shouldBreakStaleLock requires BOTH old age and a dead/absent holder", () => {
    const now = Date.now();
    const old = { mtimeMs: now - 30_000 };
    const fresh = { mtimeMs: now - 100 };
    assert.equal(shouldBreakStaleLock({ pid: DEAD_PID }, old, now), true);
    assert.equal(shouldBreakStaleLock({}, old, now), true); // no pid recorded → unverifiable
    assert.equal(shouldBreakStaleLock({ pid: process.pid }, old, now), false); // holder alive
    assert.equal(shouldBreakStaleLock({ pid: DEAD_PID }, fresh, now), false); // lock not old
    assert.equal(shouldBreakStaleLock({ pid: DEAD_PID }, null, now), false); // no stats → refuse
  });

  it("claimStaleLock claims (and removes) exactly the inspected lock", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      writeLock(lockPath, { pid: DEAD_PID, ts: Date.now() - 30_000, nonce: "stale-nonce-1" });
      const res = claimStaleLock(lockPath, "stale-nonce-1");
      assert.equal(res.claimed, true);
      assert.equal(existsSync(lockPath), false, "claimed stale lock must be removed");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("claimStaleLock RESTORES a displaced newer lock instead of destroying it (the TOCTOU kill)", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      // A NEWER lock (alive holder, fresh nonce) sits at the path — the breaker
      // inspected an OLDER stale lock (nonce "stale-old") that was already
      // replaced after its inspection. The claim grabs the newer file by rename;
      // nonce verification must detect the displacement and put it back.
      const freshContent = JSON.stringify({ pid: process.pid, ts: Date.now(), nonce: "fresh-nonce-2" });
      writeFileSync(lockPath, freshContent, "utf8");

      const res = claimStaleLock(lockPath, "stale-old");
      assert.equal(res.claimed, false);
      assert.equal(res.displaced, true);
      assert.equal(res.restored, true);
      assert.equal(existsSync(lockPath), true, "displaced lock must be restored, not destroyed");
      assert.equal(readFileSync(lockPath, "utf8"), freshContent, "restored content must be byte-identical");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("claimStaleLock reports gone when another breaker won the race", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      const res = claimStaleLock(lockPath, "any-nonce"); // path does not exist
      assert.equal(res.claimed, false);
      assert.equal(res.gone, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("acquireLock breaks a genuinely stale lock (dead holder, old mtime) and takes it", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      writeLock(lockPath, { pid: DEAD_PID, ts: Date.now() - 60_000, nonce: "old-stale" }, 60_000);
      const fd = acquireLock(lockPath, 200);
      try {
        const meta = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(meta.pid, process.pid, "acquirer must own the lock after breaking stale");
        assert.ok(typeof meta.nonce === "string" && meta.nonce.length > 0, "lock must carry a nonce");
      } finally {
        releaseLock(fd, lockPath);
      }
      assert.equal(existsSync(lockPath), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("acquireLock NEVER breaks a lock with a live holder — it times out", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      writeLock(lockPath, { pid: process.pid, ts: Date.now() - 60_000, nonce: "alive-holder" }, 60_000);
      assert.throws(() => acquireLock(lockPath, 150), /Timeout acquiring ledger lockfile/);
      const meta = JSON.parse(readFileSync(lockPath, "utf8"));
      assert.equal(meta.pid, process.pid, "live holder's lock must be untouched");
      assert.equal(meta.nonce, "alive-holder", "live holder's lock content must be untouched");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("each acquisition carries a unique nonce (identity for verified breaking)", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      const nonces = [];
      for (let i = 0; i < 2; i++) {
        const fd = acquireLock(lockPath, 1000);
        nonces.push(JSON.parse(readFileSync(lockPath, "utf8")).nonce);
        releaseLock(fd, lockPath);
      }
      assert.notEqual(nonces[0], nonces[1]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("withLedgerLock critical sections remain exclusive and self-cleaning", () => {
    const dir = tmp();
    try {
      const seen = [];
      for (let i = 0; i < 3; i++) {
        withLedgerLock(dir, () => {
          const meta = JSON.parse(readFileSync(join(dir, "ledger.lock"), "utf8"));
          seen.push(meta.pid);
        });
      }
      assert.deepEqual(seen, [process.pid, process.pid, process.pid]);
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it("claimStaleLock successfully breaks empty lockfiles and legacy locks without livelock (B1)", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      writeFileSync(lockPath, "", "utf8");
      const past = new Date(Date.now() - 30_000);
      utimesSync(lockPath, past, past);
      const res1 = claimStaleLock(lockPath, null);
      assert.equal(res1.claimed, true, "empty stale lock must be claimed, never livelocked");
      assert.equal(existsSync(lockPath), false);

      writeFileSync(lockPath, JSON.stringify({ pid: DEAD_PID, ts: Date.now() - 30_000 }), "utf8");
      utimesSync(lockPath, past, past);
      const res2 = claimStaleLock(lockPath, null);
      assert.equal(res2.claimed, true, "legacy stale lock must be claimed, never livelocked");
      assert.equal(existsSync(lockPath), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("releaseLock never unlinks a lock with a foreign nonce even if PID matches (M2)", () => {
    const dir = tmp();
    try {
      const lockPath = join(dir, "ledger.lock");
      const fd = acquireLock(lockPath, 1000);
      try {
        writeFileSync(lockPath, JSON.stringify({ pid: process.pid, ts: Date.now(), nonce: "foreign-nonce-diff" }), "utf8");
        releaseLock(fd, lockPath);
        assert.equal(existsSync(lockPath), true, "foreign-nonce lock must NOT be unlinked by prior releaser");
        const meta = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(meta.nonce, "foreign-nonce-diff");
      } finally {
        try { unlinkSync(lockPath); } catch {}
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("withLedgerLock fails closed if lock is displaced during execution (B2)", () => {
    const dir = tmp();
    try {
      assert.throws(
        () => {
          withLedgerLock(dir, () => {
            const lockPath = join(dir, "ledger.lock");
            writeFileSync(lockPath, JSON.stringify({ pid: DEAD_PID, ts: Date.now(), nonce: "displacing-nonce" }), "utf8");
          });
        },
        /Ledger lock was displaced during execution/
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
