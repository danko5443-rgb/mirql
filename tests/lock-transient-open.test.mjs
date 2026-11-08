// tests/lock-transient-open.test.mjs — issue #121: under Windows contention the loser of a
// lock open can see transient EPERM/EBUSY/ETXTBSY; acquisition must retry briefly instead of
// crashing, keep stale-lock semantics untouched, and stay bounded. Deterministic: transient
// failures are staged through the injected opener; no sleeps race real processes.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, openSync, closeSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  acquireLock,
  releaseLock,
  withLedgerLock,
  openLockExclusive,
  isTransientLockOpenError,
} from "../packages/core/lock.mjs";

const transientOpenError = (code) =>
  Object.assign(new Error(`${code}: operation not permitted, open 'ledger.lock'`), { code, syscall: "open", errno: -4048 });

describe("lock acquisition survives transient open failures (issue #121)", () => {
  let tempDir;
  let lockPath;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-lock-transient-"));
    lockPath = join(tempDir, "ledger.lock");
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("classifies only open-syscall contention codes as transient", () => {
    assert.equal(isTransientLockOpenError(transientOpenError("EPERM")), true);
    assert.equal(isTransientLockOpenError(transientOpenError("EBUSY")), true);
    assert.equal(isTransientLockOpenError(transientOpenError("ETXTBSY")), true);
    assert.equal(
      isTransientLockOpenError(transientOpenError("EACCES")),
      process.platform === "win32",
      "EACCES is contention noise only on win32",
    );
    assert.equal(
      isTransientLockOpenError(Object.assign(new Error("EPERM: write"), { code: "EPERM", syscall: "write" })),
      false,
      "only the failed open syscall retries",
    );
    assert.equal(
      isTransientLockOpenError(Object.assign(new Error("EEXIST: file exists"), { code: "EEXIST", syscall: "open" })),
      false,
      "EEXIST must keep flowing to the stale-lock path untouched",
    );
    assert.equal(isTransientLockOpenError(null), false);
    assert.equal(isTransientLockOpenError(new Error("plain")), false);
  });

  it("retries transient open failures and succeeds once contention clears", () => {
    const injected = ["EPERM", "EBUSY", "ETXTBSY"];
    let index = 0;
    const fd = openLockExclusive(lockPath, (path, flags) => {
      assert.equal(path, lockPath);
      assert.equal(flags, "wx");
      if (index < injected.length) {
        const code = injected[index];
        index += 1;
        throw transientOpenError(code);
      }
      return openSync(path, flags);
    });
    closeSync(fd);
    assert.equal(index, 3, "three transient failures were absorbed");
    assert.throws(() => openSync(lockPath, "wx"), { code: "EEXIST" }, "the surviving open exclusively created the lock file");
    unlinkSync(lockPath);
  });

  it("surfaces a persistent transient failure after at most five attempts and 250 ms", () => {
    let attempts = 0;
    const began = Date.now();
    assert.throws(
      () =>
        openLockExclusive(lockPath, () => {
          attempts += 1;
          throw transientOpenError("EPERM");
        }),
      (err) => err.code === "EPERM" && err.syscall === "open",
      "the original open error surfaces once retries are exhausted",
    );
    const elapsedMs = Date.now() - began;
    assert.equal(attempts, 5, "one initial attempt plus four bounded retries");
    assert.ok(elapsedMs < 250, `bounded backoff took ${elapsedMs} ms`);
  });

  it("does not retry non-transient opens: EEXIST reaches the stale-lock path immediately", () => {
    let attempts = 0;
    assert.throws(
      () =>
        openLockExclusive(lockPath, () => {
          attempts += 1;
          throw Object.assign(new Error("EEXIST: file exists"), { code: "EEXIST", syscall: "open" });
        }),
      { code: "EEXIST" },
    );
    assert.equal(attempts, 1);
  });

  it("acquireLock/withLedgerLock wait bounded and succeed once the holder releases", () => {
    const holder = acquireLock(lockPath, 1000);
    const began = Date.now();
    assert.throws(
      () => acquireLock(lockPath, 100),
      /Timeout acquiring ledger lockfile/,
      "a held lock makes the contender wait, then fail bounded",
    );
    assert.ok(Date.now() - began < 2000, "the wait stays bounded");
    releaseLock(holder, lockPath);

    const contender = acquireLock(lockPath, 1000);
    releaseLock(contender, lockPath);
    assert.equal(withLedgerLock(tempDir, () => "drained"), "drained");
  });
});
