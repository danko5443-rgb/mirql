import { trustFile, resolveTrustRoot } from "../packages/core/trust-root.mjs";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  withLedgerLock,
  acquireLock,
  releaseLock,
  canWriteEvent,
  WRITER_ACL,
  EXIT_CODES,
} from "../packages/core/index.mjs";
import {
  checkSwallowedExceptions,
} from "../packages/run/anti-cheat.mjs";
import {
  verifyLedger,
  runCli,
  appendEvent,
} from "../packages/log/index.mjs";
import {
  runGenesis,
} from "../packages/inbox/genesis.mjs";
import {
  renderDigest,
} from "../packages/inbox/digest.mjs";

describe("P1 Hardening: Multi-Process Locking, ACL Parity, Trust Root, & Anti-Cheat", () => {
  it("P1.1: withLedgerLock safely acquires, holds, and releases exclusive lockfile with PID ownership", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-p1-lock-"));
    try {
      let executed = false;
      const res = withLedgerLock(tmp, () => {
        executed = true;
        const lockPath = join(tmp, "ledger.lock");
        assert.ok(existsSync(lockPath), "lockfile must exist while executing fn");
        const meta = JSON.parse(readFileSync(lockPath, "utf8"));
        assert.equal(meta.pid, process.pid);
        assert.ok(Number.isSafeInteger(meta.ts));
        return "lock_success";
      });
      assert.equal(executed, true);
      assert.equal(res, "lock_success");
      assert.equal(existsSync(join(tmp, "ledger.lock")), false, "lockfile must be unlinked after release");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("P1.1b: releaseLock only unlinks lockfile owned by current PID", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-p1-lock-pid-"));
    try {
      const lockPath = join(tmp, "ledger.lock");
      // Acquire legitimately
      const fd = acquireLock(lockPath, 1000);
      assert.ok(existsSync(lockPath));

      // Overwrite with a foreign PID to simulate lease stolen after timeout
      writeFileSync(lockPath, JSON.stringify({ pid: 999999, ts: Date.now() }), "utf8");

      // Attempt release by current process
      releaseLock(fd, lockPath);

      // Lockfile MUST NOT be unlinked because PID does not match current process
      assert.ok(existsSync(lockPath), "Lockfile owned by foreign PID must not be unlinked on release");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("P1.2: policy/writers.yaml and packages/core/acl.mjs have 100% 1:1 regex pattern parity", () => {
    const yamlPath = resolve(import.meta.dirname, "../policy/writers.yaml");
    const yamlContent = readFileSync(yamlPath, "utf8");

    // Extract each writer namespace and its raw string pattern from yaml
    const yamlMap = Object.create(null);
    const lines = yamlContent.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      const sepIdx = trimmed.indexOf('":');
      if (sepIdx !== -1) {
        const key = trimmed.slice(0, sepIdx).replace(/^"/, "").trim();
        let val = trimmed.slice(sepIdx + 2).trim();
        if (val.startsWith('"') && val.endsWith('"')) {
          val = val.slice(1, -1);
        }
        val = val.replace(/\\\\/g, "\\");
        yamlMap[key] = val;
      }
    }

    const expectedNamespaces = [
      "tool:queue",
      "tool:run_supervisor",
      "tool:log",
      "tool:inbox",
      "human:owner",
      "notary:mergeproof",
      "daemon:lifeguard",
    ];

    assert.equal(Object.keys(yamlMap).length, 7, "Must define exactly 7 writer namespaces");

    for (const ns of expectedNamespaces) {
      assert.ok(yamlMap[ns], `Namespace ${ns} must be in policy/writers.yaml`);
      assert.ok(WRITER_ACL[ns], `Namespace ${ns} must be in WRITER_ACL`);
      // Direct string parity check between YAML regex and WRITER_ACL RegExp source
      assert.equal(
        WRITER_ACL[ns].source,
        yamlMap[ns],
        `Exact regex source parity failed for namespace ${ns}`,
      );
    }

    // Verify authorized single-writer routing
    assert.equal(canWriteEvent("tool:queue", "job.enqueued"), true);
    assert.equal(canWriteEvent("tool:queue", "factory.halted"), true);
    assert.equal(canWriteEvent("tool:queue", "factory.resumed"), true);
    assert.equal(canWriteEvent("tool:run_supervisor", "attempt.started"), true);
    assert.equal(canWriteEvent("tool:run_supervisor", "warrant.converged"), true);
    assert.equal(canWriteEvent("tool:run_supervisor", "job.enqueued"), false);
    assert.equal(canWriteEvent("human:owner", "mirql.genesis"), true);
    assert.equal(canWriteEvent("human:owner", "mirql.resume"), true);
    assert.equal(canWriteEvent("human:owner", "factory.resumed"), true);
    assert.equal(canWriteEvent("daemon:lifeguard", "lifeguard.heartbeat"), true);
    assert.equal(canWriteEvent("daemon:lifeguard", "mirql.rollback"), true);
    // Multi-writer carve-out for daemon:lifeguard dropped
    assert.equal(canWriteEvent("daemon:lifeguard", "mirql.resume"), false);
    assert.equal(canWriteEvent("daemon:lifeguard", "factory.resumed"), false);
  });

  it("P1.3: verifyLedger anchors trust root via --expect-head hash checking and fail-closed validation", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-p1-head-"));
    try {
      mkdirSync(resolveTrustRoot(tmp), { recursive: true });
      const keyOut = trustFile(tmp, "human.key.json");
      const genesisRes = runGenesis(tmp, { humanKeyOut: keyOut });
      assert.ok(genesisRes.head_hash, "genesis must return head_hash");
      assert.equal(genesisRes.head_hash, genesisRes.hash);

      // Verify with matching expectHead
      const verifyOk = verifyLedger(tmp, { expectHead: genesisRes.head_hash });
      assert.equal(verifyOk.valid, true);
      assert.equal(verifyOk.head_hash, genesisRes.head_hash);

      // Verify with wrong expectHead
      const verifyBad = verifyLedger(tmp, {
        expectHead: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
      });
      assert.equal(verifyBad.valid, false);
      assert.equal(verifyBad.error, "head_hash_mismatch");

      // Verify invalid format throws USAGE_ERROR
      assert.throws(
        () => verifyLedger(tmp, { expectHead: "not-a-valid-sha" }),
        (err) => err.code === "USAGE_ERROR",
      );

      // Verify CLI --expect-head with invalid format exits with USAGE_ERROR
      const cliExit = runCli(["verify", `--dir=${tmp}`, "--expect-head=invalid"]);
      assert.equal(cliExit, EXIT_CODES.USAGE_ERROR);

      // Verify digest includes head_hash in both JSON and Markdown
      const digestJson = renderDigest(tmp);
      assert.equal(digestJson.head_hash, genesisRes.head_hash);

      const digestMd = renderDigest(tmp, { format: "markdown" });
      assert.ok(
        digestMd.includes(`- **Head Hash:** \`${genesisRes.head_hash}\``),
        "Markdown digest must contain formatted Head Hash",
      );
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("P1.4: checkSwallowedExceptions detects string-brace evasion (Probe P4)", () => {
    const evasiveCode = `
      function doWork() {
        try {
          riskyOperation();
        } catch (e) {
          const s = "}"; // string contains closing brace
        }
      }
    `;

    const result = checkSwallowedExceptions(evasiveCode, "test-evasive.js");
    assert.equal(result.ok, false, "Must detect empty catch block despite string literal closing brace");
    assert.equal(result.violations.length, 1);
  });

  it("P1.5: checkSwallowedExceptions distinguishes legitimate error handlers from swallowed exceptions (Probe P6)", () => {
    // 1. Silent swallow: should fail
    const uncaughtEmpty = `
      process.on('uncaughtException', () => {
        // silent swallow
      });
    `;
    const res1 = checkSwallowedExceptions(uncaughtEmpty, "test-empty.js");
    assert.equal(res1.ok, false, "Must detect empty uncaughtException handler");
    assert.equal(res1.violations.length, 1);

    // 2. Canonical handler with nested if/log block and process.exit: MUST PASS
    const canonicalHandler = `
      process.on('uncaughtException', (err) => {
        if (err) {
          console.error("FATAL:", err.message);
        }
        process.exit(1);
      });
    `;
    const res2 = checkSwallowedExceptions(canonicalHandler, "test-canonical.js");
    assert.equal(res2.ok, true, "Canonical error handler with nested if/exit must not be flagged");

    // 3. Nested if/log WITHOUT exit or throw: MUST FAIL
    const unhandledWithNestedIf = `
      process.once('unhandledRejection', (err) => {
        if (err) {
          console.error(err);
        }
      });
    `;
    const res3 = checkSwallowedExceptions(unhandledWithNestedIf, "test-nested-swallow.js");
    assert.equal(res3.ok, false, "Handler without exit/throw must be flagged");

    // 4. Concise arrow with process.exit: MUST PASS
    const conciseExit = `process.addListener('uncaughtException', (err) => process.exit(1));`;
    const res4 = checkSwallowedExceptions(conciseExit, "test-concise.js");
    assert.equal(res4.ok, true, "Concise arrow with process.exit must pass");

    // 5. prependListener with throw: MUST PASS
    const prependThrow = `
      process.prependListener('uncaughtException', function(err) {
        throw err;
      });
    `;
    const res5 = checkSwallowedExceptions(prependThrow, "test-prepend.js");
    assert.equal(res5.ok, true, "PrependListener with throw must pass");
  });
});
