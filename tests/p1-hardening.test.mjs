import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  withLedgerLock,
  acquireLock,
  releaseLock,
  canWriteEvent,
  EXIT_CODES,
} from "../packages/core/index.mjs";
import {
  checkSwallowedExceptions,
} from "../packages/run/anti-cheat.mjs";
import {
  verifyLedger,
  appendEvent,
} from "../packages/log/index.mjs";
import {
  runGenesis,
} from "../packages/inbox/genesis.mjs";
import {
  renderDigest,
} from "../packages/inbox/digest.mjs";

describe("P1 Hardening: Multi-Process Locking, ACL Parity, Trust Root, & Anti-Cheat", () => {
  it("P1.1: withLedgerLock safely acquires, holds, and releases exclusive lockfile", () => {
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

  it("P1.2: policy/writers.yaml and packages/core/acl.mjs have 100% parity across all event types", () => {
    const yamlPath = resolve(import.meta.dirname, "../policy/writers.yaml");
    const yamlContent = readFileSync(yamlPath, "utf8");

    // Extract each writer namespace and its unescaped regex pattern
    const writerEntries = [];
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
        writerEntries.push({ ns: key, patternStr: val, regex: new RegExp(val) });
      }
    }

    assert.equal(writerEntries.length, 7, "Must define exactly 7 writer namespaces");

    const testEvents = [
      // tool:queue
      { ns: "tool:queue", type: "job.enqueued", expected: true },
      { ns: "tool:queue", type: "job.promoted", expected: true },
      { ns: "tool:queue", type: "factory.mode_changed", expected: true },
      { ns: "tool:queue", type: "factory.halted", expected: true },
      { ns: "tool:queue", type: "mirql.quiescent", expected: true },
      { ns: "tool:queue", type: "attempt.outcome", expected: false },

      // tool:run_supervisor
      { ns: "tool:run_supervisor", type: "attempt.started", expected: true },
      { ns: "tool:run_supervisor", type: "attempt.outcome", expected: true },
      { ns: "tool:run_supervisor", type: "probe.completed", expected: true },
      { ns: "tool:run_supervisor", type: "warrant.converged", expected: true },
      { ns: "tool:run_supervisor", type: "warrant.escalated", expected: true },
      { ns: "tool:run_supervisor", type: "job.enqueued", expected: false },

      // tool:log
      { ns: "tool:log", type: "ledger.snapshot", expected: true },
      { ns: "tool:log", type: "log.snapshot", expected: true },
      { ns: "tool:log", type: "ledger.compacted", expected: true },
      { ns: "tool:log", type: "job.enqueued", expected: false },

      // tool:inbox
      { ns: "tool:inbox", type: "human.approval_requested", expected: true },
      { ns: "tool:inbox", type: "human.kill", expected: true },
      { ns: "tool:inbox", type: "inbox.proposal_created", expected: true },

      // human:owner
      { ns: "human:owner", type: "mirql.genesis", expected: true },
      { ns: "human:owner", type: "mirql.resume", expected: true },
      { ns: "human:owner", type: "mirql.halt", expected: true },
      { ns: "human:owner", type: "factory.resumed", expected: true },
      { ns: "human:owner", type: "warrant.created", expected: true },
      { ns: "human:owner", type: "human.intent", expected: true },

      // notary:mergeproof
      { ns: "notary:mergeproof", type: "verdict.issued", expected: true },
      { ns: "notary:mergeproof", type: "verdict.rejected", expected: true },
      { ns: "notary:mergeproof", type: "merge.executed", expected: true },
      { ns: "notary:mergeproof", type: "promotion.accepted", expected: true },

      // daemon:lifeguard
      { ns: "daemon:lifeguard", type: "lifeguard.heartbeat", expected: true },
      { ns: "daemon:lifeguard", type: "lifeguard.circuit_trip", expected: true },
      { ns: "daemon:lifeguard", type: "mirql.rollback", expected: true },
      { ns: "daemon:lifeguard", type: "factory.rollback", expected: true },
      { ns: "daemon:lifeguard", type: "factory.resumed", expected: true },
      { ns: "daemon:lifeguard", type: "mirql.resume", expected: true },
    ];

    for (const testCase of testEvents) {
      const entry = writerEntries.find((w) => w.ns === testCase.ns);
      assert.ok(entry, `Namespace ${testCase.ns} must exist in writers.yaml`);
      assert.equal(
        entry.regex.test(testCase.type),
        testCase.expected,
        `writers.yaml check failed for (${testCase.ns}, ${testCase.type})`,
      );
      assert.equal(
        canWriteEvent(testCase.ns, testCase.type),
        testCase.expected,
        `canWriteEvent check failed for (${testCase.ns}, ${testCase.type})`,
      );
    }
  });

  it("P1.3: verifyLedger anchors trust root via --expect-head hash checking", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-p1-head-"));
    try {
      const keyOut = join(tmp, "human.key.json");
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

      // Verify digest includes head_hash
      const digest = renderDigest(tmp);
      assert.equal(digest.head_hash, genesisRes.head_hash);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("P1.4: checkSwallowedExceptions detects string-brace evasion (Probe P4)", () => {
    // Evasive payload from Probe P4: string literal containing '}'
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

  it("P1.4: checkSwallowedExceptions detects global uncaughtException error swallowing (Probe P6)", () => {
    // Evasive payload from Probe P6: process.on('uncaughtException', () => {})
    const uncaughtCode = `
      process.on('uncaughtException', () => {
        // silent swallow
      });
    `;

    const result = checkSwallowedExceptions(uncaughtCode, "test-uncaught.js");
    assert.equal(result.ok, false, "Must detect empty uncaughtException handler");
    assert.equal(result.violations.length, 1);
  });
});
