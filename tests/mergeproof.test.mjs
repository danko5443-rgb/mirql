// Work Package W2: mergeproof — the mechanical merge gate.
//
// Covers:
// - `mirql m check` against the full conformance corpus (5 bad PR fixtures
//   MP-001..MP-005, 2 good PR fixtures → auto_merge), asserting exact rule
//   matches, JCS-only stdout, and canonical exit codes.
// - CLI input modes: --pr <file>, --pr <inline json>, stdin pipe.
// - CLI error handling: missing input, unreadable file, malformed JSON,
//   unknown subcommand, and the preserved W1 stub contract.
// - --base / --head lineage assertions (MP-004 STALE_BASE).
// - Law 13: PHI_INCREASE, PHI_NOT_DECREASED, THRIFT_TEST_FAILED, and the
//   fail-closed MISSING_PROOF verdict.
// - The notary: Ed25519 key load/generate (canonical + alias + --key),
//   verdict signing into canonical event envelopes, ledger append under
//   withLedgerLock (including a real two-process race), hash chaining,
//   idempotent dedup, and keyring registration.
// - F1 anti-cheat: string/comment/template concealment of process.exit is
//   flagged by both packages/run/anti-cheat.mjs and the mergeproof evaluator.
import { test, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  jcs,
  EXIT_CODES,
  generateEd25519Keypair,
  validateDocument,
  verifyEvent,
} from "../packages/core/index.mjs";
import { checkSwallowedExceptions as runCheckSwallowed } from "../packages/run/anti-cheat.mjs";
import {
  evaluatePullRequest,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "../packages/mergeproof/evaluator.mjs";
import {
  NOTARY_WRITER_NS,
  NOTARY_KEY_FILE,
  NOTARY_KEY_ALIAS_FILE,
  GENESIS_PREV_HASH,
  VERDICT_EVENT_TYPES,
  loadOrCreateNotaryKey,
  signAndAppendVerdict,
} from "../packages/mergeproof/notary.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN = join(ROOT, "bin", "mirql.mjs");
const CONFORMANCE_BAD = join(ROOT, "conformance", "bad_prs");
const CONFORMANCE_GOOD = join(ROOT, "conformance", "good_prs");

const GOOD_01_HEAD = "1111222233334444555566667777888899990000";
const GOOD_01_BASE = "b222222222222222222222222222222222222222";

/** Spawn `node bin/mirql.mjs <args>` at the repo root (sync). */
function runMirql(args, options = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 60_000,
    ...options,
  });
}

/** Parse the single stdout line as JSON and assert it is pure JCS. */
function parseJcsStdout(res, label) {
  assert.equal(res.stdout.endsWith("\n"), true, `${label}: stdout must be newline-terminated`);
  const lines = res.stdout.split("\n").filter((l) => l.trim().length > 0);
  assert.equal(lines.length, 1, `${label}: stdout must be exactly one JSON line`);
  const doc = JSON.parse(lines[0]);
  assert.equal(
    jcs(doc) + "\n",
    res.stdout,
    `${label}: stdout must be canonical JCS (RFC 8785)`,
  );
  return doc;
}

/** Read + parse a conformance fixture. */
function loadFixture(...segments) {
  return JSON.parse(readFileSync(join(...segments), "utf8"));
}

// ---------------------------------------------------------------------------
// 1. Conformance corpus: bad PRs map exactly onto MP-001..MP-005
// ---------------------------------------------------------------------------

describe("mergeproof: conformance corpus — bad PRs", () => {
  const cases = [
    { file: "01-touch-human-only.json", rule: "MP-001", violation: "TOUCH_HUMAN_ONLY", verdict: "reject" },
    { file: "02-delete-test.json", rule: "MP-002", violation: "TEST_DELETED", verdict: "reject" },
    { file: "03-swallow-exception.json", rule: "MP-003", violation: "ANTI_CHEAT_VIOLATION", verdict: "reject" },
    { file: "04-stale-base.json", rule: "MP-004", violation: "STALE_BASE", verdict: "reject" },
    { file: "05-uncited-surface.json", rule: "MP-005", violation: "UNCITED_SURFACE", verdict: "needs_human" },
  ];

  for (const c of cases) {
    it(`bad PR ${c.file} → ${c.verdict} under ${c.rule} (${c.violation}) via CLI`, () => {
      const res = runMirql(["m", "check", "--pr", join("conformance", "bad_prs", c.file)]);
      assert.equal(res.error, undefined, res.error?.message);
      const doc = parseJcsStdout(res, c.file);
      assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE, `${c.file}: exit code`);
      assert.equal(doc.tool, "mergeproof");
      assert.equal(doc.command, "check");
      assert.equal(doc.ok, false);
      assert.equal(doc.verdict, c.verdict);
      assert.equal(doc.rule, c.rule);
      assert.equal(doc.violation, c.violation);
      assert.equal(typeof doc.detail, "string");
      assert.ok(doc.detail.length > 0, `${c.file}: detail must be non-empty`);
    });

    it(`bad PR ${c.file} → same verdict programmatically (deterministic, expected_* never read)`, () => {
      const fixture = loadFixture(CONFORMANCE_BAD, c.file);
      const gamed = {
        ...fixture,
        expected_verdict: "auto_merge",
        expected_rule: "MP-000",
        evidence: { ...fixture.evidence, violation_type: "NOTHING_TO_SEE_HERE" },
      };
      const result = evaluatePullRequest(gamed, { rootDir: ROOT });
      assert.equal(result.ok, false);
      assert.equal(result.rule, c.rule);
      assert.equal(result.violation, c.violation);
      assert.equal(result.verdict, c.verdict);
    });
  }
});

// ---------------------------------------------------------------------------
// 2. Conformance corpus: good PRs auto-merge
// ---------------------------------------------------------------------------

describe("mergeproof: conformance corpus — good PRs", () => {
  it("good PR 01 (causal repro fix) → auto_merge / MP-000 with exit 0", () => {
    const res = runMirql(["m", "check", "--pr", join("conformance", "good_prs", "01-valid-repro-fix.json")]);
    const doc = parseJcsStdout(res, "good-01");
    assert.equal(res.status, EXIT_CODES.OK);
    assert.equal(doc.ok, true);
    assert.equal(doc.verdict, "auto_merge");
    assert.equal(doc.rule, "MP-000");
    assert.equal(doc.violation, null);
    assert.equal(doc.job_id, "job_good_001");
    assert.equal(doc.pr.number, 201);
    assert.equal(doc.delta_phi, -5);
  });

  it("good PR 02 (consolidation with ΔΦ drop + thrift) → auto_merge / MP-000", () => {
    const res = runMirql(["m", "check", "--pr", join("conformance", "good_prs", "02-valid-consolidate-phi-drop.json")]);
    const doc = parseJcsStdout(res, "good-02");
    assert.equal(res.status, EXIT_CODES.OK);
    assert.equal(doc.verdict, "auto_merge");
    assert.equal(doc.rule, "MP-000");
    assert.equal(doc.delta_phi, -85);
  });
});

// ---------------------------------------------------------------------------
// 3. CLI input modes and error handling
// ---------------------------------------------------------------------------

describe("mergeproof: CLI contract", () => {
  it("bare `m`, `m status`, `m --help`, `m -h` keep the W1 stub contract", () => {
    for (const args of [[], ["status"], ["--help"], ["-h"]]) {
      const res = runMirql(["m", ...args]);
      assert.equal(res.status, EXIT_CODES.OK, `mirql m ${args.join(" ")}`);
      assert.deepEqual(JSON.parse(res.stdout), { tool: "mergeproof", status: "stub" });
    }
    // And through the full tool name too.
    const full = runMirql(["mergeproof"]);
    assert.equal(full.status, EXIT_CODES.OK);
    assert.deepEqual(JSON.parse(full.stdout), { tool: "mergeproof", status: "stub" });
  });

  it("`m help` prints usage with exit 0", () => {
    const res = runMirql(["m", "help"]);
    assert.equal(res.status, EXIT_CODES.OK);
    const doc = JSON.parse(res.stdout);
    assert.equal(doc.tool, "mergeproof");
    assert.ok(doc.subcommands.check.includes("--pr"));
  });

  it("`--pr` accepts an inline JSON document", () => {
    const fixture = loadFixture(CONFORMANCE_BAD, "01-touch-human-only.json");
    const res = runMirql(["m", "check", "--pr", JSON.stringify(fixture)]);
    const doc = parseJcsStdout(res, "inline");
    assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE);
    assert.equal(doc.rule, "MP-001");
    assert.equal(doc.violation, "TOUCH_HUMAN_ONLY");
  });

  it("without --pr the PR document is read from stdin", () => {
    const fixture = loadFixture(CONFORMANCE_GOOD, "01-valid-repro-fix.json");
    const res = runMirql(["m", "check"], { input: JSON.stringify(fixture) });
    const doc = parseJcsStdout(res, "stdin");
    assert.equal(res.status, EXIT_CODES.OK);
    assert.equal(doc.verdict, "auto_merge");
    assert.equal(doc.rule, "MP-000");
  });

  it("missing input (no --pr, empty stdin) → USAGE_ERROR 2 with JSON on stderr", () => {
    const res = runMirql(["m", "check"]);
    assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
    assert.equal(res.stdout, "");
    const err = JSON.parse(res.stderr);
    assert.equal(err.tool, "mergeproof");
    assert.equal(err.error, "USAGE_ERROR");
    assert.match(err.reason, /no PR input/);
  });

  it("unreadable --pr file → USAGE_ERROR 2", () => {
    const res = runMirql(["m", "check", "--pr", "conformance/bad_prs/does-not-exist.json"]);
    assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
    assert.match(JSON.parse(res.stderr).reason, /not found/);
  });

  it("malformed --pr JSON → USAGE_ERROR 2", () => {
    const res = runMirql(["m", "check", "--pr", "{not-json"]);
    assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
    assert.match(JSON.parse(res.stderr).reason, /valid JSON/);
  });

  it("non-object PR document → USAGE_ERROR 2", () => {
    const res = runMirql(["m", "check", "--pr", "[1,2,3]"]);
    assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
    assert.match(JSON.parse(res.stderr).reason, /JSON object/);
  });

  it("floating-point PR document violates Law 17 → USAGE_ERROR 2", () => {
    const fixture = loadFixture(CONFORMANCE_GOOD, "01-valid-repro-fix.json");
    fixture.phi.delta_phi = -5.5;
    const res = runMirql(["m", "check", "--pr", JSON.stringify(fixture)]);
    assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
    assert.match(JSON.parse(res.stderr).reason, /Law 17/);
  });

  it("unknown subcommand → USAGE_ERROR 2", () => {
    const res = runMirql(["m", "definitely-not-check"]);
    assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
    assert.match(res.stderr, /unknown subcommand/);
  });
});

// ---------------------------------------------------------------------------
// 4. --base / --head lineage assertions (MP-004)
// ---------------------------------------------------------------------------

describe("mergeproof: MP-004 stale base via --base / --head", () => {
  const goodPath = join("conformance", "good_prs", "01-valid-repro-fix.json");

  it("--base matching the PR base_sha passes MP-004 and still auto-merges", () => {
    const res = runMirql(["m", "check", "--pr", goodPath, "--base", GOOD_01_BASE]);
    const doc = parseJcsStdout(res, "base-match");
    assert.equal(res.status, EXIT_CODES.OK);
    assert.equal(doc.rule, "MP-000");
    assert.equal(doc.checks.stale_base, true);
  });

  it("--base diverging from the PR base_sha → reject STALE_BASE (MP-004)", () => {
    const res = runMirql(["m", "check", "--pr", goodPath, "--base", "0".repeat(40)]);
    const doc = parseJcsStdout(res, "base-mismatch");
    assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE);
    assert.equal(doc.rule, "MP-004");
    assert.equal(doc.violation, "STALE_BASE");
    assert.equal(doc.checks.stale_base, false);
  });

  it("--head diverging from the PR head_sha → reject STALE_BASE (MP-004)", () => {
    const res = runMirql(["m", "check", "--pr", goodPath, "--head", "9".repeat(40)]);
    const doc = parseJcsStdout(res, "head-mismatch");
    assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE);
    assert.equal(doc.rule, "MP-004");
    assert.equal(doc.violation, "STALE_BASE");
  });
});

// ---------------------------------------------------------------------------
// 5. Law 13: Monotone Potential Phi & Thrift
// ---------------------------------------------------------------------------

describe("mergeproof: Law 13 phi gate", () => {
  /** A minimal clean bugfix PR template. */
  function cleanPr(overrides = {}) {
    return {
      schema: "outcome/v1",
      job_id: "job_phi_test",
      pr: {
        number: 301,
        head_sha: "a".repeat(40),
        base_sha: "b".repeat(40),
        author: "agent/builder",
        kind: "bugfix",
      },
      diff_stat: { files_changed: ["src/calc.mjs"], lines_added: 8, lines_deleted: 2 },
      proof: { causal_cycle_completed: true },
      evidence: { forbidden_paths_touched: [], tests_deleted: [] },
      anti_cheat: { violations_count: 0, flags: [] },
      phi: { phi_base: 100, phi_head: 100, delta_phi: 0 },
      surface: { uncited_commands: [], delta_count: 0 },
      ...overrides,
    };
  }

  it("delta_phi > 0 → reject PHI_INCREASE under LAW_13", () => {
    const res = runMirql(["m", "check", "--pr", JSON.stringify(cleanPr({ phi: { phi_base: 100, phi_head: 110, delta_phi: 10 } }))]);
    const doc = parseJcsStdout(res, "phi-increase");
    assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE);
    assert.equal(doc.rule, "LAW_13");
    assert.equal(doc.violation, "PHI_INCREASE");
    assert.equal(doc.delta_phi, 10);
  });

  it("refactor with delta_phi === 0 → reject PHI_NOT_DECREASED (strict decrease)", () => {
    const pr = cleanPr({
      pr: { number: 302, head_sha: "c".repeat(40), base_sha: "b".repeat(40), author: "agent/consolidator", kind: "refactor" },
      phi: { phi_base: 100, phi_head: 100, delta_phi: 0, thrift_test_passed: true },
    });
    const result = evaluatePullRequest(pr, { rootDir: ROOT });
    assert.equal(result.ok, false);
    assert.equal(result.rule, "LAW_13");
    assert.equal(result.violation, "PHI_NOT_DECREASED");
  });

  it("refactor with delta_phi < 0 but no thrift pass → reject THRIFT_TEST_FAILED", () => {
    const pr = cleanPr({
      pr: { number: 303, head_sha: "d".repeat(40), base_sha: "b".repeat(40), author: "agent/builder", kind: "refactor" },
      phi: { phi_base: 100, phi_head: 90, delta_phi: -10 },
    });
    const result = evaluatePullRequest(pr, { rootDir: ROOT });
    assert.equal(result.ok, false);
    assert.equal(result.rule, "LAW_13");
    assert.equal(result.violation, "THRIFT_TEST_FAILED");
  });

  it("refactor with delta_phi < 0 and thrift_test_passed === true → auto_merge", () => {
    const pr = cleanPr({
      pr: { number: 304, head_sha: "e".repeat(40), base_sha: "b".repeat(40), author: "agent/consolidator", kind: "refactor" },
      phi: { phi_base: 100, phi_head: 60, delta_phi: -40, thrift_test_passed: true },
    });
    const result = evaluatePullRequest(pr, { rootDir: ROOT });
    assert.equal(result.ok, true);
    assert.equal(result.rule, "MP-000");
    assert.equal(result.verdict, "auto_merge");
  });

  it("missing proof fails closed with MISSING_PROOF (suite_pass_head alone is not causal)", () => {
    const pr = cleanPr({ proof: { suite_pass_head: true } });
    const result = evaluatePullRequest(pr, { rootDir: ROOT });
    assert.equal(result.ok, false);
    assert.equal(result.rule, "MP-000");
    assert.equal(result.violation, "MISSING_PROOF");
    assert.equal(result.verdict, "reject");
    assert.equal(result.checks.proof, false);
  });

  it("a proven suite pass (base AND head) satisfies MP-000 for consolidations", () => {
    const pr = cleanPr({ proof: { suite_pass_base: true, suite_pass_head: true } });
    const result = evaluatePullRequest(pr, { rootDir: ROOT });
    assert.equal(result.ok, true);
    assert.equal(result.rule, "MP-000");
    assert.equal(result.verdict, "auto_merge");
  });
});

// ---------------------------------------------------------------------------
// 6. Notary: key management, signing, ledger append, dedup, chaining
// ---------------------------------------------------------------------------

describe("mergeproof: notary signing & ledger append", () => {
  it("VERDICT_EVENT_TYPES maps every verdict to its Law 3 event type", () => {
    assert.deepEqual(VERDICT_EVENT_TYPES, {
      auto_merge: "verdict.issued",
      reject: "verdict.rejected",
      needs_human: "verdict.needs_human",
      accepted: "verdict.accepted",
    });
    assert.equal(NOTARY_WRITER_NS, "notary:mergeproof");
  });

  it("loadOrCreateNotaryKey generates a 0o600 keypair + keyring entry when absent", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-key-"));
    try {
      const kp = loadOrCreateNotaryKey(tmp);
      assert.equal(kp.keyId.startsWith("ed25519:"), true);
      assert.equal(kp.keyId.length, "ed25519:".length + 43);
      assert.equal(kp.sourceFile, join(tmp, "keys", NOTARY_KEY_FILE));
      assert.equal(existsSync(kp.sourceFile), true);
      const persisted = JSON.parse(readFileSync(kp.sourceFile, "utf8"));
      assert.equal(persisted.keyId, kp.keyId);
      if (process.platform !== "win32") {
        const mode = (statSync(kp.sourceFile).mode & 0o777);
        assert.equal(mode, 0o600, "notary private key file must be 0o600");
      }
      const keyring = JSON.parse(readFileSync(join(tmp, "ledger", "keyring.json"), "utf8"));
      assert.equal(keyring[kp.keyId].ns, NOTARY_WRITER_NS);
      assert.equal(keyring[kp.keyId].publicKey, kp.publicKey);
      assert.equal(keyring[NOTARY_WRITER_NS].publicKey, kp.publicKey);

      // Reload is stable (no regeneration).
      const again = loadOrCreateNotaryKey(tmp);
      assert.equal(again.keyId, kp.keyId);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("the mergeproof.key.json alias is preferred when present", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-alias-"));
    try {
      const generated = generateEd25519Keypair();
      mkdirSync(join(tmp, "keys"), { recursive: true });
      writeFileSync(
        join(tmp, "keys", NOTARY_KEY_ALIAS_FILE),
        JSON.stringify(generated, null, 2) + "\n",
      );
      const kp = loadOrCreateNotaryKey(tmp);
      assert.equal(kp.keyId, generated.keyId);
      assert.equal(kp.sourceFile, join(tmp, "keys", NOTARY_KEY_ALIAS_FILE));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("an explicit --key path wins over the keys/ directory", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-explicit-"));
    try {
      const generated = generateEd25519Keypair();
      const explicit = join(tmp, "outside-notary.key.json");
      writeFileSync(explicit, JSON.stringify(generated, null, 2) + "\n");
      const kp = loadOrCreateNotaryKey(tmp, { keyPath: explicit });
      assert.equal(kp.keyId, generated.keyId);
      assert.equal(kp.sourceFile, explicit);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("an invalid --key file fails closed with USAGE_ERROR", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-badkey-"));
    try {
      const bad = join(tmp, "bad.key.json");
      writeFileSync(bad, JSON.stringify({ privateKey: "junk" }), "utf8");
      assert.throws(
        () => loadOrCreateNotaryKey(tmp, { keyPath: bad }),
        (err) => err.code === "USAGE_ERROR",
      );
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("signAndAppendVerdict writes a schema-valid verdict.issued event anchored at genesis", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-sign-"));
    try {
      const fixture = loadFixture(CONFORMANCE_GOOD, "01-valid-repro-fix.json");
      const verdict = evaluatePullRequest(fixture, { rootDir: ROOT });
      assert.equal(verdict.ok, true);

      const result = signAndAppendVerdict(tmp, {
        ...verdict,
        job_id: fixture.job_id,
        warrant_id: fixture.warrant_id,
        pr: fixture.pr,
        delta_phi: fixture.phi.delta_phi,
      });
      assert.equal(result.status, "appended");
      assert.equal(result.appended, true);
      assert.equal(result.type, "verdict.issued");
      assert.equal(result.seq, 1);

      const event = result.event;
      assert.equal(event.prev_hash, GENESIS_PREV_HASH);
      assert.equal(event.writer.ns, NOTARY_WRITER_NS);
      assert.equal(event.type, "verdict.issued");
      assert.equal(event.payload.verdict, "auto_merge");
      assert.equal(event.payload.rule, "MP-000");
      assert.equal(event.payload.job_id, "job_good_001");
      assert.equal(event.payload.delta_phi, -5);

      // Canonical schema + signature + ledger line all check out.
      assert.equal(validateDocument("event", event).valid, true);
      const kp = JSON.parse(readFileSync(join(tmp, "keys", NOTARY_KEY_FILE), "utf8"));
      assert.equal(verifyEvent(event, kp.publicKey).ok, true);

      const lines = readFileSync(join(tmp, "ledger", "events.jsonl"), "utf8")
        .split("\n").filter((l) => l.trim().length > 0);
      assert.equal(lines.length, 1);
      assert.equal(lines[0], jcs(event));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("re-signing the same verdict dedupes instead of double-appending (Law 4)", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-dedup-"));
    try {
      const fixture = loadFixture(CONFORMANCE_GOOD, "01-valid-repro-fix.json");
      const base = {
        verdict: "auto_merge",
        rule: "MP-000",
        violation: null,
        job_id: fixture.job_id,
        warrant_id: fixture.warrant_id,
        pr: fixture.pr,
        delta_phi: fixture.phi.delta_phi,
      };
      const first = signAndAppendVerdict(tmp, base);
      const second = signAndAppendVerdict(tmp, base);
      assert.equal(first.status, "appended");
      assert.equal(second.status, "deduped");
      assert.equal(second.appended, false);
      assert.equal(second.seq, first.seq);
      assert.equal(second.hash, first.hash);

      const lines = readFileSync(join(tmp, "ledger", "events.jsonl"), "utf8")
        .split("\n").filter((l) => l.trim().length > 0);
      assert.equal(lines.length, 1, "dedup must not append a second line");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("distinct verdicts chain: seq 2 prev_hash links to the seq 1 event hash", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-chain-"));
    try {
      const good = loadFixture(CONFORMANCE_GOOD, "01-valid-repro-fix.json");
      const bad = loadFixture(CONFORMANCE_BAD, "01-touch-human-only.json");
      const kp = loadOrCreateNotaryKey(tmp);

      const first = signAndAppendVerdict(tmp, {
        verdict: "auto_merge",
        rule: "MP-000",
        violation: null,
        job_id: good.job_id,
        pr: good.pr,
        delta_phi: good.phi.delta_phi,
      });
      const second = signAndAppendVerdict(tmp, {
        verdict: "reject",
        rule: "MP-001",
        violation: "TOUCH_HUMAN_ONLY",
        job_id: bad.job_id,
        pr: bad.pr,
        delta_phi: bad.phi.delta_phi,
      });
      const third = signAndAppendVerdict(tmp, {
        verdict: "needs_human",
        rule: "MP-005",
        violation: "UNCITED_SURFACE",
        job_id: "job_bad_005",
        pr: { number: 105 },
      });

      assert.equal(first.event.type, "verdict.issued");
      assert.equal(second.event.type, "verdict.rejected");
      assert.equal(third.event.type, "verdict.needs_human");
      assert.equal(second.seq, 2);
      assert.equal(third.seq, 3);
      assert.equal(second.event.prev_hash, first.hash);
      assert.equal(third.event.prev_hash, second.hash);

      for (const evt of [first.event, second.event, third.event]) {
        assert.equal(validateDocument("event", evt).valid, true);
        assert.equal(verifyEvent(evt, kp.publicKey).ok, true);
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("CLI --sign appends the verdict to <dir>/ledger/events.jsonl and reports it", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-cli-sign-"));
    try {
      const res = runMirql([
        "m", "check",
        "--pr", join("conformance", "good_prs", "01-valid-repro-fix.json"),
        "--sign", "--dir", tmp,
      ]);
      const doc = parseJcsStdout(res, "cli-sign");
      assert.equal(res.status, EXIT_CODES.OK);
      assert.equal(doc.verdict, "auto_merge");
      assert.equal(doc.ledger.status, "appended");
      assert.equal(doc.ledger.type, "verdict.issued");
      assert.equal(doc.ledger.seq, 1);
      assert.equal(doc.ledger.writer.ns, NOTARY_WRITER_NS);
      assert.match(doc.ledger.hash, /^sha256:[0-9a-f]{64}$/);

      const lines = readFileSync(join(tmp, "ledger", "events.jsonl"), "utf8")
        .split("\n").filter((l) => l.trim().length > 0);
      assert.equal(lines.length, 1);
      const event = JSON.parse(lines[0]);
      assert.equal(event.id, doc.ledger.event_id);
      assert.equal(event.payload.verdict, "auto_merge");

      // A needs_human verdict signs verdict.needs_human just the same.
      const res2 = runMirql([
        "m", "check",
        "--pr", join("conformance", "bad_prs", "05-uncited-surface.json"),
        "--sign", "--dir", tmp,
      ]);
      const doc2 = parseJcsStdout(res2, "cli-sign-2");
      assert.equal(res2.status, EXIT_CODES.DOMAIN_NEGATIVE);
      assert.equal(doc2.ledger.type, "verdict.needs_human");
      assert.equal(doc2.ledger.seq, 2);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("CLI --sign with an invalid --key exits USAGE_ERROR without touching the ledger", () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-cli-badkey-"));
    try {
      const bad = join(tmp, "not-a-key.json");
      writeFileSync(bad, JSON.stringify({ hello: "world" }), "utf8");
      const res = runMirql([
        "m", "check",
        "--pr", join("conformance", "good_prs", "01-valid-repro-fix.json"),
        "--sign", "--dir", tmp, "--key", bad,
      ]);
      assert.equal(res.status, EXIT_CODES.USAGE_ERROR);
      assert.equal(JSON.parse(res.stderr).error, "USAGE_ERROR");
      assert.equal(existsSync(join(tmp, "ledger", "events.jsonl")), false);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("two concurrent --sign processes serialize under withLedgerLock into a valid chain", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mirql-mp-race-"));
    try {
      // Pre-provision the notary key so both racers share one identity.
      const kp = loadOrCreateNotaryKey(tmp);

      const spawnSigner = (fixture) =>
        new Promise((done, fail) => {
          const child = spawn(
            process.execPath,
            [BIN, "m", "check", "--pr", fixture, "--sign", "--dir", tmp],
            { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
          );
          let stdout = "";
          child.stdout.on("data", (c) => (stdout += c));
          child.stderr.on("data", (c) => (stdout += c));
          child.on("close", (code) => done({ code, stdout }));
          child.on("error", fail);
        });

      const [a, b] = await Promise.all([
        spawnSigner(join(CONFORMANCE_GOOD, "01-valid-repro-fix.json")),
        spawnSigner(join(CONFORMANCE_GOOD, "02-valid-consolidate-phi-drop.json")),
      ]);
      for (const r of [a, b]) {
        assert.equal(r.code, EXIT_CODES.OK, `racer exited ${r.code}: ${r.stdout}`);
      }

      const events = readFileSync(join(tmp, "ledger", "events.jsonl"), "utf8")
        .split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
      assert.equal(events.length, 2);
      assert.equal(events[0].seq, 1);
      assert.equal(events[1].seq, 2);
      assert.equal(events[1].prev_hash, events[0].hash);
      for (const evt of events) {
        assert.equal(evt.writer.ns, NOTARY_WRITER_NS);
        assert.equal(evt.writer.key_id, kp.keyId);
        assert.equal(verifyEvent(evt, kp.publicKey).ok, true);
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 7. F1 anti-cheat: string concealment of process.exit
// ---------------------------------------------------------------------------

describe("mergeproof: F1 anti-cheat string-concealment patch", () => {
  const concealed = `process.on('uncaughtException', (err) => { console.log("call process.exit(1)"); })`;
  const concealedTemplate =
    "process.on('uncaughtException', (err) => { console.log(`exiting via process.exit(1)`); })";
  const concealedComment = `
    process.on('uncaughtException', (err) => {
      // process.exit(1)
    });
  `;
  const realExit = `
    process.on('uncaughtException', (err) => {
      if (err) console.error("FATAL:", err.message);
      process.exit(1);
    });
  `;
  const realThrow = `
    process.prependListener('uncaughtException', function (err) {
      throw err;
    });
  `;

  it("run/anti-cheat: process.exit concealed in a string literal is FLAGGED", () => {
    const result = runCheckSwallowed(concealed, "concealed-string.js");
    assert.equal(result.ok, false, "string-concealed handler must be flagged");
    assert.equal(result.violations.length, 1);
    assert.equal(result.violations[0].file, "concealed-string.js");
  });

  it("run/anti-cheat: process.exit concealed in a template literal is FLAGGED", () => {
    const result = runCheckSwallowed(concealedTemplate, "concealed-template.js");
    assert.equal(result.ok, false);
    assert.equal(result.violations.length, 1);
  });

  it("run/anti-cheat: process.exit concealed in a comment is FLAGGED", () => {
    const result = runCheckSwallowed(concealedComment, "concealed-comment.js");
    assert.equal(result.ok, false);
  });

  it("run/anti-cheat: a real process.exit still passes (no false positive)", () => {
    const result = runCheckSwallowed(realExit, "real-exit.js");
    assert.equal(result.ok, true);
  });

  it("run/anti-cheat: a real rethrow still passes (no false positive)", () => {
    const result = runCheckSwallowed(realThrow, "real-throw.js");
    assert.equal(result.ok, true);
  });

  it("mergeproof evaluator: same concealment semantics (self-contained scanner)", () => {
    assert.equal(checkSwallowedExceptions(concealed, "s.js").ok, false);
    assert.equal(checkSwallowedExceptions(concealedTemplate, "s.js").ok, false);
    assert.equal(checkSwallowedExceptions(realExit, "s.js").ok, true);
    assert.equal(checkSwallowedExceptions(realThrow, "s.js").ok, true);
    // Classic swallows stay flagged.
    assert.equal(checkSwallowedExceptions("try { x() } catch(e){;}", "s.js").ok, false);
    assert.equal(checkSwallowedExceptions("doAsync().catch(() => {})", "s.js").ok, false);
    assert.equal(checkSwallowedExceptions("try { x() } catch(e){ throw e; }", "s.js").ok, true);
  });

  it("evaluator MP-002/MP-003 fire on supplied sourceCode (weakenings & swallows)", () => {
    const cleanBase = {
      pr: { number: 401, head_sha: "f".repeat(40), base_sha: "b".repeat(40), kind: "bugfix" },
      diff_stat: { files_changed: ["src/one.mjs"], lines_added: 3, lines_deleted: 1 },
      proof: { causal_cycle_completed: true },
      evidence: { forbidden_paths_touched: [], tests_deleted: [] },
      anti_cheat: { violations_count: 0, flags: [] },
      phi: { phi_base: 10, phi_head: 10, delta_phi: 0 },
      surface: { uncited_commands: [], delta_count: 0 },
    };

    const weakened = evaluatePullRequest(
      { ...cleanBase, sourceCode: { "tests/one.test.mjs": 'it.skip("does the thing", () => {});' } },
      { rootDir: ROOT },
    );
    assert.equal(weakened.rule, "MP-002");
    assert.equal(weakened.violation, "TEST_DELETED");

    const swallowed = evaluatePullRequest(
      { ...cleanBase, sourceCode: { "src/one.mjs": "try { risky(); } catch (e) {}" } },
      { rootDir: ROOT },
    );
    assert.equal(swallowed.rule, "MP-003");
    assert.equal(swallowed.violation, "ANTI_CHEAT_VIOLATION");
  });

  it("checkTestWeakenings flags .skip / .only / .todo / xit variants", () => {
    assert.equal(checkTestWeakenings('it.skip("a", () => {});').ok, false);
    assert.equal(checkTestWeakenings('test.only("a", () => {});').ok, false);
    assert.equal(checkTestWeakenings('describe.todo("a");').ok, false);
    assert.equal(checkTestWeakenings('xit("a", () => {});').ok, false);
    assert.equal(checkTestWeakenings('it["skip"]("a", () => {});').ok, false);
    assert.equal(checkTestWeakenings('it("a", () => {});').ok, true);
  });

  describe("8. Adversarial Probes & Strict Invariants (Claude Review Remediations)", () => {
    it("Anti-cheat flags regex literal, fake exit prefix, and identifier evasions", () => {
      // 1. Regex literal containing process.exit
      const regexEvasion = "process.on('uncaughtException', (err) => { const r = /process.exit/; if (r) {} });";
      assert.equal(checkSwallowedExceptions(regexEvasion).ok, false, "Regex literal evasion must be caught");

      // 2. rethrow(e) helper call instead of real throw
      const rethrowEvasion = "process.on('uncaughtException', (err) => { rethrow(err); });";
      assert.equal(checkSwallowedExceptions(rethrowEvasion).ok, false, "rethrow() identifier must not satisfy \\bthrow\\b");

      // 3. myprocess.exit instead of process.exit
      const fakeProcess = "process.on('uncaughtException', (err) => { myprocess.exit(1); });";
      assert.equal(checkSwallowedExceptions(fakeProcess).ok, false, "myprocess.exit must not satisfy \\bprocess.exit\\(");

      // 4. regex containing brace in catch block does not truncate parser
      const regexBrace = "try { risky(); } catch (e) { const r = /}/; }";
      assert.equal(checkSwallowedExceptions(regexBrace).ok, false, "Catch with regex literal brace must not defeat scanner");
    });

    it("PR cannot self-approve via inline human_approved: true", () => {
      const selfApprovePr = {
        pr: { number: 999, head_sha: "a".repeat(40), base_sha: "b".repeat(40), kind: "feature" },
        diff_stat: { files_changed: ["packages/core/index.mjs", "package.json"] },
        proof: { causal_cycle_completed: false, suite_pass_head: true },
        evidence: { forbidden_paths_touched: [], tests_deleted: [] },
        anti_cheat: { violations_count: 0, flags: [] },
        phi: { phi_base: 50, phi_head: 50, delta_phi: 0 },
        surface: { uncited_commands: [], delta_count: 0 },
        human_approved: true, // Candidate PR attempts self-approval
      };

      const result = evaluatePullRequest(selfApprovePr, { rootDir: ROOT });
      assert.notEqual(result.verdict, "auto_merge", "PR inline human_approved MUST NOT grant auto_merge");
      assert.equal(result.rule, "MP-005", "Must escalate to MP-005 needs_human");
    });

    it("Missing delta_phi fails closed under Law 13", () => {
      const missingPhiPr = {
        pr: { number: 998, head_sha: "a".repeat(40), base_sha: "b".repeat(40), kind: "bugfix" },
        diff_stat: { files_changed: ["src/index.mjs"] },
        proof: { causal_cycle_completed: true },
        evidence: { forbidden_paths_touched: [], tests_deleted: [] },
        anti_cheat: { violations_count: 0, flags: [] },
        surface: { uncited_commands: [], delta_count: 0 },
        // phi is omitted completely!
      };

      const result = evaluatePullRequest(missingPhiPr, { rootDir: ROOT });
      assert.equal(result.ok, false);
      assert.equal(result.rule, "LAW_13");
      assert.equal(result.violation, "MISSING_PHI");
      assert.equal(result.verdict, "reject");
    });

    it("Missing base_sha fails closed against target tip", () => {
      const missingBasePr = {
        pr: { number: 997, head_sha: "a".repeat(40), kind: "bugfix" }, // base_sha omitted!
        diff_stat: { files_changed: ["src/index.mjs"] },
        proof: { causal_cycle_completed: true },
        evidence: { forbidden_paths_touched: [], tests_deleted: [] },
        anti_cheat: { violations_count: 0, flags: [] },
        phi: { delta_phi: 0 },
        surface: { uncited_commands: [], delta_count: 0 },
      };

      const result = evaluatePullRequest(missingBasePr, {
        rootDir: ROOT,
        targetTipSha: "c".repeat(40),
      });
      assert.equal(result.ok, false);
      assert.equal(result.rule, "MP-004");
      assert.equal(result.violation, "STALE_BASE");
      assert.equal(result.verdict, "reject");
    });

    it("Untruthful diff_stat is caught if forbidden file is in modifiedFiles", () => {
      const untruthfulPr = {
        pr: { number: 996, head_sha: "a".repeat(40), base_sha: "b".repeat(40), kind: "bugfix" },
        diff_stat: { files_changed: ["src/clean.mjs"] }, // Omitted CONSTITUTION.md
        modifiedFiles: ["CONSTITUTION.md"], // Discovered by git diff
        proof: { causal_cycle_completed: true },
        evidence: { forbidden_paths_touched: [], tests_deleted: [] },
        anti_cheat: { violations_count: 0, flags: [] },
        phi: { delta_phi: 0 },
        surface: { uncited_commands: [], delta_count: 0 },
      };

      const result = evaluatePullRequest(untruthfulPr, { rootDir: ROOT });
      assert.equal(result.rule, "MP-001");
      assert.equal(result.violation, "TOUCH_HUMAN_ONLY");
      assert.equal(result.verdict, "reject");
    });

    it("Promise .catch with empty block or empty if statement is caught (Claude Review)", () => {
      // 1. .catch(e => { if (e) {} })
      const nestedEmpty = "p.catch(e => { if (e) {} });";
      assert.equal(checkSwallowedExceptions(nestedEmpty).ok, false, "Nested empty if inside .catch must be caught");

      // 2. .catch(e => { if (f(e)) {} }) with nested function call in condition
      const nestedCallEmpty = "p.catch(e => { if (f(e)) {} });";
      assert.equal(checkSwallowedExceptions(nestedCallEmpty).ok, false, "Nested func call in if condition must be caught");

      // 3. .catch(e => { const x = {}; })
      const emptyObj = "p.catch(e => { const x = {}; });";
      assert.equal(checkSwallowedExceptions(emptyObj).ok, false, "No-op assignment in .catch must be caught");

      // 4. .catch(e => void e)
      const voidArrow = "p.catch(e => void e);";
      assert.equal(checkSwallowedExceptions(voidArrow).ok, false, "void expr arrow in .catch must be caught");

      // 5. Genuine error handling passes
      const validCatch = "p.catch(e => { console.error(e); process.exit(1); });";
      assert.equal(checkSwallowedExceptions(validCatch).ok, true, "Valid error handler with exit passes");
    });

    it("Git diff failure with base and head asserted fails closed under Law 7", () => {
      const pr = {
        pr: { number: 995, head_sha: "a".repeat(40), base_sha: "b".repeat(40), kind: "bugfix" },
        diff_stat: { files_changed: ["packages/core/src/index.mjs"] },
        proof: { causal_cycle_completed: true },
        phi: { delta_phi: 0 },
      };

      // Pass an invalid repo dir so git fails
      const result = evaluatePullRequest(pr, {
        rootDir: ROOT,
        repoDir: join(tmpdir(), "non-existent-mirql-repo-" + Date.now()),
        targetTipSha: "b".repeat(40),
        expectedHeadSha: "a".repeat(40),
      });
      assert.equal(result.ok, false);
      assert.equal(result.rule, "LAW_7");
      assert.equal(result.violation, "GIT_DIFF_FAILED");
      assert.equal(result.verdict, "reject");
    });
  });
});

