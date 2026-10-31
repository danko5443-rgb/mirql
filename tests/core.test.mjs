// W1 core primitive tests: JCS/Law 17, hashing, ULIDs, HLCs, Ed25519 event
// signing, the Law 3 single-writer ACL, and validateDocument for all four
// canonical document kinds.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  EXIT_CODES,
  ULID_ALPHABET,
  canWriteEvent,
  compareHlc,
  computeEventHash,
  generateEd25519Keypair,
  hlcTick,
  isValidUlid,
  jcs,
  jcsHash,
  sha256,
  signEvent,
  ulid,
  validateDocument,
  verifyEvent,
  WRITER_ACL,
} from "../packages/core/index.mjs";

const LAW17_MESSAGE =
  "Law 17 violation: floating-point numbers are forbidden in JCS documents; use integer micro_usd or basis_points";

// ---------------------------------------------------------------------------
// EXIT_CODES
// ---------------------------------------------------------------------------

test("EXIT_CODES matches the canonical table and is frozen", () => {
  assert.deepEqual(EXIT_CODES, {
    OK: 0,
    DOMAIN_NEGATIVE: 1,
    USAGE_ERROR: 2,
    INTEGRITY_VIOLATION: 3,
    POLICY_DENIAL: 4,
    STALE_EPOCH: 5,
    HALTED: 6,
    BUDGET_EXHAUSTED: 7,
    NEEDS_HUMAN: 10,
    TRANSIENT: 75,
    TIMEOUT: 124,
  });
  assert.equal(Object.isFrozen(EXIT_CODES), true);
});

// ---------------------------------------------------------------------------
// jcs (RFC 8785 canonical JSON + Law 17)
// ---------------------------------------------------------------------------

test("jcs sorts object keys lexicographically by UTF-16 code units", () => {
  assert.equal(jcs({ b: 1, a: 2, C: 3, "a b": 4 }), '{"C":3,"a":2,"a b":4,"b":1}');
  // JS integer-like keys come first in ascending numeric order (language rule).
  assert.equal(jcs({ 2: "b", 1: "a" }), '{"1":"a","2":"b"}');
});

test("jcs canonicalizes nested structures deterministically", () => {
  assert.equal(
    jcs({ z: { c: 1, a: [2, 1, { y: 1, x: 2 }] }, a: null, m: true }),
    '{"a":null,"m":true,"z":{"a":[2,1,{"x":2,"y":1}],"c":1}}',
  );
  assert.equal(jcs({}), "{}");
  assert.equal(jcs([]), "[]");
  // Key order never matters.
  assert.equal(jcs({ a: { p: 1, o: 2 } }), jcs({ a: { o: 2, p: 1 } }));
});

test("jcs preserves array order and passes strings through JSON escaping", () => {
  assert.equal(jcs([3, 1, 2]), "[3,1,2]");
  assert.equal(jcs({ s: 'a"b\\c\nd\te' }), '{"s":"a\\"b\\\\c\\nd\\te"}');
  // Non-ASCII stays unescaped (raw UTF-8), as RFC 8785 requires.
  assert.equal(jcs({ u: "héllo→" }), '{"u":"héllo→"}');
  assert.equal(jcs({ f: false, t: true, n: null }), '{"f":false,"n":null,"t":true}');
});

test("Law 17: jcs rejects every non-safe-integer number", () => {
  for (const bad of [0.5, 1.5, -0.25, NaN, Infinity, -Infinity, 2 ** 53]) {
    assert.throws(() => jcs({ n: bad }), TypeError, `expected rejection for ${bad}`);
  }
  // Floats hidden deep inside nested documents are rejected too.
  assert.throws(() => jcs({ a: [{ b: { c: 0.1 } }] }), TypeError);
});

test("Law 17: jcs throws the exact canonical message on floats", () => {
  try {
    jcs({ pi: 3.14 });
    assert.fail("jcs should have thrown");
  } catch (err) {
    assert.ok(err instanceof TypeError);
    assert.equal(err.message, LAW17_MESSAGE);
  }
});

test("jcs accepts all safe integers, canonicalizing -0 to 0", () => {
  assert.equal(
    jcs({ max: Number.MAX_SAFE_INTEGER, min: Number.MIN_SAFE_INTEGER, zero: -0 }),
    '{"max":9007199254740991,"min":-9007199254740991,"zero":0}',
  );
});

test("jcs omits undefined object properties but rejects undefined elsewhere", () => {
  assert.equal(jcs({ a: 1, b: undefined }), '{"a":1}');
  assert.throws(() => jcs(undefined), TypeError);
  assert.throws(() => jcs([1, undefined, 2]), TypeError);
  assert.throws(() => jcs(() => 1), TypeError);
  assert.throws(() => jcs(new Date()), TypeError); // non-plain object
});

// ---------------------------------------------------------------------------
// sha256 / jcsHash
// ---------------------------------------------------------------------------

test("sha256 matches known vectors and the sha256:<64 hex> format", () => {
  const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
  assert.equal(
    sha256("abc"),
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.equal(
    sha256(""),
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.match(sha256("mirql"), SHA256_RE);
  // Buffers hash the same as their UTF-8 string.
  assert.equal(sha256(Buffer.from("abc", "utf8")), sha256("abc"));
  assert.throws(() => sha256(42), TypeError);
});

test("jcsHash is order-independent and collision-distinct", () => {
  assert.equal(jcsHash({ b: 1, a: 2 }), jcsHash({ a: 2, b: 1 }));
  assert.equal(jcsHash({ a: 1 }), jcsHash({ a: 1 }));
  assert.notEqual(jcsHash({ a: 1 }), jcsHash({ a: 2 }));
  assert.equal(jcsHash({ a: 1 }), sha256(jcs({ a: 1 })));
});

// ---------------------------------------------------------------------------
// ulid / isValidUlid
// ---------------------------------------------------------------------------

test("ulid produces valid 26-char Crockford Base32 ids", () => {
  const id = ulid();
  assert.equal(id.length, 26);
  assert.equal(isValidUlid(id), true);
  for (const ch of id) {
    assert.notEqual(ULID_ALPHABET.indexOf(ch), -1, `unexpected char ${ch}`);
  }
});

test("ulid is strictly monotonic within the same millisecond", () => {
  const t = 1_700_000_000_000;
  let prev = ulid(t);
  for (let i = 0; i < 1000; i++) {
    const next = ulid(t);
    assert.ok(next > prev, `expected ${next} > ${prev}`);
    prev = next;
  }
});

test("ulid sorts lexicographically across increasing milliseconds", () => {
  const a = ulid(1_000);
  const b = ulid(1_001);
  const c = ulid(1_002);
  assert.ok(a < b && b < c, `expected ${a} < ${b} < ${c}`);
});

test("ulid remains strictly monotonic under clock regression", () => {
  assert.ok(ulid(2000) < ulid(1999));
});

test("ulid's first 10 chars decode back to the input timestamp", () => {
  const t = 2_000_000_000_000;
  let decoded = 0;
  for (let i = 0; i < 10; i++) {
    decoded = decoded * 32 + ULID_ALPHABET.indexOf(ulid(t)[i]);
  }
  assert.equal(decoded, t);
});

test("isValidUlid rejects malformed ids", () => {
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FAV"), true); // classic example
  assert.equal(isValidUlid("01arz3ndektsv4rrffq69g5fav"), true); // lowercase accepted
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FA"), false); // 25 chars
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FAVV"), false); // 27 chars
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FAI"), false); // I excluded
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FAL"), false); // L excluded
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FAO"), false); // O excluded
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FAU"), false); // U excluded
  assert.equal(isValidUlid("01arz3ndektsv4rrffq69g5fau"), false); // lowercase u excluded
  assert.equal(isValidUlid("01ARZ3NDEKTSV4RRFFQ69G5FA."), false); // non-alphabet char
  assert.equal(isValidUlid(""), false);
  assert.equal(isValidUlid(null), false);
  assert.equal(isValidUlid(123), false);
});

test("ulid rejects out-of-range timestamps", () => {
  assert.throws(() => ulid(-1), RangeError);
  assert.throws(() => ulid(2 ** 48), RangeError);
  assert.throws(() => ulid(1.5), RangeError);
});

// ---------------------------------------------------------------------------
// hlcTick / compareHlc
// ---------------------------------------------------------------------------

test("hlcTick starts a fresh clock from null", () => {
  assert.deepEqual(hlcTick(null, 1000), { wall_ms: 1000, logical: 0, node: "local" });
  assert.deepEqual(hlcTick(null, 5, "node-a"), { wall_ms: 5, logical: 0, node: "node-a" });
});

test("hlcTick counts logical ticks within a millisecond and resets on advance", () => {
  const t0 = hlcTick(null, 1000);
  const t1 = hlcTick(t0, 1000);
  const t2 = hlcTick(t1, 1000);
  assert.deepEqual(t2, { wall_ms: 1000, logical: 2, node: "local" });

  const t3 = hlcTick(t2, 2000); // wall moved forward: logical resets
  assert.deepEqual(t3, { wall_ms: 2000, logical: 0, node: "local" });

  const t4 = hlcTick(t3, 1500); // wall behind local clock: never goes back
  assert.deepEqual(t4, { wall_ms: 2000, logical: 1, node: "local" });

  assert.throws(() => hlcTick(null, 1000.9), RangeError);
  assert.throws(() => hlcTick(null, -1), RangeError);
  assert.throws(() => hlcTick(null, null), RangeError);
});

test("compareHlc orders by wall_ms, then logical, then node", () => {
  const a = { wall_ms: 10, logical: 0, node: "a" };
  const b = { wall_ms: 20, logical: 0, node: "a" };
  const c = { wall_ms: 20, logical: 1, node: "a" };
  const d = { wall_ms: 20, logical: 1, node: "b" };

  assert.equal(compareHlc(a, b), -1);
  assert.equal(compareHlc(b, a), 1);
  assert.equal(compareHlc(b, c), -1);
  assert.equal(compareHlc(c, b), 1);
  assert.equal(compareHlc(c, d), -1);
  assert.equal(compareHlc(d, c), 1);
  assert.equal(compareHlc(d, d), 0);
  // Antisymmetry across the board.
  for (const [x, y] of [[a, b], [b, c], [c, d]]) {
    assert.equal(compareHlc(x, y), -compareHlc(y, x));
  }
});

// ---------------------------------------------------------------------------
// Ed25519 signing & event hashes
// ---------------------------------------------------------------------------

test("generateEd25519Keypair returns base64url keys with a matching keyId", () => {
  const kp = generateEd25519Keypair();
  assert.equal(kp.publicKey.length, 43); // raw 32 bytes -> 43 base64url chars
  assert.match(kp.publicKey, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(kp.keyId, `ed25519:${kp.publicKey}`);
  assert.equal(kp.privateKey.length > 43, true); // PKCS#8 DER, longer than the pubkey
});

test("signEvent attaches the content hash and an 86-char base64url signature", () => {
  const kp = generateEd25519Keypair();
  const base = { v: 1, id: ulid(1_700_000_000_000), payload: { amount_micro_usd: 42 } };
  const signed = signEvent(base, kp.privateKey, kp.keyId);

  assert.equal(signed.hash, computeEventHash(base));
  assert.match(signed.hash, /^sha256:[0-9a-f]{64}$/);
  assert.match(signed.sig, /^[A-Za-z0-9_-]{86}$/);

  // Pure function: the input event is not mutated.
  assert.equal("hash" in base, false);
  assert.equal("sig" in base, false);

  // Ed25519 is deterministic: same input, same signature.
  const again = signEvent(base, kp.privateKey, kp.keyId);
  assert.equal(again.sig, signed.sig);
  assert.equal(again.hash, signed.hash);
});

test("signEvent refuses a keyId that does not match the private key", () => {
  const kp = generateEd25519Keypair();
  const other = generateEd25519Keypair();
  assert.throws(
    () => signEvent({ v: 1 }, kp.privateKey, other.keyId),
    /keyId .* does not match/,
  );
});

test("verifyEvent accepts a genuinely signed event", () => {
  const kp = generateEd25519Keypair();
  const signed = signEvent(
    { v: 1, id: ulid(1), payload: { seq: 7 }, writer: { ns: "tool:queue" } },
    kp.privateKey,
    kp.keyId,
  );
  assert.deepEqual(verifyEvent(signed, kp.publicKey), { ok: true });
});

test("verifyEvent detects tampering with payload, hash or signature", () => {
  const kp = generateEd25519Keypair();
  const signed = signEvent({ v: 1, id: ulid(2), payload: { seq: 1 } }, kp.privateKey);

  const tamperedPayload = { ...signed, payload: { seq: 2 } };
  const payloadResult = verifyEvent(tamperedPayload, kp.publicKey);
  assert.equal(payloadResult.ok, false);
  assert.match(payloadResult.reason, /hash mismatch/);

  const tamperedHash = { ...signed, hash: sha256("evil") };
  assert.equal(verifyEvent(tamperedHash, kp.publicKey).ok, false);

  const corruptSig = {
    ...signed,
    sig: (signed.sig[0] === "A" ? "B" : "A") + signed.sig.slice(1),
  };
  const sigResult = verifyEvent(corruptSig, kp.publicKey);
  assert.equal(sigResult.ok, false);
  assert.ok(sigResult.reason.length > 0);

  const { sig, ...unsigned } = signed;
  void sig;
  assert.equal(verifyEvent(unsigned, kp.publicKey).ok, false);
  const { hash, ...hashless } = signed;
  void hash;
  assert.equal(verifyEvent(hashless, kp.publicKey).ok, false);
});

test("verifyEvent fails under the wrong key and never throws", () => {
  const kp = generateEd25519Keypair();
  const other = generateEd25519Keypair();
  const signed = signEvent({ v: 1, payload: {} }, kp.privateKey);

  assert.equal(verifyEvent(signed, other.publicKey).ok, false);
  assert.equal(verifyEvent(null, kp.publicKey).ok, false);
  assert.equal(verifyEvent(signed, "not-a-key").ok, false); // caught, not thrown
});

test("computeEventHash ignores pre-existing hash and sig fields", () => {
  const kp = generateEd25519Keypair();
  const signed = signEvent({ v: 1, id: ulid(3), payload: { n: 1 } }, kp.privateKey);
  assert.equal(
    computeEventHash({ ...signed, hash: "junk", sig: "junk" }),
    signed.hash,
  );
  assert.equal(computeEventHash(signed), signed.hash);
});

// ---------------------------------------------------------------------------
// Law 3 — single-writer ACL
// ---------------------------------------------------------------------------

test("WRITER_ACL contains exactly the seven canonical writer namespaces", () => {
  assert.deepEqual(Object.keys(WRITER_ACL).sort(), [
    "daemon:lifeguard",
    "human:owner",
    "notary:mergeproof",
    "tool:inbox",
    "tool:log",
    "tool:queue",
    "tool:run_supervisor",
  ]);
});

test("canWriteEvent grants each namespace only its own event types", () => {
  // tool:queue -> job|factory|mirql.*
  assert.equal(canWriteEvent("tool:queue", "job.enqueued"), true);
  assert.equal(canWriteEvent("tool:queue", "factory.halted"), true);
  assert.equal(canWriteEvent("tool:queue", "mirql.epoch_opened"), true);
  assert.equal(canWriteEvent("tool:queue", "ledger.appended"), false);
  assert.equal(canWriteEvent("tool:queue", "human.approval"), false);

  // tool:run_supervisor -> attempt|probe|warrant.*
  assert.equal(canWriteEvent("tool:run_supervisor", "attempt.started"), true);
  assert.equal(canWriteEvent("tool:run_supervisor", "probe.completed"), true);
  assert.equal(canWriteEvent("tool:run_supervisor", "warrant.issued"), true);
  assert.equal(canWriteEvent("tool:run_supervisor", "job.enqueued"), false);

  // tool:log -> ledger.*
  assert.equal(canWriteEvent("tool:log", "ledger.appended"), true);
  assert.equal(canWriteEvent("tool:log", "verdict.accepted"), false);

  // tool:inbox and human:owner -> human.*
  assert.equal(canWriteEvent("tool:inbox", "human.approval_requested"), true);
  assert.equal(canWriteEvent("human:owner", "human.decision"), true);
  assert.equal(canWriteEvent("tool:inbox", "job.enqueued"), false);
  assert.equal(canWriteEvent("human:owner", "verdict.accepted"), false);

  // notary:mergeproof -> verdict|promotion.*
  assert.equal(canWriteEvent("notary:mergeproof", "verdict.accepted"), true);
  assert.equal(canWriteEvent("notary:mergeproof", "promotion.completed"), true);
  assert.equal(canWriteEvent("notary:mergeproof", "job.enqueued"), false);

  // daemon:lifeguard -> rollback events only.
  assert.equal(canWriteEvent("daemon:lifeguard", "promotion.rollback"), true);
  assert.equal(canWriteEvent("daemon:lifeguard", "factory.rollback"), true);
  assert.equal(canWriteEvent("daemon:lifeguard", "mirql.rollback"), true);
  assert.equal(canWriteEvent("daemon:lifeguard", "factory.build"), false);
  assert.equal(canWriteEvent("daemon:lifeguard", "promotion.completed"), false);
});

test("canWriteEvent denies unknown namespaces and malformed input", () => {
  assert.equal(canWriteEvent("tool:evil", "job.enqueued"), false);
  assert.equal(canWriteEvent("", "job.enqueued"), false);
  assert.equal(canWriteEvent("tool:queue", ""), false);
  assert.equal(canWriteEvent("tool:queue", "JOB.ENQUEUED"), false); // case-sensitive
  assert.equal(canWriteEvent(undefined, "job.enqueued"), false);
  assert.equal(canWriteEvent("tool:queue", undefined), false);
  assert.equal(canWriteEvent(null, null), false);
  assert.equal(canWriteEvent("constructor", "job.leased"), false);
  assert.equal(canWriteEvent("__proto__", "job.leased"), false);
  assert.equal(canWriteEvent("toString", "job.leased"), false);
});

// ---------------------------------------------------------------------------
// validateDocument
// ---------------------------------------------------------------------------

/** Build a structurally valid, schema-clean event document. */
function makeValidEvent(overrides = {}) {
  const kp = keypair ?? (keypair = generateEd25519Keypair());
  return {
    v: 1,
    id: ulid(1_700_000_000_000),
    tenant_id: "acme",
    seq: 41,
    epoch: 3,
    hlc: { wall_ms: 1_700_000_000_000, logical: 0, node: "local" },
    ts: "2023-11-14T22:13:20.000Z",
    type: "job.enqueued",
    writer: { ns: "tool:queue", key_id: kp.keyId },
    idempotency_key: "job-41-attempt-0",
    prev_hash: sha256("genesis"),
    payload: { role: "implementer", attempt: 0 },
    hash: sha256("event-41"),
    sig: "A".repeat(86),
    ...overrides,
  };
}

let keypair = null;

/** Build a structurally valid warrant document. */
function makeValidWarrant(overrides = {}) {
  return {
    v: 1,
    id: ulid(1_700_000_001_000),
    class: "surgical",
    semantic_fingerprint: sha256("intent: tighten queue lease renewal"),
    anchors: [{ path: "packages/queue/index.mjs", line_start: 10, line_end: 40 }],
    evidence: { citations: 3, benchmarks_run: 1 },
    red_check: { vectors_reviewed: 12, vectors_failed: 0 },
    scope: { allow_globs: ["packages/queue/**"], deny_globs: ["infra/**"] },
    budget_micro_usd: 250_000,
    created_by: "human:owner",
    ...overrides,
  };
}

/** Build a structurally valid job document. */
function makeValidJob(overrides = {}) {
  return {
    v: 1,
    id: ulid(1_700_000_002_000),
    tenant_id: "acme",
    role: "implementer",
    tier: "T2",
    base_sha: sha256("base commit"),
    attempt: 0,
    limits: { wall_ms: 600_000, tool_calls: 200, micro_usd: 100_000 },
    lease: { owner: "tool:run_supervisor", epoch: 3, expires_at_ms: 1_700_000_060_000 },
    idempotency_key: "warrant-7-job-0",
    ...overrides,
  };
}

/** Build a structurally valid outcome document. */
function makeValidOutcome(overrides = {}) {
  return {
    v: 1,
    id: ulid(1_700_000_003_000),
    job_id: ulid(1_700_000_002_000),
    warrant_id: ulid(1_700_000_001_000),
    epoch: 3,
    status: "pass",
    base_sha: sha256("base commit"),
    head_sha: sha256("head commit"),
    tree_hash: sha256("produced tree"),
    evidence: { tests_total: 128, tests_failed: 0 },
    anti_cheat: { diff_scoped: 1, tests_weakened: 0 },
    phi: { scans_run: 2, leaks_found: 0 },
    surface: { files_changed: 2, lines_added: 40, lines_removed: 12 },
    thrift: { model_calls: 9, tokens_in: 42_000, tokens_out: 5_100 },
    reconciliation: { ledger_entries: 9, unbalanced: 0 },
    cost: { micro_usd: 81_234 },
    ...overrides,
  };
}

test("validateDocument accepts canonical documents of every kind", () => {
  for (const [kind, doc] of [
    ["event", makeValidEvent()],
    ["warrant", makeValidWarrant()],
    ["job", makeValidJob()],
    ["outcome", makeValidOutcome()],
  ]) {
    const result = validateDocument(kind, doc);
    assert.deepEqual(result, { valid: true, errors: [] }, `${kind} should validate`);
  }
});

test("validateDocument enforces the Law 3 single-writer ACL on events", () => {
  const forged = makeValidEvent({ type: "verdict.accepted" }); // notary-only
  const result = validateDocument("event", forged);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("single-writer ACL")));

  const wrongTool = makeValidEvent({ writer: { ns: "tool:log" }, type: "job.enqueued" });
  assert.equal(validateDocument("event", wrongTool).valid, false);

  // An event the ACL cannot even interpret is rejected too.
  const noWriter = makeValidEvent();
  delete noWriter.writer;
  assert.equal(validateDocument("event", noWriter).valid, false);

  const validEvent = makeValidEvent();
  assert.equal(
    validateDocument("event", {
      ...validEvent,
      writer: { ns: "constructor", id: "x", key_id: "..." },
    }).valid,
    false,
  );
});

test("validateDocument reports missing required fields", () => {
  const missing = makeValidEvent();
  delete missing.sig;
  const result = validateDocument("event", missing);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("sig")));

  assert.equal(validateDocument("job", { v: 1, id: ulid(1) }).valid, false);
});

test("validateDocument enforces Law 17 (integer-only documents)", () => {
  const floaty = makeValidEvent({ payload: { ratio: 0.5 } });
  const result = validateDocument("event", floaty);
  assert.equal(result.valid, false);
  assert.equal(result.errors[0], `$: ${LAW17_MESSAGE}`);

  const floatBudget = makeValidWarrant({ budget_micro_usd: 1.5 });
  assert.equal(validateDocument("warrant", floatBudget).valid, false);
});

test("validateDocument enforces pattern constraints", () => {
  assert.equal(validateDocument("event", makeValidEvent({ id: "not-a-ulid" })).valid, false);
  assert.equal(validateDocument("event", makeValidEvent({ v: 2 })).valid, false);
  assert.equal(validateDocument("event", makeValidEvent({ hash: "sha256:xyz" })).valid, false);
  assert.equal(validateDocument("event", makeValidEvent({ sig: "short" })).valid, false);
  assert.equal(
    validateDocument("event", makeValidEvent({ ts: "yesterday" })).valid,
    false,
  );
  assert.equal(
    validateDocument("event", makeValidEvent({ writer: { ns: "bogus ns" } })).valid,
    false,
  );
  assert.equal(
    validateDocument("event", makeValidEvent({ writer: { ns: "tool:queue", key_id: "ed25519:short" } }))
      .valid,
    false,
  );
  assert.equal(validateDocument("job", makeValidJob({ base_sha: "deadbeef" })).valid, false);
  assert.equal(validateDocument("job", makeValidJob({ tier: "X9" })).valid, false);
  assert.equal(validateDocument("outcome", makeValidOutcome({ job_id: "42" })).valid, false);
  assert.equal(
    validateDocument("outcome", makeValidOutcome({ tree_hash: "sha256:" + "g".repeat(64) }))
      .valid,
    false,
  );
  assert.equal(validateDocument("warrant", makeValidWarrant({ anchors: [] })).valid, false);
  assert.equal(
    validateDocument("warrant", makeValidWarrant({ semantic_fingerprint: "fingerprint.txt" }))
      .valid,
    false,
  );
});

test("validateDocument rejects additional top-level properties", () => {
  const sneaky = makeValidEvent({ sneaky_field: "unexpected" });
  const result = validateDocument("event", sneaky);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("sneaky_field")));
});

test("validateDocument rejects non-object documents and unknown kinds", () => {
  assert.equal(validateDocument("event", null).valid, false);
  assert.equal(validateDocument("event", [1, 2, 3]).valid, false);
  assert.equal(validateDocument("event", "event").valid, false);

  assert.throws(() => validateDocument("nope", {}), TypeError);
  assert.throws(() => validateDocument(undefined, {}), TypeError);
});
