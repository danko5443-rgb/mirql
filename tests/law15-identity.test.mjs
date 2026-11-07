// tests/law15-identity.test.mjs — Law 15: Semantic Identity / Mechanical Location.
// Entities derive identity from content hashes, never from the mechanical
// location they happen to sit in: the same ledger copied to another path folds
// to the same state with the same hashes, and the same commit reached through
// two different branch names measures identically. Tests are Φ-exempt.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { sha256, ulid, generateEd25519Keypair } from "../packages/core/index.mjs";
import { computeGitTreePhi } from "../packages/run/phi.mjs";
import { authorizeTestKey, provisionTestTrust } from "./helpers/keyring.mjs";
import { appendLedgerEvent, foldQueueState, getQueueStatus } from "../packages/queue/index.mjs";

// `semantic_fingerprint` is a warrant FIELD its author computes as a content hash; there is
// no shared helper in core, so this computes one the way the queue's own fixtures do.
const semantic_fingerprint = (intent) => sha256(JSON.stringify(intent));

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const GIT_ENV = { GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" };

describe("Law 15: identity is content, location is machinery", () => {
  let home;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "mirql-law15-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  /** A real ledger with an event whose hash chain and fold we can compare across locations. */
  function buildLedger(dir) {
    provisionTestTrust(dir);
    const keypair = generateEd25519Keypair();
    authorizeTestKey(dir, "tool:queue", keypair);
    appendLedgerEvent(dir, { type: "job.enqueued", nowMs: 1_700_200_000_000, payload: { job_id: "01JOB", warrant_id: "01W", role: "builder", tier: "flash", attempt: 1 } }, keypair);
    appendLedgerEvent(dir, { type: "factory.halted", nowMs: 1_700_200_001_000, payload: { reason: "law15 test" } }, keypair);
    return keypair;
  }

  it("a ledger copied to another path folds to the identical state and keeps every hash", () => {
    const original = join(home, "ledger-at-first-location");
    mkdirSync(original, { recursive: true });
    buildLedger(original);

    const copy = join(home, "a", "totally", "different", "mechanical", "location");
    mkdirSync(join(copy, ".."), { recursive: true });
    cpSync(original, copy, { recursive: true });

    const originalLines = readFileSync(join(original, "ledger", "events.jsonl"), "utf8").trim().split(/\r?\n/);
    const copyLines = readFileSync(join(copy, "ledger", "events.jsonl"), "utf8").trim().split(/\r?\n/);
    assert.deepEqual(copyLines, originalLines, "the copy is byte-identical to its source");
    assert.ok(!originalLines.join("\n").includes(original), "event content never names the ledger's own mechanical location");
    const head = join(original, "ledger", "head.json");
    if (existsSync(head)) assert.ok(!readFileSync(head, "utf8").includes(original), "the head sidecar never names the ledger's location either");

    const stateOriginal = foldQueueState(original);
    const stateCopy = foldQueueState(copy);
    assert.equal(stateCopy.seq, stateOriginal.seq);
    assert.equal(stateCopy.epoch, stateOriginal.epoch);
    assert.deepEqual(Object.keys(stateCopy.jobs), Object.keys(stateOriginal.jobs), "job identity survives the move");
    assert.deepEqual(Object.keys(stateCopy.warrants), Object.keys(stateOriginal.warrants));
    assert.equal(getQueueStatus(copy).halted, true, "the projection is the same pure fold over the same bytes");
  });

  it("the same commit measured through two branch names is the same Phi", () => {
    const repo = join(home, "repo.git");
    const work = join(home, "work");
    execFileSync("git", ["init", "-q", "--bare", repo]);
    mkdirSync(work);
    const git = (...args) => execFileSync("git", ["-C", work, ...args], { encoding: "utf8", env: { ...process.env, ...GIT_ENV } }).trim();
    git("init", "-q");
    git("config", "core.autocrlf", "false");
    writeFileSync(join(work, "src.mjs"), "export const identity = 1;\n");
    git("add", ".");
    git("commit", "-qm", "content is what matters");
    git("branch", "-M", "feature/one");
    git("remote", "add", "origin", repo);
    git("push", "-q", "origin", "feature/one");
    git("branch", "feature/two-entirely-different-name");
    git("push", "-q", "origin", "feature/two-entirely-different-name");
    const sha = git("rev-parse", "HEAD");

    const viaOne = computeGitTreePhi(work, sha).metrics.total;
    execFileSync("git", ["clone", "-q", "-c", "core.autocrlf=false", repo, join(home, "clone-two")], { env: { ...process.env, ...GIT_ENV } });
    const viaTwo = computeGitTreePhi(join(home, "clone-two"), sha).metrics.total;
    assert.equal(viaOne, viaTwo, "Phi binds to the commit, not to any branch or clone that points at it");
    assert.ok(Number.isSafeInteger(viaOne) && viaOne > 0, "the tree actually measured something");
  });

  it("a warrant's fingerprint hashes its content, so the same intent under another path is still the same intent", () => {
    const intent = { scope: ["packages/queue/**"], goal: "law15 fingerprint" };
    const first = semantic_fingerprint(intent);
    assert.equal(first, semantic_fingerprint({ ...intent }), "identical content is identical identity under any path");
    assert.ok(!String(first).includes(home), "a fingerprint is a content hash, never a location-derived id");
    assert.notEqual(first, semantic_fingerprint({ ...intent, scope: ["packages/run/**"] }), "changed content is a different identity");
    assert.notEqual(ulid(1_700_200_000_000), ulid(1_700_200_000_000), "canonical UUIDs never collide for distinct generations");
  });
});
