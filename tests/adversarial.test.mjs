import { git, initEmptyRepo } from "./helpers/git.mjs";
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSupervisor } from "../packages/run/supervisor.mjs";
import { provisionTestTrust } from "./helpers/keyring.mjs";

let root, metadata, marker, worker;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "mirql-warrant-attack-"));
  metadata = join(root, "workspace", ".mirql");
  mkdirSync(metadata, { recursive: true });
  initEmptyRepo(join(root, "workspace"));
  provisionTestTrust(metadata);
  marker = join(root, "worker-ran");
  worker = join(root, "worker.mjs");
  writeFileSync(worker, `import {writeFileSync} from "node:fs";writeFileSync(${JSON.stringify(marker)}, "ran");`);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

test("a bare warrant ID cannot fabricate human authority or start a worker", () => {
  assert.throws(() => runSupervisor({
    mirqlDir: metadata, workspaceDir: join(root, "workspace"),
    warrantId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    builderCommand: `"${process.execPath}" "${worker}"`,
    noHeartbeatTicker: true,
  }), error => error.code === "WARRANT_UNAUTHORIZED" && error.exitCode === 4);
  assert.equal(existsSync(marker), false);
});
import { readFileSync, appendFileSync, unlinkSync } from "node:fs";
import { requireAuthorizedWarrant } from "../packages/core/warrant.mjs";
import { authorizeTestWarrant, dispatchableWarrant } from "./helpers/warrant.mjs";
import { appendEvent } from "../packages/log/index.mjs";
import { generateEd25519Keypair, signEvent, jcs, sha256 } from "../packages/core/index.mjs";
import { authorizeTestKey } from "./helpers/keyring.mjs";
const ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ledger = () => join(metadata, "ledger", "events.jsonl");
const execute = overrides => runSupervisor({
  mirqlDir: metadata, workspaceDir: join(root, "workspace"), warrantId: ID,
  builderCommand: `"${process.execPath}" "${worker}"`, noHeartbeatTicker: true, ...overrides,
});

test("a human-signed warrant authorizes the exact document and real worker dispatch", () => {
  const warrant = authorizeTestWarrant(metadata, dispatchableWarrant(ID));
  assert.deepEqual(requireAuthorizedWarrant(metadata, { warrantId: ID }), warrant);
  execute();
  assert.equal(readFileSync(marker, "utf8"), "ran");
});

test("created_by human:owner and a schema-valid document grant no authority", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  writeFileSync(ledger(), "");
  assert.throws(() => execute({ warrant }), /No human-signed/);
  assert.equal(existsSync(marker), false);
});

test("changing the selected or persisted warrant invalidates its signed hash", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  const altered = { ...warrant, budget_micro_usd: warrant.budget_micro_usd + 1 };
  assert.throws(() => execute({ warrant: altered }), /differs from/);
  writeFileSync(join(metadata, "warrants", ID + ".json"), jcs(altered));
  assert.throws(() => execute(), /differs from/);
  assert.equal(existsSync(marker), false);
});

test("a machine-signed warrant.created event cannot stand in for its human owner", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  writeFileSync(ledger(), "");
  const machine = generateEd25519Keypair();
  authorizeTestKey(metadata, "tool:run_supervisor", machine);
  appendEvent(metadata, {
    type: "warrant.created", writer: "tool:run_supervisor",
    payload: { warrant_id: ID, warrant_hash: sha256(jcs(warrant)) },
  }, { signingKey: machine.privateKey, keyId: machine.keyId });
  assert.throws(() => execute(), /No human-signed/);
  assert.equal(existsSync(marker), false);
});

test("an enrolled machine cannot forge the human namespace", () => {
  authorizeTestWarrant(metadata, ID);
  const original = JSON.parse(readFileSync(ledger(), "utf8"));
  const machine = generateEd25519Keypair();
  authorizeTestKey(metadata, "tool:run_supervisor", machine);
  const forged = signEvent({ ...original, writer: { ns: "human:owner", key_id: machine.keyId } },
    machine.privateKey, machine.keyId);
  writeFileSync(ledger(), jcs(forged) + "\n");
  assert.throws(() => execute(), /Ledger authorization refused/);
  assert.equal(existsSync(marker), false);
});

test("revocation prevents replay of a previously authorized warrant", () => {
  authorizeTestWarrant(metadata, ID);
  const owner = provisionTestTrust(metadata);
  appendEvent(metadata, { type: "warrant.revoked", writer: "human:owner", payload: { warrant_id: ID } },
    { signingKey: owner.privateKey, keyId: owner.keyId });
  assert.throws(() => execute(), /revoked/);
  assert.equal(existsSync(marker), false);
});

test("an expired signed warrant is refused before dispatch", () => {
  authorizeTestWarrant(metadata, ID, { expires_at_ms: 1 });
  assert.throws(() => execute(), /expired/);
  assert.equal(existsSync(marker), false);
});

test("conflicting signed grants for one ID require human repair", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  authorizeTestWarrant(metadata, { ...warrant, budget_micro_usd: 1 });
  assert.throws(() => execute(), /Conflicting authorizations/);
  assert.equal(existsSync(marker), false);
});

test("malformed ledger lines cannot be skipped during authorization", () => {
  authorizeTestWarrant(metadata, ID);
  appendFileSync(ledger(), "{invalid\n");
  assert.throws(() => execute(), /json_parse/);
  assert.equal(existsSync(marker), false);
});

test("a broken predecessor link invalidates otherwise signed authority", () => {
  authorizeTestWarrant(metadata, ID);
  const owner = provisionTestTrust(metadata);
  const original = JSON.parse(readFileSync(ledger(), "utf8"));
  const disconnected = signEvent({ ...original, prev_hash: sha256("disconnected") }, owner.privateKey, owner.keyId);
  writeFileSync(ledger(), jcs(disconnected) + "\n");
  assert.throws(() => execute(), /chain_break/);
  assert.equal(existsSync(marker), false);
});

test("missing documents and disagreeing warrant selectors are refused", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  assert.throws(() => execute({ warrantId: "01ARZ3NDEKTSV4RRFFQ69G5FAW", warrant }), /selectors disagree/);
  unlinkSync(join(metadata, "warrants", ID + ".json"));
  assert.throws(() => execute(), /unavailable/);
  assert.equal(existsSync(marker), false);
});

import { submitWarrant } from "../packages/queue/index.mjs";

test("a signed grant may enter the queue once and cannot be resubmitted", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  const first = submitWarrant(metadata, warrant, { repoRoot: join(root, "workspace") });
  assert.equal(first.ok, true, first.error);
  assert.equal(first.status, "submitted");
  const repeated = submitWarrant(metadata, warrant, { repoRoot: join(root, "workspace") });
  assert.equal(repeated.ok, false);
  assert.equal(repeated.exit_code, 4);
});

test("a changed human grant cannot enter the queue under the same ID", () => {
  const warrant = authorizeTestWarrant(metadata, ID);
  const result = submitWarrant(metadata, { ...warrant, budget_micro_usd: 1 }, { repoRoot: join(root, "workspace") });
  assert.equal(result.ok, false);
  assert.equal(result.exit_code, 4);
});


test("a green verifier cannot override the worker's measured protected edit", async () => {
  const workspace = join(root, "workspace");
  mkdirSync(join(workspace, "policy"), { recursive: true });
  writeFileSync(join(workspace, "policy", "guard.json"), "base");
  git(workspace, "add", "policy/guard.json");
  git(workspace, "commit", "-qm", "protected base");
  authorizeTestWarrant(metadata, dispatchableWarrant(ID));
  writeFileSync(worker, 'import {writeFileSync} from "node:fs";writeFileSync("policy/guard.json","tampered");');
  const result = await execute({ runCheck: ({stage}) => ({exitCode: stage === "green_on_head" ? 0 : 1}) });
  assert.equal(result.agentResult.violation, "TOUCH_HUMAN_ONLY");
  assert.equal(result.agentResult.workerExitCode, 0);
  assert.equal(result.verified, false);
  assert.equal(result.verdict, "reject");
  assert.equal(result.outcome.status, "fail");
});
