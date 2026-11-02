import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { sendIntent } from "../packages/inbox/send.mjs";
import { verifyLedger, appendEvent } from "../packages/log/index.mjs";
import { readVerifiedLedger } from "../packages/core/ledger-verify.mjs";
import { requireAuthorizedWarrant } from "../packages/core/warrant.mjs";

let root, metadata, options;
const intent = { title: "Retryable intent", kind: "bug", scope: ["src/**"], budget_micro_usd: 100 };
beforeEach(() => {
  root=fs.mkdtempSync(join(tmpdir(),"mirql-send-retry-"));
  metadata=join(root,"workspace",".mirql");
  const genesis=runGenesis(metadata);
  options={key:genesis.human_key_path,idempotencyKey:"retry-intent",nowMs:1700000000000};
});
afterEach(() => fs.rmSync(root,{recursive:true,force:true}));
const ledgerPath=()=>join(metadata,"ledger","events.jsonl");

function interrupt(method, predicate, action) {
  const original=fs[method];
  try {
    fs[method]=(...args)=> { if(predicate(...args))throw Error("simulated interruption");return original(...args); };
    syncBuiltinESMExports();
    assert.throws(action,/simulated interruption/);
  } finally { fs[method]=original;syncBuiltinESMExports(); }
}
function humanEvent(idempotencyKey) {
  const owner=JSON.parse(fs.readFileSync(options.key,"utf8"));
  appendEvent(metadata,{type:"human.approval",writer:"human:owner",idempotency_key:idempotencyKey,payload:{reason:"interleaved"}},
    {signingKey:owner.privateKey,keyId:owner.keyId});
}

test("retry after a missing grant preserves the intent identity and chains from the actual head", () => {
  interrupt("appendFileSync",(path,bytes)=>path===ledgerPath()&&JSON.parse(bytes).type==="warrant.created",
    ()=>sendIntent(metadata,intent,options));
  const original=readVerifiedLedger(metadata).at(-1);
  assert.equal(original.type,"human.intent");
  humanEvent("interleaved");
  const retried=sendIntent(metadata,intent,{...options,nowMs:options.nowMs+1000});
  assert.equal(verifyLedger(metadata).valid,true);
  assert.equal(retried.warrant_id,original.payload.warrant_id);
  assert.equal(retried.warrant_event.seq,4);
  assert.deepEqual(requireAuthorizedWarrant(metadata,{warrantId:retried.warrant_id}),retried.warrant);
});

test("a completed retry appends nothing and returns the originally granted warrant", () => {
  const first=sendIntent(metadata,intent,options);
  const before=fs.readFileSync(ledgerPath(),"utf8");
  const repeated=sendIntent(metadata,intent,{...options,nowMs:options.nowMs+1000});
  assert.equal(repeated.warrant_id,first.warrant_id);
  assert.equal(repeated.event.hash,first.event.hash);
  assert.equal(repeated.warrant_event.hash,first.warrant_event.hash);
  assert.equal(fs.readFileSync(ledgerPath(),"utf8"),before);
});

test("retry repairs a missing warrant file after both signed events were committed", () => {
  interrupt("writeFileSync",path=>typeof path==="string"&&path.includes("warrants")&&path.endsWith(".json"),
    ()=>sendIntent(metadata,intent,options));
  const grant=readVerifiedLedger(metadata).at(-1);
  const retried=sendIntent(metadata,intent,{...options,nowMs:options.nowMs+1000});
  assert.equal(retried.warrant_id,grant.payload.warrant_id);
  assert.equal(readVerifiedLedger(metadata).length,3);
  assert.deepEqual(requireAuthorizedWarrant(metadata,{warrantId:retried.warrant_id}),retried.warrant);
});

test("an idempotency key cannot silently authorize changed intent or budget", () => {
  sendIntent(metadata,intent,options);
  const before=fs.readFileSync(ledgerPath(),"utf8");
  assert.throws(()=>sendIntent(metadata,{...intent,budget_micro_usd:101},options),/idempotency/i);
  assert.throws(()=>sendIntent(metadata,{...intent,scope:["other/**"]},options),/idempotency/i);
  assert.equal(fs.readFileSync(ledgerPath(),"utf8"),before);
});

test("a key used by another human event cannot poison a new submission", () => {
  humanEvent(options.idempotencyKey);
  const before=fs.readFileSync(ledgerPath(),"utf8");
  assert.throws(()=>sendIntent(metadata,intent,options),/idempotency/i);
  assert.equal(fs.readFileSync(ledgerPath(),"utf8"),before);
  assert.equal(verifyLedger(metadata).valid,true);
});

test("a reserved grant-key collision is refused before recording a new intent", () => {
  humanEvent(options.idempotencyKey + ":warrant");
  const before=fs.readFileSync(ledgerPath(),"utf8");
  assert.throws(()=>sendIntent(metadata,intent,options),/idempotency/i);
  assert.equal(fs.readFileSync(ledgerPath(),"utf8"),before);
});

test("retry recovers an intent committed before its cache update failed", () => {
  interrupt("writeFileSync",path=>typeof path==="string"&&path.includes("cache")&&path.endsWith("state.json.tmp"),
    ()=>sendIntent(metadata,intent,options));
  const original=readVerifiedLedger(metadata).at(-1);
  assert.equal(original.type,"human.intent");
  const retried=sendIntent(metadata,intent,options);
  assert.equal(retried.warrant_id,original.payload.warrant_id);
  assert.equal(readVerifiedLedger(metadata).length,3);
  assert.equal(verifyLedger(metadata).valid,true);
});
