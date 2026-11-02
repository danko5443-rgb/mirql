import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,readFileSync,writeFileSync,rmSync,existsSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {runGenesis} from "../packages/inbox/genesis.mjs";
import {sendIntent} from "../packages/inbox/send.mjs";
import {requireAuthorizedWarrant} from "../packages/core/warrant.mjs";
const intent={title:"Bound complexity budget",kind:"feature",scope:["src/**"]};
function fixture(run) {const root=mkdtempSync(join(tmpdir(),"mirql-phi-budget-"));try{const dir=join(root,"workspace",".mirql"),owner=runGenesis(dir);run(dir,{key:owner.human_key_path,idempotencyKey:"phi-budget"});}finally{rmSync(root,{recursive:true,force:true});}}
test("an explicit integer complexity budget is bound to the verified owner grant",()=>fixture((dir,options)=>{
 const issued=sendIntent(dir,{...intent,phi_budget:12},options);
 assert.equal(issued.warrant.phi_budget,12);
 assert.equal(requireAuthorizedWarrant(dir,{warrantId:issued.warrant_id}).phi_budget,12);
 const file=join(dir,"warrants",issued.warrant_id+".json");const changed={...issued.warrant,phi_budget:13};writeFileSync(file,JSON.stringify(changed));
 assert.throws(()=>requireAuthorizedWarrant(dir,{warrantId:issued.warrant_id}));
}));
test("budget changes conflict with an existing signed submission while exact retries reuse it",()=>fixture((dir,options)=>{
 const first=sendIntent(dir,{...intent,phi_budget:4},options),path=join(dir,"ledger","events.jsonl"),before=readFileSync(path,"utf8");
 assert.equal(sendIntent(dir,{...intent,phi_budget:4},options).warrant_id,first.warrant_id);
 assert.throws(()=>sendIntent(dir,{...intent,phi_budget:5},options),/idempotency/i);
 assert.equal(readFileSync(path,"utf8"),before);
}));
test("legacy absent budgets remain absent and resolve to the default zero",()=>fixture((dir,options)=>{
 const first=sendIntent(dir,intent,options);assert.equal(Object.hasOwn(first.warrant,"phi_budget"),false);
 assert.equal(requireAuthorizedWarrant(dir,{warrantId:first.warrant_id}).phi_budget??0,0);
}));
for(const value of [-1,1.5,Number.MAX_SAFE_INTEGER+1,"12",null,{},true])test(`invalid JSON complexity budget is rejected before writing: ${JSON.stringify(value)}`,()=>{
 const root=mkdtempSync(join(tmpdir(),"mirql-bad-phi-"));try{assert.throws(()=>sendIntent(root,{...intent,phi_budget:value}),e=>e.exitCode===2&&/phi_budget/.test(e.message));assert.equal(existsSync(join(root,"ledger","events.jsonl")),false);}finally{rmSync(root,{recursive:true,force:true});}
});
test("the public intent command accepts an integer --phi-budget",()=>fixture((dir,options)=>{
 const result=spawnSync(process.execPath,[fileURLToPath(new URL("../bin/mirql.mjs",import.meta.url)),"i","send","--dir",dir,"--key",options.key,"--title","CLI complexity budget","--phi-budget","9"],{encoding:"utf8",windowsHide:true});
 assert.equal(result.status,0,result.stderr);const issued=JSON.parse(result.stdout);assert.equal(issued.warrant.phi_budget,9);assert.equal(requireAuthorizedWarrant(dir,{warrantId:issued.warrant_id}).phi_budget,9);
}));