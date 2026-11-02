import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {join} from "node:path";
import {git} from "./helpers/git.mjs";
import {runGenesis} from "../packages/inbox/genesis.mjs";
import {sendIntent} from "../packages/inbox/send.mjs";
import {approveMerge} from "../packages/inbox/merge-approval.mjs";
import {signEvent,jcs} from "../packages/core/index.mjs";
import {trustFile} from "../packages/core/trust-root.mjs";
import {verifyAttempt} from "../packages/run/verify.mjs";
function exercise(kind, {cwdOnly=false}={}) {
 const root=mkdtempSync(join(tmpdir(),"mirql-approved-proof-"));
 try {
  mkdirSync(join(root,"packages","core"),{recursive:true});mkdirSync(join(root,"tests"));
  git(root,"init","-q");git(root,"config","user.name","test");git(root,"config","user.email","test@local");git(root,"config","commit.gpgsign","false");
  writeFileSync(join(root,"package.json"),JSON.stringify({scripts:{test:"node --test"}}));
  writeFileSync(join(root,"packages","core","feature.mjs"),"export const value=1;\n");
  git(root,"add",".");git(root,"commit","-qm","base");const baseSha=git(root,"rev-parse","HEAD").trim();
  const dir=join(root,".mirql"),owner=runGenesis(dir);
  const intent=sendIntent(dir,{title:"Approve exact causal fix",kind:"bug",scope:["packages/core/**","tests/**"]},{key:owner.human_key_path});
  writeFileSync(join(root,"packages","core","feature.mjs"),"export const value=2;\n");
  writeFileSync(join(root,"tests","repro.test.mjs"),'import test from "node:test";import assert from "node:assert/strict";import {value} from "../packages/core/feature.mjs";test("value",()=>assert.equal(value,2));\n');
  git(root,"add","packages/core/feature.mjs","tests/repro.test.mjs");git(root,"commit","-qm","candidate");let headSha=git(root,"rev-parse","HEAD").trim();
  const options={git:true,workspaceDir:root,baseSha,headSha,reproducerFile:"tests/repro.test.mjs",mirqlDir:dir,warrantId:intent.warrant_id};
  let approval;
  if(!["missing","flag"].includes(kind))approval=approveMerge(dir,{...options,key:owner.human_key_path});
  if(kind==="head" || kind==="cli-head") {writeFileSync(join(root,"extra.txt"),"extra");git(root,"add","extra.txt");git(root,"commit","-qm","other head");options.headSha=git(root,"rev-parse","HEAD").trim();}
  if(kind==="protected") {mkdirSync(join(root,"policy"));writeFileSync(join(root,"policy","guard.txt"),"edit");git(root,"add","policy/guard.txt");git(root,"commit","-qm","protected edit");options.headSha=git(root,"rev-parse","HEAD").trim();}
  if(kind==="tampered") {const path=join(dir,"ledger","events.jsonl");const rows=readFileSync(path,"utf8").trim().split(/\r?\n/);const last=JSON.parse(rows.at(-1));last.payload.paths=["fake"];rows[rows.length-1]=JSON.stringify(last);writeFileSync(path,rows.join("\n")+"\n");}
  if(kind==="machine") {
   const path=join(dir,"ledger","events.jsonl"),rows=readFileSync(path,"utf8").trim().split(/\r?\n/);
   const machine=JSON.parse(readFileSync(trustFile(dir,"keys","notary.key.json"),"utf8"));
   const event=JSON.parse(rows.at(-1));event.writer={ns:"notary:mergeproof",key_id:machine.keyId};
   rows[rows.length-1]=jcs(signEvent(event,machine.privateKey,machine.keyId));writeFileSync(path,rows.join("\n")+"\n");
  }
  if(kind==="cli" || kind==="cli-head" || kind==="cli-default") {
   const run=spawnSync(process.execPath,[fileURLToPath(new URL("../bin/mirql.mjs",import.meta.url)),"r","verify",...(cwdOnly?[]:["--workspace",root]),...(kind==="cli-default"?[]:["--base",baseSha,"--head",options.headSha]),...(cwdOnly?[]:["--reproducer","tests/repro.test.mjs"]),"--dir",dir,"--warrant-id",intent.warrant_id],{cwd:root,encoding:"utf8",windowsHide:true});
   assert.ok(run.stdout.trim() || run.stderr.trim(),"CLI must return a result");
   return {result:JSON.parse(run.stdout.trim() || run.stderr.trim()),approval,exitCode:run.status};
  }
  const result=verifyAttempt({...options,human_approved:true,approval:{sig:"self-reported"}});
  return {result,approval};
 } finally {rmSync(root,{recursive:true,force:true});}
}
test("the exact durable owner approval permits the measured causal candidate",()=>{const {result,approval}=exercise("exact");assert.equal(result.verified,true,JSON.stringify(result));assert.equal(result.proof.human_approval_hash,approval.event.hash);});
for(const kind of ["missing","flag","head","tampered","machine"])test(`approval gate refuses ${kind} authority`,()=>{const {result}=exercise(kind);assert.equal(result.verified,false);assert.equal(result.rule,"MP-005");});
test("owner approval never overrides humanOnly",()=>{const {result}=exercise("protected");assert.equal(result.verified,false);assert.equal(result.rule,"MP-001");});
test("public verify command runs causal checks with the exact signed approval",()=>{const {result,approval,exitCode}=exercise("cli");assert.equal(exitCode,0,JSON.stringify(result));assert.equal(result.verified,true);assert.equal(result.proof.human_approval_hash,approval.event.hash);});
test("public verify command refuses an approval for another head",()=>{const {result,exitCode}=exercise("cli-head");assert.equal(exitCode,4,JSON.stringify(result));assert.equal(result.rule,"MP-005");assert.equal(result.verified,false);});

test("public verify command reports a missing flag value as usage error",()=>{
 const run=spawnSync(process.execPath,[fileURLToPath(new URL("../bin/mirql.mjs",import.meta.url)),"r","verify","--workspace",process.cwd(),"--base"],{encoding:"utf8",windowsHide:true});
 assert.equal(run.status,2,run.stdout+run.stderr);assert.equal(JSON.parse(run.stderr).error,"USAGE_ERROR");
});

test("public verify command measures default refs when no base is supplied",()=>{const {result,exitCode}=exercise("cli-default");assert.equal(exitCode,0,JSON.stringify(result));assert.equal(result.verified,true);});

test("public verify command accepts refs in the current repository without workspace flags",()=>{const {result,exitCode}=exercise("cli",{cwdOnly:true});assert.equal(exitCode,0,JSON.stringify(result));assert.equal(result.verified,true);});
