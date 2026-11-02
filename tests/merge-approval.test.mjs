import { test } from "node:test";
import assert from "node:assert/strict";
import { canWriteEvent } from "../packages/core/acl.mjs";

test("only the pinned human owner namespace can author merge.approved", () => {
  assert.equal(canWriteEvent("human:owner", "merge.approved"), true);
  for (const writer of ["notary:mergeproof", "tool:run_supervisor", "tool:inbox", "tool:queue"]) {
    assert.equal(canWriteEvent(writer, "merge.approved"), false, writer);
  }
});
import { describe, beforeEach, afterEach } from "node:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { git } from "./helpers/git.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { sendIntent } from "../packages/inbox/send.mjs";
import { approveMerge } from "../packages/inbox/merge-approval.mjs";
import { measureMergeBinding, findExactMergeApproval } from "../packages/core/merge-approval.mjs";
import { validateMergeApprovalPayload } from "../packages/core/schema.mjs";
import { readVerifiedLedger } from "../packages/core/ledger-verify.mjs";
import { jcs, signEvent } from "../packages/core/index.mjs";
import { trustFile } from "../packages/core/trust-root.mjs";
import { checkAntiCheat } from "../packages/run/anti-cheat.mjs";
const ROOT=fileURLToPath(new URL("../",import.meta.url));

test("approval payloads require every immutable binding field and canonical paths", () => {
  const binding={warrant_id:"01ARZ3NDEKTSV4RRFFQ69G5FAV",base_sha:"a".repeat(40),head_sha:"b".repeat(40),tree_sha:"c".repeat(40),paths:["a.mjs","b.mjs"]};
  assert.equal(validateMergeApprovalPayload(binding).valid,true);
  for(const field of Object.keys(binding)) {
    const missing={...binding};delete missing[field];
    assert.equal(validateMergeApprovalPayload(missing).valid,false,field);
  }
  for(const paths of [["b.mjs","a.mjs"],["a.mjs","a.mjs"],["../outside"],["/absolute"],["a\\b"],[]]) {
    assert.equal(validateMergeApprovalPayload({...binding,paths}).valid,false,JSON.stringify(paths));
  }
});

describe("human-signed merge approval records", () => {
  let root,workspace,metadata,options,oldBase;
  beforeEach(() => {
    root=mkdtempSync(join(tmpdir(),"mirql-merge-approval-"));
    workspace=join(root,"repo");mkdirSync(join(workspace,"packages","core"),{recursive:true});
    git(workspace,"init","-q");git(workspace,"config","user.name","test");git(workspace,"config","user.email","test@mirql.local");git(workspace,"config","core.autocrlf","false");
    git(workspace,"commit","--allow-empty","-qm","empty base");oldBase=git(workspace,"rev-parse","HEAD").trim();
    writeFileSync(join(workspace,"packages","core","feature.mjs"),"export const value=1;\n");
    git(workspace,"add","packages/core/feature.mjs");git(workspace,"commit","-qm","base");
    const base=git(workspace,"rev-parse","HEAD").trim();
    metadata=join(workspace,".mirql");const genesis=runGenesis(metadata);
    const intent=sendIntent(metadata,{title:"Exact approval fixture",kind:"bug",scope:["packages/core/**"]},{key:genesis.human_key_path});
    writeFileSync(join(workspace,"packages","core","feature.mjs"),"export const value=2;\n");
    git(workspace,"add","packages/core/feature.mjs");git(workspace,"commit","-qm","candidate");
    options={key:genesis.human_key_path,workspaceDir:workspace,warrantId:intent.warrant_id,base,head:git(workspace,"rev-parse","HEAD").trim()};
  });
  afterEach(() => rmSync(root,{recursive:true,force:true}));
  const replaceLast = (metadata,event) => {
    const path=join(metadata,"ledger","events.jsonl");const lines=readFileSync(path,"utf8").trim().split(/\r?\n/);
    lines[lines.length-1]=jcs(event);writeFileSync(path,lines.join("\n")+"\n");
  };

  test("a real human record binds the measured commits, tree and complete paths", () => {
    const result=approveMerge(metadata,options);
    assert.equal(result.status,"approved");assert.equal(result.event.writer.ns,"human:owner");
    assert.equal(result.binding.tree_sha,git(workspace,"rev-parse",options.head+"^{tree}").trim());
    assert.deepEqual(result.binding.paths,["packages/core/feature.mjs"]);
    assert.equal(findExactMergeApproval(metadata,options).hash,result.event.hash);
    assert.equal(readVerifiedLedger(metadata).length,4);
  });
  test("explicit human credentials are required, including for repeated approvals", () => {
    approveMerge(metadata,options);
    const before=readVerifiedLedger(metadata).length;
    const ambient=process.env.MIRQL_HUMAN_KEY;
    delete process.env.MIRQL_HUMAN_KEY;
    try { assert.throws(()=>approveMerge(metadata,{...options,key:undefined}),error=>error.exitCode===4); }
    finally { if(ambient===undefined)delete process.env.MIRQL_HUMAN_KEY;else process.env.MIRQL_HUMAN_KEY=ambient; }
    assert.equal(readVerifiedLedger(metadata).length,before);
  });
  test("an enrolled machine key cannot author owner approval", () => {
    assert.throws(()=>approveMerge(metadata,{...options,key:trustFile(metadata,"keys","queue.key.json")}),error=>error.exitCode===4);
    assert.equal(findExactMergeApproval(metadata,options),null);
  });
  test("repeating the exact approval appends no event", () => {
    const first=approveMerge(metadata,options);const second=approveMerge(metadata,options);
    assert.equal(second.status,"already_approved");assert.equal(second.event.hash,first.event.hash);
    assert.equal(readVerifiedLedger(metadata).length,4);
  });
  test("a recorded approval cannot be replayed against another base or head", () => {
    approveMerge(metadata,options);
    assert.equal(findExactMergeApproval(metadata,{...options,base:oldBase}),null);
    writeFileSync(join(workspace,"packages","core","feature.mjs"),"export const value=3;\n");
    git(workspace,"add","packages/core/feature.mjs");git(workspace,"commit","-qm","another candidate");
    assert.equal(findExactMergeApproval(metadata,{...options,head:"HEAD"}),null);
  });
  test("a recorded approval cannot authorize another warrant", () => {
    approveMerge(metadata,options);
    const other=sendIntent(metadata,{title:"Different warrant",kind:"bug",scope:["packages/core/**"]},{key:options.key});
    assert.equal(findExactMergeApproval(metadata,{...options,warrantId:other.warrant_id}),null);
  });
  test("an owner signature on the wrong path set does not match the candidate", () => {
    const result=approveMerge(metadata,options);const owner=JSON.parse(readFileSync(options.key,"utf8"));
    replaceLast(metadata,signEvent({...result.event,payload:{...result.binding,paths:["unrelated.mjs"]}},owner.privateKey,owner.keyId));
    assert.equal(readVerifiedLedger(metadata).length,4);
    assert.equal(findExactMergeApproval(metadata,options),null);
  });
  test("a notary-signed replacement is refused instead of treated as owner approval", () => {
    const result=approveMerge(metadata,options);const machine=JSON.parse(readFileSync(trustFile(metadata,"keys","notary.key.json"),"utf8"));
    replaceLast(metadata,signEvent({...result.event,writer:{ns:"notary:mergeproof",key_id:machine.keyId}},machine.privateKey,machine.keyId));
    assert.throws(()=>findExactMergeApproval(metadata,options),/acl_denial/);
  });
  test("caller approval fields cannot substitute for a durable signed record", () => {
    assert.equal(findExactMergeApproval(metadata,{...options,human_approved:true,approval:{...measureMergeBinding(options),sig:"self-reported"}}),null);
  });
  test("humanOnly changes cannot be approved by this command", () => {
    mkdirSync(join(workspace,"policy"));writeFileSync(join(workspace,"policy","guard.json"),"{}");
    git(workspace,"add","policy/guard.json");git(workspace,"commit","-qm","protected candidate");
    assert.throws(()=>approveMerge(metadata,{...options,head:"HEAD"}),error=>error.code==="TOUCH_HUMAN_ONLY"&&error.exitCode===4);
  });
  test("recording approval alone does not bypass the existing closed merge gates", () => {
    const result=approveMerge(metadata,options);
    const verdict=checkAntiCheat({diff_stat:{files_changed:result.binding.paths},human_approved:true,approval:result.event,proof:{causal_cycle_completed:true}});
    assert.equal(verdict.ok,false);assert.equal(verdict.verdict,"needs_human");
  });
  test("the public CLI records the same measured binding", () => {
    const result=spawnSync(process.execPath,[join(ROOT,"bin","mirql.mjs"),"i","approve-merge","--dir",metadata,"--workspace",workspace,"--warrant-id",options.warrantId,"--base",options.base,"--head",options.head,"--key",options.key],{cwd:ROOT,encoding:"utf8",windowsHide:true});
    assert.equal(result.status,0,result.stderr);const document=JSON.parse(result.stdout);
    assert.equal(document.status,"approved");assert.deepEqual(document.binding,measureMergeBinding(options));
  });
});