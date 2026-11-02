import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
import {verifyAttempt} from "../packages/run/verify.mjs";
function check(kind) {
 const root=mkdtempSync(join(tmpdir(),"mirql-git-policy-"));
 const git=(...args)=>{const r=spawnSync("git",args,{cwd:root,encoding:"utf8",windowsHide:true});assert.equal(r.status,0,r.stderr);return r.stdout.trim();};
 try {
  git("init","-q");git("config","user.name","test");git("config","user.email","test@local");git("config","commit.gpgsign","false");
  for(const d of ["src","tests","policy","private","domain"])mkdirSync(join(root,d));
  writeFileSync(join(root,"package.json"),JSON.stringify({scripts:{test:"node --test"}}));
  writeFileSync(join(root,"policy","paths.yaml"),'humanOnly:\n  - "private/**"\nhumanApprove:\n  - "domain/**"\n');
  writeFileSync(join(root,"src","value.mjs"),"export const value=1;\n");
  writeFileSync(join(root,"private","secret.txt"),"base");writeFileSync(join(root,"domain","config.txt"),"base");
  git("add",".");git("commit","-qm","base");const baseSha=git("rev-parse","HEAD");
  writeFileSync(join(root,"src","value.mjs"),"export const value=2;\n");
  writeFileSync(join(root,"tests","repro.test.mjs"),'import test from "node:test";import assert from "node:assert/strict";import {value} from "../src/value.mjs";test("value",()=>assert.equal(value,2));\n');
  if(kind==="approve")writeFileSync(join(root,"domain","config.txt"),"changed");
  if(kind==="private" || kind==="weak")writeFileSync(join(root,"private","secret.txt"),"changed");
  if(kind==="newline")writeFileSync(join(root,"policy","guard\n.txt"),"changed");
  git("add",".");git("commit","-qm","head");let headSha=git("rev-parse","HEAD");
  if(kind==="replace") {const safe=headSha;writeFileSync(join(root,"policy","guard.txt"),"protected edit");git("add",".");git("commit","-qm","protected head");headSha=git("rev-parse","HEAD");git("replace",headSha,safe);}
  if(kind==="weak")writeFileSync(join(root,"policy","paths.yaml"),"humanOnly: []\nhumanApprove: []\n");
  if(kind==="nested")git("config","diff.relative","true");
  return verifyAttempt({git:true,workspaceDir:kind==="nested"?join(root,"src"):root,baseSha,headSha,reproducerFile:"tests/repro.test.mjs"});
 } finally {rmSync(root,{recursive:true,force:true});}
}
for(const kind of ["private","weak"])test(`base humanOnly policy is enforced for ${kind}`,()=>{const r=check(kind);assert.equal(r.rule,"MP-001",JSON.stringify(r));assert.equal(r.verified,false);});
test("base custom humanApprove policy still requires approval",()=>{const r=check("approve");assert.equal(r.rule,"MP-005",JSON.stringify(r));assert.equal(r.verified,false);});
test("nested invocation and diff.relative preserve complete root-relative measurement",()=>{const r=check("nested");assert.equal(r.verified,true,JSON.stringify(r));});
test("newline paths cannot hide a protected path",{skip:process.platform==="win32"},()=>{const r=check("newline");assert.equal(r.rule,"MP-001",JSON.stringify(r));});
test("replacement objects cannot conceal protected changes in the named head",()=>{const r=check("replace");assert.equal(r.rule,"MP-001",JSON.stringify(r));assert.equal(r.verified,false);});
