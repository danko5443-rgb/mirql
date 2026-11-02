import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
import {verifyAttempt} from "../packages/run/verify.mjs";
function exercise(kind) {
 const root=mkdtempSync(join(tmpdir(),"mirql-necessity-edge-"));
 const git=(...args)=>{const r=spawnSync("git",args,{cwd:root,encoding:"utf8",windowsHide:true});assert.equal(r.status,0,r.stderr);return r.stdout.trim();};
 try {
  git("init","-q");git("config","user.name","test");git("config","user.email","test@local");git("config","commit.gpgsign","false");
  mkdirSync(join(root,"src"));mkdirSync(join(root,"tests"));
  writeFileSync(join(root,"package.json"),JSON.stringify({scripts:{test:"node --test"}}));
  if(kind==="delete")writeFileSync(join(root,"src","obsolete.txt"),"obsolete behavior");
  if(kind==="crash" || kind==="timeout") {
   writeFileSync(join(root,"src","a.mjs"),"export const value=1;\n");
   writeFileSync(join(root,"src","b.mjs"),kind==="timeout"
    ? 'export function read(){Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,35000);return 2;}\n'
    : 'export function read(){throw new Error("runtime failure");}\n');
  }
  git("add",".");git("commit","-qm","base");const baseSha=git("rev-parse","HEAD");
  let body;
  if(kind==="add") {
   writeFileSync(join(root,"src","added.mjs"),"export const value=2;\n");
   body='const api=existsSync(new URL("../src/added.mjs",import.meta.url))?await import("../src/added.mjs"):{value:0};assert.equal(api.value,2);';
  } else if(kind==="delete") {
   rmSync(join(root,"src","obsolete.txt"));
   body='assert.equal(existsSync(new URL("../src/obsolete.txt",import.meta.url))?1:2,2);';
  } else {
   writeFileSync(join(root,"src","a.mjs"),"export const value=2;\n");
   writeFileSync(join(root,"src","b.mjs"),"export function read(){return 2;}\n");
   body='const a=await import("../src/a.mjs");assert.equal(a.value,2);const b=await import("../src/b.mjs");assert.equal(b.read(),2);';
  }
  writeFileSync(join(root,"tests","repro.test.mjs"),'import test from "node:test";import assert from "node:assert/strict";import {existsSync} from "node:fs";test("behavior",async()=>{'+body+'});\n');
  git("add",".");git("commit","-qm","head");const headSha=git("rev-parse","HEAD");
  return verifyAttempt({git:true,workspaceDir:root,baseSha,headSha,reproducerFile:"tests/repro.test.mjs"});
 } finally {rmSync(root,{recursive:true,force:true});}
}
for(const kind of ["add","delete"])test(`necessity restores the absence/presence of ${kind === "add" ? "an added" : "a deleted"} file`,()=>{
 const result=exercise(kind);assert.equal(result.verified,true,JSON.stringify(result));assert.equal(result.proof.necessity_check.necessary_files.length,1);
});
test("a rollback runtime crash cannot be classified as an unnecessary change",()=>{
 const result=exercise("crash");assert.equal(result.verified,false,JSON.stringify(result));assert.equal(result.rule,"NECESSITY_CHECK_CRASH");
});
test("a real rollback timeout is rejected explicitly", {skip:process.platform==="win32"},()=>{
 const result=exercise("timeout");assert.equal(result.verified,false,JSON.stringify(result));assert.equal(result.rule,"NECESSITY_CHECK_TIMEOUT");
});
