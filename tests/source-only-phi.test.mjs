import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from "node:fs";
import {join,dirname} from "node:path";
import {tmpdir} from "node:os";
import {computePhi} from "../packages/run/phi.mjs";
for(const path of ["tests/repro.test.mjs","conformance/sample.mjs","__tests__/sample.mjs","src/example.spec.js"])test(`test-only changes do not alter source potential: ${path}`,()=>{
 const root=mkdtempSync(join(tmpdir(),"mirql-source-phi-"));try{
  mkdirSync(join(root,"packages"));writeFileSync(join(root,"packages","value.mjs"),"export const value=2;\n");
  const before=computePhi(root),file=join(root,path);mkdirSync(dirname(file),{recursive:true});
  writeFileSync(file,'// TODO test fixture\nimport "../packages/value.mjs";\nexport function repro(value) { if(value) { return value; } }\n');
  const after=computePhi(root);assert.equal(after.total,before.total);assert.equal(after.loc,before.loc);assert.equal(after.dep_count,before.dep_count);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test("adding production source still increases source potential",()=>{
 const root=mkdtempSync(join(tmpdir(),"mirql-production-phi-"));try{const before=computePhi(root);writeFileSync(join(root,"feature.mjs"),"export const value=2;\n");assert.ok(computePhi(root).total>before.total);}finally{rmSync(root,{recursive:true,force:true});}
});