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
});const complexBody = "export function hidden(a){ if(a>1){ if(a>2){ switch(a){case 3: return 3; case 4: return 4;} } } return 0; }\n";
const hiddenPaths = { "packages/run/test/impl.mjs": "./test/impl.mjs", "packages/run/impl.spec.mjs": "./impl.spec.mjs", "conformance/impl.mjs": "../../conformance/impl.mjs" };
for (const [hiddenPath, rel] of Object.entries(hiddenPaths)) {
 test(`production code cannot hide complexity behind a test-only path: ${hiddenPath}`, () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-hidden-phi-")); try {
   mkdirSync(join(root, "packages", "run"), { recursive: true });
   writeFileSync(join(root, "packages", "run", "entry.mjs"), "export const entry = 1;\n");
   const before = computePhi(root);
   const hidden = join(root, hiddenPath); mkdirSync(dirname(hidden), { recursive: true });
   writeFileSync(hidden, complexBody);
   writeFileSync(join(root, "packages", "run", "entry.mjs"), `export * from "${rel}";\nexport const entry = 1;\n`);
   const after = computePhi(root);
   assert.ok(after.total > before.total + 10, `hidden complexity must count: ${before.total} -> ${after.total}`);
  } finally { rmSync(root, { recursive: true, force: true }); }
 });
}
test("transitively imported test-path modules count toward potential", () => {
 const root = mkdtempSync(join(tmpdir(), "mirql-hidden-transitive-")); try {
  mkdirSync(join(root, "packages", "test"), { recursive: true });
  writeFileSync(join(root, "packages", "entry.mjs"), 'import "./test/a.mjs";\n');
  writeFileSync(join(root, "packages", "test", "a.mjs"), 'import "./b.mjs";\n');
  writeFileSync(join(root, "packages", "test", "b.mjs"), complexBody);
  const counted = computePhi(root).total;
  writeFileSync(join(root, "packages", "entry.mjs"), "export const entry = 1;\n");
  assert.ok(counted > computePhi(root).total, "the transitive test-path module must be measured");
 } finally { rmSync(root, { recursive: true, force: true }); }
});
test("test-path modules only imported by tests stay exempt", () => {
 const root = mkdtempSync(join(tmpdir(), "mirql-helper-exempt-")); try {
  mkdirSync(join(root, "tests", "helpers"), { recursive: true });
  writeFileSync(join(root, "feature.mjs"), "export const value = 2;\n");
  const before = computePhi(root).total;
  writeFileSync(join(root, "tests", "helpers", "h.mjs"), complexBody);
  writeFileSync(join(root, "tests", "a.test.mjs"), 'import "./helpers/h.mjs";\nimport "../feature.mjs";\n');
  assert.equal(computePhi(root).total, before);
 } finally { rmSync(root, { recursive: true, force: true }); }
});
