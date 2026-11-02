import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,mkdirSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {spawnSync} from "node:child_process";
import * as phi from "../packages/run/phi.mjs";
function repo(run) {const root=mkdtempSync(join(tmpdir(),"mirql-tree-phi-"));const git=(...args)=>{const r=spawnSync("git",args,{cwd:root,encoding:"utf8",windowsHide:true});assert.equal(r.status,0,r.stderr);return r.stdout.trim();};try{git("init","-q");git("config","user.name","test");git("config","user.email","test@local");git("config","commit.gpgsign","false");writeFileSync(join(root,"source.mjs"),"export const value=1;\n");writeFileSync(join(root,"package.json"),JSON.stringify({dependencies:{one:"1"}}));git("add",".");git("commit","-qm","base");run(root,git,git("rev-parse","HEAD"));}finally{rmSync(root,{recursive:true,force:true});}}
test("Git-tree metrics match a clean workspace and carry actual commit/tree identities",()=>repo((root,git,base)=>{
 const r=phi.computeGitTreePhi(root,base);assert.deepEqual(r.metrics,phi.computePhi(root));assert.equal(r.commit_sha,base);assert.equal(r.tree_sha,git("rev-parse",base+"^{tree}"));
}));
test("working edits, ignored sources and malformed working package.json cannot change a pinned measurement",()=>repo((root,git,base)=>{
 const before=phi.computeGitTreePhi(root,base);writeFileSync(join(root,"source.mjs"),"export function grow(x){if(x)return 42;}\n");writeFileSync(join(root,"ignored.mjs"),"export const extra=1;\n");writeFileSync(join(root,".gitignore"),"ignored.mjs\n");writeFileSync(join(root,"package.json"),"invalid");assert.deepEqual(phi.computeGitTreePhi(root,base),before);
}));
test("replacement refs cannot substitute another tree's complexity",()=>repo((root,git,base)=>{
 const before=phi.computeGitTreePhi(root,base);writeFileSync(join(root,"source.mjs"),"export function grow(x){if(x)return 42;}\n");git("add",".");git("commit","-qm","head");const head=git("rev-parse","HEAD");assert.notEqual(phi.computeGitTreePhi(root,head).metrics.total,before.metrics.total);git("replace",base,head);assert.deepEqual(phi.computeGitTreePhi(root,base),before);
}));
test("Git object measurement never invokes checkout filters",()=>repo((root,git,base)=>{
 const before=phi.computeGitTreePhi(root,base);writeFileSync(join(root,".gitattributes"),"*.mjs filter=broken\n");git("config","filter.broken.smudge","false");git("config","filter.broken.required","true");assert.deepEqual(phi.computeGitTreePhi(root,base),before);
}));
test("malformed package metadata in the actual tree refuses measurement",()=>repo((root,git)=>{
 writeFileSync(join(root,"package.json"),"invalid");git("add",".");git("commit","-qm","invalid manifest");assert.throws(()=>phi.computeGitTreePhi(root,"HEAD"),e=>e.code==="PHI_UNMEASURED");
}));
test("an invalid reference refuses measurement instead of returning zero",()=>repo(root=>{assert.throws(()=>phi.computeGitTreePhi(root,"does-not-exist"),e=>e.code==="PHI_UNMEASURED");}));
test("subdirectory invocation measures the complete tree",()=>repo((root,git,base)=>{mkdirSync(join(root,"nested"));assert.deepEqual(phi.computeGitTreePhi(join(root,"nested"),base).metrics,phi.computeGitTreePhi(root,base).metrics);}));
test("non-UTF-8 source refuses measurement",()=>repo((root,git)=>{writeFileSync(join(root,"bad.js"),Buffer.from([0xff,0xfe]));git("add",".");git("commit","-qm","invalid encoding");assert.throws(()=>phi.computeGitTreePhi(root,"HEAD"),e=>e.code==="PHI_UNMEASURED");}));
