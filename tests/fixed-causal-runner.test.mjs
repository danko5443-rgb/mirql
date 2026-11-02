import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
import {verifyAttempt} from "../packages/run/verify.mjs";

function candidate({manifest=true,failingSuite=false,file="tests/repro.test.mjs",changedTest=true,alternating=false,fakeNpm=false}={}) {
 const root=mkdtempSync(join(tmpdir(),"mirql-fixed-runner-"));
 const git=(...args)=>{const r=spawnSync("git",args,{cwd:root,encoding:"utf8",windowsHide:true});assert.equal(r.status,0,r.stderr);return r.stdout.trim();};
 git("init","-q");git("config","user.name","test");git("config","user.email","test@local");git("config","commit.gpgsign","false");
 mkdirSync(join(root,"src"));mkdirSync(join(root,"tests"));
 if(fakeNpm)writeFileSync(join(root,"npm.cmd"),"@exit /b 0\r\n");
 if(manifest)writeFileSync(join(root,"package.json"),JSON.stringify({scripts:{test:"node --test"}}));
 writeFileSync(join(root,"src","value.mjs"),"export const value=1;\n");
 if(failingSuite)writeFileSync(join(root,"tests","unrelated.test.mjs"),'import test from "node:test";import assert from "node:assert/strict";test("legacy failure",()=>assert.fail("unrelated regression"));\n');
 const ordinary='import test from "node:test";import assert from "node:assert/strict";import {value} from "../src/value.mjs";test("value",()=>assert.equal(value,2));\n';
 if(!changedTest)writeFileSync(join(root,"probe.mjs"),ordinary.replace('../src/value.mjs','./src/value.mjs'));
 git("add",".");git("commit","-qm","base");const baseSha=git("rev-parse","HEAD");
 writeFileSync(join(root,"src","value.mjs"),"export const value=2;\n");
 if(changedTest)writeFileSync(join(root,file),alternating?
 'import test from "node:test";import assert from "node:assert/strict";import {existsSync,readFileSync,writeFileSync} from "node:fs";import {value} from "../src/value.mjs";test("value",()=>{if(value===1){const n=existsSync("counter")?Number(readFileSync("counter","utf8")):0;writeFileSync("counter",String(n+1));if(n===1)throw new Error("crash on repeated red");}assert.equal(value,2);});\n':ordinary);
 git("add",".");git("commit","-qm","head");const headSha=git("rev-parse","HEAD");
 return {options:{git:true,workspaceDir:root,baseSha,headSha,reproducerFile:changedTest?file:undefined},cleanup:()=>rmSync(root,{recursive:true,force:true})};
}
function check(settings,options,assertResult){const fixture=candidate(settings);try{assertResult(verifyAttempt({...fixture.options,...options}));}finally{fixture.cleanup();}}

test("a caller's passing command cannot replace the failing full suite",()=>{
 check({failingSuite:true},{testCommand:'node --eval "process.exit(0)"'},r=>{assert.equal(r.verified,false,JSON.stringify(r));assert.equal(r.checks?.full_suite?.passed,false);});
});
test("missing npm test metadata cannot fall back to the reproducer",()=>{
 check({manifest:false},{},r=>assert.equal(r.verified,false,JSON.stringify(r)));
});
test("a changed test filename containing spaces is passed as one argument",()=>{
 check({file:"tests/repro with spaces.test.mjs"},{},r=>assert.equal(r.verified,true,JSON.stringify(r)));
});
test("git conformance mode cannot produce an automatic merge verdict",()=>{
 check({}, {conformance:true},r=>{assert.equal(r.verified,false);assert.equal(r.verdict,"conformance_pass");});
});
test("self-reported refactor flags cannot authorize an unchanged shell reproducer",()=>{
 check({changedTest:false},{allowNoTests:true,warrantClass:"refactor",reproducerCommand:"node --test probe.mjs"},r=>{assert.equal(r.verified,false,JSON.stringify(r));assert.equal(r.rule,"REPRODUCER_NOT_IN_DIFF");});
});
test("a repeated red that crashes with the same exit code is rejected as inconsistent",()=>{
 check({alternating:true},{},r=>{assert.equal(r.verified,false,JSON.stringify(r));assert.equal(r.rule,"FLAKY_REPRODUCER");});
});
test("a candidate-local npm.cmd cannot impersonate the installed full-suite runner",{skip:process.platform!=="win32"},()=>{
 check({failingSuite:true,fakeNpm:true},{},r=>{assert.equal(r.verified,false,JSON.stringify(r));assert.equal(r.checks?.full_suite?.passed,false);});
});
