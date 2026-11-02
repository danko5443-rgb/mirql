import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { parseTapOutput, checkV8Coverage } from "../packages/run/verify.mjs";

function tapFor(body) {
  const root=mkdtempSync(join(tmpdir(),"mirql-tap-boundary-"));
  try {
    const file=join(root,"case.test.mjs");
    writeFileSync(file,'import test from "node:test"; import assert from "node:assert/strict";\ntest("case",()=>{'+body+'});\n');
    const env={...process.env}; delete env.NODE_TEST_CONTEXT;
    const result=spawnSync(process.execPath,["--test","--test-reporter=tap",file],{env,encoding:"utf8",windowsHide:true});
    assert.equal(result.status,1,result.stderr);
    return parseTapOutput(result.stdout+"\n"+result.stderr,result.status);
  } finally { rmSync(root,{recursive:true,force:true}); }
}

test("a generic runtime Error in real TAP is not a causal assertion failure",()=>{
  assert.equal(tapFor('throw new Error("broken execution");').isAssertionFailure,false);
});
test("bare not-ok output without assertion diagnostics is not a causal assertion",()=>{
  assert.equal(parseTapOutput("TAP version 13\nnot ok 1 - case\n# fail 1\n",1).isAssertionFailure,false);
});
test("a real assertion failure is accepted and an exit-zero message is not",()=>{
  assert.equal(tapFor('assert.equal(1,2);').isAssertionFailure,true);
  assert.equal(parseTapOutput("AssertionError ERR_ASSERTION",0).isAssertionFailure,false);
});
test("printed assertion words cannot turn a runtime Error into a causal assertion",()=>{
  assert.equal(tapFor('console.log("AssertionError ERR_ASSERTION expected:"); throw new Error("runtime failure");').isAssertionFailure,false);
});

function measureCoverage(source, line, {external=false, invocation="used()"}={}) {
  const root=mkdtempSync(join(tmpdir(),"mirql-coverage-boundary-"));
  try {
    const workspace=join(root,"workspace");
    const actual=external?join(root,"outside"):workspace;
    for (const dir of new Set([workspace,actual])) {
      mkdirSync(join(dir,"src"),{recursive:true});
      writeFileSync(join(dir,"src","target.mjs"),source);
    }
    const coverage=join(root,"coverage");
    const entry=join(actual,"entry.mjs");
    writeFileSync(entry,'import {used} from '+JSON.stringify(pathToFileURL(join(actual,"src","target.mjs")).href)+'; '+invocation+';\n');
    const run=spawnSync(process.execPath,[entry],{env:{...process.env,NODE_V8_COVERAGE:coverage},encoding:"utf8",windowsHide:true});
    assert.equal(run.status,0,run.stderr);
    return checkV8Coverage(coverage,workspace,new Map([["src/target.mjs",new Set([line])]]));
  } finally { rmSync(root,{recursive:true,force:true}); }
}
const functions='export function unused() {\n  const unreachable=41;\n  return unreachable+1;\n}\nexport function used() { return 42; }\n';
test("importing a module does not cover the body of an uncalled function",()=>{
  assert.equal(measureCoverage(functions,3).executedChangedLines,false);
});
test("executing a function does not cover its untaken branch",()=>{
  const source='export function used(flag) {\n  if (flag) {\n    return 99;\n  }\n  return 42;\n}\n';
  assert.equal(measureCoverage(source,3,{invocation:"used(false)"}).executedChangedLines,false);
});
test("coverage from another directory cannot satisfy a workspace path by suffix",()=>{
  assert.equal(measureCoverage(functions,5,{external:true}).executedChangedLines,false);
});
test("executed changed source in the exact workspace is counted",()=>{
  assert.equal(measureCoverage(functions,5).executedChangedLines,true);
});