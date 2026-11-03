import {join} from "node:path";
import {mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {runGenesis} from "../../packages/inbox/genesis.mjs";
import {sendIntent} from "../../packages/inbox/send.mjs";
import {verifyAttempt} from "../../packages/run/verify.mjs";
/** Authorize causal-test fixtures without changing their live working directories. */
export function verifyAuthorizedGitFixture(options) {
 const {fixtureWarrantClass="feature",...input}=options;
 if(input.conformance || input.mirqlDir || !input.workspaceDir)return verifyAttempt(input);
 const root=mkdtempSync(join(tmpdir(),"mirql-causal-authority-"));
 try {
  const mirqlDir=join(root,".mirql"),owner=runGenesis(mirqlDir);
  const issued=sendIntent(mirqlDir,{title:"Authorized causal-verifier test fixture",kind:fixtureWarrantClass==="surgical"?"bug":fixtureWarrantClass,phi_budget:10000,scope:["**"]},{key:owner.human_key_path});
  return verifyAttempt({...input,mirqlDir,warrantId:issued.warrant_id});
 } finally {rmSync(root,{recursive:true,force:true});}
}