import {computeGitTreePhi} from "./phi.mjs";
import {requireAuthorizedWarrant} from "../core/warrant.mjs";
/** Only immutable tree metrics and verified owner authority participate in this gate. */
export function measureAuthorizedPhi({repoDir,baseSha,headSha,mirqlDir,warrantId,conformance=false}) {
 let warrant=null;
 if(!conformance || mirqlDir || warrantId) {
  if(!mirqlDir || !warrantId){const e=new Error("A signed warrant is required for live complexity verification");e.code="WARRANT_UNAUTHORIZED";throw e;}
  warrant=requireAuthorizedWarrant(mirqlDir,{warrantId});
 }
 const base=computeGitTreePhi(repoDir,baseSha),head=computeGitTreePhi(repoDir,headSha);
 const delta=head.metrics.total-base.metrics.total,budget=warrant?.phi_budget??0;
 const strict=["refactor","consolidation","consolidator"].includes(warrant?.class);
 return {base_sha:base.commit_sha,head_sha:head.commit_sha,base_tree:base.tree_sha,head_tree:head.tree_sha,phi_before:base.metrics.total,phi_after:head.metrics.total,delta_phi:delta,phi_budget:budget,warrant_class:warrant?.class??null,
  ok:strict?delta<0:delta<=budget,rule:strict&&delta>=0?"LAW_13_CONSOLIDATOR_PHI":"LAW_13_PHI_INCREASE"};
}