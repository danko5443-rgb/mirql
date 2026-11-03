import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import {resolve,join} from "node:path";
const LIMIT=64*1024*1024;
function refusal(message) {const error=new Error(message);error.code=error.errorCode="PHI_UNMEASURED";return error;}
function git(root,args,input) {
 const r=spawnSync("git",["--no-replace-objects","--no-pager","-c","core.fsmonitor=false",...args],{cwd:root,input,timeout:30000,maxBuffer:LIMIT,windowsHide:true});
 if(r.error || r.signal || r.status!==0)throw refusal("Cannot read immutable Git objects for Phi");
 return r.stdout;
}
function verifyObject(type,id,bytes) {
 const hash=createHash(id.length===64?"sha256":"sha1").update(Buffer.from(type+" "+bytes.length+"\0")).update(bytes).digest("hex");
 if(hash!==id)throw refusal("Git object contents do not match their recorded identity");
}
/** Read raw regular blobs without checkout filters, replacement objects or working files. */
export function readGitPhiSnapshot(repoDir,ref) {
 const root=resolve(repoDir);
 if(typeof ref!=="string" || !ref.trim())throw refusal("An explicit commit reference is required for Phi");
 const commitSha=git(root,["rev-parse","--verify","--end-of-options",ref+"^{commit}"]).toString().trim();
 if(!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commitSha))throw refusal("Invalid measured commit identity");
 const treeSha=git(root,["rev-parse","--verify",commitSha+"^{tree}"]).toString().trim();
 verifyObject("commit",commitSha,git(root,["cat-file","commit",commitSha]));
 verifyObject("tree",treeSha,git(root,["cat-file","tree",treeSha]));
 const raw=git(root,["ls-tree","-rtz","--full-tree",commitSha]);
 const entries=[],trees=new Set();
 for(const row of raw.toString("utf8").split("\0").filter(Boolean)) {
  const match=/^([0-7]{6}) (blob|commit|tree) ([a-f0-9]{40}|[a-f0-9]{64})\t([\s\S]+)$/.exec(row);
  if(!match)throw refusal("Invalid Git tree record");
  const [,mode,type,sha,path]=match;
  if(path.startsWith("/") || path.includes("\\") || path.split("/").some(part=>!part || part==="." || part===".."))throw refusal("Noncanonical Git tree path");
  if(type==="tree"){if(mode!=="040000")throw refusal("Invalid tree mode");trees.add(sha);continue;}
  if(type==="commit")throw refusal("Submodule complexity is not measured");
  if(path.split("/").some(part=>["node_modules",".git",".mirql","coverage"].includes(part)))continue;
  if(path!=="package.json" && !/\.(mjs|js)$/.test(path))continue;
  if(!/^100(?:644|755)$/.test(mode))throw refusal("Phi input must be a regular Git blob");
  entries.push({sha,path});
 }
 if(!Buffer.from(raw.toString("utf8"),"utf8").equals(raw))throw refusal("Git tree paths must be valid UTF-8");
 const ids=[...new Set([...trees,...entries.map(entry=>entry.sha)])],blobs=new Map();
 if(ids.length) {
  const output=git(root,["cat-file","--batch"],ids.join("\n")+"\n");let cursor=0;
  for(const id of ids) {
   const end=output.indexOf(10,cursor);if(end<0)throw refusal("Incomplete Git blob header");
   const header=output.subarray(cursor,end).toString("ascii");
   const match=/^([a-f0-9]+) (blob|tree) (\d+)$/.exec(header);
   const size=match?Number(match[3]):NaN;
   if(!match || match[1]!==id || match[2] !== (trees.has(id)?"tree":"blob") || !Number.isSafeInteger(size) || size<0 || end+1+size>=output.length)throw refusal("Invalid Git blob response");
   cursor=end+1;const bytes=output.subarray(cursor,cursor+size);
   verifyObject(match[2],id,bytes);
   if(match[2]==="blob") {
    const text=bytes.toString("utf8");
    if(!Buffer.from(text,"utf8").equals(bytes))throw refusal("Phi source blobs must be UTF-8");
    blobs.set(id,text);
   }
   cursor+=size;
   if(output[cursor++]!==10)throw refusal("Invalid Git blob boundary");
  }
  if(cursor!==output.length)throw refusal("Unexpected Git blob output");
 }
 const contentsByFile=new Map();let packageJson={};
 for(const {sha,path} of entries) {
  const contents=blobs.get(sha);
  if(path==="package.json") {
   try {packageJson=JSON.parse(contents);}catch{throw refusal("Invalid package metadata in the measured tree");}
   if(!packageJson || typeof packageJson!=="object" || Array.isArray(packageJson))throw refusal("Invalid package metadata object");
   for(const key of ["dependencies","devDependencies","peerDependencies","optionalDependencies"]) {
    const value=packageJson[key];if(value!==undefined && (!value || typeof value!=="object" || Array.isArray(value)))throw refusal("Invalid dependency metadata in the measured tree");
   }
  } else contentsByFile.set(join(root,path),contents);
 }
 return {root,contentsByFile,packageJson,commitSha,treeSha};
}