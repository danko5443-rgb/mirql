import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Require assertion diagnostics from failed TAP results, not words printed by tests. */
export function parseTapOutput(output, exitCode) {
  const text=String(output ?? "");
  const hasNotOk=/^\s*not ok \d+\b/m.test(text);
  const hasOk=/^\s*ok \d+\b/m.test(text);
  const hasFailCount=/^# fail\s+[1-9]\d*\s*$/m.test(text);
  const diagnostics=[];
  let failed=false, block=null;
  for (const line of text.split(/\r?\n/)) {
    const result=/^\s*(not ok|ok) \d+\b/.exec(line);
    if (result) failed=result[1]==="not ok" && !/\s#\s*TODO\b/i.test(line);
    const start=/^(\s+)---\s*$/.exec(line);
    if (start) { block=failed?{indent:start[1].length}:null; continue; }
    if (!block) continue;
    if (new RegExp("^\\s{"+block.indent+"}\\.\\.\\.\\s*$").test(line)) {
      diagnostics.push(block); block=null; continue;
    }
    const field=/^(\s+)(code|name|failureType):\s*(.*?)\s*$/.exec(line);
    if (field && field[1].length===block.indent) {
      block[field[2]]=field[3].replace(/^(['"])(.*)\1$/,"$2");
    }
  }
  const causes=diagnostics.filter(d=>d.failureType!=="subtestsFailed");
  const assertionsOnly=causes.length>0 && causes.every(d=>
    (d.code==="ERR_ASSERTION" || d.name==="AssertionError") &&
    (d.name===undefined || d.name==="AssertionError"));
  const isAssertionFailure=exitCode===1 && hasNotOk && hasFailCount && assertionsOnly;
  return {exitCode,isAssertionFailure,isCrash:exitCode!==0 && !assertionsOnly,hasNotOk,hasOk,hasFailCount};
}

function pathIdentity(path) {
  const absolute=resolve(path);
  return process.platform==="win32"?absolute.toLowerCase():absolute;
}

// V8's outer range includes nested functions/branches. The innermost range wins,
// including a zero-count range; ignoring those zeros credits code that never ran.
function executedBetween(ranges, start, end) {
  const overlapping=ranges.filter(r=>r.startOffset<end && r.endOffset>start);
  const boundaries=[start,end];
  for (const range of overlapping) {
    boundaries.push(Math.max(start,range.startOffset),Math.min(end,range.endOffset));
  }
  const sorted=[...new Set(boundaries)].sort((a,b)=>a-b);
  for (let i=0;i+1<sorted.length;i++) {
    let narrowest=Infinity, count=0;
    for (const range of overlapping) {
      if (range.startOffset>sorted[i] || range.endOffset<sorted[i+1]) continue;
      const width=range.endOffset-range.startOffset;
      if (width<narrowest) {narrowest=width;count=range.count;}
      else if (width===narrowest) count=Math.min(count,range.count);
    }
    if (count>0) return true;
  }
  return false;
}

/** Validated flat ranges of one inspector coverage entry, or null when malformed. */
function entryRanges(entry, sourceLength) {
  if (typeof entry.url!=="string" || !entry.url.startsWith("file:") || !Array.isArray(entry.functions)) return null;
  const ranges=entry.functions.flatMap(fn=>Array.isArray(fn.ranges)?fn.ranges:[]);
  if (!ranges.length || !ranges.every(range=>range &&
      Number.isSafeInteger(range.startOffset) && Number.isSafeInteger(range.endOffset) &&
      Number.isSafeInteger(range.count) && range.count>=0 && range.startOffset>=0 &&
      range.endOffset>range.startOffset && range.endOffset<=sourceLength)) return null;
  return ranges;
}

function lineStartOffsets(source) {
  const offsets=[0];
  for (let i=0;i<source.length;i++) if (source[i]==="\n") offsets.push(i+1);
  return offsets;
}

/** Mask comments to whitespace (strings stay: a range covering a statement covers its literals). */
function maskCommentsByLine(source) {
  const maskedLines=[];
  let inBlock=false, inString=null, escaped=false, line="";
  for (let i=0;i<source.length;i++) {
    const ch=source[i];
    if (ch==="\n") { maskedLines.push(line); line=""; continue; }
    if (inBlock) {
      if (ch==="*" && source[i+1]==="/") { inBlock=false; line+="  "; i++; }
      else line+=" ";
      continue;
    }
    if (inString) {
      line+=ch;
      if (escaped) escaped=false;
      else if (ch==="\\") escaped=true;
      else if (ch===inString) inString=null;
      continue;
    }
    if (ch==="/" && source[i+1]==="/") {
      const end=source.indexOf("\n",i);
      line+=" ".repeat((end===-1?source.length:end)-i);
      i=(end===-1?source.length:end)-1;
      continue;
    }
    if (ch==="/" && source[i+1]==="*") { inBlock=true; line+="  "; i++; continue; }
    if (ch==='"' || ch==="'" || ch==="`") { inString=ch; line+=ch; continue; }
    line+=ch;
  }
  maskedLines.push(line);
  return maskedLines;
}

// Blank and comment-only lines carry no code, and V8 reports closing tokens
// after an unconditional return as unexecuted, so structural-only lines
// (`}`, `});`, `} else {`) are exempt; everything else must fully run.
function isStructuralOnlyLine(code) {
  const compact=code.replace(/\s/g,"");
  if (!compact) return true;
  const words=compact.replace(/[{}\[\]();,.]/g,"");
  return words==="" || words==="else" || words==="do";
}

// The innermost range covering each character decides; a character inside no
// range at all is unexecuted. A never-called export's `export ` prefix sits in
// the module root range, but its declaration characters sit in the function's
// own zero-count range, so the line is not fully executed.
function executedAtEveryOffset(ranges,offsets) {
  for (const offset of offsets) {
    let narrowest=Infinity,count=0;
    for (const range of ranges) {
      if (range.startOffset>offset || range.endOffset<=offset) continue;
      const width=range.endOffset-range.startOffset;
      if (width<narrowest) {narrowest=width;count=range.count;}
      else if (width===narrowest) count=Math.min(count,range.count);
    }
    if (count<=0) return false;
  }
  return true;
}

/** Check inspector coverage entries: relevance per executed line, plus full execution of every changed line. */
export function checkCoverageEntries(coverageEntries, workspaceDir, changedLinesPerFile) {
  const covered=new Map();
  const uncovered=new Map();
  for (const [file,lines] of changedLinesPerFile) {
    // Pre-classify from the head source: a line that must run stays suspect
    // until an entry proves every one of its code characters executed.
    let masked=null;
    try { masked=maskCommentsByLine(readFileSync(join(workspaceDir,file),"utf8")); }
    catch { /* Unreadable: every changed line stays suspect. */ }
    const suspect=new Set();
    for (const line of lines) {
      if (masked===null || !Number.isSafeInteger(line) || line<1 || line>masked.length ||
          !isStructuralOnlyLine(masked[line-1]??"")) suspect.add(line);
    }
    uncovered.set(file,suspect);
  }
  const report=()=>({
    executedChangedLines:[...covered.values()].some(lines=>lines.size>0),
    coveredFiles:[...covered.keys()],
    coveredLinesMap:Object.fromEntries([...covered].map(([file,lines])=>[file,[...lines]])),
    totalCovered:[...covered.values()].reduce((sum,lines)=>sum+lines.size,0),
    uncoveredLinesMap:Object.fromEntries([...uncovered].map(([file,lines])=>[file,[...lines]])),
    fullyExecutedChangedLines:[...uncovered.values()].every(lines=>lines.size===0),
  });
  if (!Array.isArray(coverageEntries)) return report();
  const targets=new Map([...changedLinesPerFile].map(([file,lines])=>[
    pathIdentity(join(workspaceDir,file)),{file,lines},
  ]));
  for (const entry of coverageEntries) {
    let identity;
    try { identity=pathIdentity(fileURLToPath(entry.url)); }
    catch { continue; }
    const target=targets.get(identity);
    if (!target) continue;
    let source;
    try { source=readFileSync(join(workspaceDir,target.file),"utf8"); }
    catch { continue; } // An unreadable file keeps every changed line suspect.
    const ranges=entryRanges(entry,source.length);
    if (!ranges) continue;
    const offsets=lineStartOffsets(source);
    const masked=maskCommentsByLine(source);
    for (const line of target.lines) {
      if (!Number.isSafeInteger(line) || line<1 || line>offsets.length) continue;
      const start=offsets[line-1], end=line<offsets.length?offsets[line]-1:source.length;
      if (end>start && executedBetween(ranges,start,end)) {
        if (!covered.has(target.file)) covered.set(target.file,new Set());
        covered.get(target.file).add(line);
      }
      const charOffsets=[];
      for (let i=0;i<end-start;i++) if (/\S/.test(masked[line-1][i]??"")) charOffsets.push(start+i);
      if (charOffsets.length===0 || executedAtEveryOffset(ranges,charOffsets)) uncovered.get(target.file).delete(line);
    }
  }
  return report();
}

/** Map coverage only to exact workspace files and actually executed source ranges. */
export function checkV8Coverage(coverageDir, workspaceDir, changedLinesPerFile) {
  const covered=new Map();
  const report=()=>({
    executedChangedLines:[...covered.values()].some(lines=>lines.size>0),
    coveredFiles:[...covered.keys()],
    coveredLinesMap:Object.fromEntries([...covered].map(([file,lines])=>[file,[...lines]])),
    totalCovered:[...covered.values()].reduce((sum,lines)=>sum+lines.size,0),
  });
  if (!existsSync(coverageDir)) return report();
  let files;
  try { files=readdirSync(coverageDir).filter(file=>file.endsWith(".json")); }
  catch { return report(); }
  const targets=new Map([...changedLinesPerFile].map(([file,lines])=>[
    pathIdentity(join(workspaceDir,file)),{file,lines},
  ]));
  for (const file of files) {
    let data;
    try { data=JSON.parse(readFileSync(join(coverageDir,file),"utf8")); }
    catch { continue; } // Unreadable evidence cannot supply coverage.
    if (!Array.isArray(data.result)) continue;
    for (const entry of data.result) {
      if (typeof entry.url!=="string" || !entry.url.startsWith("file:") || !Array.isArray(entry.functions)) continue;
      let identity;
      try { identity=pathIdentity(fileURLToPath(entry.url)); }
      catch { continue; }
      const target=targets.get(identity);
      if (!target) continue;
      let source;
      try { source=readFileSync(join(workspaceDir,target.file),"utf8"); }
      catch { continue; }
      const ranges=entryRanges(entry,source.length);
      if (!ranges) continue;
      const offsets=lineStartOffsets(source);
      for (const line of target.lines) {
        if (!Number.isSafeInteger(line) || line<1 || line>offsets.length) continue;
        const start=offsets[line-1], end=line<offsets.length?offsets[line]-1:source.length;
        if (end<=start || !executedBetween(ranges,start,end)) continue;
        if (!covered.has(target.file)) covered.set(target.file,new Set());
        covered.get(target.file).add(line);
      }
    }
  }
  return report();
}