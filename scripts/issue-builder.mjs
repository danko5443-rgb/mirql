#!/usr/bin/env node
// Issue Builder (docs/pr-court.md). Turns a trusted author's new issue into a pull
// request, so the gate and the Court take it from there. The Builder role only
// proposes JSON patches; this tool validates, commits, pushes and opens the PR
// (Law 3). It holds secrets, so it never runs the code it writes (Law 7).
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkSwallowedExceptions, checkTestWeakenings, loadPathPolicies } from "../packages/core/anti-cheat.mjs";
import { computePhi } from "../packages/run/phi.mjs";
import { measurePhiWarrant } from "./ci-phi-warrant.mjs";
import { callCourtModel, isEntrypoint, scanDiffHazards } from "./ci-review-gate.mjs";
import { allowanceOf, clip, defaultIo, fenceData, isLockedPatchPath, loadRolePrompt, pushCommit, resolveRepoFile, sanitizeCourtText, stagePatches, TRUSTED_AUTHORS } from "./pr-court.mjs";

const BASE_BRANCH = "main";
const MAX_MODEL_CALLS = 3;
const MAX_FILES = 12;
const MAX_FILE_CHARS = 100000;
const log = (message) => console.log(`issue-builder: ${message}`);
const isText = (...values) => values.every((v) => typeof v === "string");

function validateBuilder(data) {
  if (data?.verdict === "DECLINE") return { verdict: "DECLINE", reason: clip(data.reason, 2000) };
  if (data?.verdict === "NEED_FILES") return Array.isArray(data.files) && data.files.every((f) => isText(f)) ? { verdict: "NEED_FILES", files: data.files } : null;
  if (data?.verdict !== "BUILD" || !Array.isArray(data.patches) || data.patches.length === 0) return null;
  const valid = data.patches.every((p) => isText(p?.file) && (isText(p.search, p.replace) || (isText(p.content) && p.search === undefined)));
  return valid ? { verdict: "BUILD", summary: clip(data.summary, 2000), patches: data.patches } : null;
}

/** Stages a file that must not exist yet. Refuses traversal, .git*, symlinks at any depth, locked paths and what the Advocate's patches may not add. */
function stageNewFile(repoDir, file, content, policies) {
  const segments = file.split("/");
  const badPath = !file || /[\0\\]/.test(file) || isAbsolute(file) || /^[a-zA-Z]:/.test(file) || segments.some((s) => s === "" || s === "." || s === ".." || /^\.git/i.test(s));
  if (badPath || isLockedPatchPath(file, policies)) return { error: `PATCH_PATH_REFUSED: ${clip(file, 200)}` };
  let current = resolve(repoDir);
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    const stat = lstatSync(current, { throwIfNoEntry: false });
    if (stat && (stat.isSymbolicLink() || index === segments.length - 1)) return { error: `PATCH_PATH_REFUSED: ${clip(file, 200)}` };
  }
  if (checkSwallowedExceptions(content, file).violations.length > 0) return { error: `PATCH_SWALLOWS_EXCEPTION: ${file}` };
  if (checkTestWeakenings(content, file).count > 0) return { error: `PATCH_WEAKENS_TESTS: ${file}` };
  return { abs: current };
}

/** Works on a throwaway checkout, so a refused build needs no rollback. */
function applyBuild(repoDir, patches, policies) {
  const staged = stagePatches(repoDir, patches.filter((p) => p.content === undefined), policies);
  if (staged.error) return staged;
  const writes = [...staged.files].map(([file, { abs, next }]) => ({ file, abs, text: next }));
  for (const { file, content } of patches.filter((p) => p.content !== undefined)) {
    const created = writes.some((w) => w.file === file) ? { error: `PATCH_PATH_REFUSED: ${clip(file, 200)}` } : stageNewFile(repoDir, file, content, policies);
    if (created.error) return created;
    writes.push({ file, abs: created.abs, text: content });
  }
  for (const { abs, text } of writes) {
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, text);
  }
  return { files: writes.map((w) => w.file) };
}

/** Reads wanted files into `known`, skipping ones already sent. Returns the requested new files it could not provide. */
function readFiles(repoDir, wanted, known) {
  const refused = [];
  for (const file of wanted) {
    if (known.has(file)) continue;
    const abs = known.size < MAX_FILES ? resolveRepoFile(repoDir, file) : null;
    if (abs) known.set(file, clip(readFileSync(abs, "utf8"), MAX_FILE_CHARS));
    else refused.push(file);
  }
  return refused;
}

async function askBuilder({ issue, repoDir, tree, basePhi, allowance, env, fetchImpl, baseDir }) {
  const contents = new Map();
  readFiles(repoDir, tree.filter((f) => `${issue.title}\n${issue.body}`.includes(f)), contents);
  for (let call = 0; call < MAX_MODEL_CALLS; call += 1) {
    const user = fenceData({ issue: { number: issue.number, title: issue.title, body: issue.body }, phi_budget: { base_phi: basePhi, phi_allowance: allowance }, tracked_files: tree.join("\n"), file_contents: Object.fromEntries(contents) });
    const res = await callCourtModel({ role: "builder", system: loadRolePrompt(baseDir, "builder"), user, env, fetchImpl });
    if (!res.ok) return res;
    const reply = validateBuilder(res.data);
    if (!reply) return { ok: false, reason: "LLM_INVALID_REPLY" };
    if (reply.verdict !== "NEED_FILES") return { ok: true, ...reply };
    // A no-op request is fatal only when it asked about a file that could not be sent;
    // asking again about files it already has just spends another bounded model call.
    const before = contents.size;
    const refused = readFiles(repoDir, reply.files, contents);
    if (refused.length > 0 && contents.size === before) return { ok: false, reason: "NEED_FILES_UNREADABLE" };
  }
  return { ok: false, reason: "TOO_MANY_FILE_REQUESTS" };
}

async function runIssueBuilder({ env = process.env, io = defaultIo(env), fetchImpl = globalThis.fetch, baseDir = resolve(dirname(fileURLToPath(import.meta.url)), "..") } = {}) {
  const { REPO: repo, ISSUE_NUMBER: number, WORK_DIR: repoDir } = env;
  if (env.MIRQL_BUILDER_DISABLED === "1") return 0;
  const issue = io.api(`repos/${repo}/issues/${number}`);
  if (issue.pull_request || issue.state !== "open") { log("skip: NOT_AN_OPEN_ISSUE"); return 0; }
  if (!TRUSTED_AUTHORS.includes(issue.author_association)) { log("skip: UNTRUSTED_AUTHOR"); return 0; }
  const branch = `mirql/issue-${number}`;
  if (io.api(`repos/${repo}/git/matching-refs/heads/${branch}`).some((r) => r.ref === `refs/heads/${branch}`)) { log("skip: BRANCH_EXISTS"); return 0; }
  const tell = (text, code = 0) => { io.post(repo, number, `**Issue Builder:** ${sanitizeCourtText(text)}\n`); return code; };
  const token = env.MIRQL_COURT_TOKEN;
  if (!token) return tell("stopped with `NO_PUSH_TOKEN`. `MIRQL_COURT_TOKEN` is not set, so no PR was opened.", 1);
  const hazards = scanDiffHazards(`${issue.title}\n${issue.body ?? ""}`.split(/\r?\n/).map((l) => `+${l}`).join("\n"));
  if (!hazards.ok) return tell(`won't build this automatically: \`${hazards.reasons.join(", ")}\`. A person needs to take it.`);
  try {
    return await buildIssue({ issue, branch, repo, number, repoDir, token, tell, env, io, fetchImpl, baseDir });
  } catch (err) {
    console.log(`::error::issue-builder: build failed: ${err?.name}`);
    return tell(`stopped with \`BUILD_FAILED\` (${err?.name}). See the workflow run. If \`${branch}\` was pushed, delete it before retrying.`, 1);
  }
}

async function buildIssue({ issue, branch, repo, number, repoDir, token, tell, env, io, fetchImpl, baseDir }) {
  const git = (...args) => io.run("git", ["-C", repoDir, ...args]);
  const tree = git("ls-files").split("\n").filter(Boolean);
  const measured = measurePhiWarrant({ rootDir: baseDir, repoDir, tipSha: git("rev-parse", "HEAD").trim(), document: env.MIRQL_PHI_WARRANT });
  const allowance = allowanceOf(measured.ok ? measured.phi_remaining : 0);
  const basePhi = computePhi(repoDir).total;
  const res = await askBuilder({ issue: { ...issue, body: issue.body ?? "" }, repoDir, tree, basePhi, allowance, env, fetchImpl, baseDir });
  if (!res.ok) return tell(`stopped with \`${res.reason}\`. No PR was opened. To retry: \`gh workflow run "Mergeproof Issue Builder" -f issue_number=${number}\``, 1);
  if (res.verdict === "DECLINE") return tell(`no PR for this one. ${res.reason}`);
  const applied = applyBuild(repoDir, res.patches, loadPathPolicies(baseDir));
  if (applied.error) return tell(`stopped with \`${applied.error}\`. No PR was opened. A person needs to take it.`);
  const phi = computePhi(repoDir).total;
  if (phi > basePhi + allowance) return tell(`stopped with \`PHI_OVER_WARRANT\`: this change grows Phi by ${phi - basePhi}, and ${allowance} is left. No PR was opened.`);
  pushCommit(io, repoDir, applied.files, branch, token, `Build issue ${number}: ${issue.title}`, env);
  const asOwner = { env: { ...env, GH_TOKEN: token } };
  try {
    // Opened with the owner's token: a PR from GITHUB_TOKEN starts no workflows, and the Court would not trust its author.
    io.run("gh", ["pr", "create", "--repo", repo, "--base", BASE_BRANCH, "--head", branch, "--title", issue.title, "--body", `Closes #${number}\n\n${sanitizeCourtText(res.summary)}\n`], asOwner);
  } catch (err) {
    console.log(`::error::issue-builder: PR not opened: ${err?.name}`);
    io.run("gh", ["api", "--method", "DELETE", `repos/${repo}/git/refs/heads/${branch}`], asOwner);
    return tell("stopped with `PR_NOT_OPENED`. The patch was pushed but the PR failed, so the branch was deleted. Check that `MIRQL_COURT_TOKEN` has `pull-requests: write`.", 1);
  }
  return 0;
}

if (isEntrypoint(import.meta.url)) {
  const missing = ["REPO", "ISSUE_NUMBER", "WORK_DIR"].find((name) => !process.env[name]);
  if (missing || !/^\d+$/.test(process.env.ISSUE_NUMBER ?? "")) {
    console.error(`issue-builder: ${missing ?? "ISSUE_NUMBER"} is required`);
    process.exit(1);
  }
  runIssueBuilder().then((code) => process.exit(code), (err) => {
    console.error(`::error::issue-builder: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

export { runIssueBuilder, stageNewFile, validateBuilder };
