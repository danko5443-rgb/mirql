#!/usr/bin/env node
// PR Court engine (docs/pr-court.md). Runs from the base checkout only: candidate
// files and diffs are text data, never imported or executed (Law 7). LLM roles
// propose JSON; this tool validates, applies, commits, posts and merges (Law 3).
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { signoffLabel } from "./ci-owner-signoff.mjs";
import { checkSwallowedExceptions, checkTestWeakenings, isHumanOnlyPath, loadPathPolicies } from "../packages/core/anti-cheat.mjs";
import { isReviewerConfigPath } from "../packages/mergeproof/evaluator.mjs";
import { computeGitTreePhi, computePhi } from "../packages/run/phi.mjs";
import { callCourtModel, COURT_ACTOR, COURT_MODEL_TIMEOUT_MS, collectExternalFindings, findAiApproval, hasApproveCommand, hasLateChanges, inspectReviewStatus, isEntrypoint, parseCourtState, parseReviews, scanDiffHazards } from "./ci-review-gate.mjs";

const MAX_ROUNDS = 3;
const MAX_TICK_STEPS = 6;
// The workflow kills the job at 45 minutes, and a killed job leaves no trace on the PR.
const TICK_BUDGET_MS = 40 * 60000;
const MODEL_STEPS = new Set(["critic", "advocate", "judge"]);
const MAX_DIFF_CHARS = 500000;
const MAX_FILE_CHARS = 20000;
const MAX_BODY_CHARS = 60000;
const MAX_NOTARY_ATTEMPTS = 5;
const TRUSTED_AUTHORS = ["OWNER", "MEMBER", "COLLABORATOR"];
const NOTARY_JOBS = { head: "Candidate Tests (advisory)", base: "Base Suite (evidence)", gate: "Mergeproof Conscience Gate" };
const clip = (value, max) => String(value ?? "").slice(0, max);
const log = (message) => console.log(`pr-court: ${message}`);

function refusalReason(diffText, authorAssociation) {
  if (!TRUSTED_AUTHORS.includes(String(authorAssociation).toUpperCase())) return "UNTRUSTED_AUTHOR";
  const hazards = scanDiffHazards(diffText);
  if (!hazards.ok) return `DIFF_HAZARD: ${hazards.reasons.join(", ")}`;
  return diffText.length > MAX_DIFF_CHARS ? "DIFF_HAZARD: DIFF_TOO_LARGE" : null;
}

const refusalVerdict = (reason) => (String(reason).startsWith("DIFF_HAZARD") ? "ESCALATE" : "RECUSE");

function fenceData(sections) {
  const tag = `DATA_${randomBytes(8).toString("hex")}`;
  return Object.entries(sections)
    .map(([name, value]) => `<${tag} name="${name}">\n${typeof value === "string" ? value : JSON.stringify(value)}\n</${tag}>`)
    .join("\n\n");
}

function loadRolePrompt(baseDir, role) {
  const prompt = readFileSync(join(baseDir, "roles", `${role}.md`), "utf8").split("<!-- court-prompt -->")[1];
  if (!prompt?.trim()) throw new Error(`roles/${role}.md has no court prompt`);
  return prompt.trim();
}

/** LLM text is posted under the receipt identity, so it must not be able to forge a marker or command a bot. */
function sanitizeCourtText(text) {
  return String(text ?? "").replace(/<!--/g, "&lt;!--").replace(/mirql-court-state/gi, "mirql_court_state").replace(/@/g, "@\u200B");
}

function formatCourtReceipt({ round, headSha, role, verdict, count = 0, payload = {}, text = "" }) {
  const state = JSON.stringify({ round, head_sha: headSha, role, verdict, findings_count: count });
  const body = `<!-- mirql-court-state:v1 ${state} -->\n\`\`\`json court-findings\n${sanitizeCourtText(JSON.stringify(payload))}\n\`\`\`\n\n${sanitizeCourtText(clip(text, 4000))}\n`;
  if (body.length > MAX_BODY_CHARS) throw new Error("court receipt too large");
  return body;
}

const sameIdSet = (ids, seen) => seen.length === ids.length && new Set(seen).size === ids.length && ids.every((id) => seen.includes(id));

function validateCritic(data) {
  if (!["APPROVE", "COMMENT"].includes(data?.verdict) || !Array.isArray(data.findings)) return null;
  if ((data.verdict === "APPROVE") !== (data.findings.length === 0)) return null;
  const findings = data.findings.slice(0, 20).map((f) => ({ id: f?.id, severity: f?.severity, file: clip(f?.file, 300), line: Number.isSafeInteger(f?.line) ? f.line : 0, title: clip(f?.title, 200), detail: clip(f?.detail, 2000) }));
  const valid = findings.every((f) => /^[\w.-]{1,64}$/.test(f.id ?? "") && ["P1", "P2"].includes(f.severity));
  if (!valid || new Set(findings.map((f) => f.id)).size !== findings.length) return null;
  return { verdict: data.verdict, summary: clip(data.summary, 2000), findings };
}

function validateAdvocate(data, findings) {
  if (!Array.isArray(data?.responses)) return null;
  if (!sameIdSet(findings.map((f) => f.id), data.responses.map((r) => r?.finding_id))) return null;
  const responses = data.responses.map((r) => ({ finding_id: r.finding_id, action: r.action, reply: clip(r.reply, 1500), patches: Array.isArray(r.patches) ? r.patches : [] }));
  const valid = responses.every((r) => (r.action === "REBUT" && r.patches.length === 0) || (r.action === "AGREE_AND_FIX" && r.patches.length > 0 && r.patches.every((p) => ["file", "search", "replace"].every((k) => typeof p?.[k] === "string"))));
  return valid ? { summary: clip(data.summary, 2000), responses } : null;
}

function validateJudge(data, findings) {
  if (!["MERGE", "REMAND", "ESCALATE"].includes(data?.verdict) || !Array.isArray(data.rulings)) return null;
  if (!sameIdSet(findings.map((f) => f.id), data.rulings.map((r) => r?.finding_id))) return null;
  if (!data.rulings.every((r) => ["FIXED", "OVERRULED_FALSE_POSITIVE", "UNRESOLVED"].includes(r.status))) return null;
  const unresolved = data.rulings.filter((r) => r.status === "UNRESOLVED").map((r) => r.finding_id);
  if ((data.verdict === "MERGE" && unresolved.length > 0) || (data.verdict === "REMAND" && unresolved.length === 0)) return null;
  const rulings = data.rulings.map((r) => ({ finding_id: r.finding_id, status: r.status, reason: clip(r.reason, 500) }));
  return { verdict: data.verdict, rationale: clip(data.rationale, 2000), rulings, unresolved: findings.filter((f) => unresolved.includes(f.id)) };
}

/** Resolves a path to a regular file inside the repo. Refuses traversal, symlinks at any depth and anything under .git*. */
function resolveRepoFile(repoDir, file) {
  const raw = String(file ?? "");
  const segments = raw.split("/");
  if (!raw || /[\0\\]/.test(raw) || isAbsolute(raw) || /^[a-zA-Z]:/.test(raw)) return null;
  if (segments.some((s) => s === "" || s === "." || s === ".." || /^\.git/i.test(s))) return null;
  let current = resolve(repoDir);
  for (const segment of segments) {
    current = join(current, segment);
    const stat = lstatSync(current, { throwIfNoEntry: false });
    if (!stat || stat.isSymbolicLink()) return null;
  }
  return lstatSync(current).isFile() ? current : null;
}

const isLockedPatchPath = (rel, policies) => isHumanOnlyPath(rel, policies.humanOnly) || isReviewerConfigPath(rel) || ["package.json", ".npmrc"].includes(rel.split("/").at(-1));

/** Computes every patch in memory first, so a refused round has touched nothing. */
function stagePatches(repoDir, patches, policies) {
  const files = new Map();
  for (const { file, search, replace } of patches) {
    const abs = resolveRepoFile(repoDir, file);
    if (!abs || isLockedPatchPath(file, policies)) return { error: `PATCH_PATH_REFUSED: ${clip(file, 200)}` };
    const original = files.get(file)?.original ?? readFileSync(abs, "utf8");
    const current = files.get(file)?.next ?? original;
    if (!search || current.split(search).length !== 2) return { error: `PATCH_SEARCH_NOT_UNIQUE: ${clip(file, 200)}` };
    files.set(file, { abs, original, next: current.replace(search, () => replace) });
  }
  for (const [rel, { original, next }] of files) {
    if (checkSwallowedExceptions(next, rel).violations.length > checkSwallowedExceptions(original, rel).violations.length) return { error: `PATCH_SWALLOWS_EXCEPTION: ${rel}` };
    if (checkTestWeakenings(next, rel).count > checkTestWeakenings(original, rel).count) return { error: `PATCH_WEAKENS_TESTS: ${rel}` };
  }
  return { files };
}

const lockedFiles = (files, policies) => files.filter((f) => isHumanOnlyPath(f, policies.humanOnly) || isReviewerConfigPath(f));

async function runCriticRound({ diffText = "", headSha, round = 1, authorAssociation, env, fetchImpl, rolePrompt = "" }) {
  const refused = refusalReason(diffText, authorAssociation);
  if (refused) return { ok: false, refused: true, reason: refused };
  const res = await callCourtModel({ role: "critic", system: rolePrompt, user: fenceData({ head_sha: headSha, round, diff: diffText }), env, fetchImpl });
  if (!res.ok) return res;
  const reply = validateCritic(res.data);
  return reply ? { ok: true, ...reply } : { ok: false, reason: "LLM_INVALID_REPLY" };
}

async function runAdvocateRound({ repoDir, diffText = "", authorAssociation, findings = [], basePhi, round = 1, policies, env, fetchImpl, rolePrompt = "", commit = null }) {
  const escalate = (reason, extra = {}) => ({ ok: true, verdict: "ESCALATE", reason, ...extra });
  if (round > MAX_ROUNDS) return escalate("MAX_ROUNDS");
  const refused = refusalReason(diffText, authorAssociation);
  if (refused) return { ok: true, verdict: refusalVerdict(refused), reason: refused };
  const contents = {};
  for (const file of new Set(findings.map((f) => f.file))) {
    const abs = resolveRepoFile(repoDir, file);
    if (abs) contents[file] = clip(readFileSync(abs, "utf8"), MAX_FILE_CHARS);
  }
  const headPhi = computePhi(repoDir).total;
  const user = fenceData({ round, phi_budget: { base_phi: basePhi, head_phi: headPhi, delta_phi: headPhi - basePhi }, findings, diff: diffText, file_contents: contents });
  const res = await callCourtModel({ role: "advocate", system: rolePrompt, user, env, fetchImpl });
  if (!res.ok) return res;
  const reply = validateAdvocate(res.data, findings);
  if (!reply) return { ok: false, reason: "LLM_INVALID_REPLY" };
  const patches = reply.responses.flatMap((r) => r.patches);
  if (patches.length === 0) return { ok: true, verdict: "REBUT", ...reply };
  const staged = stagePatches(repoDir, patches, policies);
  if (staged.error) return escalate(staged.error, reply);
  const restore = () => { for (const { abs, original } of staged.files.values()) writeFileSync(abs, original); };
  try {
    for (const { abs, next } of staged.files.values()) writeFileSync(abs, next);
    const phi = computePhi(repoDir).total;
    if (!Number.isSafeInteger(basePhi) || phi > basePhi) { restore(); return escalate("PHI_INCREASE", reply); }
    if (!commit) { restore(); return escalate("NO_PUSH_TOKEN", reply); }
    return { ok: true, verdict: "FIXED", headSha: commit([...staged.files.keys()]), ...reply };
  } catch (err) {
    restore();
    return escalate(`PATCH_FAILED: ${err instanceof Error ? err.message : String(err)}`, reply);
  }
}

async function runJudgeArbitration({ diffText = "", files = [], headSha, authorAssociation, evidence = {}, findings = [], transcript = [], round = 1, policies, env, fetchImpl, rolePrompt = "" }) {
  const refuse = (reason, verdict = "RECUSE") => ({ ok: true, refused: true, verdict, reason, rationale: reason, rulings: [], unresolved: [] });
  const refused = refusalReason(diffText, authorAssociation);
  if (refused) return refuse(refused, refusalVerdict(refused));
  const locked = lockedFiles(files, policies);
  if (locked.length > 0) return refuse(`COURTHOUSE_LOCK: ${locked.slice(0, 10).join(", ")}`);
  if (evidence.suitePassBase !== true || evidence.suitePassHead !== true) return refuse("SUITE_NOT_GREEN", "WAIT");
  if (!Number.isSafeInteger(evidence.deltaPhi) || evidence.deltaPhi > 0) return refuse(`DELTA_PHI: ${evidence.deltaPhi}`);
  const res = await callCourtModel({ role: "judge", system: rolePrompt, user: fenceData({ head_sha: headSha, round, evidence, findings, transcript, diff: diffText }), env, fetchImpl });
  if (!res.ok) return res;
  const ruling = validateJudge(res.data, findings);
  if (!ruling) return { ok: false, reason: "LLM_INVALID_REPLY" };
  return { ok: true, ...ruling, verdict: ruling.verdict === "REMAND" && round >= MAX_ROUNDS ? "ESCALATE" : ruling.verdict };
}

function decideCourtStep(state, { externalFindings = [], externalReviewed = false, codexPending = false, locked = false, lateChanges = false } = {}) {
  if (state.judgeVerdict === "ESCALATE" || state.judgeVerdict === "RECUSE") return "stop";
  // A late finding reopens a MERGE, and a bare late CHANGES_REQUESTED holds it.
  if (state.judgeVerdict === "MERGE" && externalFindings.every((f) => state.ruled.includes(f.id))) return lateChanges ? "stop" : "merge";
  if (codexPending) return "wait";
  if (!state.last && !externalReviewed && externalFindings.length === 0) return "critic";
  if (locked) return "recuse";
  const unanswered = externalFindings.filter((f) => !state.answered.includes(f.id));
  if (state.openFindings.length + unanswered.length > 0) return state.advocateRounds >= MAX_ROUNDS ? "escalate" : "advocate";
  return "judge";
}

function notaryRun(io, repo, headSha) {
  const run = io.api(`repos/${repo}/actions/workflows/mergeproof.yml/runs?head_sha=${headSha}&event=pull_request_target&per_page=10`).workflow_runs?.[0];
  if (!run) return null;
  const jobs = io.api(`repos/${repo}/actions/runs/${run.id}/jobs?filter=latest&per_page=100`).jobs ?? [];
  const conclusion = (name) => jobs.find((j) => j.name === name)?.conclusion ?? null;
  return { run, head: conclusion(NOTARY_JOBS.head), base: conclusion(NOTARY_JOBS.base), gate: conclusion(NOTARY_JOBS.gate) };
}

function rerunFailedNotary(io, repo, run) {
  if (run?.status !== "completed" || run.conclusion !== "failure" || (run.run_attempt ?? 1) >= MAX_NOTARY_ATTEMPTS) return false;
  io.run("gh", ["run", "rerun", String(run.id), "--repo", repo, "--failed"]);
  return true;
}

async function awaitRerun(io, repo, headSha, attempt, { polls = 80, delayMs = 15000 } = {}) {
  for (let i = 0; i < polls; i += 1) {
    await new Promise((done) => { setTimeout(done, delayMs); });
    const current = notaryRun(io, repo, headSha);
    if (current?.run.status === "completed" && current.run.run_attempt > attempt) return current;
  }
  return null;
}

/** GitHub enforces nothing on this plan, so the court itself proves a green, current notary before it merges. */
async function landCourtMerge({ repo, prNumber, headSha, mergedAt, env, io, wait = {} }) {
  let notary = notaryRun(io, repo, headSha);
  if (notary?.gate !== "success") {
    // A run that started after the MERGE already saw it, so running it again cannot change the answer.
    if (notary?.run.run_started_at >= mergedAt) return "NOTARY_NOT_GREEN";
    if (!rerunFailedNotary(io, repo, notary?.run)) return "NOTARY_NOT_RERUNNABLE";
    notary = await awaitRerun(io, repo, headSha, notary.run.run_attempt ?? 1, wait);
  }
  if (notary?.gate !== "success" || notary.run.head_sha !== headSha) return "NOTARY_NOT_GREEN";
  if (env.AUTO_MERGE !== "1" || env.MIRQL_COURT_DISABLED === "1") return "AUTO_MERGE_OFF";
  const pr = io.api(`repos/${repo}/pulls/${prNumber}`);
  if (pr.state !== "open" || pr.head.sha !== headSha) return "HEAD_MOVED";
  const tip = io.api(`repos/${repo}/commits/${pr.base.ref}`).sha;
  if (notary.run.pull_requests?.[0]?.base?.sha !== tip) return "NOTARY_BASE_STALE";
  io.run("gh", ["pr", "merge", String(prNumber), "--repo", repo, "--merge", "--delete-branch", "--match-head-commit", headSha]);
  return "MERGED";
}

function pushFix(io, repoDir, files, ref, token, round, env) {
  const git = (args, options) => io.run("git", ["-C", repoDir, "-c", "core.hooksPath=/dev/null", ...args], options);
  git(["add", "--", ...files]);
  git(["-c", "user.name=mirql-court[bot]", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com", "commit", "-m", `fix: PR Court advocate round ${round}`]);
  const auth = Buffer.from(`x-access-token:${token}`).toString("base64");
  console.log(`::add-mask::${auth}`);
  git(["push", "origin", `HEAD:refs/heads/${ref}`], { env: { ...env, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader", GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${auth}` } });
  return git(["rev-parse", "HEAD"]).trim();
}

function courtSkipReason(pr, repo) {
  if (pr.state !== "open" || pr.draft) return "PR_NOT_READY";
  if (pr.head?.repo?.full_name !== repo) return "FORK_PR";
  return TRUSTED_AUTHORS.includes(pr.author_association) ? null : "UNTRUSTED_AUTHOR";
}

function defaultIo(env) {
  const run = (cmd, args, options = {}) => execFileSync(cmd, args, { encoding: "utf8", env, maxBuffer: 1 << 28, ...options });
  return {
    run,
    api: (path) => JSON.parse(run("gh", ["api", path])),
    list: (path) => parseReviews(run("gh", ["api", "--paginate", path, "--jq", ".[]"])),
    post: (repo, prNumber, body) => run("gh", ["api", `repos/${repo}/issues/${prNumber}/comments`, "--method", "POST", "--input", "-"], { input: JSON.stringify({ body }) }),
  };
}

function diffSnapshot(io, repoDir, base, head) {
  const git = (...args) => io.run("git", ["-C", repoDir, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", ...args, `${base}...${head}`]);
  return { diffText: git(), files: git("--name-only", "-z").split("\0").filter(Boolean) };
}

const advocateText = (res) => [res.summary, res.reason, ...(res.responses ?? []).map((r) => `- **${r.finding_id}** ${r.action}: ${r.reply}`)].filter(Boolean).join("\n");

/** Has no receipt marker and no mention, so it can never read as a verdict. The reason is one of the court's own codes, never model text. */
const formatCourtFailure = ({ mark, role, headSha, reason, prNumber }) => [
  `<!-- ${mark} -->`,
  `**PR Court stopped without a verdict.** The ${role} step failed at \`${headSha}\` with \`${reason}\`. This is neither an approval nor a rejection, and the gate is unchanged.`,
  "",
  `The Court tries again on its next wake-up. To retry now: \`gh workflow run "Mergeproof Court" -f pr_number=${prNumber}\``,
  "",
].join("\n");

/** Each step returns an exit code to end the tick, or null to read fresh state and continue. */
const COURT_STEPS = {
  wait: () => 0,
  stop: () => 0,
  recuse({ post, judgeRound, snapshot, ctx, prNumber }) {
    const { diffText, files } = snapshot();
    const locked = lockedFiles(files, ctx.policies);
    const refused = refusalReason(diffText, ctx.authorAssociation);
    post({ round: judgeRound, role: "judge", verdict: refusalVerdict(refused), text: refused ?? `COURTHOUSE_LOCK: ${locked.slice(0, 10).join(", ")} - ${locked.some(isReviewerConfigPath) ? "reviewer config: no sign-off clears the gate, so the owner merges by hand." : `run node scripts/owner-signoff.mjs ${prNumber}`}` }); return 0;
  },
  escalate: ({ post, judgeRound }) => { post({ round: judgeRound, role: "judge", verdict: "ESCALATE", text: "MAX_ROUNDS: findings remain open after the last Advocate round." }); return 0; },
  async critic({ ctx, snapshot, post, fail, state, prompt }) {
    const res = await runCriticRound({ ...ctx, diffText: snapshot().diffText, round: state.advocateRounds + 1, rolePrompt: prompt("critic") });
    if (res.refused) { post({ round: state.advocateRounds + 1, role: "judge", verdict: refusalVerdict(res.reason), text: res.reason }); return 0; }
    if (!res.ok) return fail(res);
    const list = res.findings.map((f) => `- **${f.severity} ${f.id}** \`${f.file}:${f.line}\` ${f.title}`);
    post({ round: state.advocateRounds + 1, role: "critic", verdict: res.verdict, count: res.findings.length, payload: { findings: res.findings }, text: [res.summary, ...list].join("\n") });
    return null;
  },
  async advocate({ ctx, snapshot, post, fail, state, prompt, findings, basePhi, env, io, pr }) {
    const round = state.advocateRounds + 1;
    const token = env.MIRQL_COURT_TOKEN;
    const commit = token ? (files) => pushFix(io, ctx.repoDir, files, pr.head.ref, token, round, env) : null;
    const res = await runAdvocateRound({ ...ctx, diffText: snapshot().diffText, findings, basePhi: basePhi(), round, rolePrompt: prompt("advocate"), commit });
    if (!res.ok) return fail(res);
    if (res.verdict === "ESCALATE" || res.verdict === "RECUSE") { post({ round, role: "judge", verdict: res.verdict, text: advocateText(res) }); return 0; }
    const titled = (id) => { const f = findings.find((x) => x.id === id); return `${f.file}:${f.line} ${f.title}`; };
    const responses = res.responses.map(({ finding_id, action, reply }) => ({ finding_id, finding: titled(finding_id), action, reply }));
    post({ round, headSha: res.headSha, role: "advocate", verdict: res.verdict, count: responses.length, payload: { responses }, text: advocateText(res) });
    return res.verdict === "FIXED" ? 0 : null;
  },
  async judge({ ctx, snapshot, post, fail, state, prompt, findings, basePhi, judgeRound, io, repo }) {
    const notary = notaryRun(io, repo, ctx.headSha);
    if (!["success", "failure"].includes(notary?.head) || !["success", "failure"].includes(notary?.base)) return 0;
    const { diffText, files } = snapshot();
    const evidence = { suitePassBase: notary.base === "success", suitePassHead: notary.head === "success", deltaPhi: computeGitTreePhi(ctx.repoDir, ctx.headSha).metrics.total - basePhi() };
    const res = await runJudgeArbitration({ ...ctx, diffText, files, evidence, findings, transcript: state.transcript, round: judgeRound, rolePrompt: prompt("judge") });
    if (!res.ok) return fail(res);
    if (res.verdict === "WAIT") return 0; // A red suite posts nothing, so a green re-run can come back.
    post({ round: judgeRound, role: "judge", verdict: res.verdict, count: res.unresolved.length, payload: { findings: res.unresolved, rulings: res.rulings }, text: res.rationale });
    return res.verdict === "MERGE" || res.verdict === "REMAND" ? null : 0;
  },
  async merge({ ctx, state, env, io, repo, prNumber }) {
    log(`landing: ${await landCourtMerge({ repo, prNumber, headSha: ctx.headSha, mergedAt: state.judgeAt, env, io })}`);
    return 0;
  },
};

async function runCourtTick({ env = process.env, io = defaultIo(env), fetchImpl = globalThis.fetch, baseDir = resolve(dirname(fileURLToPath(import.meta.url)), ".."), now = Date.now } = {}) {
  const started = now();
  const { REPO: repo, PR_NUMBER: prNumber, CANDIDATE_DIR: repoDir } = env;
  if (env.MIRQL_COURT_DISABLED === "1") return 0;
  const policies = loadPathPolicies(baseDir);
  const external = (policies.aiReviewers ?? []).filter((r) => !r.startsWith("mirql-"));
  for (let step = 0; step < MAX_TICK_STEPS; step += 1) {
    const pr = io.api(`repos/${repo}/pulls/${prNumber}`);
    const skip = courtSkipReason(pr, repo);
    if (skip) { log(`skip: ${skip}`); return 0; }
    const headSha = pr.head.sha;
    if (io.run("git", ["-C", repoDir, "rev-parse", "HEAD"]).trim() !== headSha) { log("skip: HEAD_MOVED"); return 0; }
    const comments = io.list(`repos/${repo}/issues/${prNumber}/comments`);
    const inline = io.list(`repos/${repo}/pulls/${prNumber}/comments`);
    const reviews = io.list(`repos/${repo}/pulls/${prNumber}/reviews`);
    const state = parseCourtState(comments, headSha);
    const externalFindings = collectExternalFindings(inline, headSha);
    const externalReviewed = Boolean(findAiApproval(reviews, { reviewers: external, headSha, author: pr.user?.login, comments, reviewComments: inline }));
    const baseSha = io.api(`repos/${repo}/commits/${pr.base.ref}`).sha;
    const snapshot = () => diffSnapshot(io, repoDir, baseSha, headSha);
    const name = decideCourtStep(state, { externalFindings, externalReviewed, codexPending: inspectReviewStatus(comments, headSha).codexPending, locked: lockedFiles(snapshot().files, policies).length > 0, lateChanges: hasLateChanges(reviews, state, headSha) });
    log(`step ${step}: ${name} at ${headSha}`);
    const fail = (res) => {
      console.log(`::error::pr-court: ${res.reason}`);
      if (res.reason === "NO_API_KEY") return 0;
      const mark = `mirql-court-failure:v1 ${name} ${headSha} ${res.reason}`;
      try {
        // One notice per head, role and reason, however many wake-ups fail the same way.
        const told = comments.some((c) => c.user?.login === COURT_ACTOR.login && String(c.body).includes(mark));
        if (!told) io.post(repo, prNumber, formatCourtFailure({ mark, role: name, headSha, reason: res.reason, prNumber }));
      } catch (err) { /* mp-003-allow: the failure is already logged, and the tick stays red */ console.log(`::warning::pr-court: failure notice not posted: ${err?.name}`); }
      return 1;
    };
    if (MODEL_STEPS.has(name) && now() - started > TICK_BUDGET_MS - COURT_MODEL_TIMEOUT_MS) return fail({ reason: "TICK_BUDGET" });
    const fresh = externalFindings.filter((f) => !state.findings.some((known) => known.id === f.id));
    const findings = name === "advocate" ? [...state.openFindings, ...fresh.filter((f) => !state.answered.includes(f.id))] : [...state.findings, ...fresh];
    let baseTotal = null;
    const post = (receipt) => {
      // Receipts bind to the head that was reviewed; a push during the LLM call voids this one.
      if (!receipt.headSha && io.api(`repos/${repo}/pulls/${prNumber}`).head.sha !== headSha) throw new Error("HEAD_MOVED during review");
      io.post(repo, prNumber, formatCourtReceipt({ ...receipt, headSha: receipt.headSha ?? headSha }));
    };
    const code = await COURT_STEPS[name]({
      ctx: { repoDir, headSha, authorAssociation: pr.author_association, policies, env, fetchImpl },
      state, env, io, pr, repo, prNumber, findings, post, fail,
      judgeRound: Math.max(state.advocateRounds, 1),
      prompt: (role) => loadRolePrompt(baseDir, role),
      snapshot,
      basePhi: () => { baseTotal ??= computeGitTreePhi(repoDir, baseSha).metrics.total; return baseTotal; },
    });
    if (code !== null) return code;
  }
  return 0;
}

function rerunOnApproval(io, repo, prNumber, reviewers = []) {
  const pr = io.api(`repos/${repo}/pulls/${prNumber}`);
  const [comments, reviewComments, reviews] = [`issues/${prNumber}/comments`, `pulls/${prNumber}/comments`, `pulls/${prNumber}/reviews`].map((path) => io.list(`repos/${repo}/${path}`));
  const signed = (pr.labels ?? []).some((l) => l.name === signoffLabel(pr.head.sha));
  const approved = !hasApproveCommand([...comments, ...reviewComments, ...reviews], reviewers) && findAiApproval(reviews, { reviewers, headSha: pr.head.sha, author: pr.user?.login, comments, reviewComments });
  if (pr.state === "open" && (signed || approved)) rerunFailedNotary(io, repo, notaryRun(io, repo, pr.head.sha)?.run);
}

async function main(env = process.env, io = defaultIo(env), baseDir = resolve(dirname(fileURLToPath(import.meta.url)), "..")) {
  const missing = ["REPO", "PR_NUMBER", "CANDIDATE_DIR"].find((name) => !env[name]);
  if (missing || !/^\d+$/.test(env.PR_NUMBER ?? "")) { console.error(`pr-court: ${missing ?? "PR_NUMBER"} is required`); return 1; }
  const code = await runCourtTick({ env, io, baseDir });
  // A comment alone cannot turn the gate green, so only an approval or the owner's label re-runs it, and a notary wake never does: that would loop.
  if (env.WAKE_FROM_NOTARY !== "1" && code === 0) rerunOnApproval(io, env.REPO, env.PR_NUMBER, loadPathPolicies(baseDir).aiReviewers);
  return code;
}

if (isEntrypoint(import.meta.url)) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`::error::pr-court: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

export { decideCourtStep, formatCourtReceipt, landCourtMerge, loadRolePrompt, main, MAX_ROUNDS, parseCourtState, resolveRepoFile, runAdvocateRound, runCourtTick, runCriticRound, runJudgeArbitration, sanitizeCourtText };
