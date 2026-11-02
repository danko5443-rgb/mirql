import { spawnSync } from "node:child_process";
import { jcs } from "./jcs.mjs";
import { validateMergeApprovalPayload } from "./schema.mjs";
import { readVerifiedLedger } from "./ledger-verify.mjs";
import { requireAuthorizedWarrant } from "./warrant.mjs";

function invalid(message) {
  const error = new Error(message);
  error.code = error.errorCode = "USAGE_ERROR";
  error.exitCode = 2;
  return error;
}

function git(repoDir, args) {
  const result = spawnSync("git", ["--no-pager", "-c", "core.fsmonitor=false", ...args], {
    cwd: repoDir, encoding: "utf8", timeout: 10000, windowsHide: true, maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.signal || result.status !== 0) throw invalid("Cannot measure approval binding: " + (result.error?.message ?? result.stderr?.trim() ?? "Unknown git failure"));
  return result.stdout;
}

/** Capture immutable commits, their candidate tree and every changed Git path. */
export function measureMergeBinding(options = {}) {
  const repoDir = options.workspaceDir ?? process.cwd();
  const resolve = ref => {
    if (typeof ref !== "string" || !ref.trim()) throw invalid("Explicit base and head references are required");
    const sha = git(repoDir, ["rev-parse", "--verify", "--end-of-options", ref + "^{commit}"]).trim();
    if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(sha)) throw invalid("Invalid Git commit identity");
    return sha;
  };
  const base = resolve(options.baseSha ?? options.base);
  const head = resolve(options.headSha ?? options.head);
  const tree = git(repoDir, ["rev-parse", "--verify", head + "^{tree}"]).trim();
  const paths = [...new Set(git(repoDir, ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", base, head, "--"]).split("\0").filter(Boolean))].sort();
  const binding = { warrant_id: options.warrantId, base_sha: base, head_sha: head, tree_sha: tree, paths };
  const check = validateMergeApprovalPayload(binding);
  if (!check.valid) throw invalid("Invalid merge approval binding: " + check.errors.join(", "));
  return binding;
}

/** No caller-supplied event, signature or approval flag participates in this lookup. */
export function findExactMergeApproval(mirqlDir, options = {}) {
  const binding = measureMergeBinding(options);
  requireAuthorizedWarrant(mirqlDir, { warrantId: binding.warrant_id, nowMs: options.nowMs });
  return readVerifiedLedger(mirqlDir).find(event => event.type === "merge.approved" &&
    event.writer.ns === "human:owner" && jcs(event.payload) === jcs(binding)) ?? null;
}
