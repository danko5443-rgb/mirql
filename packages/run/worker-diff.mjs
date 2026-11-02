import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function git(args, { cwd, env = process.env } = {}) {
  const result = spawnSync("git", ["--no-pager", "-c", "core.fsmonitor=false", "-c", "core.sparseCheckout=false", ...args], {
    cwd, env, encoding: "utf8", timeout: 10000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.signal || result.status !== 0) {
    throw new Error(result.error?.message || result.stderr?.trim() || "Git change measurement failed");
  }
  return result.stdout;
}

function fileFingerprint(root, path) {
  try {
    const stat = lstatSync(join(root, path));
    if (stat.isSymbolicLink()) return "link:" + readlinkSync(join(root, path));
    if (!stat.isFile()) return "type:" + stat.mode;
    return "file:" + (stat.mode & 0o777) + ":" + createHash("sha256").update(readFileSync(join(root, path))).digest("hex");
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return "missing";
    throw error;
  }
}

export function captureWorkerBase(cwd) {
  const repoDir = git(["rev-parse", "--show-toplevel"], { cwd }).trim();
  const gitDir = git(["rev-parse", "--absolute-git-dir"], { cwd }).trim();
  const baseSha = git(["rev-parse", "--verify", "HEAD^{commit}"], { cwd }).trim();
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(baseSha)) throw new Error("Invalid worker base commit");
  const paths = git(["ls-tree", "-rz", "--name-only", "--full-tree", baseSha], { cwd: repoDir }).split("\0").filter(Boolean);
  const fingerprints = new Map(paths.map(path => [path, fileFingerprint(repoDir, path)]));
  const initialPaths = git(["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", baseSha, "--"], { cwd: repoDir }).split("\0").filter(Boolean);
  return Object.freeze({ repoDir, gitDir, baseSha, fingerprints, initialPaths });
}

/** Measure trees, staged content and raw file changes without trusting worker filters or index flags. */
export function measureWorkerChanges(base) {
  const prefix = ["--git-dir", base.gitDir, "--work-tree", base.repoDir];
  const options = { cwd: base.repoDir };
  const diff = ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z"];
  const paths = new Set(base.initialPaths);
  for (const [path, fingerprint] of base.fingerprints) {
    if (fileFingerprint(base.repoDir, path) !== fingerprint) paths.add(path);
  }
  const add = output => { for (const path of output.split("\0")) if (path) paths.add(path); };
  // Tree changes include worker commits. Staged content may differ from final files.
  add(git([...prefix, ...diff, base.baseSha, "HEAD", "--"], options));
  add(git([...prefix, ...diff, "--cached", base.baseSha, "--"], options));
  const scratch = mkdtempSync(join(tmpdir(), "mirql-worker-index-"));
  try {
    const env = { ...process.env, GIT_INDEX_FILE: join(scratch, "index"), GIT_OPTIONAL_LOCKS: "0" };
    const isolated = { ...options, env };
    git([...prefix, "read-tree", base.baseSha], isolated);
    // No exclude patterns: ignored files can still match a protected path.
    add(git([...prefix, "ls-files", "--others", "-z"], isolated));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  return [...paths].sort();
}
