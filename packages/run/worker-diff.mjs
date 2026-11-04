import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join, resolve } from "node:path";

/** The supervisor's environment without anything that would redirect Git. */
export function hostEnv(extra = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !/^GIT_/i.test(key)) env[key] = value;
  }
  return { ...env, ...extra };
}

/** No global or system configuration: nothing defined there applies to these steps. */
export function configFreeEnv(extra = {}) {
  // Git for Windows cannot read os.devNull (\\.\nul) as a configuration file.
  const none = process.platform === "win32" ? "NUL" : devNull;
  return hostEnv({ GIT_CONFIG_GLOBAL: none, GIT_CONFIG_NOSYSTEM: "1", ...extra });
}

function git(args, { cwd, env = process.env } = {}) {
  const result = spawnSync("git", ["--no-replace-objects", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.sparseCheckout=false", ...args], {
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
  const commonDir = resolve(cwd, git(["rev-parse", "--git-common-dir"], { cwd }).trim());
  const objectFormat = git(["rev-parse", "--show-object-format"], { cwd }).trim();
  const baseSha = git(["rev-parse", "--verify", "HEAD^{commit}"], { cwd }).trim();
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(baseSha)) throw new Error("Invalid worker base commit");
  const paths = git(["ls-tree", "-rz", "--name-only", "--full-tree", baseSha], { cwd: repoDir }).split("\0").filter(Boolean);
  const fingerprints = new Map(paths.map(path => [path, fileFingerprint(repoDir, path)]));
  const initialPaths = git(["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", baseSha, "--"], { cwd: repoDir }).split("\0").filter(Boolean);
  return Object.freeze({ repoDir, gitDir, commonDir, objectFormat, baseSha, fingerprints, initialPaths });
}

/**
 * A store created after the worker exits, holding copies of its refs and index
 * over its objects. Git always reads the configuration and hooks of the store
 * it is pointed at, and the worker wrote those in its own, so they stay behind.
 * Refs in the reftable format are not copied, so such a repository fails closed.
 */
function sealWorkerStore(base, scratch) {
  const store = join(scratch, "store");
  git(["init", "--quiet", "--bare", "--template=", `--object-format=${base.objectFormat}`, store], { cwd: scratch, env: configFreeEnv() });
  copyFileSync(join(base.gitDir, "HEAD"), join(store, "HEAD"));
  cpSync(join(base.commonDir, "refs"), join(store, "refs"), { recursive: true });
  const packedRefs = join(base.commonDir, "packed-refs");
  if (existsSync(packedRefs)) copyFileSync(packedRefs, join(store, "packed-refs"));
  const workerIndex = join(base.gitDir, "index");
  if (existsSync(workerIndex)) copyFileSync(workerIndex, join(scratch, "worker-index"));
  for (const name of readdirSync(base.gitDir)) {
    if (name.startsWith("sharedindex.")) copyFileSync(join(base.gitDir, name), join(store, name));
  }
  return store;
}

/** Measure trees, staged content and raw file changes without trusting the worker's Git store. */
export function measureWorkerChanges(base) {
  const paths = new Set(base.initialPaths);
  for (const [path, fingerprint] of base.fingerprints) {
    if (fileFingerprint(base.repoDir, path) !== fingerprint) paths.add(path);
  }
  const add = output => { for (const path of output.split("\0")) if (path) paths.add(path); };
  const scratch = mkdtempSync(join(tmpdir(), "mirql-worker-index-"));
  try {
    const prefix = ["--git-dir", sealWorkerStore(base, scratch), "--work-tree", base.repoDir];
    const options = index => ({
      cwd: base.repoDir,
      env: configFreeEnv({ GIT_INDEX_FILE: join(scratch, index), GIT_OBJECT_DIRECTORY: join(base.commonDir, "objects"), GIT_OPTIONAL_LOCKS: "0" }),
    });
    const diff = ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z"];
    // Tree changes include worker commits. Staged content may differ from final files.
    add(git([...prefix, ...diff, base.baseSha, "HEAD", "--"], options("worker-index")));
    add(git([...prefix, ...diff, "--cached", base.baseSha, "--"], options("worker-index")));
    git([...prefix, "read-tree", base.baseSha], options("index"));
    // No exclude patterns: ignored files can still match a protected path.
    add(git([...prefix, "ls-files", "--others", "-z"], options("index")));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  return [...paths].sort();
}
