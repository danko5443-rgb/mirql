// Staging and sync-back for sandboxed workers (Law 8). The container controls
// everything inside the staged copy, so sync-back treats that copy as hostile:
// it never follows a link, validates the whole tree before changing the real
// workspace, and only ever deletes paths that were staged.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  rmdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

/** The worker tried to reach outside its workspace; maps to MP-001 WORKSPACE_ESCAPE. */
export class WorkspaceEscapeError extends Error {
  constructor(message) {
    super(message);
    this.code = "WORKSPACE_ESCAPE";
  }
}

/** True for `.git`/`.mirql` in any spelling a case-insensitive or NTFS host resolves to the same directory. */
function isProtectedSegment(segment) {
  const name = segment.split(":")[0].replace(/[. ]+$/, "").toLowerCase();
  return /^(?:\.git|\.mirql|git~\d+|mirql~\d+)$/.test(name);
}

const isStagingSkipped = (segment) => isProtectedSegment(segment) || segment.toLowerCase() === "node_modules";

function lstatOrNull(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
    throw error;
  }
}

const digestOf = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const isExecutable = (stat) => (stat.mode & 0o111) !== 0;

/** Every proper prefix of a relative path, shallowest first, followed by the path itself. */
function prefixesOf(rel) {
  const segments = rel.split("/");
  return segments.map((_, index) => segments.slice(0, index + 1).join("/"));
}

/** The first symlink on `rel` under `root`, or null. */
function linkOnPath(root, rel) {
  return prefixesOf(rel).find((prefix) => lstatOrNull(join(root, prefix))?.isSymbolicLink()) ?? null;
}

function stageEntry(cwd, stagingDir, rel, snapshot) {
  const from = join(cwd, rel), to = join(stagingDir, rel);
  const stat = lstatOrNull(from);
  if (stat === null) return; // listed by the index but deleted from the working tree
  if (stat.isDirectory()) {
    for (const entry of readdirSync(from)) {
      if (!isStagingSkipped(entry)) stageEntry(cwd, stagingDir, `${rel}/${entry}`, snapshot);
    }
    return;
  }
  if (!stat.isSymbolicLink() && !stat.isFile()) return;
  for (const prefix of prefixesOf(rel).slice(0, -1)) snapshot.set(prefix, { type: "dir" });
  mkdirSync(dirname(to), { recursive: true });
  if (stat.isSymbolicLink()) {
    const target = readlinkSync(from);
    symlinkSync(target, to);
    snapshot.set(rel, { type: "link", target });
  } else {
    copyFileSync(from, to);
    snapshot.set(rel, { type: "file", digest: digestOf(from), exec: isExecutable(stat) });
  }
}

/** Open the staged tree to any UID: the container's UID 65534 owns none of it. Links are never followed. */
function openToContainer(dir) {
  chmodSync(dir, 0o777);
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) openToContainer(full);
    else if (entry.isFile()) chmodSync(full, lstatSync(full).mode & 0o777 | 0o666);
  }
}

/**
 * Stage tracked and unignored files of `cwd` into `stagingDir`, keeping links
 * verbatim and never staging `.git`, `.mirql` or `node_modules`. `stagingDir`
 * must sit inside a private (0700) parent, because it is opened to every UID:
 * the parent keeps other host users out, while the bind mount gives the
 * container direct access to the mount point without traversing that parent.
 *
 * @returns {Map<string, object>} what was staged; {@link syncBackWorkspace} diffs against it
 */
export function stageWorkspace(cwd, stagingDir) {
  const snapshot = new Map();
  const listed = spawnSync("git", ["--no-replace-objects", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd, encoding: "utf8", timeout: 10000, windowsHide: true });
  const paths = listed.error || listed.status !== 0
    ? readdirSync(cwd).filter((entry) => !isStagingSkipped(entry))
    : listed.stdout.split("\0").filter(Boolean).map((rel) => rel.replace(/\\/g, "/"));
  for (const rel of paths) {
    if (rel.split("/").some(isStagingSkipped)) continue;
    if (dirname(rel) !== "." && linkOnPath(cwd, dirname(rel)) !== null) continue; // stale index entry behind a link
    stageEntry(cwd, stagingDir, rel, snapshot);
  }
  openToContainer(stagingDir);
  return snapshot;
}

/** Refuse a new or changed worker link unless it stays relative, unprotected and inside the staged tree. */
function assertSafeLink(rel, target, full, stagingRoot) {
  const refuse = (why) => new WorkspaceEscapeError(`Worker symlink ${rel} -> ${target} ${why}`);
  if (isAbsolute(target) || /^(?:[\\/]|[a-zA-Z]:)/.test(target)) throw refuse("is absolute");
  if (target.split(/[\\/]/).some((segment) => segment && isProtectedSegment(segment))) throw refuse("targets a protected directory");
  const inside = (path) => {
    const fromRoot = relative(stagingRoot, path);
    return fromRoot !== ".." && !fromRoot.startsWith("../") && !fromRoot.startsWith("..\\") && !isAbsolute(fromRoot);
  };
  if (!inside(resolve(dirname(full), target))) throw refuse("leaves the workspace");
  let real;
  try {
    real = realpathSync(full);
  } catch (error) {
    throw refuse(`does not resolve (${error.code})`);
  }
  if (!inside(real)) throw refuse("resolves outside the workspace");
}

/** Read the staged tree without following links and refuse anything unsafe. Changes nothing. */
function readStagedTree(stagingDir, snapshot) {
  const stagingRoot = realpathSync(stagingDir);
  const entries = new Map();
  const walk = (dir, prefix) => {
    for (const name of readdirSync(dir)) {
      if (basename(name) !== name) throw new WorkspaceEscapeError(`Worker path ${JSON.stringify(name)} is not a single path segment on this host`);
      if (isStagingSkipped(name)) continue; // never staged, so never accepted back (host tooling executes node_modules)
      const rel = prefix ? `${prefix}/${name}` : name;
      const full = join(dir, name);
      const stat = lstatSync(full);
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(full);
        const before = snapshot.get(rel);
        if (before?.type !== "link" || before.target !== target) assertSafeLink(rel, target, full, stagingRoot);
        entries.set(rel, { type: "link", target });
      } else if (stat.isDirectory()) {
        walk(full, rel);
      } else if (stat.isFile()) {
        entries.set(rel, { type: "file", path: full, digest: digestOf(full), exec: isExecutable(stat) });
      } else {
        throw new WorkspaceEscapeError(`Worker path ${rel} is not a file, directory or symlink`);
      }
    }
  };
  walk(stagingRoot, "");
  return entries;
}

function isUnchanged(before, entry) {
  if (before?.type !== entry.type) return false;
  return entry.type === "link" ? before.target === entry.target : before.digest === entry.digest && before.exec === entry.exec;
}

function writeHostEntry(cwd, rel, entry, before) {
  const target = join(cwd, rel);
  const hostMode = lstatOrNull(target);
  mkdirSync(dirname(target), { recursive: true });
  rmSync(target, { force: true }); // removes a link itself and never writes through it
  if (entry.type === "link") {
    symlinkSync(entry.target, target);
    return;
  }
  let mode = hostMode !== null && !hostMode.isSymbolicLink() ? hostMode.mode & 0o777 : entry.exec ? 0o755 : 0o644;
  if (before?.type === "file" && before.exec !== entry.exec) mode = entry.exec ? mode | 0o111 : mode & ~0o111;
  writeFileSync(target, readFileSync(entry.path), { mode });
  chmodSync(target, mode); // writeFileSync's mode is subject to the umask
}

/**
 * Apply container edits to `cwd`: changed files and links, plus deletions of
 * staged paths. Host-only files (ignored files, `.git`, `.mirql`,
 * `node_modules`) survive because a path that was never staged is never deleted
 * or overwritten, and unchanged files are not touched, so their host modes stay
 * as they were. Worker writes under `.git`, `.mirql` and `node_modules` are dropped.
 * Empty directories are not synced; directories left empty are pruned.
 *
 * @throws {WorkspaceEscapeError} before anything is applied, when the tree is unsafe
 */
export function syncBackWorkspace(stagingDir, cwd, snapshot) {
  const entries = readStagedTree(stagingDir, snapshot);
  const writes = [...entries].filter(([rel, entry]) => !isUnchanged(snapshot.get(rel), entry));
  const deletions = [...snapshot].filter(([rel, before]) => before.type !== "dir" && !entries.has(rel)).map(([rel]) => rel);

  // A host link that was not staged is outside what the worker may replace or write through.
  for (const rel of [...writes.map(([path]) => path), ...deletions]) {
    const unstagedLink = prefixesOf(rel).find((prefix) => lstatOrNull(join(cwd, prefix))?.isSymbolicLink() && snapshot.get(prefix)?.type !== "link");
    if (unstagedLink !== undefined) throw new WorkspaceEscapeError(`Worker path ${rel} crosses host symlink ${unstagedLink}, which was not staged`);
  }

  // The worker never saw a host-only file (say an ignored .env), so it may not overwrite one.
  for (const [rel] of writes) {
    if (!snapshot.has(rel) && lstatOrNull(join(cwd, rel)) !== null) throw new WorkspaceEscapeError(`Worker path ${rel} would overwrite a host file that was not staged`);
  }

  for (const rel of deletions) {
    const stat = lstatOrNull(join(cwd, rel));
    if (stat !== null && !stat.isDirectory()) rmSync(join(cwd, rel));
  }
  const stagedDirs = [...snapshot].filter(([, before]) => before.type === "dir").map(([rel]) => rel);
  for (const rel of stagedDirs.sort((a, b) => b.length - a.length)) {
    const stat = lstatOrNull(join(cwd, rel));
    if (stat?.isDirectory() && readdirSync(join(cwd, rel)).length === 0) rmdirSync(join(cwd, rel));
  }
  for (const [rel, entry] of writes) writeHostEntry(cwd, rel, entry, snapshot.get(rel));
}
