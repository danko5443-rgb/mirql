import { existsSync, lstatSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { homedir, userInfo } from "node:os";
import { createHash } from "node:crypto";

function canonicalPath(value) {
  const path = resolve(value);
  let present = false;
  try {
    lstatSync(path);
    present = true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (present) return realpathSync(path);
  const parent = dirname(path);
  if (parent === path) return path;
  return join(canonicalPath(parent), relative(parent, path));
}

function isWithin(parent, child) {
  const rel = relative(parent, child);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith("../") && !rel.startsWith("..\\"));
}

/** Reject a credentials path inside a workspace or any Git worktree. */
export function assertExternalTrustPath(path, workspaceDir) {
  const target = canonicalPath(path);
  const workspace = canonicalPath(workspaceDir);
  if (isWithin(workspace, target)) {
    throw new Error("UNSAFE_TRUST_ROOT: credentials must be outside the workspace");
  }
  // A linked worktree has a .git file, and an ordinary checkout has a
  // .git directory. Inspect every ancestor on every access, including
  // dangling markers, without launching a child process for each key read.
  for (let dir = target; ; dir = dirname(dir)) {
    let marker = false;
    try {
      lstatSync(join(dir, ".git"));
      marker = true;
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
    if (marker) throw new Error("UNSAFE_TRUST_ROOT: credentials path has a Git ancestor");
    if (dirname(dir) === dir) break;
  }
  return target;
}

/**
 * `node --test` sets NODE_TEST_CONTEXT in every test process, so a test run
 * started without the suite runner cannot reach the operator's trust root. The
 * account home comes from the OS, because a faked HOME or USERPROFILE is exactly
 * how a test legitimately points homedir() somewhere disposable.
 */
export function refuseOperatorTrustInTests(path, options = {}) {
  if ((options.env ?? process.env).NODE_TEST_CONTEXT === undefined) return;
  let accountHome = options.accountHome;
  if (accountHome === undefined) {
    try {
      accountHome = userInfo().homedir;
    } catch {
      return; // An account with no home entry has no operator trust root to protect.
    }
  }
  if (isWithin(canonicalPath(join(accountHome, ".mirql-trust")), canonicalPath(path))) {
    throw new Error("UNSAFE_TRUST_ROOT: a test run reached the operator's trust root; use npm test, or set MIRQL_TRUST_ROOT to a temporary directory");
  }
}

/** Credentials are per ledger, with a root supplied by the operator. */
export function resolveTrustRoot(mirqlDir, options = {}) {
  const ledger = canonicalPath(mirqlDir);
  const workspace = options.workspaceDir ?? (basename(ledger) === ".mirql" ? dirname(ledger) : ledger);
  const id = createHash("sha256").update(ledger).digest("hex");
  const base = options.trustRoot ?? process.env.MIRQL_TRUST_ROOT
    ?? join(homedir(), ".mirql-trust");
  refuseOperatorTrustInTests(base);
  const parent = assertExternalTrustPath(base, workspace);
  const candidate = join(parent, id);
  let linked = false;
  try {
    linked = lstatSync(candidate).isSymbolicLink();
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (linked) throw new Error("UNSAFE_TRUST_ROOT: a ledger trust directory cannot be a symlink");
  const root = assertExternalTrustPath(candidate, workspace);
  return root;
}

/** Creation must not replace an initialized ledger's missing credentials. */
export function requireTrustForKeyCreation(mirqlDir) {
  const ledger = canonicalPath(mirqlDir);
  const root = resolveTrustRoot(mirqlDir);
  const legacyKeyring = [
    join(ledger, "ledger", "keyring.json"),
    join(ledger, "keys", "keyring.json"),
    join(ledger, "keyring.json"),
  ].some(path => existsSync(path));
  const events = join(ledger, "ledger", "events.jsonl");
  if (existsSync(events) &&
      (legacyKeyring || statSync(events).size > 0) &&
      !existsSync(join(root, "keyring.json"))) {
    throw new Error("TRUST_MIGRATION_REQUIRED: move the existing keys and keyring to " + root + " before using this ledger");
  }
  return root;
}

/** Resolve and recheck a credentials file, including any existing symlink. */
export function trustFile(mirqlDir, ...parts) {
  const root = resolveTrustRoot(mirqlDir);
  const file = canonicalPath(join(root, ...parts));
  if (!isWithin(root, file)) {
    throw new Error("UNSAFE_TRUST_ROOT: credentials file escapes the trust root");
  }
  return file;
}
