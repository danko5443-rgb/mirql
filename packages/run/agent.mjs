import { captureWorkerBase, measureWorkerChanges } from "./worker-diff.mjs";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { EXIT_CODES } from "../core/index.mjs";
import { checkHumanOnlyPaths, loadHumanOnlyPatterns } from "./anti-cheat.mjs";

/**
 * Strict safe allowlist for environment variables passed to unprivileged agents.
 * Matching is performed case-insensitively.
 */
export const SAFE_ENV_ALLOWLIST = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "HOME",
  "NODE_ENV",
]);

/**
 * Sanitizes the environment by retaining ONLY explicitly allowlisted variables.
 * Matching is case-insensitive.
 *
 * @param {Record<string, string | undefined>} [env=process.env]
 * @param {string[]} [extraAllowed=[]]
 * @returns {{ env: Record<string, string>, stripped: string[] }}
 */
export function sanitizeAgentEnv(env = process.env, extraAllowed = []) {
  const clean = {};
  const stripped = [];
  const allowedSet = new Set([
    ...SAFE_ENV_ALLOWLIST,
    ...extraAllowed.map((k) => k.toUpperCase()),
  ]);

  for (const [key, val] of Object.entries(env)) {
    if (val === undefined) continue;
    if (allowedSet.has(key.toUpperCase())) {
      clean[key] = String(val);
    } else {
      stripped.push(key);
    }
  }

  // Ensure critical OS variables on Windows so child processes can spawn
  if (process.platform === "win32") {
    if (!clean.SystemRoot && process.env.SystemRoot) {
      clean.SystemRoot = process.env.SystemRoot;
    }
    if (!clean.SYSTEMDRIVE && process.env.SYSTEMDRIVE) {
      clean.SYSTEMDRIVE = process.env.SYSTEMDRIVE;
    }
  }

  return { env: clean, stripped };
}

/** Default container image for sandboxed agent execution (Law 8); operators override via `options.image`. */
export const DEFAULT_SANDBOX_IMAGE = "mirql-agent:latest";

/** Directories a sandboxed staging copy never sees: ledger state, VCS data, installed modules. */
const STAGING_SKIP = new Set([".git", ".mirql", "node_modules"]);
/** Exit codes a container runtime uses when it cannot launch a container. */
const RUNTIME_LAUNCH_FAILURE_CODES = new Set([125, 126, 127, 9009]);

/** True when the container runtime binary itself failed to launch. */
function runtimeLaunchFailed(res) {
  return (typeof res.status === "number" && RUNTIME_LAUNCH_FAILURE_CODES.has(res.status)) ||
    (typeof res.stderr === "string" && /is not recognized as an internal or external command|command not found|not found/i.test(res.stderr));
}

/**
 * Build the hardened container CLI argument vector for a sandboxed agent run
 * (Law 8: Speechless Sandboxes — no network, read-only root, tmpfs /tmp,
 * dropped capabilities, no privilege escalation, unprivileged UID 65534, the
 * staged workspace mounted read-write as the only writable surface).
 */
export function buildContainerArgs({ runtime, image, workdir, command, env = {} } = {}) {
  void runtime; // the runtime selects the binary; the flags are runtime-neutral
  const envFlags = Object.entries(env).flatMap(([key, value]) => ["--env", `${key}=${value}`]);
  return ["run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true", "--user", "65534:65534", "-v", `${workdir}:/workspace:rw`,
    "-w", "/workspace", ...envFlags, image, "sh", "-c", command];
}

/** Recursively copy `src` into `dest`, pruning directories named in `skip`. */
function copyTree(src, dest, skip) {
  for (const entry of readdirSync(src)) {
    if (skip.has(entry)) continue;
    const from = join(src, entry), to = join(dest, entry);
    if (statSync(from).isDirectory()) copyTree(from, to, skip);
    else { mkdirSync(dirname(to), { recursive: true }); cpSync(from, to, { force: true }); }
  }
}

/** Stage tracked/working files of `cwd` into `stagingDir` (never `.git`/`.mirql`/`node_modules`). */
function stageWorkspace(cwd, stagingDir) {
  const listed = spawnSync("git", ["--no-replace-objects", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd, encoding: "utf8", timeout: 10000, windowsHide: true });
  if (listed.error || listed.status !== 0) { copyTree(cwd, stagingDir, STAGING_SKIP); return; }
  for (const rel of listed.stdout.split("\0").filter(Boolean)) {
    if (rel.split(/[\\/]/).some((segment) => STAGING_SKIP.has(segment))) continue;
    mkdirSync(dirname(join(stagingDir, rel)), { recursive: true });
    cpSync(join(cwd, rel), join(stagingDir, rel), { recursive: true, force: true });
  }
}

/** Copy container edits from `stagingDir` back into `cwd` (never `.git`/`.mirql`). */
function syncBackWorkspace(stagingDir, cwd) {
  copyTree(stagingDir, cwd, new Set([".git", ".mirql"]));
}

/** Normalize a spawn status to an integer exit code; a signal never reports 0. */
function normalizeExitCode(res) {
  return res.signal ? 128 + 15 : res.status === null || res.status === undefined ? 1 : res.status;
}

/** Shared worker result envelope (identical shape across sandboxed and host runs). */
function workerResult(ok, exitCode, res, stripped, sandboxMode) {
  return { exitCode, ok, stdout: res.stdout ?? "", stderr: res.stderr ?? "", strippedEnv: stripped, sandbox: sandboxMode, signal: res.signal ?? null };
}

/** Post-run MP-001 gate: measure real changes, refuse protected paths, never trust worker claims. */
function postRunGate(baseline, patterns, base, exitCode) {
  try {
    const changedFiles = measureWorkerChanges(baseline);
    const policy = checkHumanOnlyPaths(changedFiles, patterns);
    if (!policy.ok) return { ...base, ok: false, exitCode: EXIT_CODES.POLICY_DENIAL, workerExitCode: exitCode,
      rule: "MP-001", violation: "TOUCH_HUMAN_ONLY", forbidden: policy.forbidden, changedFiles, baseSha: baseline.baseSha };
    return { ...base, changedFiles, baseSha: baseline.baseSha };
  } catch (error) {
    return { ...base, ok: false, exitCode: EXIT_CODES.POLICY_DENIAL, workerExitCode: exitCode,
      rule: "MP-001", violation: "WORKSPACE_UNVERIFIED", detail: error.message };
  }
}

/**
 * Runs an unprivileged agent worker task.
 *
 * @param {object} options
 * @param {string} [options.command] - shell command to execute
 * @param {string[]} [options.modifiedFiles] - paths touched by the agent (checked against humanOnly)
 * @param {Record<string, string>} [options.env] - environment
 * @param {string[]} [options.allowedEnv] - extra permitted environment variables
 * @param {string} [options.cwd] - working directory
 * @param {number} [options.timeout_ms=30000] - timeout limit
 * @param {"none" | "docker" | "podman"} [options.sandbox="none"] - Law 8 isolation mode
 * @param {string} [options.image] - container image used by sandboxed runs
 * @returns {{ exitCode: number, ok: boolean, sandbox: string, stdout?: string, stderr?: string, strippedEnv: string[], violation?: string, signal?: string | null }}
 */
export function runAgent(options = {}) {
  const sandboxMode = options.sandbox === "docker" || options.sandbox === "podman" ? options.sandbox : "none";
  const { env: cleanEnv, stripped } = sanitizeAgentEnv(options.env ?? process.env, options.allowedEnv ?? []);

  const hasCommand = typeof options.command === "string" && options.command.length > 0;
  let baseline;
  let patterns;
  if (hasCommand) {
    try {
      baseline = captureWorkerBase(options.cwd ?? process.cwd());
      patterns = loadHumanOnlyPatterns(baseline.repoDir);
    } catch (error) {
      return { ok: false, exitCode: EXIT_CODES.POLICY_DENIAL, violation: "WORKSPACE_UNVERIFIED",
        rule: "MP-001", detail: error.message, strippedEnv: stripped, sandbox: sandboxMode };
    }
  }

  // Policy check: agents are strictly forbidden from touching humanOnly paths (MP-001)
  if (Array.isArray(options.modifiedFiles) && options.modifiedFiles.length > 0) {
    const check = checkHumanOnlyPaths(options.modifiedFiles, patterns);
    if (!check.ok) {
      return { exitCode: EXIT_CODES.POLICY_DENIAL, ok: false, violation: "TOUCH_HUMAN_ONLY",
        rule: "MP-001", forbidden: check.forbidden, strippedEnv: stripped, sandbox: sandboxMode };
    }
  }

  // If a command is specified, spawn it in the sanitized worker environment
  if (hasCommand) {
    const workerHome = mkdtempSync(join(tmpdir(), "mirql-agent-home-"));
    for (const key of Object.keys(cleanEnv)) {
      const u = key.toUpperCase();
      if (u === "HOME" || u === "USERPROFILE" || u === "HOMEDRIVE" || u === "HOMEPATH") delete cleanEnv[key];
    }
    const workerEnv = { ...cleanEnv, HOME: workerHome, USERPROFILE: workerHome };
    if (process.platform === "win32") {
      const match = workerHome.match(/^([a-zA-Z]:)(.*)$/);
      if (match) { workerEnv.HOMEDRIVE = match[1]; workerEnv.HOMEPATH = match[2]; }
    }

    // Law 8: container-isolated execution. The workspace is staged outside
    // .mirql/.git, the container runs hardened (see buildContainerArgs), and
    // only successful container edits are synced back before the post-run gate.
    if (sandboxMode !== "none") {
      const workspace = resolve(options.cwd ?? process.cwd());
      const stagingDir = mkdtempSync(join(tmpdir(), "mirql-sandbox-stage-"));
      try {
        stageWorkspace(workspace, stagingDir);
        const args = buildContainerArgs({ runtime: sandboxMode,
          image: typeof options.image === "string" && options.image.length > 0 ? options.image : DEFAULT_SANDBOX_IMAGE,
          workdir: stagingDir, command: options.command, env: { PATH: workerEnv.PATH ?? process.env.PATH ?? "" } });
        const res = spawnSync(sandboxMode, args, { cwd: stagingDir, env: workerEnv,
          timeout: options.timeout_ms ?? 30000, encoding: "utf8", windowsHide: true, shell: process.platform === "win32" });

        if (res.error || runtimeLaunchFailed(res)) {
          return { ...workerResult(false, EXIT_CODES.POLICY_DENIAL, res, stripped, sandboxMode),
            violation: "SANDBOX_UNAVAILABLE", rule: "MP-001",
            detail: res.error?.message ?? (typeof res.stderr === "string" && res.stderr.trim().length > 0 ? res.stderr.trim()
              : `sandbox runtime ${JSON.stringify(sandboxMode)} failed to launch (exit ${res.status ?? "none"})`) };
        }

        const exitCode = normalizeExitCode(res);
        const base = workerResult(exitCode === 0 && !res.signal, exitCode, res, stripped, sandboxMode);
        if (exitCode !== 0) return base;
        syncBackWorkspace(stagingDir, workspace);
        return postRunGate(baseline, patterns, base, exitCode);
      } finally {
        try {
          rmSync(stagingDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        } catch (error) {
          // mp-003-allow: staging cleanup is best-effort; the OS temp cleaner reclaims it and no correctness guarantee depends on it.
          void error;
        }
      }
    }

    let res;
    let cleanupError;
    try {
      res = spawnSync(options.command, {
        shell: true,
        env: workerEnv,
        cwd: options.cwd ?? process.cwd(),
        timeout: options.timeout_ms ?? 30000,
        encoding: "utf8",
      });
    } finally {
      try {
        rmSync(workerHome, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      } catch (error) {
        cleanupError = error.code ? `${error.code}: ${error.message}` : error.message;
      }
      if (!cleanupError && existsSync(workerHome)) {
        cleanupError = "EEXIST: workerHome path retained after cleanup";
      }
    }

    const exitCode = normalizeExitCode(res);
    const result = workerResult(exitCode === 0 && !res.signal && !cleanupError,
      cleanupError ? EXIT_CODES.POLICY_DENIAL : exitCode, res, stripped, sandboxMode);
    if (cleanupError) { result.workerExitCode = exitCode; result.cleanupError = cleanupError; result.workerHome = workerHome; }
    return postRunGate(baseline, patterns, result, exitCode);
  }

  return { exitCode: EXIT_CODES.OK, ok: true, sandbox: sandboxMode, strippedEnv: stripped, signal: null };
}
