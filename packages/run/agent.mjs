import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { EXIT_CODES } from "../core/index.mjs";
import { checkHumanOnlyPaths } from "./anti-cheat.mjs";

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
 * @returns {{ exitCode: number, ok: boolean, stdout?: string, stderr?: string, strippedEnv: string[], violation?: string, signal?: string | null }}
 */
export function runAgent(options = {}) {
  const { env: cleanEnv, stripped } = sanitizeAgentEnv(
    options.env ?? process.env,
    options.allowedEnv ?? [],
  );

  // Policy check: agents are strictly forbidden from touching humanOnly paths (MP-001)
  if (Array.isArray(options.modifiedFiles) && options.modifiedFiles.length > 0) {
    const check = checkHumanOnlyPaths(options.modifiedFiles);
    if (!check.ok) {
      return {
        exitCode: EXIT_CODES.POLICY_DENIAL,
        ok: false,
        violation: "TOUCH_HUMAN_ONLY",
        rule: "MP-001",
        forbidden: check.forbidden,
        strippedEnv: stripped,
      };
    }
  }

  // If a command is specified, spawn it in the clean sandbox environment
  if (typeof options.command === "string" && options.command.length > 0) {
    const workerHome = mkdtempSync(join(tmpdir(), "mirql-agent-home-"));
    for (const key of Object.keys(cleanEnv)) {
      if (key.toUpperCase() === "HOME" || key.toUpperCase() === "USERPROFILE") {
        delete cleanEnv[key];
      }
    }
    let res;
    let cleanupError;
    try {
      res = spawnSync(options.command, {
        shell: true,
        env: { ...cleanEnv, HOME: workerHome, USERPROFILE: workerHome },
        cwd: options.cwd ?? process.cwd(),
        timeout: options.timeout_ms ?? 30000,
        encoding: "utf8",
      });
    } finally {
      try {
        rmSync(workerHome, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      } catch (error) {
        cleanupError = error.message;
      }
    }

    let exitCode = res.status;
    // A process terminated by a signal must not report exit 0
    if (res.signal) {
      exitCode = 128 + 15; // Non-zero exit code for signal termination
    } else if (exitCode === null || exitCode === undefined) {
      exitCode = res.error ? 1 : 1;
    }

    return {
      exitCode: cleanupError ? EXIT_CODES.POLICY_DENIAL : exitCode,
      ok: exitCode === 0 && !res.signal && !cleanupError,
      ...(cleanupError ? { workerExitCode: exitCode, cleanupError, workerHome } : {}),
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
      strippedEnv: stripped,
      signal: res.signal ?? null,
    };
  }

  return {
    exitCode: EXIT_CODES.OK,
    ok: true,
    strippedEnv: stripped,
    signal: null,
  };
}
