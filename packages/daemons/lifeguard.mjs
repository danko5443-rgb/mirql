// packages/daemons/lifeguard.mjs — N-2 Host Rollback & 30m Probation Watchdog Daemon.
// Enforces Law 2 (unblockable kill authority) and Law 14 (quiescence / fail-safe convergence).

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

/** Default probation window: 30 minutes in milliseconds. */
export const DEFAULT_PROBATION_TIMEOUT_MS = 30 * 60 * 1000; // 1,800,000 ms

/**
 * Checks if the probation watchdog has expired.
 *
 * @param {object} params
 * @param {number} params.startTimeMs
 * @param {number} [params.nowMs=Date.now()]
 * @param {number} [params.timeoutMs=DEFAULT_PROBATION_TIMEOUT_MS]
 * @returns {{ ok: boolean, tripped: boolean, elapsedMs: number, remainingMs: number }}
 */
export function checkProbationStatus({ startTimeMs, nowMs = Date.now(), timeoutMs = DEFAULT_PROBATION_TIMEOUT_MS }) {
  if (!Number.isSafeInteger(startTimeMs) || startTimeMs <= 0) {
    throw new TypeError("startTimeMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) {
    throw new TypeError("nowMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive safe integer");
  }

  const elapsedMs = Math.max(0, nowMs - startTimeMs);
  const remainingMs = Math.max(0, timeoutMs - elapsedMs);
  const tripped = elapsedMs > timeoutMs;

  return {
    ok: !tripped,
    tripped,
    elapsedMs,
    remainingMs,
  };
}

/**
 * Executes an automated rollback to an authoritative target SHA in a repository.
 *
 * @param {string} repoDir
 * @param {string} targetSha
 * @returns {{ ok: boolean, targetSha: string, output: string, error?: string }}
 */
export function executeRollback(repoDir, targetSha) {
  if (!repoDir || !existsSync(join(repoDir, ".git"))) {
    return { ok: false, targetSha, output: "", error: `Directory ${repoDir} is not a git repository` };
  }
  if (typeof targetSha !== "string" || targetSha.length === 0) {
    return { ok: false, targetSha, output: "", error: "Target SHA is required for rollback" };
  }

  try {
    const res = spawnSync("git", ["checkout", targetSha], {
      cwd: repoDir,
      encoding: "utf8",
      timeout: 30_000,
    });
    if (res.status !== 0) {
      return {
        ok: false,
        targetSha,
        output: res.stdout || "",
        error: res.stderr?.trim() || `git checkout failed with exit code ${res.status}`,
      };
    }
    return {
      ok: true,
      targetSha,
      output: res.stdout?.trim() || `Rolled back to ${targetSha}`,
    };
  } catch (err) {
    return {
      ok: false,
      targetSha,
      output: "",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Lifeguard watchdog daemon instance.
 */
export class LifeguardWatchdog {
  constructor(options = {}) {
    this.repoDir = options.repoDir ?? process.cwd();
    this.targetBaseSha = options.targetBaseSha ?? null;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_PROBATION_TIMEOUT_MS;
    this.startTimeMs = options.startTimeMs ?? Date.now();
    this.lastHeartbeatMs = this.startTimeMs;
    this.disarmed = false;
    this.rolledBack = false;
  }

  heartbeat(nowMs = Date.now()) {
    this.lastHeartbeatMs = nowMs;
  }

  disarm() {
    this.disarmed = true;
  }

  check(nowMs = Date.now()) {
    if (this.disarmed) {
      return { ok: true, disarmed: true, tripped: false };
    }
    const status = checkProbationStatus({
      startTimeMs: this.startTimeMs,
      nowMs,
      timeoutMs: this.timeoutMs,
    });

    if (status.tripped && !this.rolledBack && this.targetBaseSha) {
      const rollback = executeRollback(this.repoDir, this.targetBaseSha);
      this.rolledBack = true;
      return { ...status, ok: false, rollback };
    }

    return status;
  }
}

// CLI entrypoint
if (process.argv[1] && process.argv[1].endsWith("lifeguard.mjs")) {
  let timeoutSec = 1800;
  let baseSha = null;
  let repoDir = process.cwd();

  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === "--timeout" && process.argv[i + 1]) {
      timeoutSec = parseInt(process.argv[++i], 10);
    } else if (process.argv[i] === "--base" && process.argv[i + 1]) {
      baseSha = process.argv[++i];
    } else if (process.argv[i] === "--repo" && process.argv[i + 1]) {
      repoDir = process.argv[++i];
    }
  }

  const watchdog = new LifeguardWatchdog({
    repoDir,
    targetBaseSha: baseSha,
    timeoutMs: timeoutSec * 1000,
  });

  const checkResult = watchdog.check();
  process.stdout.write(JSON.stringify(checkResult) + "\n");
}
