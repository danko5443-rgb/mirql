// packages/daemons/lifeguard.mjs — N-2 Host Rollback & 30m Probation Watchdog Daemon.
// Enforces Law 2 (unblockable kill authority) and Law 14 (quiescence / fail-safe convergence).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** Default probation window: 30 minutes in milliseconds (1,800,000 ms). */
export const DEFAULT_PROBATION_TIMEOUT_MS = 30 * 60 * 1000;

/** Default heartbeat timeout: 5 minutes in milliseconds. */
export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 5 * 60 * 1000;

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
 * Executes an automated clean rollback to an authoritative target SHA in a repository.
 * Uses `git reset --hard` followed by `git clean -fd` to eliminate dirty/uncommitted files.
 *
 * @param {string} repoDir
 * @param {string} targetSha
 * @returns {{ ok: boolean, targetSha: string, output: string, error?: string }}
 */
export function executeRollback(repoDir, targetSha) {
  if (!repoDir || !existsSync(join(repoDir, ".git"))) {
    return { ok: false, targetSha, output: "", error: `Directory ${repoDir} is not a git repository` };
  }
  if (typeof targetSha !== "string" || targetSha.trim().length === 0) {
    return { ok: false, targetSha, output: "", error: "Target SHA is required for rollback" };
  }

  try {
    const resetRes = spawnSync("git", ["reset", "--hard", targetSha], {
      cwd: repoDir,
      encoding: "utf8",
      timeout: 30_000,
    });
    if (resetRes.status !== 0) {
      return {
        ok: false,
        targetSha,
        output: resetRes.stdout || "",
        error: resetRes.stderr?.trim() || `git reset --hard failed with exit code ${resetRes.status}`,
      };
    }

    // Clean untracked artifacts created during failed run
    const cleanRes = spawnSync("git", ["clean", "-fd"], {
      cwd: repoDir,
      encoding: "utf8",
      timeout: 15_000,
    });

    return {
      ok: true,
      targetSha,
      output: `Rolled back to ${targetSha}. ${cleanRes.stdout?.trim() || ""}`,
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
 * Terminates process IDs using unblockable SIGKILL (Law 2).
 *
 * @param {number[]} pids
 * @returns {{ killed: number[], failed: Array<{ pid: number, error: string }> }}
 */
export function killProcesses(pids = []) {
  const killed = [];
  const failed = [];

  for (const pid of pids) {
    if (!Number.isSafeInteger(pid) || pid <= 0) continue;
    try {
      process.kill(pid, "SIGKILL");
      killed.push(pid);
    } catch (err) {
      failed.push({ pid, error: err.message });
    }
  }

  return { killed, failed };
}

/**
 * Stops or kills systemd services using systemctl (Law 2).
 *
 * @param {string[]} services
 * @returns {{ killed: string[], failed: Array<{ service: string, error: string }> }}
 */
export function killServices(services = []) {
  const killed = [];
  const failed = [];

  for (const service of services) {
    if (typeof service !== "string" || service.trim().length === 0) continue;
    try {
      const res = spawnSync("systemctl", ["kill", service.trim()], {
        encoding: "utf8",
        timeout: 10_000,
      });
      if (res.status === 0) {
        killed.push(service.trim());
      } else {
        failed.push({ service, error: res.stderr?.trim() || `Exit code ${res.status}` });
      }
    } catch (err) {
      failed.push({ service, error: err.message });
    }
  }

  return { killed, failed };
}

/**
 * Lifeguard watchdog daemon instance.
 */
export class LifeguardWatchdog {
  constructor(options = {}) {
    this.repoDir = options.repoDir ?? process.cwd();
    this.targetBaseSha = options.targetBaseSha ?? null;
    this.baseShaFile = options.baseShaFile ?? null;
    this.heartbeatFile = options.heartbeatFile ?? null;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_PROBATION_TIMEOUT_MS;
    this.heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;
    this.startTimeMs = options.startTimeMs ?? Date.now();
    this.lastHeartbeatMs = this.startTimeMs;
    this.killPids = Array.isArray(options.killPids) ? [...options.killPids] : [];
    this.killServices = Array.isArray(options.killServices) ? [...options.killServices] : [];
    this.killPidFiles = Array.isArray(options.killPidFiles) ? [...options.killPidFiles] : [];
    this.disarmFile = options.disarmFile ?? null;
    this.disarmed = false;
    this.rolledBack = false;
    this.intervalId = null;
  }

  heartbeat(nowMs = Date.now()) {
    this.lastHeartbeatMs = nowMs;
  }

  registerPid(pid) {
    if (Number.isSafeInteger(pid) && pid > 0 && !this.killPids.includes(pid)) {
      this.killPids.push(pid);
    }
  }

  disarm() {
    this.disarmed = true;
    this.stop();
  }

  resolveTargetSha() {
    if (this.targetBaseSha) return this.targetBaseSha;
    if (this.baseShaFile && existsSync(this.baseShaFile)) {
      try {
        const text = readFileSync(this.baseShaFile, "utf8").trim();
        if (text.length > 0) return text;
      } catch {}
    }
    return null;
  }

  check(nowMs = Date.now()) {
    if (this.disarmed) {
      return { ok: true, disarmed: true, tripped: false };
    }

    if (this.disarmFile && existsSync(this.disarmFile)) {
      this.disarm();
      return { ok: true, disarmed: true, tripped: false, reason: "DISARM_FILE_PRESENT" };
    }

    // Check heartbeat file mtime if configured
    if (this.heartbeatFile && existsSync(this.heartbeatFile)) {
      try {
        const stats = statSync(this.heartbeatFile);
        if (stats.mtimeMs > this.lastHeartbeatMs) {
          this.lastHeartbeatMs = stats.mtimeMs;
        }
      } catch {}
    }

    const status = checkProbationStatus({
      startTimeMs: this.startTimeMs,
      nowMs,
      timeoutMs: this.timeoutMs,
    });

    const heartbeatElapsed = Math.max(0, nowMs - this.lastHeartbeatMs);
    const heartbeatTripped = heartbeatElapsed > this.heartbeatTimeoutMs;

    if ((status.tripped || heartbeatTripped) && !this.rolledBack) {
      // Collect PIDs from killPidFiles
      const allPids = [...this.killPids];
      for (const pidFile of this.killPidFiles) {
        if (existsSync(pidFile)) {
          try {
            const rawPid = parseInt(readFileSync(pidFile, "utf8").trim(), 10);
            if (Number.isSafeInteger(rawPid) && rawPid > 0 && !allPids.includes(rawPid)) {
              allPids.push(rawPid);
            }
          } catch {}
        }
      }

      // Execute unblockable kill on registered processes (Law 2)
      const killResult = killProcesses(allPids);

      // Execute kill on systemd services if specified
      const serviceKillResult = killServices(this.killServices);

      // Execute rollback if target SHA is resolvable
      const targetSha = this.resolveTargetSha();
      let rollback = null;
      if (targetSha) {
        rollback = executeRollback(this.repoDir, targetSha);
        this.rolledBack = true;
      }

      return {
        ok: false,
        tripped: true,
        reason: status.tripped ? "PROBATION_TIMEOUT_EXPIRED" : "HEARTBEAT_TIMEOUT_EXPIRED",
        elapsedMs: status.elapsedMs,
        remainingMs: status.remainingMs,
        heartbeatElapsedMs: heartbeatElapsed,
        killed: killResult.killed,
        killedServices: serviceKillResult.killed,
        rollback,
      };
    }

    return {
      ...status,
      heartbeatElapsedMs: heartbeatElapsed,
      heartbeatRemainingMs: Math.max(0, this.heartbeatTimeoutMs - heartbeatElapsed),
    };
  }

  start(intervalMs = 1000, unrefTimer = false) {
    if (this.intervalId) return;
    this.intervalId = setInterval(() => {
      const res = this.check();
      if (res.disarmed) {
        process.stdout.write("[mirql-lifeguard] Watchdog disarmed, exiting.\n");
        this.stop();
        return;
      }
      if (!res.ok && res.tripped) {
        process.stderr.write(`[mirql-lifeguard] Watchdog tripped: ${res.reason}\n`);
        this.stop();
      }
    }, intervalMs);
    // Only unref if explicitly requested (e.g. in test suites); keep event loop active in --watch mode
    if (unrefTimer && typeof this.intervalId.unref === "function") {
      this.intervalId.unref();
    }
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
}

// CLI entrypoint
if (process.argv[1] && process.argv[1].endsWith("lifeguard.mjs")) {
  let timeoutSec = 1800;
  let heartbeatTimeoutSec = 300;
  let baseSha = null;
  let baseFile = null;
  let heartbeatFile = null;
  let disarmFile = null;
  let repoDir = process.cwd();
  let watchMode = false;
  const killPids = [];
  const killServices = [];
  const killPidFiles = [];

  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg === "--timeout" && process.argv[i + 1]) {
      timeoutSec = parseInt(process.argv[++i], 10);
    } else if (arg === "--heartbeat-timeout" && process.argv[i + 1]) {
      heartbeatTimeoutSec = parseInt(process.argv[++i], 10);
    } else if (arg === "--base" && process.argv[i + 1]) {
      baseSha = process.argv[++i];
    } else if (arg === "--base-file" && process.argv[i + 1]) {
      baseFile = process.argv[++i];
    } else if (arg === "--heartbeat-file" && process.argv[i + 1]) {
      heartbeatFile = process.argv[++i];
    } else if (arg === "--disarm-file" && process.argv[i + 1]) {
      disarmFile = process.argv[++i];
    } else if (arg === "--repo" && process.argv[i + 1]) {
      repoDir = process.argv[++i];
    } else if (arg === "--kill-pid" && process.argv[i + 1]) {
      killPids.push(parseInt(process.argv[++i], 10));
    } else if (arg === "--kill-service" && process.argv[i + 1]) {
      killServices.push(process.argv[++i]);
    } else if (arg === "--kill-pid-file" && process.argv[i + 1]) {
      killPidFiles.push(process.argv[++i]);
    } else if (arg === "--watch") {
      watchMode = true;
    }
  }

  const watchdog = new LifeguardWatchdog({
    repoDir,
    targetBaseSha: baseSha,
    baseShaFile: baseFile,
    heartbeatFile,
    disarmFile,
    killPids,
    killServices,
    killPidFiles,
    timeoutMs: timeoutSec * 1000,
    heartbeatTimeoutMs: heartbeatTimeoutSec * 1000,
  });

  if (watchMode) {
    process.stdout.write(JSON.stringify({ status: "watching", timeout_ms: timeoutSec * 1000, heartbeat_file: heartbeatFile }) + "\n");
    // In watch mode, keep the event loop alive (unrefTimer = false)
    watchdog.start(2000, false);
  } else {
    const checkResult = watchdog.check();
    process.stdout.write(JSON.stringify(checkResult) + "\n");
  }
}
