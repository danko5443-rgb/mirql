// packages/daemons/lifeguard.mjs — N-2 Host Rollback & 30m Probation Watchdog Daemon.
// Enforces Law 2 (unblockable kill authority) and Law 14 (quiescence / fail-safe convergence).

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, symlinkSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

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
 * Lists the worktree paths that a rollback (`git reset --hard` + `git clean -fd`)
 * would destroy: modified/deleted tracked files plus untracked non-ignored files.
 * Honors .gitignore exactly like `git clean -fd` (ignored files are never listed).
 *
 * Fail-closed (Law 14): a git failure returns ok:false — the caller must NOT
 * proceed with destructive operations on an unmeasurable worktree.
 *
 * @param {string} repoDir
 * @returns {{ ok: boolean, paths: string[], error?: string }}
 */
export function listDestructiblePaths(repoDir, targetSha = null) {
  const gitZ = (args) => {
    const res = spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 15_000 });
    if (res.status !== 0) {
      return { ok: false, error: (res.stderr || res.stdout || `git ${args[0]} exit ${res.status}`).trim() };
    }
    const raw = String(res.stdout || "");
    const items = raw.split("\0").filter(Boolean);
    return { ok: true, items };
  };

  let tracked;
  if (typeof targetSha === "string" && targetSha.trim().length > 0) {
    tracked = gitZ(["diff", "--name-only", "-z", targetSha.trim()]);
  } else {
    tracked = gitZ(["diff", "--name-only", "-z", "HEAD"]);
    if (!tracked.ok) {
      const mod = gitZ(["ls-files", "-m", "-z"]);
      if (!mod.ok) return { ok: false, paths: [], error: mod.error };
      const cached = gitZ(["diff", "--cached", "--name-only", "-z"]);
      if (!cached.ok) return { ok: false, paths: [], error: cached.error };
      tracked = { ok: true, items: [...mod.items, ...cached.items] };
    }
  }

  if (!tracked.ok) return { ok: false, paths: [], error: tracked.error };

  const untracked = gitZ(["ls-files", "--others", "-z", "--exclude-standard"]);
  if (!untracked.ok) return { ok: false, paths: [], error: untracked.error };

  const paths = [...new Set([...tracked.items, ...untracked.items])].sort();
  return { ok: true, paths };
}

/**
 * Copies the given worktree-relative paths into a quarantine directory,
 * preserving relative structure, so destructive rollback stays recoverable.
 * Uses lstat to handle symlinks and skip directories safely without throwing EPERM.
 * Also writes binary diff snapshot against targetSha if provided.
 *
 * @param {string} repoDir
 * @param {string[]} paths
 * @param {string} quarantineDir
 * @param {string} [targetSha]
 * @returns {{ ok: boolean, dir: string, copied: string[], skipped: Array<{ path: string, reason: string }>, error?: string }}
 */
function quarantinePaths(repoDir, paths, quarantineDir, targetSha = null) {
  const copied = [];
  const skipped = [];
  try {
    mkdirSync(quarantineDir, { recursive: true });

    if (typeof targetSha === "string" && targetSha.trim().length > 0) {
      const diffRes = spawnSync("git", ["diff", "--binary", targetSha.trim()], {
        cwd: repoDir,
        encoding: "utf8",
        timeout: 30_000,
      });
      if (diffRes.status === 0 && diffRes.stdout) {
        writeFileSync(join(quarantineDir, "staged-worktree.diff"), diffRes.stdout, "utf8");
      }
    }

    for (const relPath of paths) {
      const src = join(repoDir, relPath);
      let stat;
      try {
        stat = lstatSync(src);
      } catch (err) {
        if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) {
          skipped.push({ path: relPath, reason: "already_absent", toString() { return this.path; } });
          continue;
        }
        throw err;
      }

      const dest = join(quarantineDir, relPath);
      mkdirSync(dirname(dest), { recursive: true });

      if (stat.isSymbolicLink()) {
        const linkTarget = readlinkSync(src);
        try {
          symlinkSync(linkTarget, dest);
          copied.push(relPath);
        } catch {
          writeFileSync(dest, linkTarget, "utf8");
          copied.push(relPath);
        }
      } else if (stat.isDirectory()) {
        skipped.push({ path: relPath, reason: "directory_skipped", toString() { return this.path; } });
      } else if (stat.isFile()) {
        copyFileSync(src, dest);
        copied.push(relPath);
      } else {
        skipped.push({ path: relPath, reason: "unsupported_type", toString() { return this.path; } });
      }
    }
    return { ok: true, dir: quarantineDir, copied, skipped };
  } catch (err) {
    return {
      ok: false,
      dir: quarantineDir,
      copied,
      skipped,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Executes an automated clean rollback to an authoritative target SHA in a repository.
 *
 * Quarantine-first (Law 14, fail-safe): every path that `git reset --hard` +
 * `git clean -fd` would destroy is FIRST copied to
 * `<repoDir>/.mirql/quarantine/rollback-<epochMs>-<pid>/` so concurrent agents'
 * uncommitted work is recoverable, never silently lost. If the quarantine copy
 * fails and `allowDataLoss` is false (default), the rollback ABORTS — the
 * factory converges to a safe state instead of destroying unmeasured work.
 *
 * @param {string} repoDir
 * @param {string} targetSha
 * @param {object} [options]
 * @param {string} [options.quarantineRoot] - override quarantine parent dir
 * @param {boolean} [options.allowDataLoss=false] - proceed even if quarantine fails
 * @returns {{ ok: boolean, targetSha: string, output: string, error?: string, quarantine?: object }}
 */
export function executeRollback(repoDir, targetSha, { quarantineRoot, allowDataLoss = false } = {}) {
  if (!repoDir || !existsSync(join(repoDir, ".git"))) {
    return { ok: false, targetSha, output: "", error: `Directory ${repoDir} is not a git repository` };
  }
  if (typeof targetSha !== "string" || targetSha.trim().length === 0) {
    return { ok: false, targetSha, output: "", error: "Target SHA is required for rollback" };
  }

  try {
    const destructible = listDestructiblePaths(repoDir, targetSha);
    if (!destructible.ok) {
      return {
        ok: false,
        targetSha,
        output: "",
        error: `Refusing rollback — cannot measure dirty worktree: ${destructible.error}`,
      };
    }

    let quarantine = null;
    const root = quarantineRoot ?? join(repoDir, ".mirql", "quarantine");
    if (destructible.paths.length > 0) {
      const quarantineDir = join(root, `rollback-${Date.now()}-${process.pid}`);
      quarantine = quarantinePaths(repoDir, destructible.paths, quarantineDir, targetSha);
      if (!quarantine.ok && !allowDataLoss) {
        return {
          ok: false,
          targetSha,
          output: "",
          error: `Quarantine failed, refusing destructive rollback: ${quarantine.error} ` +
            "(re-run with allowDataLoss to override; worktree left untouched)",
          quarantine,
        };
      }
    }

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
        quarantine,
      };
    }

    const cleanArgs = ["clean", "-fd"];
    const relRoot = relative(repoDir, root).replaceAll("\\", "/");
    if (relRoot && !relRoot.startsWith("..")) {
      cleanArgs.push("-e", relRoot);
    }
    const cleanRes = spawnSync("git", cleanArgs, {
      cwd: repoDir,
      encoding: "utf8",
      timeout: 15_000,
    });
    if (cleanRes.status !== 0) {
      return {
        ok: false,
        targetSha,
        output: cleanRes.stdout || "",
        error: cleanRes.stderr?.trim() || `git clean -fd failed with exit code ${cleanRes.status}`,
        quarantine,
      };
    }

    let quarantineNote = "";
    if (quarantine) {
      if (quarantine.ok) {
        quarantineNote = ` Quarantined ${quarantine.copied.length} file(s) to ${quarantine.dir}.`;
      } else {
        quarantineNote = ` Quarantine incomplete (${quarantine.error}), data loss allowed by operator.`;
      }
    }
    return {
      ok: true,
      targetSha,
      output: `Rolled back to ${targetSha}.${quarantineNote} ${cleanRes.stdout?.trim() || ""}`.trim(),
      quarantine,
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
    this.allowDataLoss = options.allowDataLoss === true;
    this.disarmed = false;
    this.rolledBack = false;
    this.intervalId = null;
    this.onDisarmExit = false;

    // Clear stale disarm file if it specifies a mismatched target SHA
    if (this.disarmFile && existsSync(this.disarmFile)) {
      try {
        const text = readFileSync(this.disarmFile, "utf8").trim();
        const targetSha = this.resolveTargetSha();
        if (text && targetSha && text !== targetSha) {
          unlinkSync(this.disarmFile);
        }
      } catch { /* mp-003-allow: an unreadable disarm file reads as armed, the safe default for the kill daemon */ }
    }
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
      } catch { /* mp-003-allow: an unreadable base-sha file means no pinned target, and the lifeguard refuses without one */ }
    }
    return null;
  }

  check(nowMs = Date.now()) {
    if (this.disarmed) {
      return { ok: true, disarmed: true, tripped: false };
    }

    if (this.disarmFile && existsSync(this.disarmFile)) {
      try {
        const text = readFileSync(this.disarmFile, "utf8").trim();
        const targetSha = this.resolveTargetSha();
        // Disarm if file is empty (global signal) or matches targetBaseSha
        if (!text || !targetSha || text === targetSha) {
          this.disarm();
          return { ok: true, disarmed: true, tripped: false, reason: "DISARMED_FOR_TARGET_SHA", targetSha };
        }
      } catch { /* mp-003-allow: an unreadable disarm file cannot prove disarm, so the kill authority stays armed (fail-closed) */ }
    }

    // Check heartbeat file mtime if configured
    if (this.heartbeatFile && existsSync(this.heartbeatFile)) {
      try {
        const stats = statSync(this.heartbeatFile);
        if (stats.mtimeMs > this.lastHeartbeatMs) {
          this.lastHeartbeatMs = stats.mtimeMs;
        }
      } catch { /* mp-003-allow: a missing heartbeat file keeps the last known mtime; staleness is judged by the heartbeat check, not here */ }
    }

    const status = checkProbationStatus({
      startTimeMs: this.startTimeMs,
      nowMs,
      timeoutMs: this.timeoutMs,
    });

    // Heartbeat check: only applies when a monitored launcher process is running
    const isLauncherRunning =
      this.killPidFiles.length > 0
        ? this.killPidFiles.some((f) => existsSync(f))
        : true;

    const heartbeatElapsed = Math.max(0, nowMs - this.lastHeartbeatMs);
    const heartbeatTripped = isLauncherRunning && heartbeatElapsed > this.heartbeatTimeoutMs;

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
          } catch { /* mp-003-allow: an unreadable pid file contributes no pid; the kill sweep proceeds with the pids it did find */ }
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
        rollback = executeRollback(this.repoDir, targetSha, { allowDataLoss: this.allowDataLoss });
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
        if (this.onDisarmExit) {
          process.exit(0);
        }
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
  let allowDataLoss = false;
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
    } else if (arg === "--allow-data-loss") {
      allowDataLoss = true;
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
    allowDataLoss,
  });

  if (watchMode) {
    watchdog.onDisarmExit = true;
    process.stdout.write(JSON.stringify({ status: "watching", timeout_ms: timeoutSec * 1000, heartbeat_file: heartbeatFile }) + "\n");
    // In watch mode, keep the event loop alive (unrefTimer = false)
    watchdog.start(2000, false);
  } else {
    const checkResult = watchdog.check();
    process.stdout.write(JSON.stringify(checkResult) + "\n");
  }
}
