import { declaredReproducer, requireAuthorizedWarrant } from "../core/warrant.mjs";
import { assertKeyEnrolled } from "../core/keyring.mjs";
import { resolveTrustRoot } from "../core/trust-root.mjs";
import { spawn, spawnSync } from "node:child_process";
import { join, resolve, relative, dirname } from "node:path";
import {
  readFileSync,
  readdirSync,
  existsSync,
  writeFileSync,
  mkdirSync,
  unlinkSync,
} from "node:fs";
import {
  ulid,
  sha256,
  jcs,
  EXIT_CODES,
  validateDocument,
  createLedgerWatcher,
} from "../core/index.mjs";
import { runAgent } from "./agent.mjs";
import {
  authorCandidate,
  captureGitAuthority,
  disposeAttempt,
  gitAuthorityChanged,
  measureTreeSurface,
  prepareAttempt,
  releaseCandidate,
  restoreGitAuthority,
  snapshotWorkerTree,
  treeMatchesBase,
} from "./supervisor-attempt.mjs";
import { verifyAttempt } from "./verify.mjs";
import { computePhi } from "./phi.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";
import { isCircuitBreakerTripped } from "./doctor.mjs";

/**
 * Law 2 — Privileged Parent Broker (mirql r supervisor).
 *
 * Coordinates unprivileged agent execution, executes verifyAttempt, creates
 * schema-checked Outcome (outcome.schema.json), signs attempt.outcome,
 * and appends to <mirqlDir>/ledger/events.jsonl.
 *
 * @param {object} options
 * @returns {any} supervisor execution result
 */
export function runSupervisor(options = {}) {
  const mirqlDir =
    options.mirqlDir ?? options.dir ?? join(process.cwd(), ".mirql");
  const workspaceDir = options.workspaceDir ?? process.cwd();
  resolveTrustRoot(mirqlDir, { workspaceDir });

  // Touch heartbeat and write launcher PID for watchdog monitoring
  const stateDir = join(mirqlDir, "state");
  const heartbeatPath = join(stateDir, "heartbeat");
  const pidPath = join(stateDir, "launcher.pid");

  try {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(heartbeatPath, `${Date.now()}\n`, "utf8");
    if (!options.skipPidFile) {
      writeFileSync(pidPath, `${process.pid}\n`, "utf8");
    }
  } catch (err) {
    if (process.env.MIRQL_DEBUG) {
      process.stderr.write(`[mirql-supervisor] State write error: ${err.message}\n`);
    }
  }

  // Start continuous heartbeat ticker process while supervisor executes
  const heartbeatTicker = options.noHeartbeatTicker ? null : startHeartbeatTicker(heartbeatPath, 2000);

  const cleanupState = () => {
    if (heartbeatTicker) {
      try { heartbeatTicker.kill(); } catch { /* mp-003-allow: best-effort kill of the detached heartbeat ticker during cleanup */ }
    }
    if (!options.skipPidFile) {
      try {
        if (existsSync(pidPath)) unlinkSync(pidPath);
      } catch { /* mp-003-allow: best-effort pidfile removal during cleanup; the process is ending anyway */ }
    }
  };

  try {

  // Law 11: caller fields select existing authority, never create it.
  const warrant = requireAuthorizedWarrant(mirqlDir, options);

  // 2. Supervisor keys are loaded from the external trust root.
  const keypair =
    options.keypair ??
    (options.signingKey
      ? { privateKey: options.signingKey, keyId: options.keyId ?? "ed25519:custom" }
      : getOrGenerateSupervisorKey(mirqlDir));

  assertKeyEnrolled(mirqlDir, "tool:run_supervisor", keypair);

  // Check circuit breaker before unprivileged worker invocation
  const workerTier = warrant.tier || options.tier || "flash";
  const supervisorNowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  if (isCircuitBreakerTripped(mirqlDir, `worker:${workerTier}`, supervisorNowMs) || isCircuitBreakerTripped(mirqlDir, "worker", supervisorNowMs)) {
    const breakerErr = new Error(`Circuit breaker tripped for worker tier "${workerTier}"`);
    breakerErr.code = "CIRCUIT_BREAKER_TRIPPED";
    throw breakerErr;
  }

  // The signed warrant names the reproducer, so a worker cannot pick the test
  // that judges its own change.
  const reproducerFile = declaredReproducer(warrant);
  const prepared = reproducerFile
    ? prepareAttempt(workspaceDir)
    : { ok: false, rule: "NO_REPRODUCER_DECLARED", detail: "The signed warrant does not name evidence.reproducer_test" };
  if (!prepared.ok) {
    return finalizeSupervisor(options, mirqlDir, workspaceDir, keypair, warrant, {
      agentResult: { ok: false, exitCode: EXIT_CODES.POLICY_DENIAL, violation: prepared.rule, detail: prepared.detail },
      verifyResult: refused(prepared.rule, prepared.detail),
      agentDuration: 0,
      treeDir: workspaceDir,
    });
  }
  try {
    return finalizeSupervisor(options, mirqlDir, workspaceDir, keypair, warrant,
      superviseAttempt(options, mirqlDir, keypair, warrant, prepared.attempt, reproducerFile));
  } finally {
    disposeAttempt(prepared.attempt);
  }
} finally {
  cleanupState();
}
}

function refused(rule, detail) {
  return { verified: false, verdict: "reject", rule, detail };
}

/**
 * One attempt: the worker runs in a private clone of the base commit, a
 * host tool authors its output (Law 3), and only the Git-mode verifier decides.
 * The verifier takes nothing from the caller beyond the warrant selection, so
 * a library caller cannot swap in its own checks and skip the warrant's scope
 * or its cumulative phi_budget (Law 13).
 */
function superviseAttempt(options, mirqlDir, keypair, warrant, attempt, reproducerFile) {
  const { attemptDir, baseSha } = attempt;
  const measured = { treeDir: attemptDir, baseCommit: baseSha };

  // Issue #47: the pre-execution Φ must be captured before the builder mutates
  // the tree. The verifier's measurement replaces it when one exists.
  measured.phiBefore = Number.isSafeInteger(options.phiBefore) ? options.phiBefore : computePhi(attemptDir).total;

  const authority = captureGitAuthority(attempt);
  const agentStartTime = Date.now();
  const agentResult = runAgent({
    ...options.agentOptions,
    env: options.env,
    command: options.builderCommand,
    modifiedFiles: options.modifiedFiles,
    cwd: attemptDir,
  });
  const done = (verifyResult, extra = {}) => ({
    ...measured, agentResult, verifyResult, agentDuration: Date.now() - agentStartTime, ...extra,
  });

  if (gitAuthorityChanged(attempt, authority)) {
    try {
      restoreGitAuthority(attempt, authority);
    } catch (error) {
      return done(refused("WORKER_TAMPERED_GIT", `The worker changed the workspace's Git configuration and restoring it failed: ${error.message}`));
    }
    return done(refused("WORKER_TAMPERED_GIT", "The worker changed the workspace's Git configuration; it was restored"));
  }
  let tree;
  try {
    tree = snapshotWorkerTree(attempt);
    measured.surface = measureTreeSurface(attempt, tree);
  } catch (error) {
    return done(refused("HOST_COMMIT_FAILED", error.message));
  }
  if (agentResult.ok !== true || agentResult.exitCode !== 0 || agentResult.signal) {
    return done(refused(agentResult.violation ?? agentResult.rule ?? "WORKER_FAILED",
      agentResult.detail ?? `The worker exited with ${agentResult.workerExitCode ?? agentResult.exitCode}`));
  }
  if (treeMatchesBase(attempt, tree)) {
    return done(refused("NO_WORKER_CHANGES", "The worker left no change to verify"));
  }
  let headSha;
  try {
    headSha = authorCandidate(attempt, tree, { jobId: options.jobId, warrantId: warrant.id });
  } catch (error) {
    return done(refused("HOST_COMMIT_FAILED", error.message));
  }
  measured.headCommit = headSha;
  let verifyResult;
  try {
    verifyResult = verifyAttempt({
      git: true,
      workspaceDir: attempt.workspaceDir,
      baseSha,
      headSha,
      reproducerFile,
      mirqlDir,
      warrantId: warrant.id,
      supervisorKeypair: keypair,
    });
    return done(verifyResult);
  } finally {
    // Only an accepted candidate stays pinned for the owner to merge.
    if (verifyResult?.verified !== true) releaseCandidate(attempt, headSha);
  }
}

/**
 * Deterministic content digest of a workspace tree (issue #16): hashes every
 * source file (sorted, path + content hash chain), excluding volatile state
 * directories. This is a REAL measurement of the produced tree — verifiable
 * by anyone re-running the same walk — never a synthetic placeholder.
 *
 * @param {string} workspaceDir
 * @returns {string} hex sha256
 */
function measureTreeDigest(workspaceDir) {
  // Skip volatile state wherever the mirql dir sits — mirql state may live in
  // .mirql/ OR (flat layouts) as sibling ledger/ and state/ directories.
  const skip = new Set([".git", ".mirql", "ledger", "state", "node_modules", "coverage", ".mutant-sandbox"]);
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (skip.has(entry.name)) continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(abs);
      } else if (entry.isFile() && /\.(mjs|json|yaml|toml|md|lock)$/.test(entry.name)) {
        files.push(abs);
      }
    }
  };
  walk(workspaceDir);
  files.sort();
  let chain = "mirql-tree-v1";
  for (const abs of files) {
    const rel = relative(workspaceDir, abs).replaceAll("\\", "/");
    try {
      chain = `${chain}\n${rel}:${sha256(readFileSync(abs, "utf8"))}`;
    } catch {
      // Unreadable file: contribute the path only — never fail open to a guess
      chain = `${chain}\n${rel}:<unreadable>`;
    }
  }
  // core sha256() already returns the canonical "sha256:<hex>" form
  return sha256(chain).replace(/^sha256:/, "");
}

/** Real git HEAD of the workspace, or null when not a git repo. */
function measureGitHead(workspaceDir) {
  try {
    const res = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: workspaceDir,
      encoding: "utf8",
      timeout: 10_000,
    });
    if (res.status === 0 && /^[0-9a-f]{40,64}\n?$/.test(res.stdout || "")) {
      return res.stdout.trim();
    }
  } catch { /* mp-003-allow: an unreadable git answer means no base sha, and the caller treats null as unavailable */ }
  return null;
}

function finalizeSupervisor(options, mirqlDir, workspaceDir, keypair, warrant, run) {
  const { agentResult, verifyResult, agentDuration, treeDir, baseCommit, headCommit } = run;
  const nowMs = Number.isSafeInteger(options.nowMs)
    ? options.nowMs
    : Date.now();
  const jobId = options.jobId ?? ulid(nowMs);
  const warrantId = warrant.id;

  // H1: leased-job configuration epoch (Law 5 fencing). The queue fold
  // discards any attempt.outcome whose epoch does not match the live lease,
  // so the supervisor must thread the leased epoch through the Outcome and
  // the signed ledger event. Defaults to 1 for legacy callers.
  const epoch =
    Number.isSafeInteger(options.epoch) && options.epoch >= 0
      ? options.epoch
      : 1;

  // Real metrics computation (no hardcoded fake placeholders). The verifier's
  // measurement of the Git trees wins. Without one, phi_before is the snapshot
  // taken before the worker ran (issue #47) and phi_after is measured here.
  const verifierPhi = verifyResult.phi;
  const hasVerifierPhi = Number.isSafeInteger(verifierPhi?.phi_before) && Number.isSafeInteger(verifierPhi?.phi_after);
  const realPhi = hasVerifierPhi ? verifierPhi.phi_after : computePhi(treeDir).total;
  const phiBefore = hasVerifierPhi ? verifierPhi.phi_before : (options.phiBefore ?? run.phiBefore ?? realPhi);
  const phiAfter = hasVerifierPhi ? realPhi : (options.phiAfter ?? realPhi);
  const deltaPhi = phiAfter - phiBefore;

  // Measured-or-flagged digests (issue #16): every SHA below is a REAL
  // measurement — a content digest of the produced tree, or a digest of an
  // actual git commit — so Law-5 base-pinning can be cross-checked against git
  // later. No synthetic "sha256 of a prose string" placeholders.
  const treeHash =
    options.treeHash && /^sha256:[0-9a-f]{64}$/.test(options.treeHash)
      ? options.treeHash
      : `sha256:${measureTreeDigest(treeDir)}`;

  // Without a host-authored candidate the attempt produced nothing past its
  // base. Without Git at all, the tree digest is the honest witness.
  const baseGit = baseCommit ?? measureGitHead(workspaceDir);
  const baseSha = baseGit ? sha256(`git-head:${baseGit}`) : treeHash; // core sha256() returns the prefixed form
  const headSha = headCommit ? sha256(`git-head:${headCommit}`) : baseSha;

  // Measured-or-flagged telemetry (issue #16): the supervisor has no real
  // usage counter of its own, so it NEVER invents thrift/cost numbers. Real
  // measurements arrive via options (gateway-backed runners) and are flagged
  // measured:1; everything else is flagged measured:0 and the ledger payload
  // carries null — downstream budget/thrift folds treat unmeasured as 0 and
  // can distinguish it via the flag. The old defaults (500/250/750 tokens,
  // cost = duration x 10) are gone.
  const thriftInput = options.thrift;
  const thriftMeasured =
    thriftInput &&
    Number.isSafeInteger(thriftInput.model_calls) &&
    Number.isSafeInteger(thriftInput.tokens_in) &&
    Number.isSafeInteger(thriftInput.tokens_out) &&
    Number.isSafeInteger(thriftInput.cache_hits);

  const costMicroUsd = Number.isSafeInteger(options.costMicroUsd)
    ? options.costMicroUsd
    : null;
  const tokensConsumed = thriftMeasured
    ? thriftInput.tokens_in + thriftInput.tokens_out
    : null;

  // If the agent command fails (non-zero exit or killed by signal),
  // outcome status must be "fail" and verdict: "reject" (B3)
  const isAgentSuccess =
    agentResult.ok === true &&
    agentResult.exitCode === 0 &&
    !agentResult.signal;

  const isOverallPass = isAgentSuccess && verifyResult.verified === true;
  const outcomeStatus = isOverallPass ? "pass" : "fail";
  const outcomeVerdict = isOverallPass ? "auto_merge" : "reject";
  // Why the attempt ended this way, shown in `mirql i digest`.
  const rule = verifyResult.rule ?? (isOverallPass ? "MP-000" : "VERIFIER_NO_RULE");

  // Build canonical Outcome document (schemas/outcome.schema.json)
  const outcome = {
    v: 1,
    id: ulid(nowMs),
    job_id: jobId,
    warrant_id: warrantId,
    epoch,
    status: outcomeStatus,
    base_sha: baseSha,
    head_sha: headSha,
    tree_hash: treeHash,
    evidence: {
      verified: isOverallPass ? 1 : 0,
      checks_run: 4,
      red_on_base: verifyResult.checks?.red_on_base?.passed ? 1 : 0,
      green_on_head: verifyResult.checks?.green_on_head?.passed ? 1 : 0,
      re_red_on_revert: (verifyResult.checks?.re_red_on_revert ?? verifyResult.checks?.necessity_check)?.passed ? 1 : 0,
      duration_ms: Math.max(1, agentDuration),
    },
    anti_cheat: {
      violations_count: verifyResult.flags?.length ?? 0,
      flags: verifyResult.flags ?? [],
    },
    phi: {
      phi_before: phiBefore,
      phi_after: phiAfter,
      delta_phi: deltaPhi,
    },
    surface: (() => {
      if (
        options.surface &&
        Number.isSafeInteger(options.surface.files_changed) &&
        Number.isSafeInteger(options.surface.lines_added) &&
        Number.isSafeInteger(options.surface.lines_removed)
      ) {
        return { measured: 1, ...options.surface };
      }
      return run.surface ? { measured: 1, ...run.surface } : { measured: 0 };
    })(),
    thrift: thriftMeasured
      ? { measured: 1, ...thriftInput }
      : { measured: 0 },
    reconciliation: {
      entries_counted: 1,
      balanced: 1,
    },
    cost: costMicroUsd !== null ? { measured: 1, micro_usd: costMicroUsd } : { measured: 0 },
  };

  const validation = validateDocument("outcome", outcome);
  if (!validation.valid) {
    throw new Error(
      `Invalid outcome document: ${JSON.stringify(validation.errors)}`,
    );
  }

  // Sign and append attempt.outcome event to ledger
  // H1: the leased epoch is recorded at both the event envelope level and in
  // the payload (`payload.epoch` is what the queue fold fences against). The
  // payload status uses the queue's terminal vocabulary ("completed"/"failed")
  // while the Outcome document keeps its own "pass"/"fail" status.
  const event = appendSupervisorEvent(
    mirqlDir,
    {
      type: "attempt.outcome",
      epoch,
      payload: {
        job_id: jobId,
        warrant_id: warrantId,
        epoch,
        status: isOverallPass ? "completed" : "failed",
        verdict: outcomeVerdict,
        rule,
        ...(verifyResult.verdict && verifyResult.verdict !== outcomeVerdict ? { verifier_verdict: verifyResult.verdict } : {}),
        head_commit: headSha,
        ...(baseCommit ? { base_commit: baseCommit } : {}),
        ...(headCommit ? { candidate_commit: headCommit } : {}),
        // Issue #46: unmeasured telemetry is omitted, never null — the log
        // fold behind `mirql l view` rejects a null cost as a Law 17
        // violation, which bricks replay of the supervisor's own ledger.
        ...(tokensConsumed !== null ? { tokens_consumed: tokensConsumed } : {}),
        ...(costMicroUsd !== null ? { cost_micro_usd: costMicroUsd } : {}),
        phi_before: phiBefore,
        phi_after: phiAfter,
      },
      nowMs,
    },
    keypair,
  );

  return {
    outcome,
    validation,
    verified: isOverallPass,
    verdict: outcomeVerdict,
    rule,
    agentResult,
    verifyResult,
    event,
  };
}


/**
 * Updates the watchdog heartbeat timestamp.
 *
 * @param {string} mirqlDir
 */
export function touchHeartbeat(mirqlDir) {
  try {
    const stateDir = join(mirqlDir, "state");
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(stateDir, "heartbeat"), `${Date.now()}\n`, "utf8");
  } catch { /* mp-003-allow: a heartbeat that cannot be written leaves the stale timestamp for the lifeguard to judge */ }
}

/**
 * Starts a background heartbeat ticker process that refreshes the heartbeat file.
 *
 * @param {string} heartbeatPath
 * @param {number} [intervalMs=2000]
 * @returns {import("node:child_process").ChildProcess | null}
 */
export function startHeartbeatTicker(heartbeatPath, intervalMs = 2000) {
  try {
    const safeInterval =
      Number.isSafeInteger(Number(intervalMs)) && Number(intervalMs) > 0
        ? Number(intervalMs)
        : 2000;
    const code = `const fs = require('node:fs'); const f = process.argv[1]; function tick() { if (process.ppid && process.ppid !== 1) { try { process.kill(process.ppid, 0); } catch { process.exit(0); } } try { fs.writeFileSync(f, Date.now() + '\\n', 'utf8'); } catch { /* mp-003-allow: the ticker child is a fire-and-forget best-effort writer */ } } tick(); setInterval(tick, ${safeInterval});`;
    const cp = spawn(
      process.execPath,
      ["-e", code, heartbeatPath],
      { stdio: "ignore", detached: false },
    );
    return cp;
  } catch {
    return null;
  }
}

/**
 * Emits a failure attempt.outcome to the ledger to release a job lease
 * when a supervisor step fails to retrieve the warrant or throws an unhandled error.
 */
function recordFailureOutcome(mirqlDir, jobId, warrantId, epoch, reason = "execution_failure", rule = "SUPERVISOR_ERROR") {
  try {
    const keypair = getOrGenerateSupervisorKey(mirqlDir);
    appendSupervisorEvent(
      mirqlDir,
      {
        type: "attempt.outcome",
        epoch,
        payload: {
          job_id: jobId,
          warrant_id: warrantId,
          epoch,
          status: "failed",
          verdict: "reject",
          rule,
          cost_micro_usd: 0,
          tokens_consumed: 0,
          error: reason,
        },
        nowMs: Date.now(),
      },
      keypair,
    );
  } catch (err) {
    if (process.env.MIRQL_DEBUG) {
      process.stderr.write(`[mirql-supervisor-reactive] recordFailureOutcome error: ${err.message}\n`);
    }
  }
}

/**
 * Law 14 & Milestone M1: Event-Driven Reactive Supervisor Loop.
 * Listens for new events on the ledger (job.enqueued, warrant.minted, human.intent)
 * via zero-polling LedgerWatcher, automatically executing supervisor steps on demand.
 *
 * @param {object} options
 * @param {string} [options.mirqlDir]
 * @param {boolean} [options.initialRun=false]
 * @param {Function} [options.leaseJob] - Optional callback to lease next job
 * @param {Function} [options.getWarrant] - Optional callback to look up warrant document
 * @returns {Promise<{ watcher: import("../core/watcher.mjs").LedgerWatcher, getStepsExecuted: () => number, close: () => void }>}
 */
export async function runSupervisorReactive(options = {}) {
  const mirqlDir = options.mirqlDir ?? options.dir ?? join(process.cwd(), ".mirql");
  const ledgerPath = join(mirqlDir, "ledger", "events.jsonl");

  let stepsExecuted = 0;
  let lastResult = null;
  let inFlight = false;
  let queuedRerun = false;
  const pendingEvents = [];
  let expiryTimer = null;
  let wakeAtMs = Infinity;
  let finished = false;
  let resolveDone;
  const done = new Promise((res) => { resolveDone = res; });

  const finish = () => {
    if (finished) return;
    finished = true;
    if (expiryTimer) {
      clearTimeout(expiryTimer);
      expiryTimer = null;
    }
    if (!watcher.closed) watcher.close();
    resolveDone();
  };

  const watcher = createLedgerWatcher(ledgerPath, {
    debounceMs: options.debounceMs ?? 25,
    fromBeginning: false,
  });

  watcher.on("error", (err) => {
    if (process.env.MIRQL_DEBUG) {
      process.stderr.write(`[mirql-supervisor-reactive] Watcher error: ${err.message}\n`);
    }
  });

  const scheduleExpiryWake = (expiresAtMs) => {
    if (watcher.closed || !Number.isSafeInteger(expiresAtMs) || expiresAtMs >= wakeAtMs) return;
    clearTimeout(expiryTimer);
    wakeAtMs = expiresAtMs;
    const now = Date.now();
    const delay = Math.min(2 ** 31 - 1, Math.max(50, expiresAtMs - now + 50));
    expiryTimer = setTimeout(() => {
      expiryTimer = null;
      wakeAtMs = Infinity;
      if (!watcher.closed) {
        runStep(null).catch(() => { /* mp-003-allow: runStep reports its own failures; this only drops the promise rejection placeholder */ });
      }
    }, delay);
  };

  const runStep = async (triggerEvent) => {
    if (watcher.closed) return null;
    if (inFlight) {
      queuedRerun = true;
      if (triggerEvent && typeof options.leaseJob !== "function") {
        pendingEvents.push(triggerEvent);
      }
      return null;
    }

    inFlight = true;
    try {
      let leasedThisPass = false;
      do {
        queuedRerun = false;
        leasedThisPass = false;

        let currentEvt = triggerEvent;
        if (typeof options.leaseJob !== "function") {
          currentEvt = pendingEvents.shift() ?? null;
          if (!currentEvt && !triggerEvent) {
            break;
          }
          if (!currentEvt) {
            currentEvt = triggerEvent;
            triggerEvent = null;
          }
        }

        let warrant = options.warrant;
        let epoch = options.epoch ?? 1;
        let jobId = options.jobId;
        let leasedWarrantId = null;

        if (typeof options.leaseJob === "function") {
          let leaseRes = null;
          try {
            leaseRes = await options.leaseJob(mirqlDir);
          } catch (leaseErr) {
            if (process.env.MIRQL_DEBUG) {
              process.stderr.write(`[mirql-supervisor-reactive] leaseJob error: ${leaseErr.message}\n`);
            }
            break;
          }

          if (watcher.closed) {
            if (leaseRes?.status === "leased") {
              recordFailureOutcome(mirqlDir, leaseRes.job_id, leaseRes.warrant_id,
                leaseRes.epoch ?? epoch, "Daemon stopped during lease acquisition");
            }
            break;
          }
          if (leaseRes?.status === "breaker_tripped") {
            // All active trips must expire before leasing is possible. A signed
            // doctor reset or throttle can release the queue earlier and has its own wake.
            const deadlines = Array.isArray(leaseRes.breakers)
              ? leaseRes.breakers.map((b) => b?.expires_at_ms).filter(Number.isSafeInteger)
              : [];
            if (deadlines.length > 0) {
              scheduleExpiryWake(Math.max(...deadlines));
            }
            if (queuedRerun) {
              continue;
            }
            break;
          }
          if (!leaseRes || !leaseRes.ok) {
            break;
          }

          if (leaseRes.status === "concurrency_limit") {
            if (leaseRes.active_lease?.expires_at_ms) {
              scheduleExpiryWake(leaseRes.active_lease.expires_at_ms);
            }
            break;
          }

          if (leaseRes.status !== "leased") {
            break;
          }

          leasedThisPass = true;
          epoch = leaseRes.epoch ?? epoch;
          jobId = leaseRes.job_id ?? jobId;
          leasedWarrantId = leaseRes.warrant_id;

          if (leaseRes.warrant) {
            warrant = leaseRes.warrant;
          } else if (typeof options.getWarrant === "function") {
            try {
              warrant = await options.getWarrant(leaseRes.warrant_id);
            } catch (wErr) {
              warrant = null;
            }
          } else {
            warrant = { id: leaseRes.warrant_id };
          }

          // If job was leased but warrant could not be resolved, fail closed & release lease!
          if (!warrant) {
            recordFailureOutcome(
              mirqlDir,
              jobId,
              leasedWarrantId,
              epoch,
              `Warrant ${leasedWarrantId} not found or resolution failed`,
            );
            continue;
          }
        } else if (currentEvt?.payload?.warrant) {
          warrant = currentEvt.payload.warrant;
          jobId = currentEvt.payload.job_id ?? jobId;
          epoch = currentEvt.epoch ?? currentEvt.payload.epoch ?? epoch;
        } else if (currentEvt?.payload?.warrant_id) {
          warrant = { id: currentEvt.payload.warrant_id };
          jobId = currentEvt.payload.job_id ?? jobId;
          epoch = currentEvt.epoch ?? currentEvt.payload.epoch ?? epoch;
        }

        if (!warrant && !options.warrantId) {
          if (typeof options.leaseJob === "function") break;
          continue;
        }

        try {
          const stepResult = await runSupervisor({
            ...options,
            warrant,
            warrantId: warrant?.id ?? options.warrantId,
            epoch,
            jobId,
            triggerEvent: currentEvt,
          });
          if (stepResult) {
            stepsExecuted++;
            lastResult = stepResult;
            watcher.emit("step", stepResult);
            // Drain mode: stop after maxSteps executed steps (the watcher's
            // do-while exits on watcher.closed, so no further leases happen).
            if (Number.isSafeInteger(options.maxSteps) && stepsExecuted >= options.maxSteps) {
              finish();
            }
          }
        } catch (stepErr) {
          if (process.env.MIRQL_DEBUG) {
            process.stderr.write(`[mirql-supervisor-reactive] Execution error: ${stepErr.message}\n`);
          }
          // If a leased job failed execution, record failure to release lease from the queue fold
          if (leasedThisPass && jobId && (leasedWarrantId || warrant?.id)) {
            recordFailureOutcome(
              mirqlDir,
              jobId,
              leasedWarrantId ?? warrant?.id,
              epoch,
              stepErr.message,
              typeof stepErr.code === "string" ? stepErr.code : undefined,
            );
          }
        }
      } while (
        ((typeof options.leaseJob === "function" ? (queuedRerun || leasedThisPass) : (queuedRerun || pendingEvents.length > 0))) &&
        !watcher.closed
      );
    } finally {
      inFlight = false;
    }
    return lastResult;
  };

  if (typeof options.leaseJob === "function") {
    const isBreakerReleaseEvent = (event) => {
      if (!event) return false;
      const p = event.payload || {};
      if (p.probe === "doctor" && p.breaker) {
        // Reset or throttle removes binding trips; cooldown changes adjust deadlines
        return true;
      }
      return event.type === "doctor_breaker";
    };
    watcher.on("probe.completed", (event) => {
      if (isBreakerReleaseEvent(event)) {
        // Events only wake the scheduler. Lease admission rechecks the signed ledger.
        runStep(null).catch((err) => watcher.emit("error", err));
      }
    });
    watcher.on("doctor_breaker", (event) => {
      if (isBreakerReleaseEvent(event)) {
        runStep(null).catch((err) => watcher.emit("error", err));
      }
    });
  }

  const reactiveEvents = ["job.enqueued", "warrant.minted", "human.intent"];

  for (const evtType of reactiveEvents) {
    watcher.on(evtType, (evt) => {
      runStep(evt).catch((err) => {
        if (process.env.MIRQL_DEBUG) {
          process.stderr.write(`[mirql-supervisor-reactive] listener error: ${err.message}\n`);
        }
      });
    });
  }

  if (options.initialRun) {
    await runStep(null).catch(() => { /* mp-003-allow: runStep reports its own failures; this only drops the promise rejection placeholder */ });
  }

  return {
    watcher,
    getStepsExecuted: () => stepsExecuted,
    getLastStep: () => lastResult,
    start: () => runStep(null),
    done,
    close: finish,
  };
}

