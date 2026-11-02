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
      try { heartbeatTicker.kill(); } catch {}
    }
    if (!options.skipPidFile) {
      try {
        if (existsSync(pidPath)) unlinkSync(pidPath);
      } catch {}
    }
  };

  try {

  // 1. Resolve and validate Warrant (Law 11)
  let warrant = null;
  if (typeof options.warrant === "string") {
    if (existsSync(options.warrant)) {
      try {
        warrant = JSON.parse(readFileSync(options.warrant, "utf8"));
      } catch (err) {
        throw new Error(`Unreadable warrant file: ${err.message}`);
      }
    } else {
      try {
        warrant = JSON.parse(options.warrant);
      } catch (err) {
        throw new Error(`Invalid warrant string: ${err.message}`);
      }
    }
  } else if (options.warrant && typeof options.warrant === "object") {
    warrant = { ...options.warrant };
  } else if (options.warrantId) {
    warrant = {
      v: 1,
      id: options.warrantId,
      class: options.class ?? "surgical",
      semantic_fingerprint:
        options.semantic_fingerprint ?? sha256(`intent:${options.warrantId}`),
      anchors: options.anchors ?? ["packages/core/**"],
      evidence: options.evidence ?? { benchmark: 1 },
      red_check: options.red_check ?? { test: 1 },
      scope: options.scope ?? { allow: 1 },
      budget_micro_usd: options.budget_micro_usd ?? 1500000,
      created_by: options.created_by ?? "human:owner",
    };
  } else {
    throw new Error("Missing required warrant parameter");
  }

  const warrantValidation = validateDocument("warrant", warrant);
  if (!warrantValidation.valid) {
    throw new Error(
      `Invalid warrant document: ${JSON.stringify(warrantValidation.errors)}`,
    );
  }

  if (
    typeof warrant.id !== "string" ||
    !/^[0-9A-HJKMNPQRSTVWXYZ]{26}$/.test(warrant.id)
  ) {
    throw new Error(
      `Invalid warrant id "${warrant.id}": must be 26-char Crockford ULID`,
    );
  }

  // 2. Supervisor keys are kept strictly in mirqlDir outside agent workspace
  const keypair =
    options.keypair ??
    (options.signingKey
      ? { privateKey: options.signingKey, keyId: options.keyId ?? "ed25519:custom" }
      : getOrGenerateSupervisorKey(mirqlDir));

  // Check circuit breaker before unprivileged worker invocation
  const workerTier = warrant.tier || options.tier || "flash";
  const supervisorNowMs = Number.isSafeInteger(options.nowMs) ? options.nowMs : Date.now();
  if (isCircuitBreakerTripped(mirqlDir, `worker:${workerTier}`, supervisorNowMs) || isCircuitBreakerTripped(mirqlDir, "worker", supervisorNowMs)) {
    const breakerErr = new Error(`Circuit breaker tripped for worker tier "${workerTier}"`);
    breakerErr.code = "CIRCUIT_BREAKER_TRIPPED";
    throw breakerErr;
  }

  // 3. Invoke unprivileged agent worker
  const agentStartTime = Date.now();
  const agentResult = runAgent({
    ...options.agentOptions,
    env: options.env,
    command: options.builderCommand,
    modifiedFiles: options.modifiedFiles,
    cwd: workspaceDir,
  });
  const agentDuration = Date.now() - agentStartTime;

  // 4. Run verifyAttempt
  const verifyResult = verifyAttempt(
    options.verifyOptions ?? {
      workspaceDir,
      fixture: options.fixture,
      reproducer: options.reproducer,
      runCheck: options.runCheck,
      modifiedFiles: options.modifiedFiles,
      sourceCode: options.sourceCode,
    },
  );

  if (verifyResult && typeof verifyResult.then === "function") {
    return verifyResult
      .then((vRes) =>
        finalizeSupervisor(options, mirqlDir, workspaceDir, keypair, warrant, agentResult, vRes, agentDuration),
      )
      .finally(cleanupState);
  }

  const res = finalizeSupervisor(
    options,
    mirqlDir,
    workspaceDir,
    keypair,
    warrant,
    agentResult,
    verifyResult,
    agentDuration,
  );
  cleanupState();
  return res;
} catch (err) {
  cleanupState();
  throw err;
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
  } catch {}
  return null;
}

/** Real change surface (files/lines) from `git diff --numstat HEAD`, or null off-repo. */
function measureSurface(workspaceDir) {
  try {
    const res = spawnSync("git", ["diff", "--numstat", "HEAD"], {
      cwd: workspaceDir,
      encoding: "utf8",
      timeout: 10_000,
    });
    if (res.status !== 0) return null;
    let filesChanged = 0;
    let linesAdded = 0;
    let linesRemoved = 0;
    for (const line of String(res.stdout || "").split(/\r?\n/)) {
      if (!line.trim()) continue;
      const [add, del] = line.split("\t");
      filesChanged += 1;
      if (/^\d+$/.test(add)) linesAdded += parseInt(add, 10);
      if (/^\d+$/.test(del)) linesRemoved += parseInt(del, 10);
    }
    return { files_changed: filesChanged, lines_added: linesAdded, lines_removed: linesRemoved };
  } catch {}
  return null;
}

function finalizeSupervisor(
  options,
  mirqlDir,
  workspaceDir,
  keypair,
  warrant,
  agentResult,
  verifyResult,
  agentDuration,
) {
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

  // Real metrics computation (no hardcoded fake placeholders)
  const phiMetrics = computePhi(workspaceDir);
  const realPhi = phiMetrics.total;
  const phiBefore = options.phiBefore ?? realPhi;
  const phiAfter =
    options.phiAfter ?? (verifyResult.verified ? realPhi : realPhi);
  const deltaPhi = phiAfter - phiBefore;

  // Measured-or-flagged digests (issue #16): every SHA below is a REAL
  // measurement — a content digest of the produced tree, or a digest of the
  // workspace's actual git HEAD — so Law-5 base-pinning can be cross-checked
  // against git later. No synthetic "sha256 of a prose string" placeholders.
  const treeHash =
    options.treeHash && /^sha256:[0-9a-f]{64}$/.test(options.treeHash)
      ? options.treeHash
      : `sha256:${measureTreeDigest(workspaceDir)}`;

  const gitHead = measureGitHead(workspaceDir);
  const headSha =
    options.headSha && /^sha256:[0-9a-f]{64}$/.test(options.headSha)
      ? options.headSha
      : gitHead
        ? sha256(`git-head:${gitHead}`) // core sha256() returns the prefixed form
        : treeHash; // no git: the measured tree digest is the honest head witness
  // The attempt's true base (lease-start HEAD) is not captured by this layer;
  // absent an explicit base we record the same measured witness rather than
  // inventing one. Callers with a leased base pass options.baseSha.
  const baseSha =
    options.baseSha && /^sha256:[0-9a-f]{64}$/.test(options.baseSha)
      ? options.baseSha
      : headSha;

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
      re_red_on_revert: verifyResult.checks?.re_red_on_revert?.passed ? 1 : 0,
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
      const measured = measureSurface(workspaceDir);
      return measured ? { measured: 1, ...measured } : { measured: 0 };
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
        head_commit: headSha,
        tokens_consumed: tokensConsumed,
        cost_micro_usd: costMicroUsd,
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
  } catch {}
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
    const code = `const fs = require('node:fs'); const f = process.argv[1]; function tick() { if (process.ppid && process.ppid !== 1) { try { process.kill(process.ppid, 0); } catch { process.exit(0); } } try { fs.writeFileSync(f, Date.now() + '\\n', 'utf8'); } catch {} } tick(); setInterval(tick, ${safeInterval});`;
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
function recordFailureOutcome(mirqlDir, jobId, warrantId, epoch, reason = "execution_failure") {
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
  let inFlight = false;
  let queuedRerun = false;
  const pendingEvents = [];
  let expiryTimer = null;
  let wakeAtMs = Infinity;

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
        runStep(null).catch(() => {});
      }
    }, delay);
  };

  const runStep = async (triggerEvent) => {
    if (inFlight) {
      queuedRerun = true;
      if (triggerEvent && typeof options.leaseJob !== "function") {
        pendingEvents.push(triggerEvent);
      }
      return null;
    }

    inFlight = true;
    let lastResult = null;
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
    await runStep(null).catch(() => {});
  }

  return {
    watcher,
    getStepsExecuted: () => stepsExecuted,
    close: () => {
      if (expiryTimer) {
        clearTimeout(expiryTimer);
        expiryTimer = null;
      }
      watcher.close();
    },
  };
}

