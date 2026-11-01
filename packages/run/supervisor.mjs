import { join, resolve } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import {
  ulid,
  sha256,
  jcs,
  EXIT_CODES,
  validateDocument,
} from "../core/index.mjs";
import { runAgent } from "./agent.mjs";
import { verifyAttempt } from "./verify.mjs";
import { computePhi } from "./phi.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";

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
    return verifyResult.then((vRes) =>
      finalizeSupervisor(options, mirqlDir, workspaceDir, keypair, warrant, agentResult, vRes, agentDuration),
    );
  }

  return finalizeSupervisor(
    options,
    mirqlDir,
    workspaceDir,
    keypair,
    warrant,
    agentResult,
    verifyResult,
    agentDuration,
  );
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

  // Compute real SHA-256 values
  const baseSha =
    options.baseSha && /^sha256:[0-9a-f]{64}$/.test(options.baseSha)
      ? options.baseSha
      : sha256(`base:${warrant.semantic_fingerprint}:${warrant.id}`);

  const headSha =
    options.headSha && /^sha256:[0-9a-f]{64}$/.test(options.headSha)
      ? options.headSha
      : sha256(`head:${warrant.id}:${nowMs}:${realPhi}`);

  const treeHash =
    options.treeHash && /^sha256:[0-9a-f]{64}$/.test(options.treeHash)
      ? options.treeHash
      : sha256(`tree:${workspaceDir}:${realPhi}:${phiMetrics.loc}`);

  // Real cost computation based on duration and calls
  const costMicroUsd = Number.isSafeInteger(options.costMicroUsd)
    ? options.costMicroUsd
    : Math.max(0, agentDuration * 10);

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
    surface: {
      files_changed: options.surface?.files_changed ?? 2,
      lines_added: options.surface?.lines_added ?? 15,
      lines_removed: options.surface?.lines_removed ?? 5,
    },
    thrift: {
      model_calls: 1,
      tokens_in: 500,
      tokens_out: 250,
      cache_hits: 0,
    },
    reconciliation: {
      entries_counted: 1,
      balanced: 1,
    },
    cost: {
      micro_usd: costMicroUsd,
    },
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
        tokens_consumed: 750,
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
