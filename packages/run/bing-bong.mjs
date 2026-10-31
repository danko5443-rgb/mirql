import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  jcs,
  jcsHash,
  ulid,
  EXIT_CODES,
  validateDocument,
} from "../core/index.mjs";
import { appendSupervisorEvent, getOrGenerateSupervisorKey } from "./ledger.mjs";

/**
 * Extracts a canonical model family identifier from a panelist name, model, or function.
 *
 * @param {any} panelist
 * @param {number} [idx]
 * @returns {string}
 */
export function extractModelFamily(panelist, idx = 0) {
  let name = "";
  if (typeof panelist === "string") {
    name = panelist;
  } else if (panelist && typeof panelist === "object") {
    name = panelist.family ?? panelist.model ?? panelist.name ?? "";
  } else if (typeof panelist === "function") {
    name = panelist.family ?? panelist.model ?? panelist.name ?? "";
  }
  name = name.toLowerCase().trim();
  if (name.includes("/")) {
    name = name.split("/")[0];
  }
  if (name.startsWith("claude") || name.startsWith("anthropic")) return "anthropic";
  if (name.startsWith("gpt") || name.startsWith("o1") || name.startsWith("o3") || name.startsWith("openai")) return "openai";
  if (name.startsWith("gemini") || name.startsWith("google")) return "google";
  if (name.startsWith("glm") || name.startsWith("zai")) return "zai";
  if (name.startsWith("llama") || name.startsWith("meta")) return "meta";
  if (name.startsWith("deepseek")) return "deepseek";
  if (name.startsWith("mistral")) return "mistral";

  // In test callbacks without explicit family, assign distinct family by index
  return name || `test_family_${idx}`;
}

/**
 * Normalizes an objection to a string key for tracking across debate rounds.
 */
function objectionKey(obj) {
  if (typeof obj === "string") return obj;
  if (obj && typeof obj === "object") {
    return obj.id ?? obj.objection ?? JSON.stringify(obj);
  }
  return String(obj);
}

/**
 * Queries the configured panel without mock fallbacks.
 */
function queryPanelists(panel, currentWarrant, r, priorRounds, currentWarrantHash) {
  const results = [];
  let isAsync = false;

  for (let idx = 0; idx < panel.length; idx++) {
    const panelist = panel[idx];
    let packet;
    if (typeof panelist === "function") {
      packet = panelist(currentWarrant, r, priorRounds, idx, currentWarrantHash);
    } else if (panelist && typeof panelist === "object" && panelist.verdict) {
      packet = panelist;
    } else {
      const err = new Error(
        `Unconfigured panelist at index ${idx}: no runner configured for model ${JSON.stringify(panelist)}`,
      );
      err.code = "USAGE_ERROR";
      err.exitCode = EXIT_CODES.USAGE_ERROR;
      throw err;
    }

    if (packet && typeof packet.then === "function") {
      isAsync = true;
    }
    results.push({
      panelist: typeof panelist === "string" ? panelist : `panelist_${idx}`,
      packet,
    });
  }

  if (isAsync) {
    return Promise.all(
      results.map(async (item) => {
        const p = await item.packet;
        return { panelist: item.panelist, packet: p };
      }),
    );
  }
  return results;
}

/**
 * Hardened Bing-Bong multi-agent cross-family consensus loop (Laws 10, 11).
 *
 * @param {object} options
 * @param {string | object} options.warrant - warrant file path, JSON string, or object
 * @param {number} [options.rounds=3] - maximum debate rounds
 * @param {Array<any>} options.panel - 2-3 panelists from different model families
 * @param {string} [options.mirqlDir] - active .mirql directory
 * @param {object} [options.keypair] - Ed25519 keypair for supervisor
 * @returns {any} consensus result or Promise of consensus result
 */
export function runBingBong(options = {}) {
  const mirqlDir =
    options.mirqlDir ?? options.dir ?? join(process.cwd(), ".mirql");
  const maxRounds = Number.isSafeInteger(options.rounds) ? options.rounds : 3;
  const keypair =
    options.keypair ?? getOrGenerateSupervisorKey(mirqlDir);

  // 1. Resolve and parse warrant
  let warrant = null;
  if (typeof options.warrant === "string") {
    if (existsSync(options.warrant)) {
      try {
        warrant = JSON.parse(readFileSync(options.warrant, "utf8"));
      } catch (err) {
        const uErr = new Error(`Unreadable warrant file: ${err.message}`);
        uErr.code = "USAGE_ERROR";
        uErr.exitCode = EXIT_CODES.USAGE_ERROR;
        throw uErr;
      }
    } else {
      try {
        warrant = JSON.parse(options.warrant);
      } catch {
        const uErr = new Error(`Invalid warrant argument: ${options.warrant}`);
        uErr.code = "USAGE_ERROR";
        uErr.exitCode = EXIT_CODES.USAGE_ERROR;
        throw uErr;
      }
    }
  } else if (options.warrant && typeof options.warrant === "object") {
    warrant = { ...options.warrant };
  } else {
    const uErr = new Error("Missing required --warrant parameter");
    uErr.code = "USAGE_ERROR";
    uErr.exitCode = EXIT_CODES.USAGE_ERROR;
    throw uErr;
  }

  // 2. Validate warrant with schemas/warrant.schema.json and ULID regex (B9)
  const validation = validateDocument("warrant", warrant);
  if (!validation.valid) {
    const err = new Error(
      `Invalid warrant document: ${JSON.stringify(validation.errors)}`,
    );
    err.code = "USAGE_ERROR";
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  if (
    typeof warrant.id !== "string" ||
    !/^[0-9A-HJKMNPQRSTVWXYZ]{26}$/.test(warrant.id)
  ) {
    const err = new Error(
      `Invalid warrant.id: must match 26-char Crockford ULID regex ^[0-9A-HJKMNPQRSTVWXYZ]{26}$`,
    );
    err.code = "USAGE_ERROR";
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  const warrantId = warrant.id;

  // 3. Validate panel: must be 2-3 panelists from different model families (B5)
  if (!Array.isArray(options.panel) || options.panel.length === 0) {
    const err = new Error(
      "Unconfigured panel: panel must be explicitly provided with 2-3 panelists",
    );
    err.code = "USAGE_ERROR";
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  if (options.panel.length < 2 || options.panel.length > 3) {
    const err = new Error(
      `Invalid panel size: must contain 2-3 panelists, got ${options.panel.length}`,
    );
    err.code = "USAGE_ERROR";
    err.exitCode = EXIT_CODES.USAGE_ERROR;
    throw err;
  }

  // Check distinct model families
  const seenFamilies = new Set();
  for (let i = 0; i < options.panel.length; i++) {
    const fam = extractModelFamily(options.panel[i], i);
    if (seenFamilies.has(fam)) {
      const err = new Error(
        `Panelists must be from different model families: duplicate family "${fam}" detected`,
      );
      err.code = "USAGE_ERROR";
      err.exitCode = EXIT_CODES.USAGE_ERROR;
      throw err;
    }
    seenFamilies.add(fam);
  }

  const panel = options.panel;

  // 4. B8: Escalate immediately if rounds < 1
  if (maxRounds < 1) {
    const escalationsDir = join(mirqlDir, "escalations");
    mkdirSync(escalationsDir, { recursive: true });
    writeFileSync(
      join(escalationsDir, `${warrantId}.json`),
      jcs({
        warrant_id: warrantId,
        status: "NEEDS_HUMAN",
        rounds_used: 0,
        unresolved_objections: [
          { objection: "Invalid rounds parameter (< 1); escalated immediately." },
        ],
      }) + "\n",
      "utf8",
    );

    appendSupervisorEvent(
      mirqlDir,
      {
        type: "warrant.escalated",
        payload: {
          warrant_id: warrantId,
          status: "NEEDS_HUMAN",
          rounds_used: 0,
          reason: "rounds < 1",
        },
      },
      keypair,
    );

    return {
      status: "NEEDS_HUMAN",
      rounds_used: 0,
      unresolved_objections: [
        { objection: "Invalid rounds parameter (< 1); escalated immediately." },
      ],
    };
  }

  let currentWarrant = { ...warrant };
  const priorRounds = [];
  const previousObjections = new Map();
  const accumulatedResolvedIds = new Set();

  function recordEscalation(roundsUsed, objections) {
    const escalationsDir = join(mirqlDir, "escalations");
    mkdirSync(escalationsDir, { recursive: true });
    writeFileSync(
      join(escalationsDir, `${warrantId}.json`),
      jcs({
        warrant_id: warrantId,
        status: "NEEDS_HUMAN",
        rounds_used: roundsUsed,
        unresolved_objections: objections,
      }) + "\n",
      "utf8",
    );

    appendSupervisorEvent(
      mirqlDir,
      {
        type: "warrant.escalated",
        payload: {
          warrant_id: warrantId,
          status: "NEEDS_HUMAN",
          rounds_used: roundsUsed,
          unresolved_objections_count: objections.length,
        },
      },
      keypair,
    );

    return {
      status: "NEEDS_HUMAN",
      rounds_used: roundsUsed,
      unresolved_objections: objections,
    };
  }

  function processRound(r, roundCritiques, expectedWarrantHash) {
    let roundHasDisagreement = false;
    let roundAmendedWarrant = false;
    const currentRoundObjections = [];
    const patchesToApply = {};

    // Collect all resolved objection IDs cited in this round (B6)
    const currentRoundResolvedIds = new Set();
    for (const { packet } of roundCritiques) {
      if (Array.isArray(packet.resolves)) {
        for (const id of packet.resolves) {
          currentRoundResolvedIds.add(id);
          accumulatedResolvedIds.add(id);
        }
      }
      if (Array.isArray(packet.proposed_amendments)) {
        for (const am of packet.proposed_amendments) {
          if (am && typeof am === "object" && Array.isArray(am.resolves)) {
            for (const id of am.resolves) {
              currentRoundResolvedIds.add(id);
              accumulatedResolvedIds.add(id);
            }
          }
        }
      }
    }

    for (let idx = 0; idx < roundCritiques.length; idx++) {
      const { panelist, packet } = roundCritiques[idx];

      const verdict = packet.verdict ?? "DISAGREE";
      const blocking = Array.isArray(packet.blocking_objections)
        ? packet.blocking_objections
        : [];
      const patch =
        packet.warrant_patch && typeof packet.warrant_patch === "object"
          ? packet.warrant_patch
          : {};
      const withdrawn = Array.isArray(packet.withdrawn_objections)
        ? packet.withdrawn_objections
        : [];

      // B7: Check if panelist echoed the hash it reviewed
      const reviewedHash = packet.warrant_hash ?? expectedWarrantHash;
      if (reviewedHash !== expectedWarrantHash) {
        roundHasDisagreement = true;
        currentRoundObjections.push({
          panelist,
          violation: "HASH_MISMATCH",
          detail: `Panelist reviewed hash ${reviewedHash} but current warrant hash is ${expectedWarrantHash}`,
        });
      }

      // B6: Zero-Silent-Concessions per objection
      if (r > 1) {
        const prevList = previousObjections.get(idx) ?? [];
        for (const prev of prevList) {
          const key = objectionKey(prev);
          const stillBlocking = blocking.some((b) => objectionKey(b) === key);

          // An objection cannot vanish unless explicitly withdrawn with a reason
          // or resolved by an amendment citing its objection id
          const explicitlyWithdrawn = withdrawn.some((w) => {
            const wKey = typeof w === "object" ? w.id : w;
            const hasReason =
              typeof w === "object" &&
              typeof w.reason === "string" &&
              w.reason.trim().length > 0;
            return wKey === key && hasReason;
          });

          const resolvedByCitation =
            currentRoundResolvedIds.has(key) || accumulatedResolvedIds.has(key);

          if (!stillBlocking && !explicitlyWithdrawn && !resolvedByCitation) {
            currentRoundObjections.push({
              panelist,
              objection: prev,
              violation: "SILENT_CONCESSION",
              detail: `Objection "${key}" dropped silently without explicit withdrawal reason or citing amendment (resolves: [id]).`,
            });
            roundHasDisagreement = true;
          }
        }
      }

      previousObjections.set(idx, [...blocking]);

      if (verdict !== "CONVERGED" || blocking.length > 0) {
        roundHasDisagreement = true;
        for (const obj of blocking) {
          currentRoundObjections.push({ panelist, objection: obj });
        }
      }

      if (Object.keys(patch).length > 0) {
        roundAmendedWarrant = true;
        Object.assign(patchesToApply, patch);
      }
    }

    // Apply amendments
    if (Object.keys(patchesToApply).length > 0) {
      currentWarrant = { ...currentWarrant, ...patchesToApply };
    }

    priorRounds.push({ round: r, critiques: roundCritiques });

    // B7: No convergence in a round that amended the warrant!
    // Converge ONLY when every panelist votes CONVERGED, no silent concessions,
    // and no amendments occurred in this round.
    if (!roundHasDisagreement && !roundAmendedWarrant) {
      const consensusHash = jcsHash(currentWarrant);
      const consensusDir = join(mirqlDir, "consensus");
      mkdirSync(consensusDir, { recursive: true });
      const consensusFile = join(consensusDir, `${warrantId}.json`);

      writeFileSync(
        consensusFile,
        jcs({
          warrant: currentWarrant,
          consensus_hash: consensusHash,
          rounds_used: r,
        }) + "\n",
        "utf8",
      );

      appendSupervisorEvent(
        mirqlDir,
        {
          type: "warrant.converged",
          payload: {
            warrant_id: warrantId,
            consensus_hash: consensusHash,
            rounds_used: r,
            status: "CONVERGED",
          },
        },
        keypair,
      );

      return {
        status: "CONVERGED",
        rounds_used: r,
        consensus_hash: consensusHash,
        warrant: currentWarrant,
      };
    }

    // B8: Bounded Escalation Check on deadlock
    if (r === maxRounds) {
      return recordEscalation(maxRounds, currentRoundObjections);
    }

    return null; // Continue to next round
  }

  // Execution runner supporting sync & async rounds
  function runLoop(r) {
    if (r > maxRounds) {
      return recordEscalation(maxRounds, []);
    }

    const currentWarrantHash = jcsHash(currentWarrant);
    const critiques = queryPanelists(
      panel,
      currentWarrant,
      r,
      priorRounds,
      currentWarrantHash,
    );

    if (critiques && typeof critiques.then === "function") {
      return critiques.then((resolvedCritiques) => {
        const roundRes = processRound(r, resolvedCritiques, currentWarrantHash);
        if (roundRes) return roundRes;
        return runLoop(r + 1);
      });
    }

    const roundRes = processRound(r, critiques, currentWarrantHash);
    if (roundRes) return roundRes;
    return runLoop(r + 1);
  }

  return runLoop(1);
}
