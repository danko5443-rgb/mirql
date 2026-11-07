// packages/core/owner-key-guard.mjs — detect a plaintext human:owner key at rest.
//
// Lives in core so the git verifier can refuse to run candidate code beside a
// readable owner key without importing the inbox tool (no tool→tool coupling).
// Files are read only to test for a plaintext `privateKey`; nothing is logged.

import { readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { assertExternalTrustPath, trustFile } from "./trust-root.mjs";

export const HUMAN_KEY_FILENAME = "human_owner.key.private.json";

/** MIRQL_ALLOW_PLAINTEXT_OWNER_KEY=1 is the explicit fixture switch for disposable keys. */
export function plaintextOwnerKeyAllowed() {
  return process.env.MIRQL_ALLOW_PLAINTEXT_OWNER_KEY === "1";
}

function firstString(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0);
}

/** Canonical path of the owner key: an explicit external path, else the ledger's trust dir. */
export function resolveHumanKeyPath(mirqlDir, options = {}) {
  const explicit = firstString(options.humanKeyOut, options["human-key-out"], options.humanKeyPath);
  if (explicit !== undefined) return assertExternalTrustPath(explicit, mirqlDir);
  return trustFile(mirqlDir, HUMAN_KEY_FILENAME);
}

function isPlaintextOwnerKeyFile(path) {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) &&
      typeof parsed.privateKey === "string" && parsed.encrypted !== true;
  } catch {
    return false;
  }
}

/**
 * Find a plaintext human:owner private key so callers can refuse to rely on
 * one (verifier preflight). Checks resolveHumanKeyPath(mirqlDir, options)
 * first, then every `<trust root>/<ledger>/human_owner.key.private.json` under
 * the default trust root. Returns the path, or null when none is found or the
 * fixture switch is set.
 */
export function findUnprotectedOwnerKey(mirqlDir, options = {}) {
  if (plaintextOwnerKeyAllowed()) return null;
  const candidates = [];
  try {
    candidates.push(resolveHumanKeyPath(mirqlDir, options));
  } catch { /* mp-003-allow: an unresolvable key path exposes no file to guard, which is the guarded answer */
    // An unresolvable key path (e.g. unsafe trust root) exposes no file here.
  }
  const base = process.env.MIRQL_TRUST_ROOT ?? join(homedir(), ".mirql-trust");
  let ledgers = [];
  try {
    ledgers = readdirSync(base, { withFileTypes: true });
  } catch {
    ledgers = [];
  }
  for (const entry of ledgers) {
    if (entry.isDirectory() && !entry.isSymbolicLink()) {
      candidates.push(join(base, entry.name, HUMAN_KEY_FILENAME));
    }
  }
  return candidates.find(isPlaintextOwnerKeyFile) ?? null;
}
