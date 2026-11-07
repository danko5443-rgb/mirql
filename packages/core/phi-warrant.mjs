// packages/core/phi-warrant.mjs — the owner's standing Phi allowance for CI (Law 13).
//
// The signed warrants in the ledger live on the owner's machine, so CI cannot
// see them. This is the same allowance in a form CI can check: one document the
// owner signs, verified against a public key pinned in the base branch. An
// unsigned document or a bare number grants nothing, and a missing pin means 0.
// A warrant may also carry a signed `phi_per_pr`: no single PR may spend more
// than that, so one large PR cannot use up the whole budget without the owner.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { verifyEvent } from "./ed25519.mjs";

export const PHI_WARRANT_DOMAIN = "mirql/phi-warrant/v1";
export const PHI_WARRANT_PIN_PATH = "policy/phi-warrant-key.json";

const SHA_RE = /^[0-9a-f]{40}$/;
const PUBLIC_KEY_RE = /^[A-Za-z0-9_-]{43}$/;

/** The pinned owner public key in this checkout, or null. Read only from the base copy. */
export function readPhiWarrantPin(rootDir = process.cwd()) {
  try {
    const { publicKey } = JSON.parse(readFileSync(join(rootDir, PHI_WARRANT_PIN_PATH), "utf8"));
    return PUBLIC_KEY_RE.test(publicKey ?? "") ? publicKey : null;
  } catch { /* mp-003-allow: a missing or unreadable pin means no allowance */
    return null;
  }
}

/**
 * Checks a warrant, given as an object or JSON text, against the pinned key.
 *
 * @returns {{ ok: true, warrant: object } | { ok: false, reason: string }}
 */
export function verifyPhiWarrant(document, publicKey) {
  let warrant = document;
  if (typeof document === "string") {
    try {
      warrant = JSON.parse(document);
    } catch { /* mp-003-allow: reported to the caller as a refusal */
      return { ok: false, reason: "NOT_JSON" };
    }
  }
  if (warrant?.domain !== PHI_WARRANT_DOMAIN) return { ok: false, reason: "WRONG_DOMAIN" };
  if (warrant.writer?.ns !== "human:owner") return { ok: false, reason: "NOT_OWNER" };
  if (warrant.writer?.key_id !== `ed25519:${publicKey}`) return { ok: false, reason: "WRONG_KEY" };
  if (!Number.isSafeInteger(warrant.phi_budget) || warrant.phi_budget < 0) return { ok: false, reason: "BAD_BUDGET" };
  if (warrant.phi_per_pr !== undefined && (!Number.isSafeInteger(warrant.phi_per_pr) || warrant.phi_per_pr < 1)) return { ok: false, reason: "BAD_PER_PR" };
  if (!SHA_RE.test(warrant.base_sha ?? "")) return { ok: false, reason: "BAD_BASE_SHA" };
  const signature = verifyEvent(warrant, publicKey);
  return signature.ok ? { ok: true, warrant } : { ok: false, reason: "BAD_SIGNATURE" };
}

/** What one PR may grow Phi by under a verified warrant: what is left, capped by `phi_per_pr` when the warrant sets one. */
export function perPrAllowance(warrant, remaining) {
  return warrant.phi_per_pr === undefined ? remaining : Math.min(remaining, warrant.phi_per_pr);
}

/** Phi one PR may add under a warrant after `spent`; 0 unless the warrant verifies against the pin. */
export function phiWarrantAllowance(rootDir, document, spent) {
  if (!Number.isSafeInteger(spent) || spent < 0) return 0;
  const publicKey = readPhiWarrantPin(rootDir);
  const verified = publicKey ? verifyPhiWarrant(document, publicKey) : { ok: false };
  return verified.ok ? perPrAllowance(verified.warrant, Math.max(0, verified.warrant.phi_budget - spent)) : 0;
}
