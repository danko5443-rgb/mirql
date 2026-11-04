import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { jcs } from "./jcs.mjs";
import { sha256 } from "./hash.mjs";
import { validateDocument } from "./schema.mjs";
import { EXIT_CODES } from "./exit-codes.mjs";
import { readVerifiedLedger } from "./ledger-verify.mjs";

function refusal(message) {
  const error = new Error("WARRANT_UNAUTHORIZED: " + message);
  error.code = error.errorCode = "WARRANT_UNAUTHORIZED";
  error.exitCode = EXIT_CODES.POLICY_DENIAL;
  return error;
}

/** A repository-relative, forward-slash path that cannot leave the repository. */
export function isReproducerPath(value) {
  return typeof value === "string"
    && value.length > 0
    && !value.includes("\\")
    && !value.includes("\0")
    && !value.startsWith("/")
    && !/^[A-Za-z]:/.test(value)
    && value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

/** The reproducer named by a signed warrant, or null if it names no valid one. */
export function declaredReproducer(warrant) {
  const declared = warrant?.evidence?.reproducer_test;
  return isReproducerPath(declared) ? declared : null;
}

/** Resolve a selection, then require its exact human-signed ledger authorization. */
export function requireAuthorizedWarrant(mirqlDir, options = {}) {
  let input = options.warrant;
  if (typeof input === "string") {
    try { input = JSON.parse(existsSync(input) ? readFileSync(input, "utf8") : input); }
    catch { throw refusal("Cannot read the selected warrant document"); }
  }
  const id = input?.id ?? options.warrantId;
  if (typeof id !== "string" || !/^[0-9A-HJKMNPQRSTVWXYZ]{26}$/.test(id)) {
    throw refusal("Select an existing warrant with a valid Crockford ULID");
  }
  if (options.warrantId && options.warrantId !== id) throw refusal("Warrant selectors disagree");
  const events = readVerifiedLedger(mirqlDir);
  const grants = events.filter(event => event.type === "warrant.created" &&
    event.writer.ns === "human:owner" && (event.payload.warrant_id ?? event.payload.id) === id);
  if (grants.length === 0) throw refusal("No human-signed warrant.created event exists for " + id);
  const hashes = new Set(grants.map(event => event.payload.warrant_hash));
  if (hashes.size !== 1) throw refusal("Conflicting authorizations exist for this warrant ID");
  const grant = grants.at(-1);
  if (events.some(event => event.type === "warrant.revoked" && event.writer.ns === "human:owner" &&
      (event.payload.warrant_id ?? event.payload.id) === id)) throw refusal("The human revoked this warrant");
  if (grant.payload.expires_at_ms !== undefined &&
      (!Number.isSafeInteger(grant.payload.expires_at_ms) || grant.payload.expires_at_ms <= (options.nowMs ?? Date.now()))) {
    throw refusal("The signed warrant has expired or has an invalid deadline");
  }
  let warrant = input && typeof input === "object" && Object.keys(input).some(key => key !== "id") ? input : grant.payload.warrant;
  if (!warrant) {
    try { warrant = JSON.parse(readFileSync(join(mirqlDir, "warrants", id + ".json"), "utf8")); }
    catch { throw refusal("The authorized warrant document is unavailable"); }
  }
  const check = validateDocument("warrant", warrant);
  if (!check.valid || warrant.id !== id || warrant.created_by !== "human:owner") {
    throw refusal("The authorized warrant document is invalid");
  }
  if (sha256(jcs(warrant)) !== grant.payload.warrant_hash) {
    throw refusal("The warrant differs from the human-signed document hash");
  }
  // A detached copy prevents callers from mutating the authority after validation.
  return JSON.parse(jcs(warrant));
}
