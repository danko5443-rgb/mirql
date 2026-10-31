/**
 * SHA-256 content addressing. All mirql hashes are strings of the form
 * `sha256:<64 lowercase hex characters>` so a hash is self-describing in logs,
 * ledgers and mergeproof evidence.
 */
import { createHash } from "node:crypto";
import { jcs } from "./jcs.mjs";

/**
 * Compute the SHA-256 of a UTF-8 string (or byte buffer).
 *
 * @param {string | Uint8Array} input
 * @returns {string} `"sha256:<64 lowercase hex>"`
 * @throws {TypeError} if input is neither a string nor a Uint8Array.
 */
export function sha256(input) {
  const hasher = createHash("sha256");
  if (typeof input === "string") {
    hasher.update(input, "utf8");
  } else if (input instanceof Uint8Array) {
    hasher.update(input);
  } else {
    throw new TypeError(
      "sha256: input must be a UTF-8 string or a Uint8Array/Buffer",
    );
  }
  return "sha256:" + hasher.digest("hex");
}

/**
 * Hash any JSON-representable value via canonical JSON. Deterministic across
 * key order, whitespace and runtime — two structurally equal documents always
 * produce the same hash.
 *
 * @param {unknown} value
 * @returns {string} `"sha256:<64 lowercase hex>"` of `jcs(value)`
 */
export function jcsHash(value) {
  return sha256(jcs(value));
}
