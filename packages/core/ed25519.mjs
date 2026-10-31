/**
 * Ed25519 signing and event-envelope hashing.
 *
 * Keys are exchanged as plain strings so they can live in logs and config:
 * - `publicKey`  : base64url of the raw 32-byte Ed25519 public key
 *                  (43 chars) — also the suffix of `keyId`.
 * - `privateKey` : base64url of the PKCS#8 DER private key.
 * - `keyId`      : `"ed25519:<43-char base64url public key>"`.
 *
 * An event's `hash` is the SHA-256 of its RFC 8785 canonical JSON with `hash`
 * and `sig` removed; the `sig` is the Ed25519 signature over the UTF-8 bytes
 * of that hash string.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import { jcsHash } from "./hash.mjs";

// Fixed DER prefix of an Ed25519 SubjectPublicKeyInfo; appending the raw
// 32-byte public key yields the full SPKI structure.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Generate a fresh Ed25519 keypair.
 *
 * @returns {{ publicKey: string, privateKey: string, keyId: string }}
 */
export function generateEd25519Keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // The last 32 bytes of the SPKI DER are the raw public key.
  const rawPublic = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  const publicB64u = rawPublic.toString("base64url"); // 43 chars
  const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
  return {
    publicKey: publicB64u,
    privateKey: privateDer.toString("base64url"),
    keyId: `ed25519:${publicB64u}`,
  };
}

/**
 * Compute an event's content hash: canonical JSON of the event with `hash`
 * and `sig` stripped. Pure — the input object is never mutated.
 *
 * @param {Record<string, unknown>} eventObj
 * @returns {string} `"sha256:<64 lowercase hex>"`
 */
export function computeEventHash(eventObj) {
  assertPlainObject(eventObj, "computeEventHash");
  const clone = { ...eventObj };
  delete clone.hash;
  delete clone.sig;
  return jcsHash(clone);
}

/**
 * Sign an event: compute its hash, sign the hash's UTF-8 bytes with Ed25519,
 * and return a new event with `hash` and `sig` attached. The input object is
 * not mutated.
 *
 * @param {Record<string, unknown>} eventWithoutHashSig
 * @param {string | import("node:crypto").KeyObject} privateKey
 *   base64url PKCS#8 DER string, or a crypto KeyObject.
 * @param {string} [keyId]
 *   Reserved key-binding id. When provided it is checked against the private
 *   key so a mismatched ledger key id fails fast instead of poisoning the log.
 * @returns {Record<string, unknown>} the event with `hash` and `sig` added
 *   (`sig` is 86-char base64url = 64 raw signature bytes).
 */
export function signEvent(eventWithoutHashSig, privateKey, keyId) {
  assertPlainObject(eventWithoutHashSig, "signEvent");
  const key = toPrivateKey(privateKey);
  if (keyId !== undefined) {
    const derived = deriveKeyId(key);
    if (keyId !== derived) {
      throw new TypeError(
        `signEvent: keyId ${JSON.stringify(keyId)} does not match the provided private key (expected ${JSON.stringify(derived)})`,
      );
    }
  }

  const hash = computeEventHash(eventWithoutHashSig);
  const signature = ed25519Sign(null, Buffer.from(hash, "utf8"), key);
  return {
    ...eventWithoutHashSig,
    hash,
    sig: signature.toString("base64url"), // 86 chars
  };
}

/**
 * Verify a signed event's integrity: recompute the hash and check the
 * Ed25519 signature. Never throws for verification failures — the result is
 * the return value.
 *
 * @param {Record<string, unknown>} eventObj
 * @param {string | import("node:crypto").KeyObject} publicKey
 *   base64url raw-32-byte public key string, or a crypto KeyObject.
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyEvent(eventObj, publicKey) {
  try {
    if (!isPlainObject(eventObj)) {
      return { ok: false, reason: "event must be a plain object" };
    }
    if (typeof eventObj.hash !== "string" || eventObj.hash.length === 0) {
      return { ok: false, reason: "event is missing its hash" };
    }
    const expectedHash = computeEventHash(eventObj);
    if (eventObj.hash !== expectedHash) {
      return {
        ok: false,
        reason: `hash mismatch: expected ${expectedHash}, got ${eventObj.hash}`,
      };
    }
    if (typeof eventObj.sig !== "string" || eventObj.sig.length === 0) {
      return { ok: false, reason: "event is missing its signature" };
    }
    const key = toPublicKey(publicKey);
    const signatureBytes = Buffer.from(eventObj.sig, "base64url");
    if (signatureBytes.length !== 64) {
      return {
        ok: false,
        reason: `signature must decode to 64 raw bytes, got ${signatureBytes.length}`,
      };
    }
    const valid = ed25519Verify(
      null,
      Buffer.from(eventObj.hash, "utf8"),
      key,
      signatureBytes,
    );
    return valid
      ? { ok: true }
      : { ok: false, reason: "Ed25519 signature verification failed" };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/** @param {unknown} value @param {string} who @returns {void} */
function assertPlainObject(value, who) {
  if (!isPlainObject(value)) {
    throw new TypeError(`${who}: event must be a plain object`);
  }
}

/** @param {unknown} value @returns {boolean} */
function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** @param {string | KeyObject} privateKey @returns {KeyObject} */
function toPrivateKey(privateKey) {
  if (privateKey instanceof KeyObject) return privateKey;
  if (typeof privateKey === "string") {
    return createPrivateKey({
      key: Buffer.from(privateKey, "base64url"),
      format: "der",
      type: "pkcs8",
    });
  }
  throw new TypeError(
    "privateKey must be a base64url PKCS#8 DER string or a crypto KeyObject",
  );
}

/** @param {string | KeyObject} publicKey @returns {KeyObject} */
function toPublicKey(publicKey) {
  if (publicKey instanceof KeyObject) return publicKey;
  if (typeof publicKey === "string") {
    return createPublicKey({
      key: Buffer.concat([
        SPKI_ED25519_PREFIX,
        Buffer.from(publicKey, "base64url"),
      ]),
      format: "der",
      type: "spki",
    });
  }
  throw new TypeError(
    "publicKey must be a base64url raw-key string or a crypto KeyObject",
  );
}

/** @param {import("node:crypto").KeyObject} privateKey @returns {string} */
function deriveKeyId(privateKey) {
  const spki = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  return `ed25519:${spki.subarray(-32).toString("base64url")}`;
}
