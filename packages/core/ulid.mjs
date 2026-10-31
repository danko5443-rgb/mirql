/**
 * Monotonic ULIDs (universally unique, lexicographically sortable ids).
 *
 * 26 characters of Crockford Base32: 10 chars of 48-bit UNIX millisecond
 * timestamp followed by 16 chars of 80-bit randomness. Within a single
 * millisecond the 80-bit payload is incremented, so ids generated in the same
 * process always sort in generation order.
 */
import { randomBytes } from "node:crypto";

/** Crockford Base32 alphabet (no I, L, O, U). */
export const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const ULID_RE = /^[0-9A-HJKMNPQRSTVWXYZ]{26}$/i; // case-insensitive for human entry
const TIME_CHARS = 10;
const RANDOM_CHARS = 16;
const TIME_MAX = 0xffffffffffff; // 48 bits of milliseconds
const RANDOM_MAX = (1n << 80n) - 1n; // 80 bits of monotonic payload

// Monotonic state for this process.
let lastTime = -1;
let lastRandom = 0n;

/**
 * Generate a monotonic ULID for wall-clock time `nowMs`.
 *
 * @param {number} [nowMs] UNIX time in milliseconds (defaults to Date.now()).
 * @returns {string} 26-character Crockford Base32 ULID (uppercase).
 * @throws {RangeError} if `nowMs` is not an integer in [0, 2^48).
 */
export function ulid(nowMs = Date.now()) {
  // Strict integers only (Law 17): fractional, negative or out-of-range
  // timestamps are caller bugs, not things to silently round.
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > TIME_MAX) {
    throw new RangeError(
      `ulid: timestamp ${nowMs} is not an integer in the 48-bit millisecond range`,
    );
  }
  const time = nowMs;

  let effectiveTime;

  if (time <= lastTime) {
    effectiveTime = lastTime;
    lastRandom += 1n;
    if (lastRandom > RANDOM_MAX) {
      lastTime += 1;
      effectiveTime = lastTime;
      lastRandom = 0n;
    }
  } else {
    lastTime = time;
    lastRandom = bytesToBigInt(randomBytes(10));
    effectiveTime = lastTime;
  }

  return encodeTime(effectiveTime) + encodeRandom(lastRandom);
}

/**
 * Check whether `str` is a syntactically valid ULID (26 Crockford Base32
 * characters; case-insensitive for human entry).
 *
 * @param {unknown} str
 * @returns {boolean}
 */
export function isValidUlid(str) {
  return typeof str === "string" && ULID_RE.test(str);
}

/** @param {number} time @returns {string} */
function encodeTime(time) {
  let out = "";
  for (let i = 0; i < TIME_CHARS; i++) {
    out = ULID_ALPHABET[time % 32] + out;
    time = Math.floor(time / 32);
  }
  return out;
}

/** @param {bigint} random @returns {string} */
function encodeRandom(random) {
  let out = "";
  for (let i = 0; i < RANDOM_CHARS; i++) {
    out = ULID_ALPHABET[Number(random & 31n)] + out;
    random >>= 5n;
  }
  return out;
}

/** @param {Uint8Array} bytes @returns {bigint} */
function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}
