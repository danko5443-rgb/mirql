/**
 * RFC 8785 Canonical JSON (JCS) with mirql's Law 17 integer-only enforcement.
 *
 * - Object keys are sorted lexicographically by UTF-16 code units
 *   (JavaScript's default string sort).
 * - Array order is preserved.
 * - Strings use JSON escaping (ECMAScript JSON.stringify semantics).
 * - Only plain objects, arrays, strings, booleans, `null` and *safe integers*
 *   are representable.
 *
 * Law 17: any non-safe-integer number (floats, NaN, ±Infinity, integers past
 * Number.MAX_SAFE_INTEGER) is forbidden. Money is integer micro_usd, ratios
 * are basis_points — never IEEE-754 doubles — so that hashes are reproducible
 * on every machine and runtime.
 */

const LAW17_MESSAGE =
  "Law 17 violation: floating-point numbers are forbidden in JCS documents; use integer micro_usd or basis_points";

/**
 * Canonicalize `value` to an RFC 8785 (JCS) string, rejecting every number
 * that is not a safe integer.
 *
 * @param {unknown} value
 * @returns {string}
 * @throws {TypeError} on floats/NaN/Infinity (Law 17), non-plain objects,
 *   undefined at the top level or inside arrays, and other non-JSON values.
 */
export function jcs(value) {
  if (value === undefined) {
    throw new TypeError("jcs: undefined is not a valid top-level JSON value");
  }
  return writeValue(value, "$");
}

/** @param {unknown} value @param {string} path @returns {string} */
function writeValue(value, path) {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      if (!Number.isSafeInteger(value)) throw new TypeError(LAW17_MESSAGE);
      return String(value); // -0 canonicalizes to "0"

    case "string":
      return JSON.stringify(value);

    case "object":
      break; // handled below

    default:
      // undefined (inside arrays), function, symbol, bigint, ...
      throw new TypeError(
        `jcs: value at ${path} of type ${typeof value} is not valid JSON`,
      );
  }

  if (Array.isArray(value)) {
    let out = "[";
    for (let i = 0; i < value.length; i++) {
      const element = value[i];
      if (element === undefined) {
        throw new TypeError(
          `jcs: undefined array element at ${path}[${i}] is not valid JSON`,
        );
      }
      if (i > 0) out += ",";
      out += writeValue(element, `${path}[${i}]`);
    }
    return out + "]";
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(
      `jcs: value at ${path} must be a plain object, array, string, boolean, null or safe integer`,
    );
  }

  // Object.keys: own enumerable string keys (symbol keys are ignored, matching
  // JSON.stringify); default .sort() is exactly UTF-16 code-unit order.
  const keys = Object.keys(value).sort();
  let out = "{";
  let first = true;
  for (const key of keys) {
    const member = value[key];
    if (member === undefined) continue; // undefined properties are omitted
    if (!first) out += ",";
    first = false;
    out += JSON.stringify(key) + ":" + writeValue(member, `${path}.${key}`);
  }
  return out + "}";
}
