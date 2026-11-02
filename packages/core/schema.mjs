/**
 * Canonical schema validation, zero dependencies.
 *
 * The JSON files under `schemas/` are the single source of truth. This module
 * loads them lazily, validates documents against them with a small JSON
 * Schema (2020-12 subset) validator, and enforces mirql's cross-field laws:
 * Law 17 (integer-only documents, via jcs) and Law 3 (single-writer ACL for
 * events).
 */
import { readFileSync } from "node:fs";
import { jcs } from "./jcs.mjs";
import { canWriteEvent } from "./acl.mjs";

/** The canonical document kinds. */
export const SCHEMA_KINDS = Object.freeze(["event", "warrant", "job", "outcome"]);

const SCHEMA_IDS = Object.freeze({
  event: "https://mirql.local/schemas/event/v1.json",
  warrant: "https://mirql.local/schemas/warrant/v1.json",
  job: "https://mirql.local/schemas/job/v1.json",
  outcome: "https://mirql.local/schemas/outcome/v1.json",
});

/** @type {Map<string, object>} */
const schemaCache = new Map();

/** @type {Map<string, RegExp>} */
const patternCache = new Map();

/**
 * Load (and cache) the canonical schema for `kind`.
 *
 * @param {"event" | "warrant" | "job" | "outcome"} kind
 * @returns {object} parsed JSON Schema
 * @throws {TypeError} for an unknown kind; Error if the file is missing or
 *   does not declare the expected `$id`.
 */
export function loadSchema(kind) {
  if (typeof kind !== "string" || !(kind in SCHEMA_IDS)) {
    throw new TypeError(
      `loadSchema: unknown kind ${JSON.stringify(kind)}; expected one of ${SCHEMA_KINDS.join(", ")}`,
    );
  }
  const cached = schemaCache.get(kind);
  if (cached) return cached;

  const url = new URL(`../../schemas/${kind}.schema.json`, import.meta.url);
  let schema;
  try {
    schema = JSON.parse(readFileSync(url, "utf8"));
  } catch (err) {
    throw new Error(
      `loadSchema: cannot read schema for ${JSON.stringify(kind)} at ${url.href}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (schema.$id !== SCHEMA_IDS[kind]) {
    throw new Error(
      `loadSchema: schemas/${kind}.schema.json declares unexpected $id ${JSON.stringify(schema.$id)}`,
    );
  }
  schemaCache.set(kind, schema);
  return schema;
}

/**
 * Validate a canonical document of kind `kind`.
 *
 * Checks, in order:
 * 1. Law 17 — the document must be integer-only (`jcs` throws otherwise).
 * 2. Structural constraints from `schemas/<kind>.schema.json`.
 * 3. Law 3 — for events, the single-writer ACL gates (writer.ns, type).
 *
 * @param {"event" | "warrant" | "job" | "outcome"} kind
 * @param {unknown} doc
 * @returns {{ valid: boolean, errors: string[] }}
 * @throws {TypeError} for an unknown kind.
 */
export function validateDocument(kind, doc) {
  if (typeof kind !== "string" || !(kind in SCHEMA_IDS)) {
    throw new TypeError(
      `validateDocument: unknown kind ${JSON.stringify(kind)}; expected one of ${SCHEMA_KINDS.join(", ")}`,
    );
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return { valid: false, errors: ["$: expected a JSON object document"] };
  }

  try {
    jcs(doc);
  } catch (err) {
    return {
      valid: false,
      errors: [`$: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  /** @type {string[]} */
  const errors = [];
  validateAgainstSchema(loadSchema(kind), doc, "$", errors);

  if (kind === "event" && !canWriteEvent(doc.writer?.ns, doc.type)) {
    errors.push(
      `$.writer: writer ${JSON.stringify(doc.writer?.ns ?? null)} may not emit event type ${JSON.stringify(doc.type ?? null)} (Law 3: single-writer ACL)`,
    );
  }

  if (kind === "event" && doc.type === "merge.approved") {
    const payload = validateMergeApprovalPayload(doc.payload);
    errors.push(...payload.errors.map(error => "$.payload" + error.slice(1)));
  }

  return { valid: errors.length === 0, errors };
}

/**
 * JSON Schema (2020-12 subset) walker. Supports: type, const, enum, pattern,
 * minLength/maxLength, minimum/maximum, minItems/maxItems, items, required,
 * properties, additionalProperties (boolean or schema).
 *
 * @param {object | boolean | null | undefined} schema
 * @param {unknown} value
 * @param {string} path
 * @param {string[]} errors
 * @returns {void}
 */
function validateAgainstSchema(schema, value, path, errors) {
  if (schema === true || schema === undefined || schema === null) return;
  if (schema === false) {
    errors.push(`${path}: value not allowed`);
    return;
  }
  if (typeof schema !== "object") return;

  if (schema.type !== undefined) {
    const wanted = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!wanted.some((t) => matchesType(t, value))) {
      errors.push(
        `${path}: expected type ${wanted.join(" | ")}, got ${jsonType(value)}`,
      );
      return;
    }
  }

  if (schema.const !== undefined && value !== schema.const) {
    errors.push(
      `${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`,
    );
  }

  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    errors.push(
      `${path}: expected one of ${schema.enum.map((v) => JSON.stringify(v)).join(" | ")}`,
    );
  }

  if (typeof value === "string") {
    if (typeof schema.pattern === "string" && !compile(schema.pattern).test(value)) {
      const preview = value.length > 48 ? `${value.slice(0, 45)}...` : value;
      errors.push(
        `${path}: ${JSON.stringify(preview)} does not match pattern ${JSON.stringify(schema.pattern)}`,
      );
    }
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      errors.push(`${path}: string length ${value.length} < minLength ${schema.minLength}`);
    }
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
      errors.push(`${path}: string length ${value.length} > maxLength ${schema.maxLength}`);
    }
  }

  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      errors.push(`${path}: ${value} < minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      errors.push(`${path}: ${value} > maximum ${schema.maximum}`);
    }
  }

  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) {
      errors.push(`${path}: array length ${value.length} < minItems ${schema.minItems}`);
    }
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
      errors.push(`${path}: array length ${value.length} > maxItems ${schema.maxItems}`);
    }
    if (schema.items !== undefined) {
      value.forEach((element, i) =>
        validateAgainstSchema(schema.items, element, `${path}[${i}]`, errors),
      );
    }
  }

  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const key of schema.required ?? []) {
      if (!(key in value)) {
        errors.push(`${path}: missing required property ${JSON.stringify(key)}`);
      }
    }
    const properties = schema.properties ?? {};
    for (const [key, sub] of Object.entries(properties)) {
      if (key in value) {
        validateAgainstSchema(sub, value[key], `${path}.${key}`, errors);
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in properties)) {
          errors.push(`${path}: additional property ${JSON.stringify(key)} is not allowed`);
        }
      }
    } else if (
      typeof schema.additionalProperties === "object" &&
      schema.additionalProperties !== null
    ) {
      for (const [key, v] of Object.entries(value)) {
        if (!(key in properties)) {
          validateAgainstSchema(
            schema.additionalProperties,
            v,
            `${path}.${key}`,
            errors,
          );
        }
      }
    }
  }
}

/** @param {string} t @param {unknown} value @returns {boolean} */
function matchesType(t, value) {
  switch (t) {
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "number":
      return typeof value === "number";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "null":
      return value === null;
    case "array":
      return Array.isArray(value);
    case "object":
      return value !== null && typeof value === "object" && !Array.isArray(value);
    default:
      return true; // unknown type keyword: do not constrain
  }
}

/** @param {unknown} value @returns {string} */
function jsonType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/** @param {string} pattern @returns {RegExp} */
function compile(pattern) {
  let re = patternCache.get(pattern);
  if (!re) {
    re = new RegExp(pattern);
    patternCache.set(pattern, re);
  }
  return re;
}


/** The approval is an event payload, rather than a fifth top-level document kind. */
export function validateMergeApprovalPayload(value) {
  const errors = [];
  try { jcs(value); } catch (error) { return { valid: false, errors: ["$: " + error.message] }; }
  const key = "event:merge.approved";
  let schema = schemaCache.get(key);
  if (!schema) {
    schema = JSON.parse(readFileSync(new URL("../../schemas/merge-approval.schema.json", import.meta.url), "utf8"));
    if (schema.$id !== "https://mirql.local/schemas/merge-approval/v1.json") throw new Error("Invalid merge approval schema identity");
    schemaCache.set(key, schema);
  }
  validateAgainstSchema(schema, value, "$", errors);
  if (errors.length === 0) {
    const canonical = [...new Set(value.paths)].sort();
    if (jcs(canonical) !== jcs(value.paths) || value.paths.some(path => path.startsWith("/") || path.includes("\\") ||
        path.includes("\0") || /^[a-zA-Z]:/.test(path) || path.split("/").some(part => !part || part === "." || part === ".."))) {
      errors.push("$.paths: expected sorted, unique repository-relative paths");
    }
  }
  return { valid: errors.length === 0, errors };
}
