// packages/inbox/keys.mjs — Key Management & Keyring Provisioning for mirql-inbox.
//
// Law 6 (Human Sovereignty & Credentials):
// - The human:owner private key is NEVER persisted inside `.mirql/` (and in
//   particular never under `.mirql/keys/`). It lives in an operator-controlled
//   file OUTSIDE the ledger directory, written with file mode 0o600.
// - `.mirql/keys/` holds factory (machine) writer keys only.
// - Loading human credentials is always explicit: `--key <path>` /
//   `--signing-key <material>` or the `MIRQL_HUMAN_KEY` environment variable.
//   There is no implicit fallback; omitted credentials fail closed.
//
// Law 3 (Single-Writer ACL) / keyring namespace binding:
// - `ledger/keyring.json` entries are objects binding each key to exactly one
//   writer namespace: `{ "<keyId>": { "ns": "<namespace>", "publicKey": "<pub>" } }`
//   (legacy plain-string entries are still readable). A key registered for one
//   namespace can never authenticate events claiming another namespace.
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
  rmSync,
} from "node:fs";
import { join, dirname, sep as pathSep, resolve as resolvePath } from "node:path";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { generateEd25519Keypair, EXIT_CODES } from "../core/index.mjs";

/** The human writer namespace. */
export const HUMAN_WRITER_NS = "human:owner";

/** Legacy filenames that MUST never contain the human private key anymore. */
export const HUMAN_KEY_FORBIDDEN_FILES = Object.freeze([
  "human.key.json",
  "human_owner.key.json",
]);

/** Default filename of the human private key, written OUTSIDE `.mirql/`. */
export const HUMAN_KEY_FILENAME = "human_owner.key.private.json";

/**
 * Machine (factory) writer namespaces provisioned at genesis inside
 * `.mirql/keys/`. The human:owner key is deliberately absent (Law 6).
 */
export const FACTORY_WRITERS = Object.freeze([
  { ns: "tool:queue", file: "queue.key.json", aliases: [] },
  { ns: "tool:run_supervisor", file: "run_supervisor.key.json", aliases: [] },
  { ns: "tool:log", file: "log.key.json", aliases: [] },
  { ns: "tool:inbox", file: "inbox.key.json", aliases: [] },
  { ns: "notary:mergeproof", file: "notary.key.json", aliases: ["mergeproof.key.json"] },
  { ns: "daemon:lifeguard", file: "lifeguard.key.json", aliases: [] },
]);

/**
 * All canonical writer namespaces (kept for backwards compatibility).
 * `human:owner` is special-cased: its private key never lands in `.mirql/keys/`.
 */
export const CANONICAL_WRITERS = Object.freeze([
  { ns: HUMAN_WRITER_NS, file: "human.key.json", aliases: ["human_owner.key.json"], humanOnly: true },
  ...FACTORY_WRITERS,
]);

/** Structured domain error with a machine-readable code for CLI JSON output. */
function domainError(code, message, exitCode, hint) {
  const err = new Error(message);
  err.errorCode = code;
  err.exitCode = exitCode;
  if (hint) err.hint = hint;
  return err;
}

/** Credentials error: always a policy denial (fail closed, Law 6). */
function credentialsError(code, message, hint) {
  return domainError(
    code,
    message,
    EXIT_CODES.POLICY_DENIAL,
    hint ?? "provide --key <path> or MIRQL_HUMAN_KEY outside .mirql",
  );
}

/** First non-empty string among the arguments. @returns {string | undefined} */
function firstString(...values) {
  for (const v of values) {
    if (typeof v === "string" && v.length > 0) return v;
  }
  return undefined;
}

/**
 * Derive the raw public key and `ed25519:` key id from a base64url PKCS#8
 * private key. Returns null when the material is not a usable Ed25519 key.
 *
 * @param {string} privateKey
 * @returns {{ publicKey: string, keyId: string } | null}
 */
export function derivePublicParts(privateKey) {
  if (typeof privateKey !== "string" || privateKey.length === 0) return null;
  try {
    const key = createPrivateKey({
      key: Buffer.from(privateKey, "base64url"),
      format: "der",
      type: "pkcs8",
    });
    const spki = createPublicKey(key).export({ format: "der", type: "spki" });
    const publicKey = spki.subarray(-32).toString("base64url");
    if (publicKey.length !== 43) return null;
    return { publicKey, keyId: `ed25519:${publicKey}` };
  } catch {
    return null;
  }
}

/** @returns {boolean} true when `child` is inside `parent` on disk. */
function isInsidePath(parent, child) {
  const p = resolvePath(parent);
  const c = resolvePath(child);
  if (c === p) return true;
  return c.startsWith(p + pathSep);
}

/**
 * Normalize one keyring entry to `{ ns, publicKey }`.
 * Accepts the canonical object form and legacy plain-string values (whose
 * namespace is only known when the entry is keyed by the namespace itself).
 *
 * @param {unknown} entry
 * @param {string} [entryKey]
 * @returns {{ ns: string | null, publicKey: string } | null}
 */
export function keyringEntry(entry, entryKey) {
  if (typeof entry === "string" && entry.length > 0) {
    const ns = typeof entryKey === "string" && entryKey.includes(":") && !entryKey.startsWith("ed25519:")
      ? entryKey
      : null;
    return { ns, publicKey: entry };
  }
  if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
    const publicKey = typeof entry.publicKey === "string"
      ? entry.publicKey
      : (typeof entry.pubkey === "string" ? entry.pubkey : null);
    if (!publicKey) return null;
    const ns = typeof entry.ns === "string"
      ? entry.ns
      : (typeof entry.namespace === "string" ? entry.namespace : null);
    return { ns, publicKey };
  }
  return null;
}

/**
 * Write a file containing private key material with mode 0o600.
 *
 * @param {string} filePath
 * @param {string} contents
 */
export function writePrivateFile(filePath, contents) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, contents, { encoding: "utf8", mode: 0o600 });
  try {
    chmodSync(filePath, 0o600);
  } catch {
    // Some platforms ignore mode bits; the explicit 0o600 above is best effort.
  }
}

/** Read and validate a keypair JSON document. @returns {object | null} */
function readKeypairFile(filePath) {
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    if (parsed && typeof parsed === "object" && typeof parsed.privateKey === "string") {
      return parsed;
    }
  } catch {}
  return null;
}

/**
 * Resolve where the human private key lives: explicit `--human-key-out` /
 * `options.humanKeyPath`, else `<operatorDir>/human_owner.key.private.json`
 * where operatorDir is the parent of the `.mirql` directory (always outside
 * `.mirql/`).
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {string} absolute path outside `.mirql/`
 */
export function resolveHumanKeyPath(mirqlDir, options = {}) {
  const explicit = firstString(
    options.humanKeyOut,
    options["human-key-out"],
    options.humanKeyPath,
  );
  if (typeof explicit === "string" && explicit.length > 0) {
    return resolvePath(explicit);
  }
  const operatorDir = dirname(resolvePath(mirqlDir)) || resolvePath(mirqlDir);
  return join(operatorDir, HUMAN_KEY_FILENAME);
}

/** Remove any stale human private key files left inside `.mirql/keys/` (Law 6). */
function purgeStaleHumanKeys(keysDir) {
  for (const name of HUMAN_KEY_FORBIDDEN_FILES) {
    const p = join(keysDir, name);
    if (existsSync(p)) {
      try {
        rmSync(p, { force: true });
      } catch {}
    }
  }
}

/**
 * Generate (or reload) every canonical writer keypair and register their
 * public keys in `<mirqlDir>/ledger/keyring.json` with explicit namespace
 * binding: `{ "<keyId>": { ns, publicKey }, "<ns>": { ns, publicKey } }`.
 *
 * The keyring is REBUILT from scratch so attacker-planted entries in a
 * pre-existing keyring.json cannot survive a fresh genesis (remediation B4).
 * Only factory (machine) keys are persisted under `.mirql/keys/`; the
 * human:owner private key is returned to the caller and must be persisted
 * outside `.mirql/` (see genesis.mjs).
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @param {string} [options.humanKeyPath] existing human key file to reuse (outside .mirql/)
 * @param {object} [options.humanKeypair] explicit human keypair to register
 * @returns {Record<string, { publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } }>}
 */
export function generateFactoryKeypairs(mirqlDir, options = {}) {
  const keysDir = join(mirqlDir, "keys");
  const ledgerDir = join(mirqlDir, "ledger");
  mkdirSync(keysDir, { recursive: true });
  mkdirSync(ledgerDir, { recursive: true });
  purgeStaleHumanKeys(keysDir);

  // B4: fresh genesis rebuilds the keyring — no pre-planted entries survive.
  const keyring = {};

  const result = {};

  // Human:owner — reuse the operator-held key file when it exists, else generate.
  let humanKp = null;
  if (options.humanKeypair && typeof options.humanKeypair.privateKey === "string") {
    humanKp = options.humanKeypair;
  } else if (typeof options.humanKeyPath === "string" && options.humanKeyPath.length > 0) {
    humanKp = readKeypairFile(resolvePath(options.humanKeyPath));
  }
  if (!humanKp) {
    humanKp = generateEd25519Keypair();
  }
  const humanDerived = derivePublicParts(humanKp.privateKey);
  if (!humanDerived) {
    throw domainError(
      "credentials_invalid",
      "stored human:owner key material is not a usable Ed25519 private key",
      EXIT_CODES.INTEGRITY_VIOLATION,
    );
  }
  const humanEntry = {
    publicKey: humanDerived.publicKey,
    privateKey: humanKp.privateKey,
    keyId: humanDerived.keyId,
    writer: { ns: HUMAN_WRITER_NS, key_id: humanDerived.keyId },
  };
  result[HUMAN_WRITER_NS] = humanEntry;
  registerKeyringEntry(keyring, HUMAN_WRITER_NS, humanEntry);

  // Factory writers — machine keys persisted inside .mirql/keys/.
  for (const item of FACTORY_WRITERS) {
    const keyPath = join(keysDir, item.file);
    let kp = null;

    if (existsSync(keyPath)) {
      const parsed = readKeypairFile(keyPath);
      if (parsed) {
        const derived = derivePublicParts(parsed.privateKey);
        if (derived) {
          kp = {
            publicKey: derived.publicKey,
            privateKey: parsed.privateKey,
            keyId: derived.keyId,
            writer: { ns: item.ns, key_id: derived.keyId },
          };
        }
      }
    }

    if (!kp) {
      const generated = generateEd25519Keypair();
      kp = {
        publicKey: generated.publicKey,
        privateKey: generated.privateKey,
        keyId: generated.keyId,
        writer: { ns: item.ns, key_id: generated.keyId },
      };
      writeFileSync(keyPath, JSON.stringify(kp, null, 2) + "\n", "utf8");
      for (const alias of item.aliases) {
        writeFileSync(join(keysDir, alias), JSON.stringify(kp, null, 2) + "\n", "utf8");
      }
    }

    result[item.ns] = kp;
    registerKeyringEntry(keyring, item.ns, kp);
  }

  writeFileSync(join(ledgerDir, "keyring.json"), JSON.stringify(keyring, null, 2) + "\n", "utf8");
  return result;
}

/** Register one writer key in the keyring under both its keyId and namespace. */
function registerKeyringEntry(keyring, ns, kp) {
  const entry = { ns, publicKey: kp.publicKey };
  keyring[kp.keyId] = entry;
  keyring[ns] = entry;
}

/**
 * Load keyring from <mirqlDir>/ledger/keyring.json.
 * @param {string} mirqlDir
 * @returns {Record<string, unknown>}
 */
export function loadKeyring(mirqlDir) {
  const keyringPath = join(mirqlDir, "ledger", "keyring.json");
  if (!existsSync(keyringPath)) return {};
  try {
    const parsed = JSON.parse(readFileSync(keyringPath, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Load the private key for a FACTORY writer namespace, falling back to
 * `<mirqlDir>/keys/<name>.key.json`. For `human:owner` there is deliberately
 * NO filesystem fallback: human credentials must be passed explicitly
 * (see requireHumanKey) and never load implicitly from `.mirql/` (Law 6).
 *
 * @param {string} mirqlDir
 * @param {string} writerNs
 * @param {object} [options]
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } } | null}
 */
export function loadWriterKey(mirqlDir, writerNs, options = {}) {
  const directKey = firstString(options.signingKey, options.privateKey, options["signing-key"]);
  if (directKey) {
    const kp = parseKeyMaterial(directKey);
    if (kp) {
      return { ...kp, writer: { ns: writerNs, key_id: kp.keyId } };
    }
    return null;
  }

  const customKeyFile = firstString(options.key, options.keyFile, options["key-file"]);
  if (customKeyFile) {
    const kp = readKeypairFile(resolvePath(customKeyFile));
    if (kp) {
      const derived = derivePublicParts(kp.privateKey);
      if (derived) {
        return {
          publicKey: derived.publicKey,
          privateKey: kp.privateKey,
          keyId: derived.keyId,
          writer: { ns: writerNs, key_id: derived.keyId },
        };
      }
    }
    return null;
  }

  if (writerNs === HUMAN_WRITER_NS) {
    // Law 6: no implicit human credentials, ever.
    return null;
  }

  const writerEntry = FACTORY_WRITERS.find((w) => w.ns === writerNs);
  if (!writerEntry) return null;

  const keyPath = join(mirqlDir, "keys", writerEntry.file);
  if (existsSync(keyPath)) {
    const parsed = readKeypairFile(keyPath);
    if (parsed) {
      const derived = derivePublicParts(parsed.privateKey);
      if (derived) {
        return {
          publicKey: derived.publicKey,
          privateKey: parsed.privateKey,
          keyId: derived.keyId,
          writer: { ns: writerNs, key_id: derived.keyId },
        };
      }
    }
  }

  return null;
}

/**
 * Parse inline key material: a JSON keypair document or a raw base64url
 * PKCS#8 private key. The publicKey/keyId are always derived from the
 * private key so they cannot be spoofed.
 *
 * @param {string} material
 * @returns {{ publicKey: string, privateKey: string, keyId: string } | null}
 */
function parseKeyMaterial(material) {
  if (typeof material !== "string" || material.trim().length === 0) return null;
  const text = material.trim();
  let privateKey = text;
  if (text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed.privateKey === "string") {
        privateKey = parsed.privateKey;
      } else {
        return null;
      }
    } catch {
      return null;
    }
  }
  const derived = derivePublicParts(privateKey);
  if (!derived) return null;
  return { publicKey: derived.publicKey, privateKey, keyId: derived.keyId };
}

/**
 * Require explicit human:owner credentials (Law 6). Resolution order:
 *   1. inline material: `--signing-key` / `--private-key`
 *   2. key file: `--key <path>` / `--key-file <path>`
 *   3. environment: `MIRQL_HUMAN_KEY` (path, or inline material)
 *
 * The key file must live OUTSIDE `.mirql/`. Every failure mode throws a
 * structured error with exit code POLICY_DENIAL (fail closed).
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string }, sourceFile: string | null }}
 * @throws structured Error (errorCode credentials_*)
 */
export function requireHumanKey(mirqlDir, options = {}) {
  const inline = firstString(options.signingKey, options.privateKey, options["signing-key"]);
  let material = null;
  let sourceFile = null;

  if (inline) {
    material = inline;
  } else {
    const explicit = firstString(options.key, options.keyFile, options["key-file"]);
    const fromEnv = firstString(process.env.MIRQL_HUMAN_KEY);
    const candidate = explicit ?? fromEnv;
    if (!candidate) {
      throw credentialsError(
        "credentials_required",
        "credentials_required: human:owner private key is required for this action",
        "provide --key <path> (or --signing-key <material> or MIRQL_HUMAN_KEY) pointing to a key outside .mirql/",
      );
    }
    const abs = resolvePath(candidate);
    if (existsSync(abs)) {
      if (isInsidePath(mirqlDir, abs)) {
        throw credentialsError(
          "credentials_location_forbidden",
          `credentials_location_forbidden: human key file ${candidate} is inside ${mirqlDir}; human credentials must live outside .mirql/`,
          "move the key file outside .mirql/ and pass --key <path> (or MIRQL_HUMAN_KEY)",
        );
      }
      sourceFile = abs;
      material = readFileSync(abs, "utf8");
    } else if (/^\{/.test(candidate) || /^[A-Za-z0-9_-]{40,}$/.test(candidate)) {
      // MIRQL_HUMAN_KEY may carry inline material rather than a path.
      material = candidate;
    } else {
      throw credentialsError(
        "credentials_required",
        `credentials_required: human key file not found: ${candidate}`,
        "provide --key <path> (or --signing-key <material> or MIRQL_HUMAN_KEY) pointing to an existing file outside .mirql/",
      );
    }
  }

  const kp = parseKeyMaterial(material);
  if (!kp) {
    throw credentialsError(
      "credentials_invalid",
      "credentials_invalid: provided material is not a valid Ed25519 private key or keypair document",
    );
  }

  return { ...kp, writer: { ns: HUMAN_WRITER_NS, key_id: kp.keyId }, sourceFile };
}

/**
 * Authenticate the human:owner writer: load the explicitly provided private
 * key and verify it is the key registered for `human:owner` in the keyring
 * (namespace binding, Law 3). A key registered under any other namespace
 * (e.g. `tool:queue`) is rejected — fail closed.
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string }, sourceFile: string | null }}
 * @throws structured Error (POLICY_DENIAL)
 */
export function authenticateHumanWriter(mirqlDir, options = {}) {
  if (options.writer && options.writer !== HUMAN_WRITER_NS) {
    throw domainError(
      "writer_forbidden",
      `writer_forbidden: non-human writer ${JSON.stringify(options.writer)} cannot execute human actions (Law 6)`,
      EXIT_CODES.POLICY_DENIAL,
    );
  }

  const kp = requireHumanKey(mirqlDir, options);
  const keyring = loadKeyring(mirqlDir);

  // 1. The key registered for human:owner (if any) must be THIS key.
  const registered = keyringEntry(keyring[HUMAN_WRITER_NS], HUMAN_WRITER_NS);
  if (registered && registered.publicKey !== kp.publicKey) {
    throw domainError(
      "key_mismatch",
      "key_mismatch: signing key does not match the human:owner public key registered in keyring.json",
      EXIT_CODES.POLICY_DENIAL,
    );
  }

  // 2. The key must not be bound to any other writer namespace.
  for (const [entryKey, raw] of Object.entries(keyring)) {
    const entry = keyringEntry(raw, entryKey);
    if (!entry || entry.publicKey !== kp.publicKey) continue;
    if (entry.ns && entry.ns !== HUMAN_WRITER_NS) {
      throw domainError(
        "namespace_binding_violation",
        `namespace_binding_violation: signing key is registered for ${entry.ns} and cannot act as ${HUMAN_WRITER_NS} (Law 3)`,
        EXIT_CODES.POLICY_DENIAL,
      );
    }
  }

  return kp;
}
