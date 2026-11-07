import { writePrivateFile, writePrivateFiles, protectPrivatePaths } from "../core/private-files.mjs";
import { requireTrustForKeyCreation } from "../core/trust-root.mjs";
import { readSignedKeyring, sealKeyring, readOwnerPin } from "../core/keyring.mjs";
import { HUMAN_KEY_FILENAME, plaintextOwnerKeyAllowed, resolveHumanKeyPath } from "../core/owner-key-guard.mjs";
export { HUMAN_KEY_FILENAME, plaintextOwnerKeyAllowed, resolveHumanKeyPath, findUnprotectedOwnerKey } from "../core/owner-key-guard.mjs";
import { resolveTrustRoot, trustFile, assertExternalTrustPath } from "../core/trust-root.mjs";
// packages/inbox/keys.mjs — Key Management & Keyring Provisioning for mirql-inbox.
//
// Law 6 (Human Sovereignty & Credentials):
// - The human:owner private key is NEVER persisted inside `.mirql/` (and in
//   particular never under `.mirql/keys/`). It lives in an operator-controlled
//   file OUTSIDE the ledger directory, written with file mode 0o600.
// - At rest that file is encrypted with a passphrase (scrypt + AES-256-GCM)
//   whenever one is available, so a stolen file alone cannot sign. A locked
//   key fails closed with OWNER_KEY_LOCKED instead of being regenerated.
// - `.mirql/keys/` holds factory (machine) writer keys only (plaintext).
// - Loading human credentials is always explicit: `--key <path>` /
//   `--signing-key <material>` or the `MIRQL_HUMAN_KEY` environment variable.
//   There is no implicit fallback; omitted credentials fail closed.
//
// Law 3 (Single-Writer ACL) / keyring namespace binding:
// - `trust-root keyring.json` entries are objects binding each key to exactly one
//   writer namespace: `{ "<keyId>": { "ns": "<namespace>", "publicKey": "<pub>" } }`
//   (legacy plain-string entries are still readable). A key registered for one
//   namespace can never authenticate events claiming another namespace.
import { readFileSync, existsSync, mkdirSync, chmodSync, statSync, rmSync } from "node:fs";
import { join, sep as pathSep, resolve as resolvePath } from "node:path";
import { createPrivateKey, createPublicKey, randomBytes, scryptSync, createCipheriv, createDecipheriv } from "node:crypto";
import { generateEd25519Keypair, EXIT_CODES } from "../core/index.mjs";

/** The human writer namespace. */
export const HUMAN_WRITER_NS = "human:owner";

/** Legacy filenames that MUST never contain the human private key anymore. */
export const HUMAN_KEY_FORBIDDEN_FILES = Object.freeze([
  "human.key.json",
  "human_owner.key.json",
]);

/** Default filename of the human private key, written OUTSIDE `.mirql/`. */

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

/** Encrypted owner-key envelope version and KDF bounds (Law 6, at rest). */
const OWNER_KEY_FORMAT_VERSION = 1;
/** Minimum accepted scrypt cost (N >= 2^15): a tampered file cannot downgrade the KDF. */
const OWNER_KEY_KDF_MIN_N = 1 << 15;
/** scrypt parameters used when writing (128*N*r = 32 MiB, well under ~300 ms). */
const OWNER_KEY_KDF = Object.freeze({ N: 1 << 15, r: 8, p: 1 });
/** scrypt maxmem headroom; also caps what a tampered file can demand (128 MiB). */
const OWNER_KEY_SCRYPT_MAXMEM = 128 * (1 << 17) * 8;
/** Minimum passphrase length accepted whenever an owner key is encrypted. */
const OWNER_KEY_MIN_PASSPHRASE = 12;

/** Passphrase source: options.passphrase, else MIRQL_HUMAN_PASSPHRASE. Never stored or logged. */
function resolveOwnerKeyPassphrase(options = {}) {
  return firstString(options.passphrase, process.env.MIRQL_HUMAN_PASSPHRASE);
}

/**
 * The single error every locked-owner-key refusal throws: no detail about
 * WHY unlocking failed (missing passphrase, wrong passphrase, or tampered
 * envelope) is ever revealed.
 */
function ownerKeyLockedError() {
  return credentialsError(
    "OWNER_KEY_LOCKED",
    "OWNER_KEY_LOCKED: the encrypted human:owner key could not be unlocked",
    "provide --passphrase <secret> or set MIRQL_HUMAN_PASSPHRASE",
  );
}

/** An owner key may only be encrypted under a passphrase of sane length. */
function assertPassphraseStrength(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < OWNER_KEY_MIN_PASSPHRASE) {
    throw domainError(
      "OWNER_KEY_PASSPHRASE_REQUIRED",
      `OWNER_KEY_PASSPHRASE_REQUIRED: encrypting the owner key requires a passphrase of at least ${OWNER_KEY_MIN_PASSPHRASE} characters`,
      EXIT_CODES.POLICY_DENIAL,
      "provide --passphrase <secret> or set MIRQL_HUMAN_PASSPHRASE",
    );
  }
}

/** Additional authenticated data binding the envelope's public identity. */
function ownerKeyAad(keyId, publicKey) {
  return Buffer.from(`mirql.owner.key:v${OWNER_KEY_FORMAT_VERSION}:${keyId}:${publicKey}`, "utf8");
}

/**
 * Encrypt one owner-key document (scrypt + AES-256-GCM). The publicKey/keyId
 * in the envelope are DERIVED from the private key and bound as GCM
 * additional authenticated data, so editing them makes decryption fail.
 *
 * @param {{ privateKey: string }} document plaintext keypair document
 * @param {string} passphrase
 * @returns {object} encrypted envelope ({ v, encrypted, kdf, kdfParams, salt, iv, tag, ciphertext, publicKey, keyId })
 */
function encryptOwnerKeyDocument(document, passphrase) {
  assertPassphraseStrength(passphrase);
  const derived = derivePublicParts(document.privateKey);
  if (!derived) {
    throw domainError(
      "credentials_invalid",
      "owner key material is not a usable Ed25519 private key",
      EXIT_CODES.INTEGRITY_VIOLATION,
    );
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, {
    N: OWNER_KEY_KDF.N, r: OWNER_KEY_KDF.r, p: OWNER_KEY_KDF.p,
    maxmem: OWNER_KEY_SCRYPT_MAXMEM,
  });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(ownerKeyAad(derived.keyId, derived.publicKey));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(document), "utf8")),
    cipher.final(),
  ]);
  return {
    v: OWNER_KEY_FORMAT_VERSION,
    encrypted: true,
    kdf: "scrypt",
    kdfParams: { N: OWNER_KEY_KDF.N, r: OWNER_KEY_KDF.r, p: OWNER_KEY_KDF.p },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    publicKey: derived.publicKey,
    keyId: derived.keyId,
  };
}

/**
 * Decrypt an encrypted owner-key envelope back into its keypair document.
 * Every refusal — no passphrase, wrong passphrase, tampered fields, or a
 * downgraded KDF — throws the same OWNER_KEY_LOCKED error with no detail.
 *
 * @param {object} envelope
 * @param {string | undefined} passphrase
 * @returns {object} the original keypair document
 */
function decryptOwnerKeyDocument(envelope, passphrase) {
  const params = envelope && typeof envelope === "object" ? envelope.kdfParams : null;
  if (envelope?.kdf !== "scrypt" || params === null ||
      !Number.isSafeInteger(params.N) || params.N < OWNER_KEY_KDF_MIN_N ||
      !Number.isSafeInteger(params.r) || !Number.isSafeInteger(params.p) ||
      typeof envelope.salt !== "string" || typeof envelope.iv !== "string" ||
      typeof envelope.tag !== "string" || typeof envelope.ciphertext !== "string" ||
      typeof envelope.publicKey !== "string" || typeof envelope.keyId !== "string" ||
      typeof passphrase !== "string" || passphrase.length === 0) {
    throw ownerKeyLockedError();
  }
  let document = null;
  try {
    const key = scryptSync(passphrase, Buffer.from(envelope.salt, "base64"), 32, {
      N: params.N, r: params.r, p: params.p, maxmem: OWNER_KEY_SCRYPT_MAXMEM,
    });
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(ownerKeyAad(envelope.keyId, envelope.publicKey));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    document = JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8"));
  } catch {
    throw ownerKeyLockedError();
  }
  const derived = document && typeof document.privateKey === "string"
    ? derivePublicParts(document.privateKey)
    : null;
  if (!derived || derived.publicKey !== envelope.publicKey || derived.keyId !== envelope.keyId) {
    throw ownerKeyLockedError();
  }
  return document;
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
 * Write a file containing private key material with mode 0o600 (H4: unified
 * private-key permissions). The parent directory is created with mode 0o700
 * and best-effort re-chmodded, since `mkdirSync` mode bits only apply to
 * newly created directories.
 *
 * @param {string} filePath
 * @param {string} contents
 */
export { writePrivateFile };

/**
 * Read and validate a keypair JSON document. Plaintext documents need a
 * `privateKey` string; encrypted envelopes are decrypted with the resolved
 * passphrase, and a locked or tampered envelope throws OWNER_KEY_LOCKED
 * instead of returning null (a locked key is never silently regenerated).
 *
 * @param {string} filePath
 * @param {object} [options] passphrase carrier (options.passphrase / env)
 * @returns {object | null}
 */
function readKeypairFile(filePath, options = {}) {
  let parsed = null;
  try {
    protectPrivatePaths([filePath]);
    parsed = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    if (error.code === "PRIVATE_PERMISSIONS") throw error;
    return null;
  }
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    if (parsed.encrypted === true) {
      return decryptOwnerKeyDocument(parsed, resolveOwnerKeyPassphrase(options));
    }
    if (typeof parsed.privateKey === "string") {
      return parsed;
    }
  }
  return null;
}

/** Remove any stale human private key files left inside `.mirql/keys/` (Law 6). */
export function purgeStaleHumanKeys(keysDir) {
  for (const name of HUMAN_KEY_FORBIDDEN_FILES) {
    const p = join(keysDir, name);
    if (existsSync(p)) {
      try {
        rmSync(p, { force: true });
      } catch { /* mp-003-allow: a stale key file that cannot be removed now is left for the next run; enrollment does not depend on the removal */ }
    }
  }
}

/**
 * Generate (or reload) every canonical writer keypair and register their
 * public keys in `<trustRoot>/keyring.json` with explicit namespace
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
 * @param {string} [options.passphrase] encrypt the owner key at rest (else MIRQL_HUMAN_PASSPHRASE)
 * @returns {Record<string, { publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } }>}
 */
export function generateFactoryKeypairs(mirqlDir, options = {}) {
  requireTrustForKeyCreation(mirqlDir);
  const events = join(mirqlDir, "ledger", "events.jsonl");
  const configured = existsSync(trustFile(mirqlDir, "owner.pub.json")) ||
    existsSync(trustFile(mirqlDir, "keyring.json"));
  if ((existsSync(events) && statSync(events).size > 0) ||
      (configured && !options.humanKeyPath && !options.humanKeypair)) {
    throw credentialsError("credentials_required", "Existing trust requires explicit human enrollment; use mirql i enroll-key");
  }
  const keysDir = trustFile(mirqlDir, "keys");
  const ledgerDir = resolveTrustRoot(mirqlDir);
  // H4: private-key material lives only under 0o700 directories.
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  mkdirSync(ledgerDir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(keysDir, 0o700);
  } catch { /* mp-003-allow: chmod is re-applied best-effort because mkdir mode bits do not hold on every platform; the guard re-checks on use */ }
  try {
    chmodSync(ledgerDir, 0o700);
  } catch { /* mp-003-allow: chmod is re-applied best-effort because mkdir mode bits do not hold on every platform; the guard re-checks on use */ }
  purgeStaleHumanKeys(keysDir);

  // B4: fresh genesis rebuilds the keyring — no pre-planted entries survive.
  const keyring = {};

  const result = {};
  const privateFiles = [];

  // Human:owner — reuse the operator-held key file when it exists, else generate.
  let humanKp = null;
  if (options.humanKeypair && typeof options.humanKeypair.privateKey === "string") {
    humanKp = options.humanKeypair;
  } else {
    const humanPath = resolveHumanKeyPath(mirqlDir, options);
    humanKp = readKeypairFile(humanPath, options);
    if (existsSync(humanPath) && !humanKp) {
      throw credentialsError("credentials_invalid", "Existing human key is unreadable; refusing to replace it");
    }
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
  if (existsSync(trustFile(mirqlDir, "owner.pub.json")) &&
      readOwnerPin(mirqlDir).publicKey !== humanEntry.publicKey) {
    throw credentialsError("key_mismatch", "Human key differs from the existing owner pin; refusing to overwrite credentials");
  }
  result[HUMAN_WRITER_NS] = humanEntry;
  registerKeyringEntry(keyring, HUMAN_WRITER_NS, humanEntry);

  // Factory writers — machine keys persisted inside the external trust root.
  for (const item of FACTORY_WRITERS) {
    const keyPath = trustFile(mirqlDir, "keys", item.file);
    let kp = null;

    if (existsSync(keyPath)) {
      const parsed = readKeypairFile(keyPath);
      const derived = parsed ? derivePublicParts(parsed.privateKey) : null;
      if (!derived) {
        throw credentialsError("credentials_invalid", "Existing factory key is invalid; refusing to replace " + keyPath);
      }
      kp = {
        publicKey: derived.publicKey,
        privateKey: parsed.privateKey,
        keyId: derived.keyId,
        writer: { ns: item.ns, key_id: derived.keyId },
      };
    }

    if (!kp) {
      const generated = generateEd25519Keypair();
      kp = {
        publicKey: generated.publicKey,
        privateKey: generated.privateKey,
        keyId: generated.keyId,
        writer: { ns: item.ns, key_id: generated.keyId },
      };
      // H4: every private key file (including aliases) is written 0o600.
      privateFiles.push({ path: keyPath, contents: JSON.stringify(kp, null, 2) + "\n" });
      for (const alias of item.aliases) {
        privateFiles.push({ path: trustFile(mirqlDir, "keys", alias), contents: JSON.stringify(kp, null, 2) + "\n" });
      }
    }

    result[item.ns] = kp;
    registerKeyringEntry(keyring, item.ns, kp);
  }

  // The human key is encrypted at rest whenever a passphrase is available;
  // without one the legacy plaintext document is kept (library callers and
  // MIRQL_ALLOW_PLAINTEXT_OWNER_KEY fixtures; the CLI gate refuses to mint).
  const ownerPassphrase = resolveOwnerKeyPassphrase(options);
  const humanEntryDoc = ownerPassphrase !== undefined
    ? JSON.stringify(encryptOwnerKeyDocument(humanEntry, ownerPassphrase), null, 2) + "\n"
    : JSON.stringify(humanEntry, null, 2) + "\n";
  privateFiles.push({ path: resolveHumanKeyPath(mirqlDir, options), contents: humanEntryDoc });
  writePrivateFiles(privateFiles, { directories: [resolveTrustRoot(mirqlDir), keysDir] });
  sealKeyring(mirqlDir, keyring, humanEntry, { initialize: true });
  return result;
}

/** Register one writer key in the keyring under both its keyId and namespace. */
function registerKeyringEntry(keyring, ns, kp) {
  const entry = { ns, publicKey: kp.publicKey };
  keyring[kp.keyId] = entry;
  keyring[ns] = entry;
}

/**
 * Load keyring from <trustRoot>/keyring.json.
 * @param {string} mirqlDir
 * @returns {Record<string, unknown>}
 */
export function loadKeyring(mirqlDir) {
  return readSignedKeyring(mirqlDir);
}

/**
 * Load the private key for a FACTORY writer namespace, falling back to
 * `<trustRoot>/keys/<name>.key.json`. For `human:owner` there is deliberately
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
    const kp = parseKeyMaterial(directKey, options);
    if (kp) {
      return { ...kp, writer: { ns: writerNs, key_id: kp.keyId } };
    }
    return null;
  }

  const customKeyFile = firstString(options.key, options.keyFile, options["key-file"]);
  if (customKeyFile) {
    const kp = readKeypairFile(resolvePath(customKeyFile), options);
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

  const keyPath = trustFile(mirqlDir, "keys", writerEntry.file);
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
 * Parse inline key material: a JSON keypair document (plaintext or encrypted
 * envelope) or a raw base64url PKCS#8 private key. The publicKey/keyId are
 * always derived from the private key so they cannot be spoofed. An encrypted
 * envelope is decrypted with the resolved passphrase and throws
 * OWNER_KEY_LOCKED when it cannot be unlocked.
 *
 * @param {string} material
 * @param {object} [options] passphrase carrier (options.passphrase / env)
 * @returns {{ publicKey: string, privateKey: string, keyId: string } | null}
 */
function parseKeyMaterial(material, options = {}) {
  if (typeof material !== "string" || material.trim().length === 0) return null;
  const text = material.trim();
  let privateKey = text;
  if (text.startsWith("{")) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null;
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && parsed.encrypted === true) {
      privateKey = decryptOwnerKeyDocument(parsed, resolveOwnerKeyPassphrase(options)).privateKey;
    } else if (parsed && typeof parsed === "object" && typeof parsed.privateKey === "string") {
      privateKey = parsed.privateKey;
    } else {
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
 * The key file must live OUTSIDE `.mirql/`. A plaintext keypair document and
 * an encrypted envelope (unlocked with `--passphrase` / MIRQL_HUMAN_PASSPHRASE)
 * are both accepted; a locked or tampered envelope fails closed with
 * OWNER_KEY_LOCKED. Every failure mode throws a structured error with exit
 * code POLICY_DENIAL (fail closed).
 *
 * @param {string} mirqlDir
 * @param {object} [options]
 * @param {string} [options.passphrase] passphrase for an encrypted owner key file
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string }, sourceFile: string | null }}
 * @throws structured Error (errorCode credentials_* / OWNER_KEY_LOCKED)
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
      protectPrivatePaths([abs]);
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

  const kp = parseKeyMaterial(material, options);
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

/**
 * Encrypt an existing plaintext human:owner key file in place (Law 6, at
 * rest). The replacement is atomic (temp file mode 0o600 + rename via
 * writePrivateFile) and only happens after the envelope is verified to
 * decrypt back to the same keypair. An already-encrypted file is reported
 * as { status: "already_protected" } without touching it.
 *
 * @param {string} mirqlDir
 * @param {object} [options] humanKeyOut/humanKeyPath resolution + options.passphrase
 * @returns {{ status: "protected" | "already_protected", key_path: string }}
 */
export function protectOwnerKey(mirqlDir, options = {}) {
  const keyPath = resolveHumanKeyPath(mirqlDir, options);
  let parsed = null;
  try {
    protectPrivatePaths([keyPath]);
    parsed = JSON.parse(readFileSync(keyPath, "utf8"));
  } catch (error) {
    if (error.code === "PRIVATE_PERMISSIONS") throw error;
  }
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && parsed.encrypted === true) {
    return { status: "already_protected", key_path: keyPath };
  }
  if (!parsed || typeof parsed !== "object" || typeof parsed.privateKey !== "string") {
    throw credentialsError(
      "credentials_invalid",
      `no readable plaintext owner key at ${keyPath}`,
      "run mirql i genesis first, then mirql i protect-key",
    );
  }
  const passphrase = resolveOwnerKeyPassphrase(options);
  if (passphrase === undefined) {
    throw domainError(
      "OWNER_KEY_PASSPHRASE_REQUIRED",
      "OWNER_KEY_PASSPHRASE_REQUIRED: a passphrase is required to encrypt the owner key",
      EXIT_CODES.POLICY_DENIAL,
      "provide --passphrase <secret> or set MIRQL_HUMAN_PASSPHRASE",
    );
  }
  const envelope = encryptOwnerKeyDocument(parsed, passphrase);
  // Refuse to replace the file unless the envelope reopens to the same key.
  const reopened = decryptOwnerKeyDocument(envelope, passphrase);
  const before = derivePublicParts(parsed.privateKey);
  const after = derivePublicParts(reopened.privateKey);
  if (!before || !after || before.publicKey !== after.publicKey) {
    throw domainError(
      "INTEGRITY_VIOLATION",
      "encrypted owner key did not round-trip to the same keypair; refusing to replace it",
      EXIT_CODES.INTEGRITY_VIOLATION,
    );
  }
  writePrivateFile(keyPath, JSON.stringify(envelope, null, 2) + "\n");
  return { status: "protected", key_path: keyPath };
}

/**
 * Create a brand-new encrypted human:owner key at an external path (Law 6):
 * generated in memory, encrypted before any write, verified to reopen, then
 * published with exclusive creation. The private key never rests on disk in
 * plaintext and an existing file is never replaced.
 *
 * @param {string} keyPath path of the key file to create
 * @param {object} [options] passphrase carrier (options.passphrase / env)
 * @returns {{ key_path: string, keyId: string, publicKey: string }}
 */
export function createOwnerKey(keyPath, options = {}) {
  const passphrase = resolveOwnerKeyPassphrase(options);
  assertPassphraseStrength(passphrase);
  const destination = resolvePath(keyPath);
  if (existsSync(destination)) {
    throw credentialsError("credentials_required", `refusing to replace the existing key file ${destination}`, "choose another --key path");
  }
  const kp = generateEd25519Keypair();
  const envelope = encryptOwnerKeyDocument({ privateKey: kp.privateKey }, passphrase);
  const reopened = decryptOwnerKeyDocument(envelope, passphrase);
  if (reopened.privateKey !== kp.privateKey) {
    throw domainError("INTEGRITY_VIOLATION", "the new owner key did not round-trip through its envelope; nothing was written", EXIT_CODES.INTEGRITY_VIOLATION);
  }
  writePrivateFile(destination, JSON.stringify(envelope, null, 2) + "\n", { exclusive: true });
  return { key_path: destination, keyId: envelope.keyId, publicKey: envelope.publicKey };
}
