// packages/inbox/keys.mjs — Key Management & Keyring Provisioning for mirql-inbox.
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import { join } from "node:path";
import { generateEd25519Keypair } from "../core/index.mjs";

/**
 * The canonical writer namespaces provisioned at genesis.
 */
export const CANONICAL_WRITERS = Object.freeze([
  { ns: "human:owner", file: "human.key.json", aliases: ["human_owner.key.json"] },
  { ns: "tool:queue", file: "queue.key.json", aliases: [] },
  { ns: "tool:run_supervisor", file: "run_supervisor.key.json", aliases: [] },
  { ns: "tool:log", file: "log.key.json", aliases: [] },
  { ns: "tool:inbox", file: "inbox.key.json", aliases: [] },
  { ns: "notary:mergeproof", file: "notary.key.json", aliases: ["mergeproof.key.json"] },
  { ns: "daemon:lifeguard", file: "lifeguard.key.json", aliases: [] },
]);

/**
 * Generate or load all canonical factory keypairs and register their public
 * keys in <mirqlDir>/ledger/keyring.json so all tools can sign and verify out-of-the-box.
 *
 * @param {string} mirqlDir
 * @returns {Record<string, { publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } }>}
 */
export function generateFactoryKeypairs(mirqlDir) {
  const keysDir = join(mirqlDir, "keys");
  const ledgerDir = join(mirqlDir, "ledger");
  mkdirSync(keysDir, { recursive: true });
  mkdirSync(ledgerDir, { recursive: true });

  const keyringPath = join(ledgerDir, "keyring.json");
  let keyring = {};
  if (existsSync(keyringPath)) {
    try {
      const parsed = JSON.parse(readFileSync(keyringPath, "utf8"));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        keyring = parsed;
      }
    } catch {}
  }

  const result = {};

  for (const item of CANONICAL_WRITERS) {
    const keyPath = join(keysDir, item.file);
    let kp = null;

    if (existsSync(keyPath)) {
      try {
        const parsed = JSON.parse(readFileSync(keyPath, "utf8"));
        if (parsed?.publicKey && parsed?.privateKey && parsed?.keyId) {
          kp = {
            publicKey: parsed.publicKey,
            privateKey: parsed.privateKey,
            keyId: parsed.keyId,
            writer: { ns: item.ns, key_id: parsed.keyId },
          };
        }
      } catch {}
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
    // Register by keyId (used by packages/log) AND by writer namespace (used by packages/queue)
    keyring[kp.keyId] = kp.publicKey;
    keyring[item.ns] = kp.publicKey;
  }

  writeFileSync(keyringPath, JSON.stringify(keyring, null, 2) + "\n", "utf8");
  return result;
}

/**
 * Load keyring from <mirqlDir>/ledger/keyring.json.
 * @param {string} mirqlDir
 * @returns {Record<string, string>}
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
 * Load the private key for a given writer namespace.
 * Checks options.signingKey / options.privateKey, then options.key (file path),
 * then <mirqlDir>/keys/<name>.key.json.
 *
 * @param {string} mirqlDir
 * @param {string} writerNs
 * @param {object} [options]
 * @returns {{ publicKey: string, privateKey: string, keyId: string, writer: { ns: string, key_id: string } } | null}
 */
export function loadWriterKey(mirqlDir, writerNs, options = {}) {
  const directKey = options.signingKey || options.privateKey;
  if (typeof directKey === "string" && directKey.length > 0) {
    if (directKey.startsWith("{")) {
      try {
        const parsed = JSON.parse(directKey);
        if (parsed.privateKey) {
          return {
            publicKey: parsed.publicKey,
            privateKey: parsed.privateKey,
            keyId: parsed.keyId,
            writer: { ns: writerNs, key_id: parsed.keyId },
          };
        }
      } catch {}
    }
    // If it's a raw base64url private key string
    return {
      publicKey: options.publicKey || "",
      privateKey: directKey,
      keyId: options.keyId || "",
      writer: { ns: writerNs, key_id: options.keyId || "" },
    };
  }

  const customKeyFile = options.key || options.keyFile;
  if (typeof customKeyFile === "string" && existsSync(customKeyFile)) {
    try {
      const parsed = JSON.parse(readFileSync(customKeyFile, "utf8"));
      if (parsed.privateKey) {
        return {
          publicKey: parsed.publicKey,
          privateKey: parsed.privateKey,
          keyId: parsed.keyId,
          writer: { ns: writerNs, key_id: parsed.keyId },
        };
      }
    } catch {}
  }

  const writerEntry = CANONICAL_WRITERS.find((w) => w.ns === writerNs);
  if (!writerEntry) return null;

  const keyPath = join(mirqlDir, "keys", writerEntry.file);
  if (existsSync(keyPath)) {
    try {
      const parsed = JSON.parse(readFileSync(keyPath, "utf8"));
      if (parsed.privateKey && parsed.publicKey && parsed.keyId) {
        return {
          publicKey: parsed.publicKey,
          privateKey: parsed.privateKey,
          keyId: parsed.keyId,
          writer: { ns: writerNs, key_id: parsed.keyId },
        };
      }
    } catch {}
  }

  return null;
}
