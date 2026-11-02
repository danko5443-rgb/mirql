import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { signEvent, verifyEvent } from "./ed25519.mjs";
import { withLedgerLock } from "./lock.mjs";
import { jcs } from "./jcs.mjs";
import { resolveTrustRoot, trustFile } from "./trust-root.mjs";

function denial(message) {
  const error = new Error(message);
  error.code = "KEYRING_INTEGRITY";
  error.errorCode = error.code;
  error.exitCode = 3;
  return error;
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw denial("Cannot read trusted keyring material: " + file);
  }
}

function atomicWrite(file, value) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const temp = file + "." + randomUUID() + ".tmp";
  try {
    writeFileSync(temp, jcs(value) + "\n", { mode: 0o600, flag: "wx" });
    renameSync(temp, file);
  } finally {
    if (existsSync(temp)) unlinkSync(temp);
  }
}

export function readOwnerPin(mirqlDir) {
  const pin = readJson(trustFile(mirqlDir, "owner.pub.json"));
  if (!pin || typeof pin.publicKey !== "string" || pin.keyId !== "ed25519:" + pin.publicKey) {
    throw denial("Invalid pinned human public key");
  }
  return pin;
}

function verifiedDocument(mirqlDir) {
  const pin = readOwnerPin(mirqlDir);
  const document = readJson(trustFile(mirqlDir, "keyring.sig"));
  if (!document || document.domain !== "mirql/keyring/v1" ||
      document.ledgerId !== basename(resolveTrustRoot(mirqlDir)) ||
      document.ownerKeyId !== pin.keyId || !verifyEvent(document, pin.publicKey).ok) {
    throw denial("Keyring signature does not match this ledger and its pinned owner");
  }
  const ring = document.keyring;
  if (!ring || typeof ring !== "object" || Array.isArray(ring) ||
      ring["human:owner"]?.publicKey !== pin.publicKey ||
      ring["human:owner"]?.ns !== "human:owner") {
    throw denial("Signed keyring does not bind its pinned human owner");
  }
  return document;
}

/** A missing ring grants no trust. A present but damaged ring fails closed. */
export function readSignedKeyring(mirqlDir) {
  const file = trustFile(mirqlDir, "keyring.json");
  const signature = trustFile(mirqlDir, "keyring.sig");
  if (!existsSync(file) && !existsSync(signature)) return {};
  const document = verifiedDocument(mirqlDir);
  const mirror = readJson(file);
  if (jcs(mirror) !== jcs(document.keyring)) {
    throw denial("Keyring was modified without the pinned human owner's signature");
  }
  return document.keyring;
}

/** Caller holds the ledger lock. Initialization is an explicit operator action. */
export function sealKeyring(mirqlDir, keyring, owner, { initialize = false } = {}) {
  const pinPath = trustFile(mirqlDir, "owner.pub.json");
  const signature = signEvent({
    domain: "mirql/keyring/v1",
    ledgerId: basename(resolveTrustRoot(mirqlDir)),
    ownerKeyId: owner.keyId,
    keyring,
  }, owner.privateKey, owner.keyId);
  if (!verifyEvent(signature, owner.publicKey).ok ||
      keyring?.["human:owner"]?.publicKey !== owner.publicKey ||
      keyring?.["human:owner"]?.ns !== "human:owner") {
    throw denial("Signing material does not match the enrolled human owner");
  }
  if (existsSync(pinPath)) {
    if (readOwnerPin(mirqlDir).publicKey !== owner.publicKey) {
      throw denial("Owner key differs from the pinned trust root");
    }
  } else {
    if (!initialize) throw denial("Initialize the owner pin explicitly before enrollment");
    // Exclusive creation prevents concurrent bootstrap from replacing an owner pin.
    mkdirSync(dirname(pinPath), { recursive: true, mode: 0o700 });
    writeFileSync(pinPath, jcs({ keyId: owner.keyId, publicKey: owner.publicKey }) + "\n",
      { mode: 0o600, flag: "wx" });
  }
  atomicWrite(trustFile(mirqlDir, "keyring.json"), keyring);
  atomicWrite(trustFile(mirqlDir, "keyring.sig"), signature);
}

/** Retry from the last signed document, never from an altered unsigned mirror. */
export function enrollKey(mirqlDir, namespace, publicKey, owner, { initialize = false } = {}) {
  return withLedgerLock(mirqlDir, () => {
    if (!/^(human|tool|notary|daemon):[a-z0-9_-]+$/.test(namespace) ||
        !/^[A-Za-z0-9_-]{43}$/.test(publicKey)) {
      throw denial("Invalid namespace or Ed25519 public key");
    }
    if (initialize) {
      const signature = trustFile(mirqlDir, "keyring.sig");
      let ring;
      if (existsSync(signature)) {
        const previous = readJson(signature);
        if (!previous || previous.domain !== "mirql/keyring/v1" ||
            previous.ownerKeyId !== owner.keyId || !verifyEvent(previous, owner.publicKey).ok) {
          throw denial("Only the signing human can rebind an existing keyring");
        }
        ring = previous.keyring;
      } else {
        ring = readJson(trustFile(mirqlDir, "keyring.json"));
      }
      if (typeof ring?.["human:owner"] === "string") {
        if (ring["human:owner"] !== owner.publicKey) throw denial("Legacy owner key does not match signing material");
        const human = { ns: "human:owner", publicKey: owner.publicKey };
        ring["human:owner"] = human;
        ring[owner.keyId] = human;
      }
      for (const [ns, value] of Object.entries(ring)) {
        if (/^(human|tool|notary|daemon):/.test(ns) && typeof value === "string") {
          const entry = { ns, publicKey: value };
          ring[ns] = entry;
          ring["ed25519:" + value] = entry;
        }
      }
      sealKeyring(mirqlDir, ring, owner, { initialize: true });
    }
    const document = verifiedDocument(mirqlDir);
    const pin = readOwnerPin(mirqlDir);
    if (owner.publicKey !== pin.publicKey) throw denial("Enrollment requires the pinned human key");
    const keyring = { ...document.keyring };
    const existing = keyring[namespace];
    const existingPublicKey = typeof existing === "string" ? existing : existing?.publicKey ?? existing?.pubkey;
    if (existing && existingPublicKey !== publicKey) {
      throw denial("Changing an existing namespace key requires explicit key rotation");
    }
    const keyId = "ed25519:" + publicKey;
    const binding = keyring[keyId];
    const boundNamespace = typeof binding === "object" ? binding?.ns ?? binding?.namespace : null;
    if (boundNamespace && boundNamespace !== namespace) {
      throw denial("A key cannot authenticate multiple writer namespaces");
    }
    const entry = { ns: namespace, publicKey };
    keyring[namespace] = entry;
    keyring[keyId] = entry;
    sealKeyring(mirqlDir, keyring, owner);
    return { namespace, key_id: keyId, status: "enrolled" };
  });
}

export function assertKeyEnrolled(mirqlDir, namespace, keypair) {
  const ring = readSignedKeyring(mirqlDir);
  const entry = ring[keypair.keyId] ?? ring[namespace];
  const publicKey = keypair.publicKey ?? keypair.keyId?.slice("ed25519:".length);
  if (entry?.ns !== namespace || entry.publicKey !== publicKey) {
    throw denial("Key is not enrolled for " + namespace + "; use mirql i enroll-key with the human key");
  }
  const probe = signEvent({ domain: "mirql/key-possession/v1" }, keypair.privateKey, keypair.keyId);
  if (!verifyEvent(probe, publicKey).ok) throw denial("Private signing material does not match its enrolled key");
}
