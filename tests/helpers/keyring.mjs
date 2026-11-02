// Fixtures author trusted state explicitly using an operator-held test key.
import { readFileSync, writeFileSync } from "node:fs";
import { generateFactoryKeypairs, resolveHumanKeyPath } from "../../packages/inbox/keys.mjs";
import { readSignedKeyring, sealKeyring } from "../../packages/core/keyring.mjs";
import { trustFile } from "../../packages/core/trust-root.mjs";
import { existsSync } from "node:fs";

export function provisionTestTrust(mirqlDir) {
  if (!existsSync(trustFile(mirqlDir, "owner.pub.json"))) {
    generateFactoryKeypairs(mirqlDir);
  }
  return JSON.parse(readFileSync(resolveHumanKeyPath(mirqlDir), "utf8"));
}

export function saveTestKeyring(mirqlDir, additions, options = {}) {
  const owner = options.owner ?? provisionTestTrust(mirqlDir);
  const ring = options.overwrite ? {} : readSignedKeyring(mirqlDir);
  for (const [key, value] of Object.entries(additions)) {
    const entry = typeof value === "string" && !key.startsWith("ed25519:")
      ? { ns: key, publicKey: value } : value;
    ring[key] = entry;
    if (entry && typeof entry === "object" && entry.ns && entry.publicKey) {
      ring["ed25519:" + entry.publicKey] = entry;
    }
  }
  const human = { ns: "human:owner", publicKey: owner.publicKey };
  ring["human:owner"] ??= human;
  ring[owner.keyId] ??= human;
  sealKeyring(mirqlDir, ring, owner);
}

export function authorizeTestKey(mirqlDir, namespace, keypair) {
  saveTestKeyring(mirqlDir, { [namespace]: { ns: namespace, publicKey: keypair.publicKey } });
  const files = {
    "tool:queue": "queue.key.json",
    "tool:run_supervisor": "run_supervisor.key.json",
    "notary:mergeproof": "notary.key.json",
  };
  if (files[namespace]) {
    writeFileSync(trustFile(mirqlDir, "keys", files[namespace]), JSON.stringify(keypair), { mode: 0o600 });
  }
}
