import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256, jcs } from "../../packages/core/index.mjs";
import { appendEvent } from "../../packages/log/index.mjs";
import { provisionTestTrust } from "./keyring.mjs";

/** Author a real human-signed fixture grant, without a production bypass. */
export function authorizeTestWarrant(mirqlDir, input, payload = {}) {
  const owner = provisionTestTrust(mirqlDir);
  const warrant = typeof input === "string" ? {
    v: 1, id: input, class: "surgical", semantic_fingerprint: sha256("test:" + input),
    anchors: ["packages/**"], evidence: { test: 1 }, red_check: { test: 1 },
    scope: { allow: ["packages/**"] }, budget_micro_usd: 1500000, created_by: "human:owner",
  } : input;
  mkdirSync(join(mirqlDir, "warrants"), { recursive: true });
  writeFileSync(join(mirqlDir, "warrants", warrant.id + ".json"), jcs(warrant) + "\n");
  appendEvent(mirqlDir, {
    type: "warrant.created", writer: "human:owner",
    payload: { warrant_id: warrant.id, warrant_hash: sha256(jcs(warrant)), ...payload },
  }, { signingKey: owner.privateKey, keyId: owner.keyId });
  return warrant;
}
