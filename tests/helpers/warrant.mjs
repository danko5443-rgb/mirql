import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256, jcs } from "../../packages/core/index.mjs";
import { appendEvent } from "../../packages/log/index.mjs";
import { provisionTestTrust } from "./keyring.mjs";

function testWarrant(id) {
  return {
    v: 1, id, class: "surgical", semantic_fingerprint: sha256("test:" + id),
    anchors: ["packages/**"], evidence: { test: 1 }, red_check: { test: 1 },
    scope: { allow: ["packages/**"] }, budget_micro_usd: 1500000, created_by: "human:owner",
  };
}

/**
 * A warrant that names a reproducer, so the supervisor runs its worker. Without
 * one the supervisor refuses before the worker starts.
 */
export function dispatchableWarrant(id, reproducer = "tests/repro.test.mjs") {
  const warrant = testWarrant(id);
  return { ...warrant, evidence: { ...warrant.evidence, reproducer_test: reproducer } };
}

/** Author a real human-signed fixture grant, without a production bypass. */
export function authorizeTestWarrant(mirqlDir, input, payload = {}) {
  const owner = provisionTestTrust(mirqlDir);
  const warrant = typeof input === "string" ? testWarrant(input) : input;
  mkdirSync(join(mirqlDir, "warrants"), { recursive: true });
  writeFileSync(join(mirqlDir, "warrants", warrant.id + ".json"), jcs(warrant) + "\n");
  appendEvent(mirqlDir, {
    type: "warrant.created", writer: "human:owner",
    payload: { warrant_id: warrant.id, warrant_hash: sha256(jcs(warrant)), ...payload },
  }, { signingKey: owner.privateKey, keyId: owner.keyId });
  return warrant;
}
