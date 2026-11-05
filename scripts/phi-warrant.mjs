#!/usr/bin/env node
// scripts/phi-warrant.mjs — the owner's commands for the standing Phi warrant (Law 13).
//
//   node scripts/phi-warrant.mjs pin --key <owner key file>
//   node scripts/phi-warrant.mjs grant --budget <n> --key <owner key file>
//
// `pin` writes the owner's public key to policy/phi-warrant-key.json; commit it
// through a PR. `grant` signs an allowance of <n> Phi, counted from the current
// default branch tip, and stores it in the MIRQL_PHI_WARRANT repository variable.
// Run grant again when it is spent; `gh variable delete MIRQL_PHI_WARRANT` revokes.
//
// Run these yourself, in a terminal; they refuse to run without one. An encrypted
// key reads its passphrase from MIRQL_HUMAN_PASSPHRASE.
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { signEvent } from "../packages/core/ed25519.mjs";
import { PHI_WARRANT_DOMAIN, PHI_WARRANT_PIN_PATH, readPhiWarrantPin, verifyPhiWarrant } from "../packages/core/phi-warrant.mjs";
import { requireHumanKey } from "../packages/inbox/keys.mjs";
import { isEntrypoint } from "./ci-review-gate.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/phi-warrant.mjs pin --key <file> | grant --budget <n> --key <file>";

function gh(args) {
  const res = spawnSync("gh", args, { encoding: "utf8" });
  if (res.error) throw res.error;
  if (res.status !== 0) throw new Error(`gh ${args[0]} failed: ${res.stderr.trim()}`);
  return res.stdout;
}

async function askOnTerminal(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
}

function pin(owner, rootDir, log) {
  writeFileSync(join(rootDir, PHI_WARRANT_PIN_PATH), `${JSON.stringify({ keyId: owner.keyId, publicKey: owner.publicKey })}\n`);
  log(`Wrote ${PHI_WARRANT_PIN_PATH} for ${owner.keyId}. Commit it through a PR; CI reads the pin only from the base branch.`);
  return 0;
}

async function grant(owner, budgetText, { rootDir, runGh, ask, log, now }) {
  if (!/^(0|[1-9][0-9]*)$/.test(budgetText ?? "") || !Number.isSafeInteger(Number(budgetText))) {
    log(USAGE);
    return 2;
  }
  if (readPhiWarrantPin(rootDir) !== owner.publicKey) {
    log(`phi-warrant: this key is not the one in ${PHI_WARRANT_PIN_PATH}, so CI would ignore the warrant. Pin it first.`);
    return 1;
  }
  const baseSha = runGh(["api", "repos/{owner}/{repo}/commits/HEAD", "--jq", ".sha"]).trim();
  log(`Budget: ${budgetText} Phi, counted from default branch commit ${baseSha}`);
  log(`Signing key: ${owner.keyId}`);
  log("This replaces any warrant already set. PRs inside it merge without your sign-off.");
  const answer = await ask("Type yes to sign this warrant: ");
  if (answer.trim().toLowerCase() !== "yes") {
    log("Not signed.");
    return 1;
  }
  const warrant = signEvent({
    domain: PHI_WARRANT_DOMAIN,
    writer: { ns: "human:owner", key_id: owner.keyId },
    phi_budget: Number(budgetText),
    base_sha: baseSha,
    issued_at: now().toISOString(),
  }, owner.privateKey, owner.keyId);
  if (!verifyPhiWarrant(warrant, owner.publicKey).ok) throw new Error("the signed warrant failed its own verification");
  runGh(["variable", "set", "MIRQL_PHI_WARRANT", "--body", JSON.stringify(warrant)]);
  log(`Set MIRQL_PHI_WARRANT (${warrant.hash}). Revoke it any time with: gh variable delete MIRQL_PHI_WARRANT`);
  return 0;
}

export async function run(argv, { runGh = gh, ask = askOnTerminal, isTty = process.stdin.isTTY, log = console.log, rootDir = ROOT, now = () => new Date() } = {}) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: true, options: { key: { type: "string" }, budget: { type: "string" } } });
  } catch (err) {
    log(`${USAGE}\n${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
  const { positionals: [command], values } = parsed;
  if (parsed.positionals.length !== 1 || !["pin", "grant"].includes(command)) {
    log(USAGE);
    return 2;
  }
  if (!isTty) {
    log("phi-warrant: refusing to run without a terminal; the owner runs this by hand.");
    return 2;
  }
  const owner = requireHumanKey(join(rootDir, ".mirql"), { key: values.key });
  return command === "pin" ? pin(owner, rootDir, log) : grant(owner, values.budget, { rootDir, runGh, ask, log, now });
}

if (isEntrypoint(import.meta.url)) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`phi-warrant: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    },
  );
}
