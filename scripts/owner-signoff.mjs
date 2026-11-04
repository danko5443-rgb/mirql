#!/usr/bin/env node
// scripts/owner-signoff.mjs — the owner's one command to sign off a reviewed PR.
//
//   node scripts/owner-signoff.mjs <pr-number>
//
// Shows what the PR's head commit is right now, asks for a typed yes, then adds
// the `reviewed:<head sha>` label, which re-runs the Mergeproof gate. Showing
// the head first matters: a commit pushed after your review is not what you
// reviewed. Run it yourself, in a terminal; it refuses to run without one.

import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import { signoffLabel } from "./ci-owner-signoff.mjs";

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

export async function run(argv, { runGh = gh, ask = askOnTerminal, isTty = process.stdin.isTTY, log = console.log } = {}) {
  const pr = argv[0];
  if (argv.length !== 1 || !/^[1-9][0-9]*$/.test(pr)) {
    log("usage: node scripts/owner-signoff.mjs <pr-number>");
    return 2;
  }
  if (!isTty) {
    log("owner-signoff: refusing to run without a terminal; the owner runs this by hand.");
    return 2;
  }
  const view = JSON.parse(runGh(["pr", "view", pr, "--json", "headRefOid,title,files"]));
  const label = signoffLabel(view.headRefOid);
  log(`PR ${pr}: ${view.title}`);
  log(`Head commit: ${view.headRefOid}`);
  log(`Files (${view.files.length}):`);
  for (const f of view.files) log(`  ${f.path}`);
  const answer = await ask("Did you review this exact commit? Type yes to sign off: ");
  if (answer.trim().toLowerCase() !== "yes") {
    log("Not signed off.");
    return 1;
  }
  runGh(["label", "create", label, "--force", "--color", "0e8a16", "--description", "Owner reviewed this head commit"]);
  runGh(["api", "--method", "POST", `repos/{owner}/{repo}/issues/${pr}/labels`, "-f", `labels[]=${label}`]);
  log(`Added ${label}. The Mergeproof gate re-runs now; a new push voids this sign-off.`);
  return 0;
}

function isEntrypoint() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1] ?? "");
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`owner-signoff: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    },
  );
}
