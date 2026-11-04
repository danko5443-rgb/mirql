#!/usr/bin/env node
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

// Phase 0.0a: MIRQL_TEST_ROOT lets CI run the BASE notary's copy of this
// runner against the candidate checkout, so a PR cannot swap the runner that
// judges it. Default: the tree this script lives in.
const root = process.env.MIRQL_TEST_ROOT
  ? resolve(process.env.MIRQL_TEST_ROOT)
  : resolve(import.meta.dirname, "..");
const testsDir = join(root, "tests");
const files = readdirSync(testsDir)
  .filter((f) => f.endsWith(".test.mjs"))
  .sort()
  .map((f) => join(testsDir, f));

if (files.length === 0) {
  console.log("No test files found in tests/");
  process.exit(0);
}

// W5b: the inbox suite and the E2E tracer bullet are mandatory — refuse to
// run a partial suite if either file is missing.
const REQUIRED_SUITES = ["inbox.test.mjs", "e2e-tracer.test.mjs"];
const present = new Set(files.map((f) => f.split(/[\\/]/).pop()));
const missing = REQUIRED_SUITES.filter((name) => !present.has(name));
if (missing.length > 0) {
  console.error(`Missing required test suites: ${missing.join(", ")}`);
  process.exit(1);
}

// Tests mint per-ledger owner keys under the trust root, which defaults to
// ~/.mirql-trust. Give every run a throwaway home and trust root so a suite can
// neither litter nor read the operator's real credentials. The HOMEDRIVE and
// HOMEPATH pair goes too: it is the other way Windows tools find a home.
// Names compare uppercased because Windows environment names ignore case.
const AMBIENT_ONLY = new Set(["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "MIRQL_TRUST_ROOT", "MIRQL_HUMAN_KEY"]);
const inherited = Object.entries(process.env).filter(([name]) => !AMBIENT_ONLY.has(name.toUpperCase()));
const testHome = mkdtempSync(join(tmpdir(), "mirql-test-home-"));

const extraArgs = process.argv.slice(2);
let res;
try {
  res = spawnSync(process.execPath, ["--test", ...extraArgs, ...files], {
    cwd: root,
    env: {
      ...Object.fromEntries(inherited),
      HOME: testHome,
      USERPROFILE: testHome,
      MIRQL_TRUST_ROOT: join(testHome, ".mirql-trust"),
      MIRQL_ALLOW_PLAINTEXT_OWNER_KEY: "1", // fixtures use plaintext owner keys
    },
    stdio: "inherit",
  });
} finally {
  try {
    rmSync(testHome, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch (error) {
    // A stuck temp dir must not change the suite's verdict.
    console.error(`Could not remove test home ${testHome}: ${error.message}`);
  }
}
process.exit(res?.status ?? 1);
