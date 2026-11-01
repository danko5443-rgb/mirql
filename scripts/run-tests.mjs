#!/usr/bin/env node
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
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

const extraArgs = process.argv.slice(2);
const res = spawnSync(process.execPath, ["--test", ...extraArgs, ...files], {
  cwd: root,
  stdio: "inherit",
});
process.exit(res.status ?? 1);
