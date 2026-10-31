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

const extraArgs = process.argv.slice(2);
const res = spawnSync(process.execPath, ["--test", ...extraArgs, ...files], {
  cwd: root,
  stdio: "inherit",
});
process.exit(res.status ?? 1);
