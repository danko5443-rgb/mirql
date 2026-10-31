#!/usr/bin/env node
// bin/mirql-inbox — standalone entrypoint for the `inbox` tool (W1 stub; W4
// lands the real human approval inbox).
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { main } from "../packages/inbox/index.mjs";

function resolveArgv1(entry) {
  try {
    return realpathSync(entry);
  } catch {
    return resolve(entry);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolveArgv1(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
