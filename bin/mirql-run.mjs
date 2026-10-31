#!/usr/bin/env node
// bin/mirql-run — standalone entrypoint for the `run` tool (W1 stub; W3 lands
// the real attempt supervisor).
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { main } from "../packages/run/index.mjs";

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
