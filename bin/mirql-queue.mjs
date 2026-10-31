#!/usr/bin/env node
// bin/mirql-queue — standalone entrypoint for the `queue` tool (W1 stub; W5
// lands the real job queue).
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { main } from "../packages/queue/index.mjs";

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
