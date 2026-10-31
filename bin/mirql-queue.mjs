#!/usr/bin/env node
// bin/mirql-queue — standalone entrypoint for the `queue` tool (W1 stub; W5
// lands the real job queue).
import { pathToFileURL } from "node:url";
import { main } from "../packages/queue/index.mjs";

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
