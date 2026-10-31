#!/usr/bin/env node
// bin/mirql-run — standalone entrypoint for the `run` tool (W1 stub; W3 lands
// the real attempt supervisor).
import { pathToFileURL } from "node:url";
import { main } from "../packages/run/index.mjs";

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
