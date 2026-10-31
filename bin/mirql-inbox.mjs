#!/usr/bin/env node
// bin/mirql-inbox — standalone entrypoint for the `inbox` tool (W1 stub; W4
// lands the real human approval inbox).
import { pathToFileURL } from "node:url";
import { main } from "../packages/inbox/index.mjs";

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
