#!/usr/bin/env node
// bin/mirql-log — standalone entrypoint for the `log` tool (W1 stub; W5 lands
// the real signed ledger CLI).
import { pathToFileURL } from "node:url";
import { main } from "../packages/log/index.mjs";

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
