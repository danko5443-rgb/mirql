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
  const result = main(process.argv.slice(2));
  if (result && typeof result.then === "function") {
    result
      .then((code) => {
        if (typeof code === "number") process.exitCode = code;
      })
      .catch((err) => {
        process.stderr.write(JSON.stringify({ error: err?.message || String(err) }) + "\n");
        process.exitCode = 1;
      });
  } else if (typeof result === "number") {
    process.exitCode = result;
  }
}
