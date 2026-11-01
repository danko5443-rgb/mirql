// reproducer/breaker-enforcement.mjs — Law 16 verified reproducer for issue #15.
//
// Runs the candidate's breaker enforcement suite against the checkout under
// test (MIRQL_TARGET_ROOT, set by the ci-evidence reproducer pipeline). The
// suite imports the target's core/queue/doctor modules, so on the advisory-only
// base it fails (no getActiveTrippedBreakers; leases granted despite trips),
// and on the fixed head it passes. Exit code mirrors the suite.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const root = process.env.MIRQL_TARGET_ROOT;
if (!root) {
  console.error("reproducer: MIRQL_TARGET_ROOT is not set");
  process.exit(5);
}
const suite = resolve(fileURLToPath(import.meta.url), "..", "..", "tests", "breaker-enforcement.test.mjs");
const res = spawnSync(process.execPath, ["--test", suite], {
  cwd: root,
  env: { ...process.env, MIRQL_TARGET_ROOT: root },
  stdio: "inherit",
  timeout: 120000,
});
process.exit(Number.isSafeInteger(res.status) ? res.status : 1);
