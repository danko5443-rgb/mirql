// Law 6: daemon flags that cannot be interpreted exactly are refused, never
// silently defaulted, because the daemon runs unattended around the clock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { parseDaemonFlags } from "../bin/mirql.mjs";

const BIN = fileURLToPath(new URL("../bin/mirql.mjs", import.meta.url));
const parse = (...args) => parseDaemonFlags(["supervisor", "--daemon", ...args]);

test("the initial drain can be disabled in every documented form", () => {
  assert.equal(parse().initialRun, true);
  assert.equal(parse("--initial-run", "false").initialRun, false);
  assert.equal(parse("--initial-run=false").initialRun, false);
  assert.equal(parse("--no-initial-run").initialRun, false);
  assert.equal(parse("--no-initial-run", "--dir", "x").dir, "x", "--no-initial-run must not swallow the next flag's value");
  assert.equal(parse("--initial-run", "true").initialRun, true);
});

test("max-steps accepts only positive integers", () => {
  assert.equal(parse("--max-steps", "3").maxSteps, 3);
  assert.equal(parse().maxSteps, undefined);
  for (const bad of ["0", "-1", "abc", "1.5", "07", "9007199254740993", ""]) {
    assert.throws(() => parse(`--max-steps=${bad}`), /--max-steps/, bad);
  }
  assert.throws(() => parse("--max-steps"), /--max-steps/);
});

test("ambiguous or conflicting flags are refused", () => {
  assert.throws(() => parse("--initial-run", "maybe"), /--initial-run/);
  assert.throws(() => parse("--no-initial-run", "--initial-run", "true"), /conflict/);
  assert.throws(() => parseDaemonFlags(["supervisor", "--daemon=1"]), /--daemon/);
  for (const name of ["dir", "workspace", "command"]) assert.throws(() => parse(`--${name}`), new RegExp(`--${name}`));
});

test("an invalid daemon invocation exits with a usage error before claiming the launcher pid", () => {
  const root = mkdtempSync(join(tmpdir(), "mirql-daemon-flags-")); try {
    const dir = join(root, ".mirql");
    for (const args of [["--max-steps", "abc"], ["--initial-run", "nope"]]) {
      const result = spawnSync(process.execPath, [BIN, "r", "supervisor", "--daemon", "--dir", dir, ...args],
        { encoding: "utf8", windowsHide: true, timeout: 20000, env: { ...process.env, MIRQL_TRUST_ROOT: join(root, "trust") } });
      assert.equal(result.status, 2, result.stderr);
      assert.equal(JSON.parse(result.stderr.trim()).error, "USAGE_ERROR");
      assert.equal(existsSync(join(dir, "state", "launcher.pid")), false);
    }
    const valued = spawnSync(process.execPath, [BIN, "r", "supervisor", "--daemon=1", "--dir", dir],
      { encoding: "utf8", windowsHide: true, timeout: 20000, env: { ...process.env, MIRQL_TRUST_ROOT: join(root, "trust") } });
    assert.equal(valued.status, 2, "a valued --daemon must not fall through to a one-shot supervisor run");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
