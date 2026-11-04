// A suite run must leave the operator's trust root untouched. Every run here
// happens under a fake home and a small fixture tree, so this test never goes
// near the real ~/.mirql-trust and does not re-run the full suite.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { refuseOperatorTrustInTests } from "../packages/core/trust-root.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const RUNNER = join(ROOT, "scripts", "run-tests.mjs");
const TRUST_ROOT_MODULE = pathToFileURL(join(ROOT, "packages", "core", "trust-root.mjs")).href;

// Creates ledger trust directories the way product code does: once through the
// inherited MIRQL_TRUST_ROOT, and once through the home default that a test
// reaches after clearing that variable.
const WRITER = `
import test from "node:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { resolveTrustRoot } from ${JSON.stringify(TRUST_ROOT_MODULE)};

const newLedger = () => join(mkdtempSync(join(tmpdir(), "mirql-isolation-ledger-")), ".mirql");

test("mints trust directories", () => {
  const seen = {
    home: homedir(),
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    trustRoot: process.env.MIRQL_TRUST_ROOT,
    humanKey: process.env.MIRQL_HUMAN_KEY,
  };
  writeFileSync(process.env.MIRQL_ISOLATION_REPORT, JSON.stringify(seen));
  mkdirSync(resolveTrustRoot(newLedger()), { recursive: true });
  delete process.env.MIRQL_TRUST_ROOT;
  mkdirSync(resolveTrustRoot(newLedger()), { recursive: true });
});
`;

const countDirs = (dir) => readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory()).length;

describe("test runner isolation", () => {
  let sandbox;
  let fakeHome;
  let fakeHomeTrust;
  let fakeAmbientTrust;
  let fixture;
  let report;

  // Drop NODE_TEST_CONTEXT so the nested `node --test` reports as a top-level run.
  function ambientEnv(extra = {}) {
    const { NODE_TEST_CONTEXT: _ctx, MIRQL_TRUST_ROOT: _root, MIRQL_HUMAN_KEY: _key, ...env } = process.env;
    return { ...env, HOME: fakeHome, USERPROFILE: fakeHome, MIRQL_ISOLATION_REPORT: report, ...extra };
  }

  function runSuite(extra) {
    return spawnSync(process.execPath, [RUNNER], {
      encoding: "utf8",
      timeout: 120000,
      env: ambientEnv({ MIRQL_TEST_ROOT: fixture, ...extra }),
    });
  }

  beforeEach(() => {
    sandbox = mkdtempSync(join(tmpdir(), "mirql-isolation-"));
    fakeHome = join(sandbox, "home");
    fakeHomeTrust = join(fakeHome, ".mirql-trust");
    fakeAmbientTrust = join(sandbox, "ambient-trust");
    report = join(sandbox, "report.json");
    for (const dir of [fakeHomeTrust, fakeAmbientTrust]) {
      mkdirSync(join(dir, "existing-a"), { recursive: true });
      mkdirSync(join(dir, "existing-b"));
    }
    fixture = join(sandbox, "tree");
    mkdirSync(join(fixture, "tests"), { recursive: true });
    for (const name of ["inbox.test.mjs", "e2e-tracer.test.mjs"]) {
      writeFileSync(join(fixture, "tests", name), 'import test from "node:test";\ntest("ok", () => {});\n');
    }
    writeFileSync(join(fixture, "tests", "writer.test.mjs"), WRITER);
  });

  afterEach(() => {
    rmSync(sandbox, { recursive: true, force: true });
  });

  it("control: the same writer run without the runner does add to the home trust root", () => {
    const before = countDirs(fakeHomeTrust);
    const res = spawnSync(process.execPath, ["--test", join(fixture, "tests", "writer.test.mjs")], {
      cwd: fixture,
      encoding: "utf8",
      timeout: 120000,
      env: ambientEnv(),
    });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.equal(countDirs(fakeHomeTrust), before + 2);
  });

  it("a suite run creates nothing under the home or ambient trust root", () => {
    const homeBefore = countDirs(fakeHomeTrust);
    const ambientBefore = countDirs(fakeAmbientTrust);
    const res = runSuite({ MIRQL_TRUST_ROOT: fakeAmbientTrust });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.equal(countDirs(fakeHomeTrust), homeBefore);
    assert.equal(countDirs(fakeAmbientTrust), ambientBefore);
  });

  it("test processes get a throwaway home and no ambient human key", () => {
    const res = runSuite({ MIRQL_TRUST_ROOT: fakeAmbientTrust, MIRQL_HUMAN_KEY: join(sandbox, "real.key") });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    const seen = JSON.parse(readFileSync(report, "utf8"));
    assert.notEqual(seen.home, fakeHome);
    assert.equal(seen.HOME, seen.home);
    assert.equal(seen.USERPROFILE, seen.home);
    assert.equal(seen.trustRoot, join(seen.home, ".mirql-trust"));
    assert.equal(seen.humanKey, undefined);
  });

  it("the throwaway home is deleted after a passing run and after a failing run", () => {
    const passed = runSuite();
    assert.equal(passed.status, 0, passed.stdout + passed.stderr);
    assert.equal(existsSync(JSON.parse(readFileSync(report, "utf8")).home), false);

    rmSync(report);
    writeFileSync(
      join(fixture, "tests", "zz-fail.test.mjs"),
      'import test from "node:test";\nimport assert from "node:assert/strict";\ntest("marker", () => assert.fail("ISOLATION_FAIL_MARKER"));\n',
    );
    const failed = runSuite();
    assert.notEqual(failed.status, 0);
    assert.match(failed.stdout + failed.stderr, /ISOLATION_FAIL_MARKER/);
    assert.equal(existsSync(JSON.parse(readFileSync(report, "utf8")).home), false);
  });

  // Run through a real `node --test` so a change to what that flag sets fails
  // here. resolveTrustRoot only computes a path, so this creates nothing even if
  // the refusal regresses.
  it("a direct node --test run is refused the account's own trust root", () => {
    const refused = join(fixture, "tests", "refused.test.mjs");
    writeFileSync(refused, `
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { resolveTrustRoot } from ${JSON.stringify(TRUST_ROOT_MODULE)};

test("refused", () => {
  process.env.HOME = process.env.USERPROFILE = userInfo().homedir;
  delete process.env.MIRQL_TRUST_ROOT;
  const ledger = join(mkdtempSync(join(tmpdir(), "mirql-isolation-ledger-")), ".mirql");
  assert.throws(() => resolveTrustRoot(ledger), /operator's trust root/);
});
`);
    const res = spawnSync(process.execPath, ["--test", refused], {
      cwd: fixture,
      encoding: "utf8",
      timeout: 120000,
      env: ambientEnv(),
    });
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });

  it("the refusal covers only the account's trust root, and only in a test process", () => {
    const options = { env: { NODE_TEST_CONTEXT: "child-v8" }, accountHome: fakeHome };
    assert.throws(() => refuseOperatorTrustInTests(fakeHomeTrust, options), /operator's trust root/);
    assert.throws(() => refuseOperatorTrustInTests(join(fakeHomeTrust, "nested"), options), /operator's trust root/);
    // Elsewhere under the home stays open: the OS temp directory often lives there.
    refuseOperatorTrustInTests(join(fakeHome, "AppData", "Temp", "trust"), options);
    refuseOperatorTrustInTests(fakeAmbientTrust, options);
    refuseOperatorTrustInTests(fakeHomeTrust, { env: {}, accountHome: fakeHome });
  });

  it("journey CLI children use the journey's home over the caller's", () => {
    mkdirSync(join(fixture, "bin"));
    writeFileSync(
      join(fixture, "bin", "mirql.mjs"),
      'import { homedir } from "node:os";\nconsole.log(JSON.stringify({ home: homedir(), trustRoot: process.env.MIRQL_TRUST_ROOT }));\n',
    );
    const homeDir = join(sandbox, "journey-home");
    const script = `
      import { executeCli } from ${JSON.stringify(pathToFileURL(join(ROOT, "packages", "run", "journey.mjs")).href)};
      console.log(JSON.stringify(executeCli([], { repoRoot: ${JSON.stringify(fixture)}, homeDir: ${JSON.stringify(homeDir)} }).parsed));
    `;
    const res = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      timeout: 120000,
      env: ambientEnv({ MIRQL_TRUST_ROOT: fakeAmbientTrust }),
    });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.deepEqual(JSON.parse(res.stdout), { home: homeDir, trustRoot: join(homeDir, ".mirql-trust") });
  });

  // The real CLI, so genesis really mints keys. TEMP points into the sandbox to
  // show where they went and that nothing outlives the journey.
  function runJourneyCli(...flags) {
    const temp = join(sandbox, "temp");
    mkdirSync(temp, { recursive: true });
    const res = spawnSync(process.execPath, [
      join(ROOT, "bin", "mirql.mjs"), "r", "journey", "--scenario", "init-to-merge", "--json", ...flags,
    ], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 120000,
      env: ambientEnv({ MIRQL_TRUST_ROOT: fakeAmbientTrust, TEMP: temp, TMP: temp, TMPDIR: temp }),
    });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.equal(JSON.parse(res.stdout).ok, true, res.stdout);
    return temp;
  }

  it("mirql r journey leaves the caller's home and trust root untouched and cleans up", () => {
    const homeBefore = countDirs(fakeHomeTrust);
    const ambientBefore = countDirs(fakeAmbientTrust);
    const temp = runJourneyCli();
    assert.equal(countDirs(fakeHomeTrust), homeBefore);
    assert.equal(countDirs(fakeAmbientTrust), ambientBefore);
    assert.deepEqual(readdirSync(temp).filter((name) => name.startsWith("mirql-journey-")), []);
  });

  it("a journey's keys are minted under its throwaway home, outside its sandbox", () => {
    const temp = runJourneyCli("--keep-sandbox");
    const kept = readdirSync(temp).filter((name) => name.startsWith("mirql-journey-"));
    assert.equal(kept.length, 1);
    assert.equal(countDirs(join(temp, kept[0], "home", ".mirql-trust")), 1);
    assert.equal(existsSync(join(temp, kept[0], "sandbox", ".mirql-trust")), false);
  });

  // executeCli builds its child's env from scratch, so a dropped variable sends
  // homedir() back to the OS profile. The stand-in bin only reports what it sees,
  // so a regression here fails without writing to the real trust root.
  it("journey CLI children keep the caller's home and trust root", () => {
    mkdirSync(join(fixture, "bin"));
    writeFileSync(
      join(fixture, "bin", "mirql.mjs"),
      'import { homedir } from "node:os";\nconsole.log(JSON.stringify({ home: homedir(), trustRoot: process.env.MIRQL_TRUST_ROOT }));\n',
    );
    const script = `
      import { executeCli } from ${JSON.stringify(pathToFileURL(join(ROOT, "packages", "run", "journey.mjs")).href)};
      console.log(JSON.stringify(executeCli([], { repoRoot: ${JSON.stringify(fixture)} }).parsed));
    `;
    const res = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      timeout: 120000,
      env: ambientEnv({ MIRQL_TRUST_ROOT: fakeAmbientTrust }),
    });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.deepEqual(JSON.parse(res.stdout), { home: fakeHome, trustRoot: fakeAmbientTrust });
  });
});
