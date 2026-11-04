import {verifyAuthorizedGitFixture} from "./helpers/authorized-verification.mjs";
import { git, initEmptyRepo } from "./helpers/git.mjs";
import { authorizeTestWarrant, dispatchableWarrant } from "./helpers/warrant.mjs";
import { provisionTestTrust, authorizeTestKey } from "./helpers/keyring.mjs";
import { foldEvents } from "../packages/log/index.mjs";
import { test, describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  EXIT_CODES,
  validateDocument,
  verifyEvent,
  jcs,
  generateEd25519Keypair,
} from "../packages/core/index.mjs";

import {
  computePhi,
  checkPhiReduction,
  verifyAttempt,
  runSupervisor,
  runAgent,
  sanitizeAgentEnv,
  SAFE_ENV_ALLOWLIST,
  runProbe,
  runBingBong,
  checkAntiCheat,
  checkHumanOnlyPaths,
  checkHumanApprovePaths,
  checkSwallowedExceptions,
  checkTestWeakenings,
  isHumanOnlyPath,
  normalizePath,
} from "../packages/run/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

/** Spawns a bin script relative to repo root */
function runBin(binRelPath, args, options = {}) {
  return spawnSync(process.execPath, [join(ROOT, binRelPath), ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30000,
    ...options,
  });
}

describe("Work Package W5a: `mirql-run` and `bing-bong` Consensus Loop", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-w5a-test-"));
    provisionTestTrust(tempDir);
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // -------------------------------------------------------------------------
  // 1. Triple-Execution Red-Green-ReRed Verifier (verifyAttempt, B1 & B2)
  // -------------------------------------------------------------------------
  describe("1. Triple-Execution Red-Green-ReRed Verifier", () => {
    it("passes when a real bug/feature fails on base, passes on head, and fails on revert", async () => {
      let srcReverted = false;

      const runCheck = async ({ stage }) => {
        if (stage === "red_on_base") {
          return { exitCode: 1, stderr: "AssertionError: expected 42 got undefined" };
        }
        if (stage === "green_on_head") {
          return { exitCode: 0, stdout: "pass" };
        }
        if (stage === "re_red_on_revert") {
          srcReverted = true;
          return { exitCode: 1, stderr: "AssertionError: expected 42 got undefined" };
        }
        return { exitCode: 0 };
      };

      const result = await verifyAttempt({
        runCheck,
        modifiedFiles: ["packages/core/math.mjs", "tests/math.test.mjs"],
      });

      assert.equal(result.verified, true);
      assert.equal(result.verdict, "auto_merge");
      assert.equal(result.rule, "MP-000");
      assert.equal(result.proof?.causal_cycle_completed, true);
      assert.equal(srcReverted, true);
      assert.equal(result.checks?.red_on_base?.passed, true);
      assert.equal(result.checks?.green_on_head?.passed, true);
      assert.equal(result.checks?.re_red_on_revert?.passed, true);
    });

    it("fails with RE_RED_FAILED when builder submits a tautological test", async () => {
      const runCheck = async ({ stage }) => {
        if (stage === "red_on_base") {
          return { exitCode: 1, stderr: "assertion error on base" };
        }
        if (stage === "green_on_head") {
          return { exitCode: 0, stdout: "ok" };
        }
        if (stage === "re_red_on_revert") {
          // Tautology: assert.equal(1, 1) still passes with src reverted!
          return { exitCode: 0, stdout: "ok" };
        }
        return { exitCode: 0 };
      };

      const result = await verifyAttempt({
        runCheck,
        modifiedFiles: ["packages/core/calc.mjs", "tests/calc.test.mjs"],
      });

      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.equal(result.rule, "RE_RED_FAILED");
      assert.equal(result.violation, "RE_RED_FAILED");
      assert.match(result.detail, /re-red.*tautological/i);
    });

    it("fails with RED_ON_BASE_FAILED when reproducer already passes on base", async () => {
      const runCheck = async ({ stage }) => {
        if (stage === "red_on_base") {
          return { exitCode: 0, stdout: "already passes" };
        }
        return { exitCode: 0 };
      };

      const result = await verifyAttempt({ runCheck });
      assert.equal(result.verified, false);
      assert.equal(result.rule, "RED_ON_BASE_FAILED");
      assert.equal(result.violation, "RED_ON_BASE_FAILED");
    });

    it("fails with RED_ON_BASE_CRASH when reproducer crashes on base (exit 2)", async () => {
      // B1: A crash on base is NOT a valid red
      const runCheck = async ({ stage }) => {
        if (stage === "red_on_base") {
          return { exitCode: 2, stderr: "Segmentation fault or unhandled crash" };
        }
        return { exitCode: 0 };
      };

      const result = await verifyAttempt({ runCheck });
      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.equal(result.rule, "RED_ON_BASE_CRASH");
      assert.equal(result.violation, "RED_ON_BASE_CRASH");
      assert.match(result.detail, /crash on base is not a valid red/i);
    });

    it("fails with GREEN_ON_HEAD_FAILED when full suite fails on head", async () => {
      const runCheck = async ({ stage }) => {
        if (stage === "red_on_base") {
          return { exitCode: 1 };
        }
        if (stage === "green_on_head") {
          return { exitCode: 1, stderr: "broken test on head" };
        }
        return { exitCode: 0 };
      };

      const result = await verifyAttempt({ runCheck });
      assert.equal(result.verified, false);
      assert.equal(result.rule, "GREEN_ON_HEAD_FAILED");
      assert.equal(result.violation, "GREEN_ON_HEAD_FAILED");
    });

    it("B1: fails closed when no callback or runner is provided", () => {
      const result = verifyAttempt({});
      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.equal(result.rule, "MISSING_RUNNER");
    });

    it("B1: fails closed when exit code is null or non-integer", async () => {
      const runCheck = () => ({ exitCode: null });
      const result = await verifyAttempt({ runCheck });
      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.equal(result.rule, "NON_INTEGER_EXIT_CODE");
    });

    it("B1: CLI `mirql r verify` with no inputs fails with exit 2 (USAGE_ERROR)", () => {
      const res = runBin("bin/mirql.mjs", ["r", "verify"]);
      assert.equal(res.status, EXIT_CODES.USAGE_ERROR); // 2
      const doc = JSON.parse(res.stderr);
      assert.equal(doc.error, "USAGE_ERROR");
    });

    it("B1 & B2: end-to-end test against a temporary git repo verifying full cycle and tautological test rejection", () => {
      const repoDir = join(tempDir, "git-test-repo");
      spawnSync("git", ["init", "-b", "main", repoDir], { encoding: "utf8" });
      spawnSync("git", ["config", "user.name", "Mirql Test"], { cwd: repoDir });
      spawnSync("git", ["config", "user.email", "test@mirql.local"], { cwd: repoDir });

      // Base commit: broken implementation
      writeFileSync(
        join(repoDir, "package.json"),
        JSON.stringify({ type: "module", scripts: { test: "node --test" } }),
        "utf8",
      );
      const srcDir = join(repoDir, "src");
      mkdirSync(srcDir, { recursive: true });
      writeFileSync(
        join(srcDir, "math.mjs"),
        "export function add(a, b) { return a - b; } // BUG!\n",
        "utf8",
      );
      spawnSync("git", ["add", "."], { cwd: repoDir });
      spawnSync("git", ["commit", "-m", "base: bug in math"], { cwd: repoDir });
      const baseSha = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();

      // Head commit: fix bug + add real reproducer
      writeFileSync(
        join(srcDir, "math.mjs"),
        "export function add(a, b) { return a + b; }\n",
        "utf8",
      );
      const testsDir = join(repoDir, "tests");
      mkdirSync(testsDir, { recursive: true });
      writeFileSync(
        join(testsDir, "math.test.mjs"),
        `import assert from "node:assert/strict";
import test from "node:test";
import { add } from "../src/math.mjs";

test("add correctly computes sum", () => {
  assert.equal(add(2, 3), 5);
});
`,
        "utf8",
      );
      spawnSync("git", ["add", "."], { cwd: repoDir });
      spawnSync("git", ["commit", "-m", "head: fix math bug and add test"], { cwd: repoDir });
      const headSha = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();

      // Run real git verification on valid repro fix
      const validGitResult = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: repoDir,
        baseSha,
        headSha,
        reproducerCommand: "node --test tests/math.test.mjs",
        testCommand: "node --test tests/math.test.mjs",
      });

      assert.equal(
        validGitResult.verified,
        true,
        `validGitResult failed: ${JSON.stringify(validGitResult)}`,
      );
      assert.equal(validGitResult.verdict, "auto_merge");
      assert.equal(validGitResult.rule, "MP-000");
      assert.equal(validGitResult.proof?.causal_cycle_completed, true);

      // Now create a tautological test on top of base
      spawnSync("git", ["checkout", "-b", "tautology-branch", baseSha], { cwd: repoDir });
      mkdirSync(testsDir, { recursive: true });
      writeFileSync(
        join(testsDir, "tautology.test.mjs"),
        `import assert from "node:assert/strict";
import test from "node:test";
import { add } from "../src/math.mjs";

test("tautological test", () => {
  // Always passes regardless of implementation!
  assert.equal(1, 1);
});
`,
        "utf8",
      );
      // Fix math so head passes
      writeFileSync(
        join(srcDir, "math.mjs"),
        "export function add(a, b) { return a + b; }\n",
        "utf8",
      );
      spawnSync("git", ["add", "."], { cwd: repoDir });
      spawnSync("git", ["commit", "-m", "tautological test commit"], { cwd: repoDir });
      const tautologyHeadSha = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();

      // On base, tautology still passes -> RED_ON_BASE_FAILED
      const tautologyGitResult = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: repoDir,
        baseSha,
        headSha: tautologyHeadSha,
        reproducerCommand: "node --test tests/tautology.test.mjs",
      });

      assert.equal(tautologyGitResult.verified, false);
      assert.equal(tautologyGitResult.verdict, "reject");
      assert.equal(tautologyGitResult.rule, "RED_ON_BASE_FAILED");
    });
  });

  // -------------------------------------------------------------------------
  // 2. AST / Conformance Anti-Cheat Gate (MP-001..MP-005, B11)
  // -------------------------------------------------------------------------
  describe("2. AST / Conformance Anti-Cheat Gate", () => {
    it("bad PR 01: rejects TOUCH_HUMAN_ONLY under rule MP-001 (CLI & programmatic)", () => {
      const fixturePath = "conformance/bad_prs/01-touch-human-only.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.rule, "MP-001");
      assert.equal(programmatic.violation, "TOUCH_HUMAN_ONLY");
      assert.equal(programmatic.verdict, "reject");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.POLICY_DENIAL); // 4
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.rule, "MP-001");
      assert.equal(doc.violation, "TOUCH_HUMAN_ONLY");
    });

    it("bad PR 02: rejects TEST_DELETED under rule MP-002 (CLI & programmatic)", () => {
      const fixturePath = "conformance/bad_prs/02-delete-test.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.rule, "MP-002");
      assert.equal(programmatic.violation, "TEST_DELETED");
      assert.equal(programmatic.verdict, "reject");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.DOMAIN_NEGATIVE); // 1
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.rule, "MP-002");
      assert.equal(doc.violation, "TEST_DELETED");
    });

    it("bad PR 03: rejects ANTI_CHEAT_VIOLATION under rule MP-003 (CLI & programmatic)", () => {
      const fixturePath = "conformance/bad_prs/03-swallow-exception.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.rule, "MP-003");
      assert.equal(programmatic.violation, "ANTI_CHEAT_VIOLATION");
      assert.equal(programmatic.verdict, "reject");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.DOMAIN_NEGATIVE); // 1
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.rule, "MP-003");
      assert.equal(doc.violation, "ANTI_CHEAT_VIOLATION");
    });

    it("bad PR 04: rejects STALE_BASE under rule MP-004 (CLI & programmatic)", () => {
      const fixturePath = "conformance/bad_prs/04-stale-base.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.rule, "MP-004");
      assert.equal(programmatic.violation, "STALE_BASE");
      assert.equal(programmatic.verdict, "reject");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.DOMAIN_NEGATIVE); // 1
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.rule, "MP-004");
      assert.equal(doc.violation, "STALE_BASE");
    });

    // Phase 0.0a: bin/** is humanOnly, so 05's bin/mirql.mjs edit trips MP-001.
    it("bad PR 05: rejects TOUCH_HUMAN_ONLY under rule MP-001 (bin/** is humanOnly)", () => {
      const fixturePath = "conformance/bad_prs/05-uncited-surface.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.rule, "MP-001");
      assert.equal(programmatic.violation, "TOUCH_HUMAN_ONLY");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.POLICY_DENIAL); // 4
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.rule, "MP-001");
      assert.equal(doc.violation, "TOUCH_HUMAN_ONLY");
    });

    // Phase 0.2/0.3: a fixture is self-reported and touches packages/**, so it
    // never verifies and goes to a human.
    it("good PR 01: valid repro fix is not verified → needs_human (exit 4)", () => {
      const fixturePath = "conformance/good_prs/01-valid-repro-fix.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.verdict, "needs_human");
      assert.equal(programmatic.rule, "MP-005");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.POLICY_DENIAL);
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.verified, false);
      assert.equal(doc.verdict, "needs_human");
    });

    // Phase 0.2/0.3: a fixture is self-reported and touches packages/**, so it
    // never verifies and goes to a human.
    it("good PR 02: valid consolidate phi drop is not verified → needs_human (exit 4)", () => {
      const fixturePath = "conformance/good_prs/02-valid-consolidate-phi-drop.json";
      const programmatic = verifyAttempt({ fixture: join(ROOT, fixturePath) });
      assert.equal(programmatic.verified, false);
      assert.equal(programmatic.verdict, "needs_human");
      assert.equal(programmatic.rule, "MP-005");

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.POLICY_DENIAL);
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.verified, false);
      assert.equal(doc.verdict, "needs_human");
    });

    it("B11: tokenizer catches empty catches across all evasive forms", () => {
      // 1. catch(e){;}
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){;}").ok, false);
      // 2. catch(e){ void e }
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){ void e }").ok, false);
      // 3. .catch(() => {})
      assert.equal(checkSwallowedExceptions("doAsync().catch(() => {})").ok, false);
      assert.equal(checkSwallowedExceptions("doAsync().catch(err => { void err })").ok, false);
      // 4. catch(e){ /* ignore */ }
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){ /* ignore exception */ }").ok, false);
      // 5. catch(e){ if(0) throw e }
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){ if(0) throw e }").ok, false);
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){ if(false) { throw e; } }").ok, false);

      // Valid non-empty catches
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){ console.error(e); }").ok, true);
      assert.equal(checkSwallowedExceptions("try { x() } catch(e){ throw e; }").ok, true);
      assert.equal(checkSwallowedExceptions("doAsync().catch(err => log(err))").ok, true);
    });

    it("B11: direct source scanning flags all test weakening patterns", () => {
      assert.equal(checkTestWeakenings("describe('suite', () => { it.skip('flaky', () => {}); });").ok, false);
      assert.equal(checkTestWeakenings("test.skip('skipped', () => {});").ok, false);
      assert.equal(checkTestWeakenings("test.only('single test', () => {});").ok, false);
      assert.equal(checkTestWeakenings("it.todo('unimplemented', () => {});").ok, false);
      assert.equal(checkTestWeakenings("test('opts', { skip: true }, () => {});").ok, false);
      assert.equal(checkTestWeakenings("test('ctx', (t) => { t.skip('reason'); });").ok, false);
      assert.equal(checkTestWeakenings("describe['skip']('bracket notation', () => {});").ok, false);
      assert.equal(checkTestWeakenings("describe('suite', () => { it('real test', () => {}); });").ok, true);
    });

    it("B11: path normalization handles case-folding, trailing dots, and relative traversals", () => {
      assert.equal(normalizePath("CONSTITUTION.MD."), "constitution.md");
      assert.equal(normalizePath("./packages/../CONSTITUTION.md"), "constitution.md");
      assert.equal(normalizePath(".\\policy\\paths.yaml"), "policy/paths.yaml");
      assert.equal(isHumanOnlyPath("CONSTITUTION.MD."), true);
      assert.equal(isHumanOnlyPath("policy/../CONSTITUTION.md"), true);
      assert.equal(isHumanOnlyPath("CONSTITUTION.md"), true);
      assert.equal(isHumanOnlyPath("policy/paths.yaml"), true);
      assert.equal(isHumanOnlyPath("packages/core/src/index.mjs"), false);
      assert.equal(checkHumanOnlyPaths(["CONSTITUTION.md.", "packages/core/math.mjs"]).ok, false);
    });
  });

  // -------------------------------------------------------------------------
  // 3. Two-Process Privilege Split (B10, B3)
  // -------------------------------------------------------------------------
  describe("3. Two-Process Privilege Split", () => {
    it("B10: agent strips secrets and retains ONLY safe allowlist variables", () => {
      initEmptyRepo(tempDir);
      const dirtyEnv = {
        ...process.env,
        NODE_ENV: "production",
        MIRQL_PRIVATE_KEY: "super_secret_key",
        MIRQL_SIGNING_KEY: "secret_signing_key",
        GITHUB_TOKEN: "ghp_secrettoken123",
        CUSTOM_SECRET: "should_be_stripped",
      };

      const res = runAgent({
        cwd: tempDir,
        env: dirtyEnv,
        command: "node -v",
      });

      assert.equal(res.ok, true);
      assert.equal(res.exitCode, 0);
      assert.ok(res.strippedEnv.includes("MIRQL_PRIVATE_KEY"));
      assert.ok(res.strippedEnv.includes("GITHUB_TOKEN"));
      assert.ok(res.strippedEnv.includes("CUSTOM_SECRET"));
    });

    it("B3: supervisor produces a valid schema-checked Outcome with real computed metrics", async () => {
      initEmptyRepo(tempDir);
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);

      authorizeTestWarrant(tempDir, dispatchableWarrant("01HWWWWWWWWWWWWWWWWWWWWWWW"));
      const res = await runSupervisor({
        workspaceDir: tempDir,
        mirqlDir: tempDir,
        signingKey: kp.privateKey,
        keyId: kp.keyId,
        keypair: kp,
        jobId: "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        warrantId: "01HWWWWWWWWWWWWWWWWWWWWWWW",
        builderCommand: "node -v",
      });

      // 1. Outcome schema validation. The accepted path is pinned against real
      // work in tests/daemon-git-mode.test.mjs and the queue suite's H1 test.
      const validation = validateDocument("outcome", res.outcome);
      assert.equal(validation.valid, true, `Outcome document invalid: ${JSON.stringify(validation.errors)}`);
      assert.equal(res.outcome.v, 1);
      assert.equal(res.outcome.status, "fail");
      assert.equal(res.rule, "NO_WORKER_CHANGES");
      // Issue #16: unmeasured telemetry is flagged, never invented — this run
      // supplied no gateway cost, so no micro_usd number may appear.
      assert.equal(res.outcome.cost.measured, 0);
      assert.equal(res.outcome.cost.micro_usd, undefined);
      assert.equal(res.outcome.thrift.measured, 0);
      assert.ok(Number.isSafeInteger(res.outcome.phi.phi_before));
      assert.ok(Number.isSafeInteger(res.outcome.phi.phi_after));

      // SHAs must be real 64-char hex sha256 strings (not fake zeros)
      assert.ok(res.outcome.base_sha.startsWith("sha256:"));
      assert.notEqual(res.outcome.base_sha, `sha256:${"0".repeat(64)}`);
      assert.ok(res.outcome.head_sha.startsWith("sha256:"));
      assert.notEqual(res.outcome.head_sha, `sha256:${"1".repeat(64)}`);

      // 2. Ledger event verification
      const eventsPath = join(tempDir, "ledger", "events.jsonl");
      assert.ok(existsSync(eventsPath), "events.jsonl must exist");
      const content = readFileSync(eventsPath, "utf8").trim();
      const eventDoc = content.split(/\r?\n/).map(JSON.parse).at(-1);

      assert.equal(eventDoc.type, "attempt.outcome");
      assert.equal(eventDoc.writer.ns, "tool:run_supervisor");
      assert.equal(eventDoc.seq, 2);
      assert.ok(eventDoc.hash.startsWith("sha256:"));
      assert.ok(eventDoc.sig.length > 0);

      const verified = verifyEvent(eventDoc, kp.publicKey);
      assert.equal(verified.ok, true);
    });

    it("B3: supervisor rejects and signs fail if agent worker command fails", async () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);

      authorizeTestWarrant(tempDir, "01H00000000000000000000002");
      const res = await runSupervisor({
        mirqlDir: tempDir,
        keypair: kp,
        jobId: "01H00000000000000000000001",
        warrantId: "01H00000000000000000000002",
        builderCommand: "node -e \"process.exit(1)\"", // Non-zero agent exit!
        runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
      });

      assert.equal(res.verified, false);
      assert.equal(res.verdict, "reject");
      assert.equal(res.outcome.status, "fail");
    });
  });

  // -------------------------------------------------------------------------
  // 4. 0-Token Probes (B4)
  // -------------------------------------------------------------------------
  describe("3b. Issues #46/#47: supervisor ledger honesty", () => {
    it("#46: unmeasured cost/tokens are omitted so the ledger replays through `mirql l view`", async () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);
      authorizeTestWarrant(tempDir, "01JE0000000000000000000000");

      const res = await runSupervisor({
        mirqlDir: tempDir,
        keypair: kp,
        jobId: "01JE0000000000000000000001",
        warrantId: "01JE0000000000000000000000",
        builderCommand: "node -v",
        runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
      });
      assert.ok(res.event, "supervisor must append an attempt.outcome event");

      // Unmeasured telemetry must be omitted, never null: the log fold behind
      // `mirql l view` / `l replay` rejects cost_micro_usd: null as a Law 17
      // violation (issue #46), so a null field bricks the operator's window.
      assert.ok(!("cost_micro_usd" in res.event.payload), "unmeasured cost must be omitted, not null");
      assert.ok(!("tokens_consumed" in res.event.payload), "unmeasured tokens must be omitted, not null");
      assert.doesNotThrow(() => foldEvents([res.event]), "ledger must replay through the log fold");
    });

    it("#47: phi_before measures the pre-execution workspace, not the post-run one", async () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);
      authorizeTestWarrant(tempDir, dispatchableWarrant("01JE0000000000000000000002"));

      const ws = mkdtempSync(join(tmpdir(), "mirql-phi-ws-"));
      try {
        initEmptyRepo(ws);
        // The builder grows the workspace after the supervisor starts: the
        // pre-execution snapshot must not see its output (issue #47).
        // Escape-free builder source: real newlines between statements and a
        // runtime nl constant keep this immune to any escaping-layer surprises.
        writeFileSync(join(ws, "grow.js"), `const fs = require('node:fs');
const nl = String.fromCharCode(10);
let s = 'export function added(a, b) {' + nl;
for (let i = 0; i < 20; i++) s = s + '  if (a && b) { return 1; }' + nl;
s = s + '}' + nl;
fs.writeFileSync('added.mjs', s);
`);
        git(ws, "add", "-A");
        git(ws, "commit", "-qm", "builder script");
        const phiBeforeExpected = computePhi(ws).total;
        assert.ok(Number.isSafeInteger(phiBeforeExpected));

        const res = await runSupervisor({
          mirqlDir: tempDir,
          workspaceDir: ws,
          keypair: kp,
          jobId: "01JE0000000000000000000003",
          warrantId: "01JE0000000000000000000002",
          builderCommand: "node grow.js",
          runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
        });

        assert.equal(res.outcome.phi.phi_before, phiBeforeExpected,
          "phi_before must snapshot the workspace before the builder runs");
        assert.ok(res.outcome.phi.delta_phi > 0,
          `builder grew the workspace, so delta_phi must be positive (got ${res.outcome.phi.delta_phi})`);
      } finally {
        rmSync(ws, { recursive: true, force: true });
      }
    });
  });

  describe("4. 0-Token Probes", () => {
    it("B4: tests probe with MEASURED counts records a signed pass (issue #16: no fake 189)", () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);
      const res = runProbe({
        mirqlDir: tempDir,
        probe: "tests",
        keypair: kp,
        failures: 0,
        passed: 472,
      });

      assert.equal(res.ok, true);
      assert.equal(res.probe.name, "unit_conformance_suite");
      assert.equal(res.probe.status, "pass");
      assert.equal(res.probe.failures, 0);
      assert.equal(res.probe.passed_count, 472);

      const eventsPath = join(tempDir, "ledger", "events.jsonl");
      const eventDoc = JSON.parse(readFileSync(eventsPath, "utf8").trim());
      assert.equal(eventDoc.type, "probe.completed");
      assert.equal(eventDoc.writer.ns, "tool:run_supervisor");

      const verified = verifyEvent(eventDoc, kp.publicKey);
      assert.equal(verified.ok, true);
    });

    it("B4: tests probe without measured counts NEVER signs a pass (inside a test run)", () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);
      const res = runProbe({
        mirqlDir: tempDir,
        probe: "tests",
        keypair: kp,
      });

      assert.equal(res.ok, false);
      assert.equal(res.probe.status, "not_implemented");
      assert.equal(res.probe.passed, false);
      assert.match(res.probe.error, /no measured counts supplied/);
    });

    it("B4: complexity probe computes real metrics and checks threshold from policy/probes.toml", () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);
      const res = runProbe({
        mirqlDir: tempDir,
        probe: "complexity",
        keypair: kp,
        workspaceDir: ROOT,
      });

      assert.equal(res.probe.name, "ast_cyclomatic_complexity");
      assert.ok(Number.isSafeInteger(res.probe.cyclomatic));
      assert.ok(Number.isSafeInteger(res.probe.max_cyclomatic));
      assert.equal(res.probe.max_cyclomatic, 15);
      // Since repo cyclomatic is 1700 > 15, status is "fail"
      assert.equal(res.probe.status, "fail");
      assert.equal(res.ok, false);
    });

    it("B4: unknown probe name fails with exit 2 (USAGE_ERROR)", () => {
      assert.throws(
        () => runProbe({ probe: "completely_unknown_probe" }),
        (err) => err.code === "USAGE_ERROR" && err.exitCode === EXIT_CODES.USAGE_ERROR,
      );

      const cli = runBin("bin/mirql.mjs", ["r", "probe", "--type", "invalid_probe"]);
      assert.equal(cli.status, EXIT_CODES.USAGE_ERROR); // 2
    });

    it("B4: unimplemented probe reports status not_implemented", () => {
      const kp = generateEd25519Keypair();
      authorizeTestKey(tempDir, "tool:run_supervisor", kp);
      const res = runProbe({
        mirqlDir: tempDir,
        probe: "drift",
        keypair: kp,
      });

      assert.equal(res.ok, false);
      assert.equal(res.probe.status, "not_implemented");
      assert.equal(res.probe.passed, false);
    });
  });

  // -------------------------------------------------------------------------
  // 5. `bing-bong` Consensus Loop (B5, B6, B7, B8, B9)
  // -------------------------------------------------------------------------
  describe("5. `bing-bong` Consensus Loop", () => {
    const validWarrant = {
      v: 1,
      id: "01H1234567890ABCDEFGHJKMNP",
      class: "bugfix",
      semantic_fingerprint: `sha256:${"a".repeat(64)}`,
      anchors: ["packages/core/src/calc.mjs"],
      evidence: { test_suite: 1 },
      red_check: { command: 1 },
      scope: { allow: 1 },
      budget_micro_usd: 1500000,
      created_by: "human:owner",
    };

    it("multi-round debate: Round 1 DISAGREE, Round 2 resolves objection and converges", async () => {
      const panel = [
        async (currWarrant, round, prior, idx, hash) => {
          if (round === 1) {
            return {
              verdict: "DISAGREE",
              blocking_objections: [{ id: "OBJ-1", objection: "Law 10 repro needed" }],
              proposed_amendments: [{ id: "AM-1", text: "Add precision guard", resolves: ["OBJ-1"] }],
              warrant_patch: { precision_guard: 6 },
              warrant_hash: hash,
            };
          }
          return {
            verdict: "CONVERGED",
            blocking_objections: [],
            proposed_amendments: [],
            warrant_patch: {},
            warrant_hash: hash,
          };
        },
        async (currWarrant, round, prior, idx, hash) => {
          return {
            verdict: "CONVERGED",
            blocking_objections: [],
            proposed_amendments: [],
            warrant_patch: {},
            warrant_hash: hash,
          };
        },
      ];
      // Assign distinct families
      panel[0].family = "anthropic";
      panel[1].family = "zai";

      const res = await runBingBong({
        mirqlDir: tempDir,
        warrant: validWarrant,
        rounds: 3,
        panel,
      });

      assert.equal(res.status, "CONVERGED");
      assert.equal(res.rounds_used, 2);
      assert.ok(res.consensus_hash.startsWith("sha256:"));

      const consensusFile = join(tempDir, "consensus", `${validWarrant.id}.json`);
      assert.ok(existsSync(consensusFile));
      const consensusDoc = JSON.parse(readFileSync(consensusFile, "utf8"));
      assert.equal(consensusDoc.consensus_hash, res.consensus_hash);
      assert.equal(consensusDoc.warrant.precision_guard, 6);

      const eventsFile = join(tempDir, "ledger", "events.jsonl");
      const eventDoc = JSON.parse(readFileSync(eventsFile, "utf8").trim());
      assert.equal(eventDoc.type, "warrant.converged");
      assert.equal(eventDoc.writer.ns, "tool:run_supervisor");
    });

    it("B6: zero-silent-concessions rejects silently dropped objections", async () => {
      const panel = [
        async (currWarrant, round, prior, idx, hash) => {
          if (round === 1) {
            return {
              verdict: "DISAGREE",
              blocking_objections: [{ id: "OBJ-CRITICAL", objection: "Critical security flaw" }],
              proposed_amendments: [],
              warrant_patch: {},
              warrant_hash: hash,
            };
          }
          // Round 2: silently drops OBJ-CRITICAL without reason or amendment citing it!
          return {
            verdict: "CONVERGED",
            blocking_objections: [],
            proposed_amendments: [],
            warrant_patch: {},
            warrant_hash: hash,
          };
        },
        async (currWarrant, round, prior, idx, hash) => ({
          verdict: "CONVERGED",
          blocking_objections: [],
          proposed_amendments: [],
          warrant_patch: {},
          warrant_hash: hash,
        }),
      ];
      panel[0].family = "anthropic";
      panel[1].family = "zai";

      const res = await runBingBong({
        mirqlDir: tempDir,
        warrant: validWarrant,
        rounds: 2,
        panel,
      });

      // Must escalate to NEEDS_HUMAN due to silent concession!
      assert.equal(res.status, "NEEDS_HUMAN");
      assert.ok(
        res.unresolved_objections.some((o) => o.violation === "SILENT_CONCESSION"),
      );
    });

    it("B7: no convergence in a round that amended the warrant", async () => {
      const panel = [
        async (currWarrant, round, prior, idx, hash) => {
          if (round === 1) {
            return {
              verdict: "CONVERGED",
              blocking_objections: [],
              proposed_amendments: ["Patching warrant"],
              warrant_patch: { new_field: "amended" },
              warrant_hash: hash,
            };
          }
          return {
            verdict: "CONVERGED",
            blocking_objections: [],
            proposed_amendments: [],
            warrant_patch: {},
            warrant_hash: hash,
          };
        },
        async (currWarrant, round, prior, idx, hash) => ({
          verdict: "CONVERGED",
          blocking_objections: [],
          proposed_amendments: [],
          warrant_patch: {},
          warrant_hash: hash,
        }),
      ];
      panel[0].family = "anthropic";
      panel[1].family = "zai";

      const res = await runBingBong({
        mirqlDir: tempDir,
        warrant: validWarrant,
        rounds: 2,
        panel,
      });

      // Cannot converge in round 1 because warrant was amended; converges in round 2
      assert.equal(res.status, "CONVERGED");
      assert.equal(res.rounds_used, 2);
    });

    it("B8: deadlocked debate records signed warrant.escalated event in ledger", async () => {
      const panel = [
        async (currWarrant, round, prior, idx, hash) => ({
          verdict: "DISAGREE",
          blocking_objections: ["Deadlock objection"],
          proposed_amendments: [],
          warrant_patch: {},
          warrant_hash: hash,
        }),
        async (currWarrant, round, prior, idx, hash) => ({
          verdict: "CONVERGED",
          blocking_objections: [],
          proposed_amendments: [],
          warrant_patch: {},
          warrant_hash: hash,
        }),
      ];
      panel[0].family = "anthropic";
      panel[1].family = "zai";

      const res = await runBingBong({
        mirqlDir: tempDir,
        warrant: validWarrant,
        rounds: 2,
        panel,
      });

      assert.equal(res.status, "NEEDS_HUMAN");
      assert.equal(res.rounds_used, 2);

      const eventsFile = join(tempDir, "ledger", "events.jsonl");
      const eventDoc = JSON.parse(readFileSync(eventsFile, "utf8").trim());
      assert.equal(eventDoc.type, "warrant.escalated");
      assert.equal(eventDoc.writer.ns, "tool:run_supervisor");
    });

    it("B8: escalates immediately when rounds < 1", () => {
      const panel = [
        { model: "claude-opus-5-5-medium", family: "anthropic", verdict: "CONVERGED" },
        { model: "zai/glm-5.3#max", family: "zai", verdict: "CONVERGED" },
      ];

      const res = runBingBong({
        mirqlDir: tempDir,
        warrant: validWarrant,
        rounds: 0,
        panel,
      });

      assert.equal(res.status, "NEEDS_HUMAN");
      assert.equal(res.rounds_used, 0);

      const eventsFile = join(tempDir, "ledger", "events.jsonl");
      const eventDoc = JSON.parse(readFileSync(eventsFile, "utf8").trim());
      assert.equal(eventDoc.type, "warrant.escalated");
    });

    it("B5: rejects unconfigured panel or panel with duplicate model family", () => {
      // Missing panel
      assert.throws(
        () => runBingBong({ warrant: validWarrant, panel: [] }),
        (err) => err.code === "USAGE_ERROR",
      );

      // Duplicate family: both claude
      const duplicatePanel = [
        { model: "claude-opus-5-5-medium", family: "anthropic", verdict: "CONVERGED" },
        { model: "claude-sonnet-4-5", family: "anthropic", verdict: "CONVERGED" },
      ];
      assert.throws(
        () => runBingBong({ warrant: validWarrant, panel: duplicatePanel }),
        (err) => err.code === "USAGE_ERROR",
      );
    });

    it("B9: validates warrant against schema and Crockford ULID regex before file operations", () => {
      const invalidIdWarrant = {
        ...validWarrant,
        id: "../../../path-traversal-id",
      };
      const panel = [
        { model: "claude-opus-5-5-medium", family: "anthropic", verdict: "CONVERGED" },
        { model: "zai/glm-5.3#max", family: "zai", verdict: "CONVERGED" },
      ];

      assert.throws(
        () => runBingBong({ warrant: invalidIdWarrant, panel }),
        (err) => err.code === "USAGE_ERROR",
      );
    });

    it("CLI invocation via `mirql r bing-bong` with valid warrant and panel converges (exit 0)", () => {
      const warrantPath = join(tempDir, "warrant.json");
      writeFileSync(warrantPath, JSON.stringify(validWarrant), "utf8");

      const panelPath = join(tempDir, "panel.json");
      writeFileSync(
        panelPath,
        JSON.stringify([
          { model: "claude-opus-5-5-medium", family: "anthropic", verdict: "CONVERGED" },
          { model: "zai/glm-5.3#max", family: "zai", verdict: "CONVERGED" },
        ]),
        "utf8",
      );

      const res = runBin("bin/mirql.mjs", [
        "r",
        "bing-bong",
        "--warrant",
        warrantPath,
        "--panel",
        panelPath,
        "--dir",
        tempDir,
        "--rounds",
        "2",
      ]);

      assert.equal(res.status, 0, `CLI failed with ${res.status}: ${res.stderr}`);
      const doc = JSON.parse(res.stdout);
      assert.equal(doc.status, "CONVERGED");
    });

    it("CLI invocation via `mirql r bb` with valid warrant and panel converges (exit 0)", () => {
      const warrantPath = join(tempDir, "warrant_bb.json");
      writeFileSync(warrantPath, JSON.stringify(validWarrant), "utf8");

      const panelPath = join(tempDir, "panel_bb.json");
      writeFileSync(
        panelPath,
        JSON.stringify([
          { model: "claude-opus-5-5-medium", family: "anthropic", verdict: "CONVERGED" },
          { model: "zai/glm-5.3#max", family: "zai", verdict: "CONVERGED" },
        ]),
        "utf8",
      );

      const res = runBin("bin/mirql.mjs", [
        "r",
        "bb",
        "--warrant",
        warrantPath,
        "--panel",
        panelPath,
        "--dir",
        tempDir,
        "--rounds",
        "2",
      ]);

      assert.equal(res.status, 0, `CLI failed with ${res.status}: ${res.stderr}`);
      const doc = JSON.parse(res.stdout);
      assert.equal(doc.status, "CONVERGED");
    });
  });

  // -------------------------------------------------------------------------
  // 6. Complexity Potential Phi (computePhi, Law 11 & Law 13, B13)
  // -------------------------------------------------------------------------
  describe("6. Law 11 & 13: Complexity Potential Phi", () => {
    it("computePhi returns integer-only metrics", () => {
      const phi = computePhi(ROOT);
      assert.ok(Number.isSafeInteger(phi.loc), "loc must be safe integer");
      assert.ok(Number.isSafeInteger(phi.export_count), "export_count must be safe integer");
      assert.ok(Number.isSafeInteger(phi.cyclomatic), "cyclomatic must be safe integer");
      assert.ok(Number.isSafeInteger(phi.dep_count), "dep_count must be safe integer");
      assert.ok(Number.isSafeInteger(phi.dup_blocks), "dup_blocks must be safe integer");
      assert.ok(Number.isSafeInteger(phi.total), "total must be safe integer");
      assert.ok(phi.loc > 0);
      assert.ok(phi.total > 0);
    });

    it("checkPhiReduction verifies non-increasing or strictly decreasing potential", () => {
      assert.equal(checkPhiReduction(100, 95, true).ok, true);
      assert.equal(checkPhiReduction(100, 100, false).ok, true);
      assert.equal(checkPhiReduction(100, 100, true).ok, false); // consolidator needs < 0
      assert.equal(checkPhiReduction(100, 105, false).ok, false);
    });

    it("B13: verifyAttempt enforces Law 13 Delta Phi <= 0 (and strictly < 0 for consolidator)", async () => {
      const baseOptions = {
        runCheck: () => ({ exitCode: 0 }),
      };

      // 1. Delta Phi > 0 is rejected under Law 13
      const increaseRes = await verifyAttempt({
        ...baseOptions,
        phiBefore: 100,
        phiAfter: 105, // +5 increase
      });
      assert.equal(increaseRes.verified, false);
      assert.equal(increaseRes.verdict, "reject");
      assert.equal(increaseRes.rule, "LAW_13_PHI_INCREASE");

      // 2. Consolidator with Delta Phi = 0 is rejected under Law 13
      const consolidatorZeroRes = await verifyAttempt({
        ...baseOptions,
        role: "consolidator",
        phiBefore: 100,
        phiAfter: 100, // 0 delta
      });
      assert.equal(consolidatorZeroRes.verified, false);
      assert.equal(consolidatorZeroRes.verdict, "reject");
      assert.equal(consolidatorZeroRes.rule, "LAW_13_CONSOLIDATOR_PHI");

      // 3. Consolidator with Delta Phi < 0 passes Law 13
      const consolidatorDropRes = await verifyAttempt({
        role: "consolidator",
        phiBefore: 100,
        phiAfter: 90, // -10 drop
        runCheck: ({ stage }) => ({ exitCode: stage === "green_on_head" ? 0 : 1 }),
      });
      assert.equal(consolidatorDropRes.verified, true);
      assert.equal(consolidatorDropRes.verdict, "auto_merge");
    });
  });
});

// ---------------------------------------------------------------------------
// P0 Remediation package: C1 (proof loophole), H1 (epoch threading),
// H2 (worktree isolation), H3 (env sanitization), H5 (git-mode anti-cheat).
// ---------------------------------------------------------------------------
describe("P0 Remediation: C1, H1, H2, H3, H5", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-p0-test-"));
    provisionTestTrust(tempDir);
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  /** Initialize a tiny git repo with base/head commits around a math bug. */
  function buildMathRepo(repoDir, { extraBaseFiles = {}, extraHeadFiles = {} } = {}) {
    spawnSync("git", ["init", "-b", "main", repoDir], { encoding: "utf8" });
    spawnSync("git", ["config", "user.name", "Mirql Test"], { cwd: repoDir, encoding: "utf8" });
    spawnSync("git", ["config", "user.email", "test@mirql.local"], { cwd: repoDir, encoding: "utf8" });

    writeFileSync(
      join(repoDir, "package.json"),
      JSON.stringify({ type: "module", scripts: { test: "node --test" } }),
      "utf8",
    );
    const srcDir = join(repoDir, "src");
    mkdirSync(srcDir, { recursive: true });
    writeFileSync(
      join(srcDir, "math.mjs"),
      "export function add(a, b) { return a - b; } // BUG!\n",
      "utf8",
    );
    for (const [rel, content] of Object.entries(extraBaseFiles)) {
      const p = join(repoDir, rel);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, content, "utf8");
    }
    spawnSync("git", ["add", "."], { cwd: repoDir, encoding: "utf8" });
    spawnSync("git", ["commit", "-m", "base: bug in math"], { cwd: repoDir, encoding: "utf8" });
    const baseSha = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: repoDir,
      encoding: "utf8",
    }).stdout.trim();

    writeFileSync(
      join(srcDir, "math.mjs"),
      "export function add(a, b) { return a + b; }\n",
      "utf8",
    );
    const testsDir = join(repoDir, "tests");
    mkdirSync(testsDir, { recursive: true });
    writeFileSync(
      join(testsDir, "math.test.mjs"),
      `import assert from "node:assert/strict";
import test from "node:test";
import { add } from "../src/math.mjs";

test("add correctly computes sum", () => {
  assert.equal(add(2, 3), 5);
});
`,
      "utf8",
    );
    for (const [rel, content] of Object.entries(extraHeadFiles)) {
      const p = join(repoDir, rel);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, content, "utf8");
    }
    spawnSync("git", ["add", "."], { cwd: repoDir, encoding: "utf8" });
    spawnSync("git", ["commit", "-m", "head: fix math bug and add test"], { cwd: repoDir, encoding: "utf8" });
    const headSha = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: repoDir,
      encoding: "utf8",
    }).stdout.trim();

    return { baseSha, headSha };
  }

  // -------------------------------------------------------------------------
  // C1: suite_pass_head is not causal proof
  // -------------------------------------------------------------------------
  describe("C1: suite_pass_head proof loophole eliminated", () => {
    it("rejects a self-reported suite_pass_head-only proof with MISSING_PROOF (programmatic)", () => {
      const result = verifyAttempt({
        diff_stat: { files_changed: ["src/calc.mjs"], lines_added: 10, lines_deleted: 2 },
        proof: { suite_pass_base: true, suite_pass_head: true, cases_dropped: 0 },
        evidence: { forbidden_paths_touched: [], tests_deleted: [] },
        anti_cheat: { violations_count: 0, flags: [] },
        phi: { phi_base: 100, phi_head: 95, delta_phi: -5 },
      });

      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.equal(result.rule, "MISSING_PROOF");
      assert.equal(result.violation, "MISSING_PROOF");
    });

    it("rejects a suite_pass_head-only fixture via the CLI with exit code 1 and the rule violation on stderr", () => {
      const fixturePath = join(tempDir, "suite-pass-head-only.json");
      writeFileSync(
        fixturePath,
        JSON.stringify({
          schema: "outcome/v1",
          expected_verdict: "auto_merge",
          diff_stat: { files_changed: ["src/calc.mjs"], lines_added: 10, lines_deleted: 2 },
          proof: { suite_pass_base: true, suite_pass_head: true, cases_dropped: 0 },
          evidence: { forbidden_paths_touched: [], tests_deleted: [] },
          anti_cheat: { violations_count: 0, flags: [] },
          phi: { phi_base: 100, phi_head: 95, delta_phi: -5 },
          surface: { uncited_commands: [], delta_count: 0 },
        }),
        "utf8",
      );

      const cli = runBin("bin/mirql.mjs", ["r", "verify", "--fixture", fixturePath]);
      assert.equal(cli.status, EXIT_CODES.DOMAIN_NEGATIVE); // 1
      const doc = JSON.parse(cli.stderr);
      assert.equal(doc.verified, false);
      assert.equal(doc.rule, "MISSING_PROOF");
      assert.equal(doc.violation, "MISSING_PROOF");
    });

    it("checkAntiCheat: suite_pass_head alone no longer unlocks humanApprove paths (MP-005)", () => {
      const base = { diff_stat: { files_changed: ["packages/core/src/ulid.mjs"] } };

      // Self-reported suite pass does NOT count as causal proof anymore.
      const withSuitePass = checkAntiCheat({
        ...base,
        proof: { suite_pass_head: true },
      });
      assert.equal(withSuitePass.ok, false);
      assert.equal(withSuitePass.rule, "MP-005");
      assert.equal(withSuitePass.violation, "UNCITED_SURFACE");
      assert.equal(withSuitePass.verdict, "needs_human");

      // Phase 0.3: neither a self-reported causal proof nor a
      // human_approved flag unlocks humanApprove paths any more.
      const withCausalProof = checkAntiCheat({
        ...base,
        proof: { causal_cycle_completed: true },
      });
      assert.equal(withCausalProof.ok, false);
      assert.equal(withCausalProof.rule, "MP-005");

      const withHumanApproval = checkAntiCheat({
        ...base,
        proof: { suite_pass_head: true },
        human_approved: true,
      });
      assert.equal(withHumanApproval.ok, false);
    });
  });

  // -------------------------------------------------------------------------
  // H1: --epoch threading through the supervisor CLI
  // -------------------------------------------------------------------------
  describe("H1: leased-job epoch threaded through supervisor", () => {
    it("CLI accepts --epoch <int> and threads it into the Outcome and signed attempt.outcome event", () => {
      authorizeTestWarrant(tempDir, "01HWWWWWWWWWWWWWWWWWWWWWWW");
      const res = runBin("bin/mirql-run.mjs", [
        "supervisor",
        "--dir", tempDir,
        "--workspace", tempDir,
        "--warrant-id", "01HWWWWWWWWWWWWWWWWWWWWWWW",
        "--command", "node -v",
        "--epoch", "2",
      ]);

      // Verification itself fails closed here (no runner passed via CLI),
      // so the exit code is 1 — what matters is the epoch threading.
      assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE, `stderr: ${res.stderr}`);
      const doc = JSON.parse(res.stdout);
      assert.equal(doc.outcome.epoch, 2);
      assert.equal(doc.event.epoch, 2);
      assert.equal(doc.event.payload.epoch, 2);
      assert.equal(doc.event.type, "attempt.outcome");

      // The persisted ledger event carries the same epoch.
      const eventDoc = JSON.parse(
        readFileSync(join(tempDir, "ledger", "events.jsonl"), "utf8").trim().split(/\r?\n/).at(-1),
      );
      assert.equal(eventDoc.epoch, 2);
      assert.equal(eventDoc.payload.epoch, 2);
    });

    it("CLI rejects a non-integer --epoch with exit code 2 (USAGE_ERROR)", () => {
      const res = runBin("bin/mirql-run.mjs", [
        "supervisor",
        "--dir", tempDir,
        "--warrant-id", "01HWWWWWWWWWWWWWWWWWWWWWWW",
        "--epoch", "not-an-integer",
      ]);
      assert.equal(res.status, EXIT_CODES.USAGE_ERROR); // 2
      const doc = JSON.parse(res.stderr);
      assert.equal(doc.error, "USAGE_ERROR");
    });

    it("defaults the epoch to 1 when --epoch is omitted (backwards compatible)", () => {
      authorizeTestWarrant(tempDir, "01HWWWWWWWWWWWWWWWWWWWWWWW");
      const res = runBin("bin/mirql-run.mjs", [
        "supervisor",
        "--dir", tempDir,
        "--workspace", tempDir,
        "--warrant-id", "01HWWWWWWWWWWWWWWWWWWWWWWW",
        "--command", "node -v",
      ]);
      assert.equal(res.status, EXIT_CODES.DOMAIN_NEGATIVE);
      const doc = JSON.parse(res.stdout);
      assert.equal(doc.outcome.epoch, 1);
      assert.equal(doc.event.epoch, 1);
    });
  });

  // -------------------------------------------------------------------------
  // H2: git triple-exec isolated in a disposable worktree
  // -------------------------------------------------------------------------
  describe("H2: disposable worktree isolation", () => {
    it("verifies a real fix without touching the live working tree or uncommitted files", () => {
      const repoDir = join(tempDir, "isolated-repo");
      const { baseSha, headSha } = buildMathRepo(repoDir);

      // Simulate precious uncommitted work in the live tree.
      writeFileSync(
        join(repoDir, "uncommitted-notes.txt"),
        "precious uncommitted work\n",
        "utf8",
      );

      const result = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: repoDir,
        baseSha,
        headSha,
        reproducerCommand: "node --test tests/math.test.mjs",
        testCommand: "node --test tests/math.test.mjs",
      });

      assert.equal(
        result.verified,
        true,
        `verification failed: ${JSON.stringify(result)}`,
      );
      assert.equal(result.proof?.causal_cycle_completed, true);

      // The uncommitted file is byte-for-byte intact.
      assert.equal(
        readFileSync(join(repoDir, "uncommitted-notes.txt"), "utf8"),
        "precious uncommitted work\n",
      );

      // The live tree is otherwise clean and HEAD never moved.
      const statusOut = spawnSync("git", ["status", "--porcelain"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();
      assert.equal(statusOut, "?? uncommitted-notes.txt");

      const head = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();
      assert.equal(head, headSha);

      // The disposable worktree was cleaned up.
      const worktrees = spawnSync("git", ["worktree", "list"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim().split(/\r?\n/);
      assert.equal(worktrees.length, 1, `leftover worktrees: ${worktrees.join(" | ")}`);
    });

    it("fails closed with WORKTREE_SETUP_FAILED outside a git repository", () => {
      const notARepo = join(tempDir, "not-a-repo");
      mkdirSync(notARepo, { recursive: true });

      const result = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: notARepo,
        baseSha: "HEAD~1",
        headSha: "HEAD",
        reproducerCommand: "node -v",
      });

      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.ok(
        result.rule === "GIT_DIFF_FAILED" || result.rule === "WORKTREE_SETUP_FAILED",
        `unexpected rule: ${result.rule}`,
      );
    });
  });

  // -------------------------------------------------------------------------
  // H3: sanitized runner environment
  // -------------------------------------------------------------------------
  describe("H3: candidate runner environment sanitization", () => {
    it("strips MIRQL_HUMAN_KEY and AI provider keys from child processes while keeping safe vars", () => {
      const repoDir = join(tempDir, "env-sanitize-repo");
      const dumpPath = join(tempDir, "child-env.json");

      const { baseSha, headSha } = buildMathRepo(repoDir, {
        extraBaseFiles: {
          "package.json": JSON.stringify({ type: "module", scripts: { test: "node --test && node dump-env.mjs" } }),
          // Committed at base (a non-test file): dumps the child env to an
          // absolute path that survives worktree cleanup.
          "dump-env.mjs":
            `import { writeFileSync } from "node:fs";\n` +
            `writeFileSync(${JSON.stringify(dumpPath)}, JSON.stringify(process.env));\n`,
        },
      });

      const secrets = {
        MIRQL_HUMAN_KEY: "human-secret-material",
        OPENAI_API_KEY: "sk-test-openai-secret",
        ANTHROPIC_API_KEY: "sk-ant-test-secret",
        GOOGLE_API_KEY: "google-test-secret",
      };
      const saved = {};
      for (const k of Object.keys(secrets)) {
        saved[k] = process.env[k];
        process.env[k] = secrets[k];
      }

      try {
        const result = verifyAuthorizedGitFixture({
          git: true,
          workspaceDir: repoDir,
          baseSha,
          headSha,
          reproducerCommand: "node --test tests/math.test.mjs",
        });

        assert.equal(
          result.verified,
          true,
          `verification failed: ${JSON.stringify(result)}`,
        );

        assert.ok(existsSync(dumpPath), "child env dump must exist");
        const childEnv = JSON.parse(readFileSync(dumpPath, "utf8"));

        // Secrets never reached the candidate child process.
        assert.equal(childEnv.MIRQL_HUMAN_KEY, undefined);
        assert.equal(childEnv.OPENAI_API_KEY, undefined);
        assert.equal(childEnv.ANTHROPIC_API_KEY, undefined);
        assert.equal(childEnv.GOOGLE_API_KEY, undefined);

        // Safe allowlisted variables survive (case varies by platform).
        const pathValue = childEnv.PATH ?? childEnv.Path;
        assert.ok(typeof pathValue === "string" && pathValue.length > 0, "PATH must survive sanitization");
        if (process.platform === "win32") {
          assert.ok(childEnv.SystemRoot ?? childEnv.SYSTEMROOT, "SystemRoot must survive sanitization");
        }
      } finally {
        for (const [k, v] of Object.entries(saved)) {
          if (v === undefined) {
            delete process.env[k];
          } else {
            process.env[k] = v;
          }
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // H5: anti-cheat wired into git-mode verification
  // -------------------------------------------------------------------------
  describe("H5: anti-cheat gate in git-mode verification", () => {
    it("returns needs_human under MP-001 when the git diff touches CONSTITUTION.md", () => {
      const repoDir = join(tempDir, "constitution-repo");
      const { baseSha, headSha } = buildMathRepo(repoDir, {
        extraBaseFiles: {
          "CONSTITUTION.md": "# Constitution\n\nOriginal law text.\n",
        },
        extraHeadFiles: {
          "CONSTITUTION.md": "# Constitution\n\nAttacker-edited law text.\n",
        },
      });

      const result = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: repoDir,
        baseSha,
        headSha,
        reproducerCommand: "node --test tests/math.test.mjs",
      });

      assert.equal(result.verified, false);
      assert.equal(result.verdict, "needs_human");
      assert.equal(result.rule, "MP-001");
      assert.equal(result.violation, "TOUCH_HUMAN_ONLY");

      // The live tree (and the constitution) was never touched.
      assert.equal(
        readFileSync(join(repoDir, "CONSTITUTION.md"), "utf8"),
        "# Constitution\n\nAttacker-edited law text.\n",
      );
    });

    it("rejects under MP-002 when the git diff deletes an existing test file", () => {
      const repoDir = join(tempDir, "deleted-test-repo");
      spawnSync("git", ["init", "-b", "main", repoDir], { encoding: "utf8" });
      spawnSync("git", ["config", "user.name", "Mirql Test"], { cwd: repoDir, encoding: "utf8" });
      spawnSync("git", ["config", "user.email", "test@mirql.local"], { cwd: repoDir, encoding: "utf8" });

      writeFileSync(
        join(repoDir, "package.json"),
        JSON.stringify({ type: "module", scripts: { test: "node --test" } }),
        "utf8",
      );
      mkdirSync(join(repoDir, "src"), { recursive: true });
      writeFileSync(
        join(repoDir, "src", "math.mjs"),
        "export function add(a, b) { return a - b; } // BUG!\n",
        "utf8",
      );
      mkdirSync(join(repoDir, "tests"), { recursive: true });
      writeFileSync(
        join(repoDir, "tests", "legacy.test.mjs"),
        `import assert from "node:assert/strict";
import test from "node:test";

test("legacy coverage", () => {
  assert.equal(1 + 1, 2);
});
`,
        "utf8",
      );
      spawnSync("git", ["add", "."], { cwd: repoDir, encoding: "utf8" });
      spawnSync("git", ["commit", "-m", "base with legacy test"], { cwd: repoDir, encoding: "utf8" });
      const baseSha = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();

      // Head: fix the bug, add a reproducer, and DELETE the legacy test.
      writeFileSync(
        join(repoDir, "src", "math.mjs"),
        "export function add(a, b) { return a + b; }\n",
        "utf8",
      );
      writeFileSync(
        join(repoDir, "tests", "math.test.mjs"),
        `import assert from "node:assert/strict";
import test from "node:test";
import { add } from "../src/math.mjs";

test("add correctly computes sum", () => {
  assert.equal(add(2, 3), 5);
});
`,
        "utf8",
      );
      rmSync(join(repoDir, "tests", "legacy.test.mjs"));
      spawnSync("git", ["add", "."], { cwd: repoDir, encoding: "utf8" });
      spawnSync("git", ["commit", "-m", "head: fix and delete legacy test"], { cwd: repoDir, encoding: "utf8" });
      const headSha = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: repoDir,
        encoding: "utf8",
      }).stdout.trim();

      const result = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: repoDir,
        baseSha,
        headSha,
        reproducerCommand: "node --test tests/math.test.mjs",
      });

      assert.equal(result.verified, false);
      assert.equal(result.verdict, "reject");
      assert.equal(result.rule, "MP-002");
      assert.equal(result.violation, "TEST_DELETED");
      assert.match(result.detail, /legacy\.test\.mjs/);
    });

    it("still auto-merges a clean git fix whose diff passes the anti-cheat gate", () => {
      const repoDir = join(tempDir, "clean-repo");
      const { baseSha, headSha } = buildMathRepo(repoDir);

      const result = verifyAuthorizedGitFixture({
        git: true,
        workspaceDir: repoDir,
        baseSha,
        headSha,
        reproducerCommand: "node --test tests/math.test.mjs",
        testCommand: "node --test tests/math.test.mjs",
      });

      assert.equal(result.verified, true);
      assert.equal(result.verdict, "auto_merge");
      assert.equal(result.rule, "MP-000");
      assert.equal(result.checks?.anti_cheat?.passed, true);
    });
  });
});

test("each worker receives an empty temporary home and removes it after exit", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mirql-home-test-"));
  initEmptyRepo(workspace);
  const script = join(workspace, "inspect-home.mjs");
  writeFileSync(script, `import {readdirSync,writeFileSync} from "node:fs";
    const home=process.env.HOME;
    const drive=process.env.HOMEDRIVE;
    const path=process.env.HOMEPATH;
    console.log(JSON.stringify({home,profile:process.env.USERPROFILE,drive,path,files:readdirSync(home)}));
    writeFileSync(home+"/private-marker","test");
    process.exit(Number(process.argv[2]));`);
  try {
    const homes = [];
    for (const exit of [0, 1]) {
      const result = runAgent({
        command: `"${process.execPath}" "${script}" ${exit}`,
        cwd: workspace,
        env: { ...process.env, HOME: workspace, USERPROFILE: workspace, home: workspace },
        allowedEnv: ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"],
      });
      const report = JSON.parse(result.stdout.trim());
      assert.equal(result.exitCode, exit);
      assert.equal(report.home, report.profile);
      assert.notEqual(report.home, workspace);
      if (process.platform === "win32" && report.drive && report.path) {
        assert.equal(report.home.toLowerCase(), (report.drive + report.path).toLowerCase());
      }
      assert.deepEqual(report.files, []);
      assert.equal(existsSync(report.home), false);
      homes.push(report.home);
    }
    assert.notEqual(homes[0], homes[1]);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("a worker cleanup failure preserves output and exit status", {
  skip: process.platform === "win32" || process.getuid?.() === 0,
}, () => {
  const workspace = mkdtempSync(join(tmpdir(), "mirql-cleanup-test-"));
  initEmptyRepo(workspace);
  const script = join(workspace, "lock-home.mjs");
  writeFileSync(script, `import {mkdirSync,writeFileSync,chmodSync} from "node:fs";
    const locked=process.env.HOME+"/locked";
    mkdirSync(locked);
    writeFileSync(locked+"/file","data");
    chmodSync(locked,0o500);
    console.log("worker output");
    process.exit(7);`);
  let home;
  try {
    const result = runAgent({ command: `"${process.execPath}" "${script}"`, cwd: workspace });
    home = result.workerHome;
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, EXIT_CODES.POLICY_DENIAL);
    assert.equal(result.workerExitCode, 7);
    assert.match(result.stdout, /worker output/);
    assert.ok(result.cleanupError);
  } finally {
    if (home) {
      chmodSync(join(home, "locked"), 0o700);
      rmSync(home, { recursive: true, force: true });
    }
    rmSync(workspace, { recursive: true, force: true });
  }
});
