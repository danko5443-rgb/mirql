// The owner's standing Phi warrant (Law 13): signature checks, the evaluator's
// use of it, spend counted from real git history, and the owner's command.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateEd25519Keypair, signEvent } from "../packages/core/ed25519.mjs";
import { PHI_WARRANT_DOMAIN, PHI_WARRANT_PIN_PATH, phiWarrantAllowance, readPhiWarrantPin, verifyPhiWarrant } from "../packages/core/phi-warrant.mjs";
import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";
import { main, measurePhiWarrant } from "../scripts/ci-phi-warrant.mjs";
import { run } from "../scripts/phi-warrant.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OWNER = generateEd25519Keypair();
const OTHER = generateEd25519Keypair();
const BASE_SHA = "a".repeat(40);
const GIT_ENV = { GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" };

function warrantFields(signer = OWNER, overrides = {}) {
  return { domain: PHI_WARRANT_DOMAIN, writer: { ns: "human:owner", key_id: signer.keyId }, phi_budget: 100, base_sha: BASE_SHA, issued_at: "2026-11-05T00:00:00Z", ...overrides };
}
const sign = (signer = OWNER, overrides = {}) => signEvent(warrantFields(signer, overrides), signer.privateKey, signer.keyId);

/** A checkout holding the real path policy and, by default, the owner's pin. */
function withCheckout(fn, { pin = OWNER } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "phi-warrant-"));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  let result;
  try {
    mkdirSync(join(dir, "policy"));
    copyFileSync(join(ROOT, "policy", "paths.yaml"), join(dir, "policy", "paths.yaml"));
    if (pin) writeFileSync(join(dir, PHI_WARRANT_PIN_PATH), JSON.stringify({ keyId: pin.keyId, publicKey: pin.publicKey }));
    result = fn(dir);
  } catch (error) {
    cleanup();
    throw error;
  }
  if (typeof result?.then === "function") return result.finally(cleanup);
  cleanup();
  return result;
}

describe("phi warrant: verification", () => {
  it("accepts a warrant signed by the pinned key, as an object or as JSON text", () => {
    const warrant = sign();
    assert.deepEqual(verifyPhiWarrant(warrant, OWNER.publicKey), { ok: true, warrant });
    assert.equal(verifyPhiWarrant(JSON.stringify(warrant), OWNER.publicKey).ok, true);
  });

  it("refuses anything else, with the reason", () => {
    const pub = OWNER.publicKey;
    const cases = [
      ["not json", "NOT_JSON"],
      [null, "WRONG_DOMAIN"],
      [100, "WRONG_DOMAIN"],
      [warrantFields(), "BAD_SIGNATURE"],
      [{ ...sign(), phi_budget: 1000000 }, "BAD_SIGNATURE"],
      [{ ...sign(), base_sha: "b".repeat(40) }, "BAD_SIGNATURE"],
      [sign(OTHER), "WRONG_KEY"],
      [{ ...sign(OTHER), writer: { ns: "human:owner", key_id: OWNER.keyId } }, "BAD_SIGNATURE"],
      [sign(OWNER, { domain: "mirql/other/v1" }), "WRONG_DOMAIN"],
      [sign(OWNER, { writer: { ns: "agent:builder", key_id: OWNER.keyId } }), "NOT_OWNER"],
      [sign(OWNER, { phi_budget: -1 }), "BAD_BUDGET"],
      [sign(OWNER, { phi_budget: "100" }), "BAD_BUDGET"],
      [sign(OWNER, { base_sha: "main" }), "BAD_BASE_SHA"],
    ];
    for (const [document, reason] of cases) {
      assert.deepEqual(verifyPhiWarrant(document, pub), { ok: false, reason }, reason);
    }
  });

  it("does not accept an owner-signed event from another domain", () => {
    const ledgerEvent = signEvent({ type: "warrant.authorized", writer: { ns: "human:owner", key_id: OWNER.keyId }, phi_budget: 100, base_sha: BASE_SHA }, OWNER.privateKey, OWNER.keyId);
    assert.deepEqual(verifyPhiWarrant(ledgerEvent, OWNER.publicKey), { ok: false, reason: "WRONG_DOMAIN" });
  });

  it("reads the pin only when it is a well-formed key", () => {
    withCheckout((dir) => assert.equal(readPhiWarrantPin(dir), OWNER.publicKey));
    withCheckout((dir) => assert.equal(readPhiWarrantPin(dir), null), { pin: null });
    withCheckout((dir) => {
      writeFileSync(join(dir, PHI_WARRANT_PIN_PATH), JSON.stringify({ publicKey: "short" }));
      assert.equal(readPhiWarrantPin(dir), null);
      writeFileSync(join(dir, PHI_WARRANT_PIN_PATH), "{not json");
      assert.equal(readPhiWarrantPin(dir), null);
    }, { pin: null });
  });

  it("the allowance is the budget less spend, and 0 for anything it cannot verify", () => {
    withCheckout((dir) => {
      assert.equal(phiWarrantAllowance(dir, sign(), 0), 100);
      assert.equal(phiWarrantAllowance(dir, JSON.stringify(sign()), 30), 70);
      assert.equal(phiWarrantAllowance(dir, sign(), 100), 0);
      assert.equal(phiWarrantAllowance(dir, sign(), 500), 0);
      for (const spent of [undefined, null, -1, 1.5, "0", Number.NaN]) assert.equal(phiWarrantAllowance(dir, sign(), spent), 0, String(spent));
      assert.equal(phiWarrantAllowance(dir, sign(OTHER), 0), 0);
      assert.equal(phiWarrantAllowance(dir, undefined, 0), 0);
      assert.equal(phiWarrantAllowance(dir, "100", 0), 0);
    });
    withCheckout((dir) => assert.equal(phiWarrantAllowance(dir, sign(), 0), 0), { pin: null });
  });
});

describe("phi warrant: evaluator", () => {
  const grow = (overrides = {}) => ({
    schema: "outcome/v1",
    pr: { number: 1, author: "ahmed-3m", kind: "bugfix" },
    diff_stat: { files_changed: ["packages/run/journey.mjs"] },
    proof: { causal_cycle_completed: true },
    evidence: { forbidden_paths_touched: [], tests_deleted: [] },
    anti_cheat: { violations_count: 0, flags: [] },
    phi: { phi_base: 10, phi_head: 51, delta_phi: 41 },
    surface: { uncited_commands: [], delta_count: 0 },
    ...overrides,
  });
  const SUITE_ONLY = { proof: { suite_pass_base: true, suite_pass_head: true } };
  const judge = (doc, options) => withCheckout((rootDir) => evaluatePullRequest(doc, { rootDir, ...options }));

  it("without a warrant growth is still rejected, and the message says why", () => {
    const res = judge(grow());
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "PHI_INCREASE");
    assert.match(res.detail, /no signed warrant/);
  });

  it("growth inside the warrant runs the remaining rules and never reaches auto_merge", () => {
    const res = judge(grow(), { phiWarrant: sign(), phiSpent: 0 });
    assert.equal(res.verdict, "conformance_pass");
    assert.equal(res.checks.phi, true);
  });

  it("growth exactly at what is left passes, and one more does not", () => {
    assert.equal(judge(grow(), { phiWarrant: sign(), phiSpent: 59 }).verdict, "conformance_pass");
    const over = judge(grow(), { phiWarrant: sign(), phiSpent: 60 });
    assert.equal(over.verdict, "reject");
    assert.equal(over.violation, "PHI_INCREASE");
    assert.match(over.detail, /only \+40 left/);
  });

  it("without a causal proof it stops at needs_human, which is what a court receipt clears", () => {
    const res = judge(grow(SUITE_ONLY), { phiWarrant: sign(), phiSpent: 0 });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.violation, "NO_CAUSAL_PROOF");
    assert.match(res.detail, /\+41, inside the \+100 left on the signed warrant/);
  });

  it("grants nothing for an unsigned, tampered or foreign warrant, or a bare number", () => {
    const refused = [
      { phiWarrant: warrantFields(), phiSpent: 0 },
      { phiWarrant: { ...sign(OWNER, { phi_budget: 1 }), phi_budget: 100 }, phiSpent: 0 },
      { phiWarrant: sign(OTHER), phiSpent: 0 },
      { phiSpent: 0 },
      { phiWarrant: sign() },
      { phiWarrant: 1000, phiSpent: 0 },
    ];
    for (const options of refused) {
      assert.equal(judge(grow(), options).violation, "PHI_INCREASE");
    }
  });

  it("the warrant does not relax a refactor, a consolidation, or a locked path", () => {
    const signed = { phiWarrant: sign(), phiSpent: 0 };
    for (const kind of ["refactor", "consolidation"]) {
      const res = judge(grow({ pr: { number: 1, author: "ahmed-3m", kind } }), signed);
      assert.equal(res.verdict, "reject", kind);
      assert.equal(res.violation, "PHI_INCREASE", kind);
    }
    const locked = judge(grow({ evidence: { forbidden_paths_touched: ["CONSTITUTION.md"], tests_deleted: [] } }), signed);
    assert.equal(locked.verdict, "reject");
    assert.equal(locked.rule, "MP-001");
  });

  it("growth past the warrant can still take an owner sign-off", () => {
    const res = judge(grow(), { phiWarrant: sign(OWNER, { phi_budget: 1 }), phiSpent: 0, ownerSignoff: "ahmed-3m" });
    assert.equal(res.verdict, "needs_human");
    assert.equal(res.checks.phi, false);
    assert.match(res.detail, /no warrant allowance covered it/);
  });

  it("a shrinking PR needs no warrant, whatever the warrant says", () => {
    const shrink = { phi: { phi_base: 51, phi_head: 10, delta_phi: -41 } };
    assert.equal(judge(grow(shrink), {}).verdict, judge(grow(shrink), { phiWarrant: "garbage", phiSpent: 0 }).verdict);
  });

  it("the CLI passes both flags through, and bad input means no allowance rather than an error", () => {
    withCheckout((cwd) => {
      const check = (...flags) => {
        const res = spawnSync(process.execPath, [join(ROOT, "bin", "mirql.mjs"), "m", "check", "--pr", JSON.stringify(grow()), ...flags], { cwd, encoding: "utf8" });
        return JSON.parse(res.stdout.trim().split("\n").at(-1));
      };
      const warrant = JSON.stringify(sign());
      assert.equal(check("--phi-warrant", warrant, "--phi-spent", "0").verdict, "conformance_pass");
      assert.equal(check("--phi-warrant", warrant, "--phi-spent", "60").violation, "PHI_INCREASE");
      assert.equal(check("--phi-warrant", warrant).violation, "PHI_INCREASE");
      assert.equal(check("--phi-spent", "0").violation, "PHI_INCREASE");
      assert.equal(check("--phi-warrant", warrant, "--phi-spent", "x").violation, "PHI_INCREASE");
      assert.equal(check("--phi-warrant", "garbage", "--phi-spent", "0").violation, "PHI_INCREASE");
    });
  });
});

describe("phi warrant: spend from merged history", () => {
  /** A repo whose main goes: base, +2 lines, -1 line, then a side branch merged with +3 lines. */
  function withHistory(fn) {
    return withCheckout((dir) => {
      const git = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: { ...process.env, ...GIT_ENV } }).trim();
      git("init", "-q", "-b", "main");
      git("config", "core.autocrlf", "false");
      const commit = (name, lines) => {
        writeFileSync(join(dir, name), `${lines.join("\n")}\n`);
        git("add", name);
        git("commit", "-q", "-m", `change ${name}`);
        return git("rev-parse", "HEAD");
      };
      const line = (n) => `export const v${n} = ${n};`;
      const base = commit("src.mjs", [line(1)]);
      const grown = commit("src.mjs", [line(1), line(2), line(3)]);
      const shrunk = commit("src.mjs", [line(1), line(2)]);
      git("checkout", "-q", "-b", "side");
      const side = commit("side.mjs", [line(4), line(5), line(6)]);
      git("checkout", "-q", "main");
      git("merge", "-q", "--no-ff", "-m", "merge side", "side");
      return fn({ dir, git, base, grown, shrunk, side, tip: git("rev-parse", "HEAD") });
    });
  }
  const measure = (dir, tipSha, document, extra = {}) => measurePhiWarrant({ rootDir: dir, repoDir: dir, tipSha, document, ...extra });

  it("adds every increase, refunds no decrease, and walks merges by first parent", () => {
    withHistory(({ dir, base, grown, shrunk, tip }) => {
      const warrant = sign(OWNER, { base_sha: base, phi_budget: 100000 });
      assert.equal(measure(dir, base, warrant).phi_spent, 0);
      const afterGrowth = measure(dir, grown, warrant).phi_spent;
      assert.ok(afterGrowth > 0);
      assert.equal(measure(dir, shrunk, warrant).phi_spent, afterGrowth, "a decrease refunds nothing");
      const atTip = measure(dir, tip, warrant);
      assert.ok(atTip.phi_spent > afterGrowth);
      assert.equal(atTip.phi_remaining, 100000 - atTip.phi_spent);
      assert.equal(atTip.warrant_hash, warrant.hash);
    });
  });

  it("status reports the same spend CI counts, without a key or a terminal", async () => {
    await withHistory(async ({ dir, base, tip }) => {
      const warrant = sign(OWNER, { base_sha: base, phi_budget: 100000 });
      const { phi_spent: spent } = measure(dir, tip, warrant);
      const calls = [];
      const logs = [];
      const runGh = (args) => { calls.push(args); return args[0] === "api" ? `${tip}\n` : `${JSON.stringify(warrant)}\n`; };
      assert.equal(await run(["status"], { isTty: false, rootDir: dir, log: (line) => logs.push(line), runGh }), 0);
      assert.match(logs.join("\n"), new RegExp(`${spent} of 100000 spent, ${100000 - spent} left`));
      assert.equal(calls.some((args) => args.includes("set")), false, "status only reads");
    });
  });

  it("status says why there is no allowance, and exits 1", async () => {
    await withHistory(async ({ dir, tip }) => {
      const logs = [];
      const runGh = (args) => (args[0] === "api" ? `${tip}\n` : "\n");
      assert.equal(await run(["status"], { isTty: false, rootDir: dir, log: (line) => logs.push(line), runGh }), 1);
      assert.match(logs.join("\n"), /No Phi allowance: NO_WARRANT/);
    });
  });

  it("the remaining allowance floors at 0", () => {
    withHistory(({ dir, base, tip }) => {
      assert.equal(measure(dir, tip, sign(OWNER, { base_sha: base, phi_budget: 1 })).phi_remaining, 0);
    });
  });

  it("fails closed on a missing, unverifiable or unanchored warrant", () => {
    withHistory(({ dir, base, side, shrunk, tip }) => {
      const reason = (document, tipSha = tip, extra = {}) => measure(dir, tipSha, document, extra).reason;
      assert.equal(reason(""), "NO_WARRANT");
      assert.equal(reason(undefined), "NO_WARRANT");
      assert.equal(reason("garbage"), "NOT_JSON");
      assert.equal(reason(sign(OTHER, { base_sha: base })), "WRONG_KEY");
      assert.equal(reason(sign(OWNER, { base_sha: base }), "HEAD"), "BAD_TIP_SHA");
      assert.equal(reason(sign(OWNER, { base_sha: side })), "BASE_NOT_ON_CHAIN", "a base on a merged side branch");
      assert.equal(reason(sign(OWNER, { base_sha: tip }), shrunk), "BASE_NOT_ON_CHAIN", "a base newer than the tip");
      assert.match(reason(sign(OWNER, { base_sha: "f".repeat(40) })), /^MEASURE_FAILED/);
      assert.match(reason(sign(OWNER, { base_sha: base }), tip, { maxCommits: 1 }), /^TOO_MANY_COMMITS/);
    });
  });

  it("needs the pin from the base copy, not the repo being measured", () => {
    withHistory(({ dir, base, tip }) => {
      withCheckout((noPin) => {
        const res = measurePhiWarrant({ rootDir: noPin, repoDir: dir, tipSha: tip, document: sign(OWNER, { base_sha: base }) });
        assert.deepEqual(res, { ok: false, reason: "NO_PIN" });
      }, { pin: null });
    });
  });

  it("main writes the spend only on success, and always exits 0", () => {
    withHistory(({ dir, base, tip }) => {
      const output = join(dir, "github-output");
      const lines = [];
      const original = console.log;
      console.log = (line) => lines.push(line);
      try {
        const warrant = JSON.stringify(sign(OWNER, { base_sha: base, phi_budget: 100000 }));
        assert.equal(main({ PHI_WARRANT: warrant, BASE_SHA: tip, GITHUB_OUTPUT: output }, dir), 0);
        const spent = measure(dir, tip, warrant).phi_spent;
        assert.equal(readFileSync(output, "utf8"), `spent=${spent}\n`);
        rmSync(output);
        assert.equal(main({ PHI_WARRANT: "", BASE_SHA: tip, GITHUB_OUTPUT: output }, dir), 0);
        assert.equal(lines.some((line) => line.startsWith("::warning::")), false, "no warrant is not worth a warning");
        assert.equal(main({ PHI_WARRANT: "garbage", BASE_SHA: tip, GITHUB_OUTPUT: output }, dir), 0);
        assert.equal(existsSync(output), false);
        assert.ok(lines.some((line) => line === "::warning::Phi warrant grants no allowance: NOT_JSON"));
      } finally {
        console.log = original;
      }
    });
  });

  it("what main measures is what the evaluator accepts", () => {
    withHistory(({ dir, base, tip }) => {
      const warrant = JSON.stringify(sign(OWNER, { base_sha: base, phi_budget: 100000 }));
      const { phi_spent: spent, phi_remaining: remaining } = measure(dir, tip, warrant);
      const doc = { schema: "outcome/v1", pr: { number: 1, author: "ahmed-3m", kind: "bugfix" }, diff_stat: { files_changed: ["packages/run/journey.mjs"] }, proof: { causal_cycle_completed: true }, evidence: { forbidden_paths_touched: [], tests_deleted: [] }, anti_cheat: { violations_count: 0, flags: [] }, phi: { phi_base: 0, phi_head: remaining, delta_phi: remaining }, surface: { uncited_commands: [], delta_count: 0 } };
      assert.equal(evaluatePullRequest(doc, { rootDir: dir, phiWarrant: warrant, phiSpent: spent }).verdict, "conformance_pass");
      const over = { ...doc, phi: { phi_base: 0, phi_head: remaining + 1, delta_phi: remaining + 1 } };
      assert.equal(evaluatePullRequest(over, { rootDir: dir, phiWarrant: warrant, phiSpent: spent }).violation, "PHI_INCREASE");
    });
  });
});

describe("phi warrant: owner command", () => {
  const MAIN_TIP = "c".repeat(40);
  function harness(dir, { answer = "yes", isTty = true } = {}) {
    const calls = [];
    const logs = [];
    const keyFile = join(dir, "owner.key.json");
    writeFileSync(keyFile, JSON.stringify({ privateKey: OWNER.privateKey }));
    const options = {
      isTty,
      rootDir: dir,
      log: (line) => logs.push(line),
      ask: async () => answer,
      now: () => new Date("2026-11-05T00:00:00Z"),
      runGh: (args) => { calls.push(args); return args[0] === "api" ? `${MAIN_TIP}\n` : ""; },
    };
    return { calls, logs, keyFile, options };
  }

  it("pin writes the owner's public key and nothing private", async () => {
    await withCheckout(async (dir) => {
      const { keyFile, options } = harness(dir);
      assert.equal(await run(["pin", "--key", keyFile], options), 0);
      assert.equal(readPhiWarrantPin(dir), OWNER.publicKey);
      assert.doesNotMatch(readFileSync(join(dir, PHI_WARRANT_PIN_PATH), "utf8"), new RegExp(OWNER.privateKey));
    }, { pin: null });
  });

  it("grant signs from the live tip and stores a warrant CI accepts", async () => {
    await withCheckout(async (dir) => {
      const { calls, keyFile, options } = harness(dir);
      assert.equal(await run(["grant", "--budget", "5000", "--key", keyFile], options), 0);
      const set = calls.find((args) => args[0] === "variable");
      assert.deepEqual(set.slice(0, 4), ["variable", "set", "MIRQL_PHI_WARRANT", "--body"]);
      const warrant = JSON.parse(set[4]);
      assert.equal(warrant.base_sha, MAIN_TIP);
      assert.equal(warrant.phi_budget, 5000);
      assert.equal(phiWarrantAllowance(dir, set[4], 1000), 4000);
      assert.doesNotMatch(set[4], new RegExp(OWNER.privateKey));
    });
  });

  it("signs nothing unless the owner types yes", async () => {
    await withCheckout(async (dir) => {
      const { calls, keyFile, options } = harness(dir, { answer: "no" });
      assert.equal(await run(["grant", "--budget", "5000", "--key", keyFile], options), 1);
      assert.equal(calls.some((args) => args[0] === "variable"), false);
    });
  });

  it("refuses to run without a terminal", async () => {
    await withCheckout(async (dir) => {
      const { calls, keyFile, options } = harness(dir, { isTty: false });
      assert.equal(await run(["grant", "--budget", "5000", "--key", keyFile], options), 2);
      assert.equal(await run(["pin", "--key", keyFile], options), 2);
      assert.deepEqual(calls, []);
    }, { pin: null });
  });

  it("refuses a key other than the pinned one, since CI would ignore the warrant", async () => {
    await withCheckout(async (dir) => {
      const { calls, logs, keyFile, options } = harness(dir);
      assert.equal(await run(["grant", "--budget", "5000", "--key", keyFile], options), 1);
      assert.deepEqual(calls, []);
      assert.match(logs.join("\n"), /Pin it first/);
    }, { pin: OTHER });
  });

  it("rejects bad usage", async () => {
    await withCheckout(async (dir) => {
      const { calls, keyFile, options } = harness(dir);
      for (const budget of ["-1", "1.5", "lots", "", "99999999999999999999"]) {
        assert.equal(await run(["grant", `--budget=${budget}`, "--key", keyFile], options), 2, budget);
      }
      assert.equal(await run(["grant", "--key", keyFile], options), 2);
      assert.equal(await run(["revoke", "--key", keyFile], options), 2);
      assert.equal(await run(["grant", "--nope", "--key", keyFile], options), 2);
      assert.equal(await run([], options), 2);
      assert.deepEqual(calls, []);
    });
  });

  it("refuses a key kept inside .mirql", async () => {
    await withCheckout(async (dir) => {
      mkdirSync(join(dir, ".mirql"));
      const inside = join(dir, ".mirql", "owner.key.json");
      writeFileSync(inside, JSON.stringify({ privateKey: OWNER.privateKey }));
      const { options } = harness(dir);
      await assert.rejects(run(["pin", "--key", inside], options), /credentials_location_forbidden/);
    }, { pin: null });
  });
});
