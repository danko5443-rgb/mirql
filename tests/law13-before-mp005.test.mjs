// tests/law13-before-mp005.test.mjs — Phi growth cannot pass behind MP-005.
//
// MP-005 returns needs_human, which an owner label or an AI approval clears.
// Law 13 must therefore run first, or touching any humanApprove path would turn
// a Phi rejection into a reviewable verdict.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluatePullRequest } from "../packages/mergeproof/evaluator.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const BIN = join(ROOT, "bin", "mirql.mjs");

/** The evidence shape scripts/ci-evidence.mjs writes: suites measured, no causal cycle. */
const ciDoc = (phi, overrides = {}) => ({
  schema: "outcome/v1",
  pr: { number: 72, author: "ahmed-3m", kind: "pr" },
  diff_stat: { files_changed: ["packages/core/acl.mjs"] },
  proof: { causal_cycle_completed: false, suite_pass_base: true, suite_pass_head: true },
  evidence: { forbidden_paths_touched: [], tests_deleted: [] },
  anti_cheat: { violations_count: 0, flags: [] },
  ...(phi === undefined ? {} : { phi }),
  surface: { uncited_commands: [], delta_count: 0 },
  ...overrides,
});

const evaluate = (doc, options = {}) => evaluatePullRequest(doc, { rootDir: ROOT, ...options });

describe("Law 13 runs before MP-005 on a humanApprove path", () => {
  it("rejects Phi growth and reports both failed checks", () => {
    const res = evaluate(ciDoc({ delta_phi: 325 }));
    assert.equal(res.verdict, "reject");
    assert.equal(res.rule, "LAW_13");
    assert.equal(res.violation, "PHI_INCREASE");
    assert.equal(res.delta_phi, 325);
    assert.equal(res.checks.phi, false);
    assert.equal(res.checks.surface, false);
  });

  it("does not let a reviewer clear Phi growth", () => {
    const res = evaluate(
      ciDoc({ delta_phi: 1 }, { diff_stat: { files_changed: ["packages/core/acl.mjs", "scripts/x.mjs"] } }),
      { humanOnlyReviewer: "ahmed-3m" },
    );
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "PHI_INCREASE");
  });

  for (const file of ["roles/x.md", "package.json"]) {
    it(`touching ${file} does not dodge Law 13`, () => {
      const res = evaluate(ciDoc({ delta_phi: 1 }, { diff_stat: { files_changed: [file] } }));
      assert.equal(res.verdict, "reject");
      assert.equal(res.violation, "PHI_INCREASE");
    });
  }

  it("uncited surface does not dodge Law 13", () => {
    const res = evaluate(
      ciDoc({ delta_phi: 1 }, {
        diff_stat: { files_changed: ["README.md"] },
        surface: { uncited_commands: ["mirql new"], delta_count: 1 },
      }),
    );
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "PHI_INCREASE");
  });

  for (const delta of [-5, 0]) {
    it(`keeps needs_human and reports Phi as checked when delta_phi is ${delta}`, () => {
      const res = evaluate(ciDoc({ delta_phi: delta }));
      assert.equal(res.verdict, "needs_human");
      assert.equal(res.rule, "MP-005");
      assert.equal(res.violation, "UNCITED_SURFACE");
      assert.equal(res.delta_phi, delta);
      assert.deepEqual(res.human_approve_paths, ["packages/core/acl.mjs"]);
      assert.equal(res.checks.phi, true);
      assert.equal(res.checks.surface, false);
    });
  }

  for (const [label, phi] of [["absent", undefined], ["empty", {}], ["not an integer", { delta_phi: 1.5 }]]) {
    it(`fails closed when Phi is ${label}`, () => {
      const res = evaluate(ciDoc(phi));
      assert.equal(res.verdict, "reject");
      assert.equal(res.rule, "LAW_13");
      assert.equal(res.violation, "MISSING_PHI");
      assert.equal(res.checks.phi, false);
    });
  }

  it("holds a consolidation on a protected path to a strict Phi decrease", () => {
    const res = evaluate(ciDoc({ delta_phi: 0 }, { pr: { number: 72, author: "a", kind: "refactor" } }));
    assert.equal(res.verdict, "reject");
    assert.equal(res.violation, "PHI_NOT_DECREASED");
  });
});

describe("checks.phi says whether Law 13 ran", () => {
  it("is null when an earlier rule stopped the evaluation", () => {
    const res = evaluate(ciDoc({ delta_phi: 325 }, { diff_stat: { files_changed: ["policy/x.yaml"] } }));
    assert.equal(res.rule, "MP-001");
    assert.equal(res.verdict, "reject");
    assert.equal(res.checks.phi, null);
  });

  it("is true past Law 13 on an unprotected path", () => {
    const res = evaluate(ciDoc({ delta_phi: 0 }, { diff_stat: { files_changed: ["README.md"] } }));
    assert.equal(res.rule, "LAW_16");
    assert.equal(res.checks.phi, true);
    assert.equal(res.checks.surface, true);
  });
});

describe("gate output", () => {
  const check = (doc) => {
    const dir = mkdtempSync(join(tmpdir(), "mirql-law13-"));
    try {
      const prPath = join(dir, "pr.json");
      writeFileSync(prPath, JSON.stringify(doc));
      const res = spawnSync(process.execPath, [BIN, "m", "check", "--pr", prPath], {
        cwd: ROOT,
        encoding: "utf8",
        timeout: 60_000,
      });
      assert.equal(res.error, undefined, res.error?.message);
      return JSON.parse(res.stdout);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it("shows the rejection and the measured increase", () => {
    const out = check(ciDoc({ delta_phi: 325 }));
    assert.equal(out.verdict, "reject");
    assert.equal(out.violation, "PHI_INCREASE");
    assert.equal(out.delta_phi, 325);
    assert.equal(out.checks.phi, false);
    assert.match(out.detail, /\+325/);
  });

  it("shows needs_human with Phi checked when Phi fell", () => {
    const out = check(ciDoc({ delta_phi: -5 }));
    assert.equal(out.verdict, "needs_human");
    assert.equal(out.rule, "MP-005");
    assert.equal(out.delta_phi, -5);
    assert.equal(out.checks.phi, true);
  });
});
