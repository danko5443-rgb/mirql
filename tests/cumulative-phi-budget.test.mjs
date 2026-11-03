// Law 13: a warrant's signed phi_budget is one cumulative allowance, not a
// per-transition grant that an agent can re-spend on every change.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { git } from "./helpers/git.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { sendIntent } from "../packages/inbox/send.mjs";
import { verifyAttempt } from "../packages/run/verify.mjs";
import { computeGitTreePhi } from "../packages/run/phi.mjs";
import { measureAuthorizedPhi, recordPhiConsumption, PHI_CONSUMED_EVENT } from "../packages/run/authorized-phi.mjs";

const REPRO = 'import test from "node:test";import assert from "node:assert/strict";import {value} from "../src/value.mjs";'
  + 'test("value",()=>assert.equal(value(),VALUE));\n';

/** Builds base -> step1 -> step2, each step a genuine causal fix that grows Phi. */
function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "mirql-cumulative-phi-"));
  try {
    mkdirSync(join(root, "src")); mkdirSync(join(root, "tests"));
    git(root, "init", "-q"); git(root, "config", "user.name", "test"); git(root, "config", "user.email", "test@local");
    git(root, "config", "commit.gpgsign", "false");
    writeFileSync(join(root, "package.json"), JSON.stringify({ scripts: { test: "node --test" } }));
    writeFileSync(join(root, "src", "value.mjs"), "export function value(){return 1;}\n");
    git(root, "add", "."); git(root, "commit", "-qm", "base");
    const shas = [git(root, "rev-parse", "HEAD").trim()];
    for (const step of [2, 3]) {
      const extras = Array.from({ length: 6 * step }, (_, i) => `export const s${step}_${i}=${i};`).join("\n");
      writeFileSync(join(root, "src", "value.mjs"), `export function value(){return ${step};}\n${extras}\n`);
      writeFileSync(join(root, "tests", "repro.test.mjs"), REPRO.replace("VALUE", String(step)));
      git(root, "add", "."); git(root, "commit", "-qm", "step " + step);
      shas.push(git(root, "rev-parse", "HEAD").trim());
    }
    const phi = shas.map(sha => computeGitTreePhi(root, sha).metrics.total);
    const deltas = [phi[1] - phi[0], phi[2] - phi[1]];
    assert.ok(deltas.every(delta => delta > 0), "fixture steps must grow Phi");
    const dir = join(root, ".mirql"), owner = runGenesis(dir);
    const grant = (budget, kind = "feature") => sendIntent(dir,
      { title: `Cumulative budget ${budget} ${kind}`, kind, phi_budget: budget, scope: ["src/**", "tests/**"] },
      { key: owner.human_key_path }).warrant_id;
    const verify = (warrantId, from, to) => verifyAttempt({ git: true, workspaceDir: root, baseSha: shas[from], headSha: shas[to],
      reproducerFile: "tests/repro.test.mjs", mirqlDir: dir, warrantId });
    const consumptions = () => readFileSync(join(dir, "ledger", "events.jsonl"), "utf8").split("\n").filter(Boolean)
      .map(line => JSON.parse(line)).filter(event => event.type === PHI_CONSUMED_EVENT);
    run({ root, dir, shas, deltas, grant, verify, consumptions });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test("an allowance spent by one transition cannot be re-spent by the next", () => fixture(({ deltas, grant, verify }) => {
  const warrantId = grant(deltas[0] + deltas[1] - 1);
  const first = verify(warrantId, 0, 1);
  assert.equal(first.verified, true, JSON.stringify(first));
  assert.equal(first.phi.phi_consumed, 0);
  const second = verify(warrantId, 1, 2);
  assert.equal(second.verified, false, JSON.stringify(second));
  assert.equal(second.rule, "LAW_13_PHI_BUDGET_EXHAUSTED");
  assert.equal(second.phi.phi_consumed, deltas[0]);
  assert.ok(deltas[1] <= second.phi.phi_budget, "the step alone fits the budget; only the cumulative spend exceeds it");
}));

test("an allowance large enough for both transitions accepts both and records each spend", () => fixture(({ deltas, grant, verify, consumptions }) => {
  const warrantId = grant(deltas[0] + deltas[1]);
  assert.equal(verify(warrantId, 0, 1).verified, true);
  const second = verify(warrantId, 1, 2);
  assert.equal(second.verified, true, JSON.stringify(second));
  assert.equal(second.phi.phi_remaining, deltas[1]);
  assert.deepEqual(consumptions().map(event => event.payload.delta_phi), deltas);
  assert.ok(consumptions().every(event => event.writer.ns === "tool:run_supervisor" && event.payload.warrant_id === warrantId));
}));

test("re-verifying the same transition is idempotent and spends nothing extra", () => fixture(({ deltas, grant, verify, consumptions }) => {
  const warrantId = grant(deltas[0]);
  assert.equal(verify(warrantId, 0, 1).verified, true);
  const again = verify(warrantId, 0, 1);
  assert.equal(again.verified, true, JSON.stringify(again));
  assert.equal(again.phi.phi_consumed, 0);
  assert.equal(consumptions().length, 1);
}));

test("budgets are tracked per warrant", () => fixture(({ deltas, grant, verify }) => {
  const spent = grant(deltas[0]);
  assert.equal(verify(spent, 0, 1).verified, true);
  const fresh = grant(deltas[1]);
  assert.equal(verify(fresh, 1, 2).verified, true);
}));

test("a measurement made before a concurrent spend is re-checked inside the ledger lock", () => fixture(({ root, dir, shas, deltas, grant }) => {
  const warrantId = grant(Math.max(deltas[0], deltas[1]));
  const first = measureAuthorizedPhi({ repoDir: root, baseSha: shas[0], headSha: shas[1], mirqlDir: dir, warrantId });
  const second = measureAuthorizedPhi({ repoDir: root, baseSha: shas[1], headSha: shas[2], mirqlDir: dir, warrantId });
  assert.equal(first.ok && second.ok, true, "both fit the untouched budget when measured");
  assert.ok(recordPhiConsumption(dir, first));
  assert.throws(() => recordPhiConsumption(dir, second), error => error.code === "LAW_13_PHI_BUDGET_EXHAUSTED");
}));

test("non-increasing transitions spend nothing and decreases never refund", () => fixture(({ root, dir, shas, deltas, grant, consumptions }) => {
  const warrantId = grant(deltas[0]);
  const forward = measureAuthorizedPhi({ repoDir: root, baseSha: shas[0], headSha: shas[1], mirqlDir: dir, warrantId });
  recordPhiConsumption(dir, forward);
  const backward = measureAuthorizedPhi({ repoDir: root, baseSha: shas[1], headSha: shas[0], mirqlDir: dir, warrantId });
  assert.ok(backward.delta_phi < 0);
  assert.equal(recordPhiConsumption(dir, backward), null);
  assert.equal(consumptions().length, 1);
  const retry = measureAuthorizedPhi({ repoDir: root, baseSha: shas[1], headSha: shas[2], mirqlDir: dir, warrantId });
  assert.equal(retry.phi_consumed, deltas[0], "the decrease must not have restored any allowance");
  assert.equal(retry.ok, false);
}));
