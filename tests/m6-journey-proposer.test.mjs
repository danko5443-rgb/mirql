// tests/m6-journey-proposer.test.mjs — Comprehensive test suite for Milestone M6: Journey Harness & 1-Tap Proposer.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  distillIntent,
  createProposal,
  create1TapProposal,
  formatIntentDistilledEvent,
  formatProposalCreatedEvent,
  INTENT_CATEGORIES,
} from "../packages/inbox/propose.mjs";
import { actOnItem } from "../packages/inbox/act.mjs";
import { renderDigest, formatMicroUsd } from "../packages/inbox/digest.mjs";
import { runGenesis } from "../packages/inbox/genesis.mjs";
import { main as inboxCliMain } from "../packages/inbox/index.mjs";
import {
  runJourney,
  runAllJourneys,
  createJourneySandbox,
  JOURNEY_SCENARIOS,
  formatJourneyGapEvent,
  formatRegressionReportedEvent,
} from "../packages/run/journey.mjs";
import { main as runCliMain } from "../packages/run/index.mjs";
import {
  EXIT_CODES,
  jcs,
  sha256,
  ulid,
  validateDocument,
  verifyEvent,
} from "../packages/core/index.mjs";
import { foldQueueState } from "../packages/queue/ledger.mjs";
import { leaseNextJob } from "../packages/queue/index.mjs";

describe("Milestone M6: Journey Harness & 1-Tap Proposer", () => {
  describe("1. Proposer Intent Distillation (roles/proposer.md & Law 16)", () => {
    it("distills bugfix intent with reproducer from raw bug report", () => {
      const rawText = "Fix crash in queue lease timeout where warrants expire too early under heavy load";
      const distilled = distillIntent(rawText, {
        "red-check": "npm test -- tests/queue.test.mjs",
      });

      assert.equal(distilled.kind, "bugfix");
      assert.equal(distilled.roadmap_ref, "M1"); // inferred from queue/lease/warrant keywords
      assert.ok(distilled.title.length > 0);
      assert.ok(distilled.reproducer_verified);
      assert.equal(distilled.red_check, "npm test -- tests/queue.test.mjs");
      assert.ok(distilled.proposed_invariants.length > 0);
    });

    it("distills feature intent with default reproducer and explicit roadmap citation", () => {
      const rawText = "Add 1-tap proposer approval workflow for milestone M6";
      const distilled = distillIntent(rawText);

      assert.equal(distilled.kind, "feature");
      assert.equal(distilled.roadmap_ref, "M6");
      assert.ok(distilled.reproducer_verified);
      assert.equal(distilled.red_check, "npm test");
      assert.equal(distilled.surface_impact, "none");
    });

    it("distills refactor and docs categories correctly", () => {
      const refactorRes = distillIntent("Refactor and simplify doctor circuit breaker event handlers");
      assert.equal(refactorRes.kind, "refactor");

      const docsRes = distillIntent("Update README docs and architecture guide for bing-bong");
      assert.equal(docsRes.kind, "docs");
    });

    it("detects surface impact when public CLI surface is mentioned", () => {
      const distilled = distillIntent("Add new public command and update surface.lock entrypoints");
      assert.ok(distilled.surface_impact.includes("surface.lock"));
    });

    it("formats canonical intent.distilled event with safe integers and valid envelope", () => {
      const distilled = distillIntent("Add journey harness for M6");
      const event = formatIntentDistilledEvent(distilled, { nowMs: 1700000000000 });

      assert.equal(event.v, 1);
      assert.equal(event.type, "intent.distilled");
      assert.equal(event.payload.category, "feature");
      assert.equal(event.payload.roadmap_ref, "M6");
      assert.equal(event.payload.timestamp_ms, 1700000000000);
      assert.ok(Number.isSafeInteger(event.payload.timestamp_ms));
    });

    it("formats canonical proposal.created event with deterministic ULID", () => {
      const proposal = {
        id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        title: "Test proposal",
        description: "Testing proposal format",
        surface_impact: "none",
        proposed_invariants: ["invariant: clean execution"],
        action_type: "1_tap_approve",
        roadmap_ref: "M6",
        red_check: "npm test",
      };
      const event = formatProposalCreatedEvent(proposal, { nowMs: 1700000000000 });

      assert.equal(event.v, 1);
      assert.equal(event.type, "proposal.created");
      assert.equal(event.payload.proposal_id, proposal.id);
      assert.equal(event.payload.action_type, "1_tap_approve");
      assert.equal(event.payload.roadmap_ref, "M6");
    });
  });

  describe("2. Bounded Proposer Intake & 1-Tap Proposals", () => {
    let tempDir, mirqlDir;

    function setupSandbox() {
      tempDir = mkdtempSync(join(tmpdir(), "mirql-propose-test-"));
      mirqlDir = join(tempDir, ".mirql");
      mkdirSync(mirqlDir, { recursive: true });

      // Create minimal ROADMAP.md and NOT-ROADMAP.md
      writeFileSync(join(tempDir, "ROADMAP.md"), "# ROADMAP\nM1\nM2\nM3\nM4\nM5\nM6\nM7\n");
      writeFileSync(join(tempDir, "NOT-ROADMAP.md"), '{"anti_goals":[{"id":"NG-001","phrase":"telemetry collection"}]}\n# NOT-ROADMAP\n');
    }

    function tearDownSandbox() {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }

    it("creates 1-tap proposal with roadmap citation and persists document", () => {
      setupSandbox();
      try {
        const res = create1TapProposal(mirqlDir, {
          roadmap_ref: "M6",
          title: "Implement user journey simulator",
          description: "End-to-end journey simulation for CLI validation",
          proposed_invariants: ["all-journeys-pass"],
        });

        assert.equal(res.status, "proposed");
        assert.ok(res.proposal_id);
        assert.equal(res.proposal.action_type, "1_tap_approve");
        assert.equal(res.proposal.status, "pending");

        const savedFile = join(mirqlDir, "proposals", `${res.proposal_id}.json`);
        assert.ok(existsSync(savedFile));
        const saved = JSON.parse(readFileSync(savedFile, "utf8"));
        assert.equal(saved.title, "Implement user journey simulator");
      } finally {
        tearDownSandbox();
      }
    });

    it("synthesizes proposal from raw text using distillIntent", () => {
      setupSandbox();
      try {
        const res = createProposal(mirqlDir, {
          text: "Fix broken doctor circuit breaker reset logic in M5",
        });

        assert.equal(res.status, "proposed");
        assert.equal(res.proposal.roadmap_ref, "M5");
        assert.equal(res.proposal.kind, "bugfix");
        assert.ok(res.intent_distilled);
        assert.ok(res.proposal_created_event);
      } finally {
        tearDownSandbox();
      }
    });

    it("rejects proposal violating NOT-ROADMAP.md negative-space gate", () => {
      setupSandbox();
      try {
        assert.throws(() => {
          createProposal(mirqlDir, {
            roadmap_ref: "M6",
            title: "Add auto-approve timeout for human verdicts",
            description: "Timeout auto-approval without human signature",
          });
        }, (err) => {
          return err.exitCode === EXIT_CODES.POLICY_DENIAL;
        });
      } finally {
        tearDownSandbox();
      }
    });

    it("enforces 3-proposal capacity quota ceiling", () => {
      setupSandbox();
      try {
        for (let i = 1; i <= 3; i++) {
          createProposal(mirqlDir, {
            roadmap_ref: "M6",
            title: `Proposal ${i}`,
            description: `Description ${i}`,
          }, { nowMs: 1700000000000 + i * 10 });
        }

        // 4th proposal must be rejected by quota gate
        assert.throws(() => {
          createProposal(mirqlDir, {
            roadmap_ref: "M6",
            title: "Proposal 4",
            description: "Should fail quota",
          });
        }, (err) => {
          return err.exitCode === EXIT_CODES.POLICY_DENIAL;
        });
      } finally {
        tearDownSandbox();
      }
    });
  });

  describe("3. 1-Tap Human Action & Direct Warrant Minting (Law 6, Law 11, Law 16)", () => {
    let tempDir, mirqlDir, humanKeyFile;

    function setupSandbox() {
      tempDir = mkdtempSync(join(tmpdir(), "mirql-act-test-"));
      mirqlDir = join(tempDir, ".mirql");
      mkdirSync(mirqlDir, { recursive: true });

      writeFileSync(join(tempDir, "ROADMAP.md"), "# ROADMAP\nM1\nM2\nM3\nM4\nM5\nM6\nM7\n");
      writeFileSync(join(tempDir, "NOT-ROADMAP.md"), '{"anti_goals":[]}\n# NOT-ROADMAP\n');

      humanKeyFile = join(tempDir, "human_owner.key.json");
      runGenesis(mirqlDir, { humanKeyOut: humanKeyFile });
    }

    function tearDownSandbox() {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }

    it("fails closed without human credentials (Law 6: Silence is never consent)", () => {
      setupSandbox();
      try {
        const prop = createProposal(mirqlDir, {
          roadmap_ref: "M6",
          title: "Require human signature",
          description: "Cannot approve without key",
        });

        assert.throws(() => {
          actOnItem(mirqlDir, {
            decision: "approve",
            target_id: prop.proposal_id,
          });
        }, (err) => {
          return err.exitCode === EXIT_CODES.POLICY_DENIAL;
        });
      } finally {
        tearDownSandbox();
      }
    });

    it("1-tap approve mints warrant, persists warrant doc, appends warrant.created, and enqueues to queue", () => {
      setupSandbox();
      try {
        const prop = createProposal(mirqlDir, {
          roadmap_ref: "M6",
          title: "1-Tap workflow feature",
          description: "Enqueues directly into queue on human approve",
          proposed_invariants: ["verified-warrant"],
        });

        const actRes = actOnItem(mirqlDir, {
          decision: "approve",
          target_id: prop.proposal_id,
          key: humanKeyFile,
        }, { key: humanKeyFile });

        assert.equal(actRes.status, "acted");
        assert.equal(actRes.decision, "approve");
        assert.ok(actRes.warrant_id);
        assert.ok(actRes.warrant);

        // Verify warrant document exists on disk and is schema-valid
        const warrantFile = join(mirqlDir, "warrants", `${actRes.warrant_id}.json`);
        assert.ok(existsSync(warrantFile));
        const warrantDoc = JSON.parse(readFileSync(warrantFile, "utf8"));
        const validation = validateDocument("warrant", warrantDoc);
        assert.ok(validation.valid, `Warrant invalid: ${validation.errors.join("; ")}`);
        assert.equal(warrantDoc.evidence.proposal_id, prop.proposal_id);

        // Verify proposal updated
        const propFile = join(mirqlDir, "proposals", `${prop.proposal_id}.json`);
        const updatedProp = JSON.parse(readFileSync(propFile, "utf8"));
        assert.equal(updatedProp.status, "approved");
        assert.equal(updatedProp.warrant_id, actRes.warrant_id);

        // Verify queue folded state registers the newly minted warrant
        const qState = foldQueueState(mirqlDir);
        assert.ok(qState.warrants[actRes.warrant_id]);
        assert.equal(qState.warrants[actRes.warrant_id].status, "active");

        // Verify queue can lease the warrant immediately
        const leaseRes = leaseNextJob(mirqlDir, { worker_id: "worker-test-1" });
        assert.ok(leaseRes.ok);
        assert.equal(leaseRes.status, "leased");
        assert.equal(leaseRes.warrant_id, actRes.warrant_id);
      } finally {
        tearDownSandbox();
      }
    });

    it("1-tap reject updates proposal status without minting warrant", () => {
      setupSandbox();
      try {
        const prop = createProposal(mirqlDir, {
          roadmap_ref: "M6",
          title: "Proposal to reject",
          description: "Will be rejected by human",
        });

        const actRes = actOnItem(mirqlDir, {
          decision: "reject",
          target_id: prop.proposal_id,
          reason: "scope too broad",
          key: humanKeyFile,
        }, { key: humanKeyFile });

        assert.equal(actRes.status, "acted");
        assert.equal(actRes.decision, "reject");
        assert.equal(actRes.warrant_id, undefined);

        const propFile = join(mirqlDir, "proposals", `${prop.proposal_id}.json`);
        const updatedProp = JSON.parse(readFileSync(propFile, "utf8"));
        assert.equal(updatedProp.status, "rejected");
        assert.equal(updatedProp.action_reason, "scope too broad");
      } finally {
        tearDownSandbox();
      }
    });

    it("rejects directory traversal in target_id (Law 3 & Law 6)", () => {
      setupSandbox();
      try {
        assert.throws(() => {
          actOnItem(mirqlDir, {
            decision: "approve",
            target_id: "../../../etc/passwd",
            key: humanKeyFile,
          }, { key: humanKeyFile });
        }, (err) => {
          return err.errorCode === "invalid_target_id";
        });
      } finally {
        tearDownSandbox();
      }
    });
  });

  describe("4. Keyless Read-Only Digest (Law 6 & Law 17)", () => {
    let tempDir, mirqlDir, humanKeyFile;

    function setupSandbox() {
      tempDir = mkdtempSync(join(tmpdir(), "mirql-digest-test-"));
      mirqlDir = join(tempDir, ".mirql");
      mkdirSync(mirqlDir, { recursive: true });
      writeFileSync(join(tempDir, "ROADMAP.md"), "# ROADMAP\nM1\nM2\nM3\nM4\nM5\nM6\nM7\n");
      writeFileSync(join(tempDir, "NOT-ROADMAP.md"), '{"anti_goals":[]}\n# NOT-ROADMAP\n');
      humanKeyFile = join(tempDir, "human.key.json");
      runGenesis(mirqlDir, { humanKeyOut: humanKeyFile });
    }

    function tearDownSandbox() {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }

    it("formats integer micro-USD without floats", () => {
      assert.equal(formatMicroUsd(0), "$0.00");
      assert.equal(formatMicroUsd(1500000), "$1.50");
      assert.equal(formatMicroUsd(250000), "$0.25");
      assert.equal(formatMicroUsd(10000000), "$10.00");

      assert.throws(() => formatMicroUsd(1.5), /Law 17/);
      assert.throws(() => formatMicroUsd("100"), /Law 17/);
    });

    it("renders digest with pending 1-tap action command hints", () => {
      setupSandbox();
      try {
        const prop = createProposal(mirqlDir, {
          roadmap_ref: "M6",
          title: "Feature with 1-tap hint",
          description: "Digest test",
        });

        const digest = renderDigest(mirqlDir);
        assert.equal(digest.tool, "inbox");
        assert.equal(digest.mutates_ledger, false);
        assert.ok(digest.pending_proposals.length > 0);

        const found = digest.pending_proposals.find((p) => p.id === prop.proposal_id);
        assert.ok(found);
        assert.ok(found.action_hint.includes(prop.proposal_id));

        const markdown = renderDigest(mirqlDir, { format: "markdown" });
        assert.ok(typeof markdown === "string");
        assert.ok(markdown.includes(prop.proposal_id));
        assert.ok(markdown.includes("--approve"));
      } finally {
        tearDownSandbox();
      }
    });
  });

  describe("5. User Journey Simulation Harness (roles/scout-journey.md)", () => {
    it("creates isolated sandbox with standard repo baselines", () => {
      const sb = createJourneySandbox();
      try {
        assert.ok(existsSync(sb.sandboxDir));
        assert.ok(existsSync(join(sb.sandboxDir, "surface.lock")));
        assert.ok(existsSync(join(sb.sandboxDir, "ROADMAP.md")));
        assert.ok(existsSync(join(sb.sandboxDir, "NOT-ROADMAP.md")));
      } finally {
        sb.cleanup();
        assert.ok(!existsSync(sb.sandboxDir));
      }
    });

    it("executes Scenario 1: init-to-merge end-to-end", async () => {
      const res = await runJourney("init-to-merge");
      assert.equal(res.ok, true, res.error);
      assert.equal(res.journey_name, "init-to-merge");
      assert.ok(res.steps_completed.length >= 6);
      assert.ok(res.duration_ms >= 0);
    });

    it("executes Scenario 2: fault-to-recovery end-to-end", async () => {
      const res = await runJourney("fault-to-recovery");
      assert.equal(res.ok, true, res.error);
      assert.equal(res.journey_name, "fault-to-recovery");
      assert.ok(res.steps_completed.length >= 5);
    });

    it("executes Scenario 3: quarantine-to-harden end-to-end", async () => {
      const res = await runJourney("quarantine-to-harden");
      assert.equal(res.ok, true, res.error);
      assert.equal(res.journey_name, "quarantine-to-harden");
      assert.ok(res.steps_completed.length >= 4);
    });

    it("executes runAllJourneys across all 3 scenarios", async () => {
      const allRes = await runAllJourneys();
      assert.equal(allRes.ok, true);
      assert.equal(allRes.scenarios_passed, 3);
      assert.equal(allRes.scenarios_failed, 0);
      assert.equal(allRes.gaps.length, 0);
      assert.equal(allRes.regressions.length, 0);
    });

    it("formats canonical journey.gap_found and regression.reported on failure", () => {
      const gap = formatJourneyGapEvent({
        journey_name: "test-journey",
        step_failed: "mirql i act",
        expected_behavior: "1-tap approval completes",
        observed_behavior: "Credentials required",
        exit_code: EXIT_CODES.POLICY_DENIAL,
      }, { nowMs: 1700000000000 });

      assert.equal(gap.v, 1);
      assert.equal(gap.type, "journey.gap_found");
      assert.equal(gap.payload.journey_name, "test-journey");
      assert.equal(gap.payload.exit_code, EXIT_CODES.POLICY_DENIAL);

      const regression = formatRegressionReportedEvent({
        severity: "critical",
        minimal_repro: ["mirql i genesis", "mirql i act"],
        details: "1-tap approval ceremony failed",
        journey_name: "test-journey",
      }, { nowMs: 1700000000000 });

      assert.equal(regression.v, 1);
      assert.equal(regression.type, "regression.reported");
      assert.equal(regression.payload.severity, "critical");
    });
  });

  describe("6. CLI Entrypoints Integration (surface.lock alignment)", () => {
    it("mirql r journey answers --scenario init-to-merge with exit code 0", async () => {
      const exitCode = await runCliMain(["journey", "--scenario", "init-to-merge"]);
      assert.equal(exitCode, EXIT_CODES.OK);
    });

    it("mirql r journey with invalid scenario exits with code 1 (DOMAIN_NEGATIVE)", async () => {
      const exitCode = await runCliMain(["journey", "--scenario", "non-existent-scenario"]);
      assert.equal(exitCode, EXIT_CODES.DOMAIN_NEGATIVE);
    });

    it("mirql r journey runs all scenarios with exit code 0", async () => {
      const exitCode = await runCliMain(["journey"]);
      assert.equal(exitCode, EXIT_CODES.OK);
    });
  });
});
