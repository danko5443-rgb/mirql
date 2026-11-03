import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";

const ROOT = resolve(import.meta.dirname, "..");

/**
 * Recursively verifies that every number in an object or array is a safe integer.
 */
function assertSafeIntegersOnly(obj, path = "$") {
  if (obj === null || obj === undefined) return;
  if (typeof obj === "number") {
    assert.ok(
      Number.isSafeInteger(obj),
      `Expected safe integer at ${path}, got floating point or non-safe integer: ${obj}`
    );
    return;
  }
  if (Array.isArray(obj)) {
    obj.forEach((item, idx) => assertSafeIntegersOnly(item, `${path}[${idx}]`));
    return;
  }
  if (typeof obj === "object") {
    for (const [key, value] of Object.entries(obj)) {
      assertSafeIntegersOnly(value, `${path}.${key}`);
    }
  }
}

/**
 * Extracts YAML frontmatter key-value pairs from markdown files.
 */
function parseFrontmatter(markdown) {
  const match = markdown.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;
  const lines = match[1].split(/\r?\n/);
  const data = {};
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon !== -1) {
      const key = line.slice(0, colon).trim();
      const val = line.slice(colon + 1).trim();
      data[key] = val;
    }
  }
  return data;
}

/**
 * Parses writer rules from policy/writers.yaml into a map of namespace -> RegExp.
 */
function parseWritersYaml(yamlText) {
  const map = {};
  const lines = yamlText.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed === "writers:") continue;
    const sepIdx = trimmed.indexOf('":');
    if (sepIdx !== -1) {
      const key = trimmed.slice(0, sepIdx).replace(/^"/, "").trim();
      let val = trimmed.slice(sepIdx + 2).trim();
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      val = val.replace(/\\\\/g, "\\");
      map[key] = new RegExp(val);
    }
  }
  return map;
}

/**
 * Deterministic ledger event reducer folding events into state projection.
 */
function reduceEvents(events) {
  const state = {
    epoch: 0,
    macro_state: null,
    events_processed: 0,
    warrants: {},
    jobs: {},
    metrics: {
      total_cost_micro_usd: 0,
      total_tokens_consumed: 0,
      warrants_total: 0,
      warrants_completed: 0,
      jobs_total: 0,
      jobs_completed: 0
    }
  };

  for (const evt of events) {
    state.events_processed += 1;
    switch (evt.type) {
      case "mirql.genesis":
        state.epoch = evt.epoch;
        state.macro_state = evt.payload.macro_state;
        break;
      case "human.intent":
        // Ingested into inbox / queue pending warrant
        break;
      case "warrant.created":
        state.warrants[evt.payload.warrant_id] = {
          id: evt.payload.warrant_id,
          intent_id: evt.payload.intent_id,
          role: evt.payload.role,
          tier: evt.payload.tier,
          status: "active",
          budget_micro_usd: evt.payload.budget_micro_usd
        };
        state.metrics.warrants_total += 1;
        break;
      case "job.leased":
        state.jobs[evt.payload.job_id] = {
          id: evt.payload.job_id,
          warrant_id: evt.payload.warrant_id,
          worker_id: evt.payload.worker_id,
          status: "leased",
          outcome_verdict: null
        };
        state.metrics.jobs_total += 1;
        break;
      case "attempt.outcome": {
        const job = state.jobs[evt.payload.job_id];
        if (job) {
          job.status = evt.payload.status;
          job.outcome_verdict = evt.payload.verdict;
          state.metrics.jobs_completed += 1;
        }
        const warrant = state.warrants[evt.payload.warrant_id];
        if (warrant && evt.payload.status === "completed") {
          warrant.status = "completed";
          state.metrics.warrants_completed += 1;
        }
        state.metrics.total_cost_micro_usd += evt.payload.cost_micro_usd;
        state.metrics.total_tokens_consumed += evt.payload.tokens_consumed;
        break;
      }
      default:
        break;
    }
  }
  return state;
}

describe("Work Package W2: Conformance Suite", () => {
  describe("1. Top-Level Normative Documents", () => {
    it("CONSTITUTION.md contains all 17 Normative Laws", () => {
      const constitutionPath = join(ROOT, "CONSTITUTION.md");
      assert.ok(existsSync(constitutionPath), "CONSTITUTION.md must exist");
      const content = readFileSync(constitutionPath, "utf8");

      const expectedLaws = [
        "Law 1: Offline Litmus",
        "Law 2: Lifeguard Law",
        "Law 3: Roles Propose / Tools Author",
        "Law 4: One Durable Ledger",
        "Law 5: Base-Pinned Mortal Verdicts",
        "Law 6: Silence Is Never Consent",
        "Law 7: Notary Outside Blast Radius",
        "Law 8: Speechless Sandboxes",
        "Law 9: N-1 Processes N",
        "Law 10: Ship Invariants Not Features",
        "Law 11: No Warrant No Work",
        "Law 12: The Probe Doctrine",
        "Law 13: Monotone Potential PHI & Thrift Test",
        "Law 14: Quiescence Is Success",
        "Law 15: Semantic Identity / Mechanical Location",
        "Law 16: GREEN Must Be Causal",
        "Law 17: Per-Product Tenant Isolation & Integer-Only JCS"
      ];

      for (let i = 1; i <= 17; i++) {
        assert.ok(
          content.includes(`Law ${i}:`),
          `CONSTITUTION.md must define Law ${i}`
        );
      }

      for (const law of expectedLaws) {
        assert.ok(
          content.includes(law),
          `CONSTITUTION.md must contain exact law heading: "${law}"`
        );
      }
    });

    it("ROADMAP.md defines Milestones M1 through M7", () => {
      const roadmapPath = join(ROOT, "ROADMAP.md");
      assert.ok(existsSync(roadmapPath), "ROADMAP.md must exist");
      const content = readFileSync(roadmapPath, "utf8");

      const milestones = ["M1", "M2", "M3", "M4", "M5", "M6", "M7"];
      for (const m of milestones) {
        assert.ok(content.includes(m), `ROADMAP.md must define Milestone ${m}`);
      }
    });

    it("NOT-ROADMAP.md starts with required anti-goal JSON signature and cites Law 6", () => {
      const notRoadmapPath = join(ROOT, "NOT-ROADMAP.md");
      assert.ok(existsSync(notRoadmapPath), "NOT-ROADMAP.md must exist");
      const content = readFileSync(notRoadmapPath, "utf8");

      const jsonMatch = content.match(/```json\r?\n([\s\S]*?)\r?\n```/);
      assert.ok(jsonMatch, "NOT-ROADMAP.md must contain a ```json code block");
      const parsed = JSON.parse(jsonMatch[1]);
      assert.ok(Array.isArray(parsed), "Parsed JSON must be an array");

      const firstItem = parsed[0];
      assert.equal(firstItem.id, "nr-0001");
      assert.equal(
        firstItem.reason,
        "Never auto-approve HUMAN verdicts on timeout"
      );
      assert.deepEqual(firstItem.surface_delta, [
        "config:inbox.auto_approve_timeout_s"
      ]);
      assert.ok(
        firstItem.violates_law && firstItem.violates_law.includes("Law 6"),
        "nr-0001 must cite Law 6 (Cryptographic Human Sovereignty)"
      );
    });

    it("README.md exists and introduces mirql architecture including bing-bong", () => {
      const readmePath = join(ROOT, "README.md");
      assert.ok(existsSync(readmePath), "README.md must exist");
      const content = readFileSync(readmePath, "utf8");
      assert.ok(content.includes("mergeproof"), "README must explain mergeproof");
      assert.ok(content.includes("inbox"), "README must explain inbox");
      assert.ok(content.includes("run"), "README must explain run");
      assert.ok(content.includes("queue"), "README must explain queue");
      assert.ok(content.includes("log"), "README must explain log");
      assert.ok(
        content.includes("bing-bong") || content.includes("mirql r bb"),
        "README must document bing-bong command"
      );
    });

    it("surface.lock matches exact public surface specification and has integer-only values", () => {
      const surfacePath = join(ROOT, "surface.lock");
      assert.ok(existsSync(surfacePath), "surface.lock must exist");
      const content = readFileSync(surfacePath, "utf8");
      const parsed = JSON.parse(content);

      assertSafeIntegersOnly(parsed, "surface.lock");

      assert.equal(parsed.v, 1);
      assert.deepEqual(parsed.bins, [
        "mirql",
        "mirql-run",
        "mirql-queue",
        "mirql-log",
        "mirql-inbox"
      ]);

      const expectedCommands = [
        "mirql m check",
        "mirql i genesis",
        "mirql i enroll-key",
        "mirql i send",
        "mirql i digest",
        "mirql i act",
        "mirql i approve-merge",
        "mirql i protect-key",
        "mirql i propose",
        "mirql r supervisor",
        "mirql r agent",
        "mirql r verify",
        "mirql r probe",
        "mirql r bing-bong",
        "mirql r phi",
        "mirql r drift",
        "mirql r mutant",
        "mirql r flake",
        "mirql r doctor",
        "mirql r journey",
        "mirql q tick",
        "mirql q submit",
        "mirql q status",
        "mirql q promote",
        "mirql q halt",
        "mirql q resume",
        "mirql l append",
        "mirql l view",
        "mirql l replay",
        "mirql l verify",
        "mirql l snapshot"
      ];
      assert.deepEqual(parsed.commands, expectedCommands);
      assert.deepEqual(parsed.schemas, [
        "event/v1",
        "warrant/v1",
        "job/v1",
        "outcome/v1"
      ]);
      assert.deepEqual(parsed.dependencies, []);
    });
  });

  describe("2. Policy Files", () => {
    it("policy/mirql.json has valid values, zero floats, and critic tier mapping", () => {
      const policyPath = join(ROOT, "policy/mirql.json");
      assert.ok(existsSync(policyPath), "policy/mirql.json must exist");
      const parsed = JSON.parse(readFileSync(policyPath, "utf8"));

      assertSafeIntegersOnly(parsed, "policy/mirql.json");

      assert.equal(parsed.daily_budget_micro_usd, 25000000);
      assert.equal(parsed.per_job_budget_micro_usd, 1500000);
      assert.deepEqual(parsed.ladder, ["flash", "mid", "max", "human"]);
      assert.equal(parsed.critic, "claude-opus-5-5-medium");
      assert.equal(parsed.retries_per_tier, 2);
      assert.equal(parsed.max_awaiting_human, 3);
      assert.equal(parsed.lease_ttl_ms, 900000);
      assert.equal(parsed.refactor_cooldown_ms, 172800000);
      assert.deepEqual(parsed.macro_states, [
        "BUILD",
        "HARDEN",
        "PATROL",
        "QUIESCENT"
      ]);
      assert.equal(parsed.quiescent_max_budget_bp, 500);
    });

    it("policy/paths.yaml lists humanOnly and humanApprove paths", () => {
      const pathsFile = join(ROOT, "policy/paths.yaml");
      assert.ok(existsSync(pathsFile), "policy/paths.yaml must exist");
      const content = readFileSync(pathsFile, "utf8");

      assert.ok(content.includes("humanOnly:"));
      assert.ok(content.includes("CONSTITUTION.md"));
      assert.ok(content.includes("NOT-ROADMAP.md"));
      assert.ok(content.includes("policy/**"));
      assert.ok(content.includes("conformance/**"));
      assert.ok(content.includes(".github/**"));

      assert.ok(content.includes("humanApprove:"));
      assert.ok(content.includes("schemas/**"));
      assert.ok(content.includes("packages/core/**"));
      assert.ok(content.includes("packages/log/**"));
      assert.ok(content.includes("packages/queue/**"));
      assert.ok(content.includes("packages/run/verify*"));
      assert.ok(content.includes("package.json"));
    });

    it("policy/writers.yaml maps all authorized namespaces to event regex", () => {
      const writersFile = join(ROOT, "policy/writers.yaml");
      assert.ok(existsSync(writersFile), "policy/writers.yaml must exist");
      const content = readFileSync(writersFile, "utf8");

      const expectedWriters = [
        "tool:queue",
        "tool:run_supervisor",
        "tool:log",
        "tool:inbox",
        "human:owner",
        "notary:mergeproof",
        "daemon:lifeguard"
      ];
      for (const w of expectedWriters) {
        assert.ok(
          content.includes(w),
          `policy/writers.yaml must configure namespace "${w}"`
        );
      }
    });

    it("policy/probes.toml defines declarative probes with integer thresholds", () => {
      const probesFile = join(ROOT, "policy/probes.toml");
      assert.ok(existsSync(probesFile), "policy/probes.toml must exist");
      const content = readFileSync(probesFile, "utf8");

      assert.ok(content.includes("[probes.tests]"));
      assert.ok(content.includes("[probes.drift]"));
      assert.ok(content.includes("[probes.mutants]"));
      assert.ok(content.includes("[probes.complexity]"));
      assert.ok(content.includes("[probes.surface]"));
    });
  });

  describe("3. Role Roster (11 Shipped Roles)", () => {
    const expectedRoles = [
      { name: "orchestrator", tier: "max", authority: "A" },
      { name: "builder", tier: "mid", authority: "B" },
      { name: "critic", tier: "critic", authority: "C" },
      { name: "proposer", tier: "max", authority: "A" },
      { name: "doctor", tier: "max", authority: "B" },
      { name: "scout-bugs", tier: "flash", authority: "C" },
      { name: "scout-drift", tier: "flash", authority: "C" },
      { name: "scout-mutants", tier: "mid", authority: "C" },
      { name: "scout-journey", tier: "flash", authority: "C" },
      { name: "consolidator", tier: "mid", authority: "B" },
      { name: "bing-bong", tier: "max", authority: "A" }
    ];

    it("all 11 role files exist in roles/ directory", () => {
      const rolesDir = join(ROOT, "roles");
      assert.ok(existsSync(rolesDir), "roles/ directory must exist");
      const files = readdirSync(rolesDir).filter((f) => f.endsWith(".md"));
      assert.equal(files.length, 11, "Exactly 11 role files must exist");
    });

    for (const exp of expectedRoles) {
      it(`role "${exp.name}" has valid frontmatter, mission, and contracts`, () => {
        const filePath = join(ROOT, "roles", `${exp.name}.md`);
        assert.ok(existsSync(filePath), `${exp.name}.md must exist`);
        const content = readFileSync(filePath, "utf8");

        const fm = parseFrontmatter(content);
        assert.ok(fm, `${exp.name}.md must have valid YAML frontmatter`);
        assert.equal(fm.role, exp.name);
        assert.equal(fm.tier, exp.tier);
        assert.equal(fm.authority, exp.authority);
        assert.ok(fm.emits, `${exp.name}.md must define emitted event types`);

        assert.ok(
          content.includes("## Mission"),
          `${exp.name}.md must contain "## Mission"`
        );
        assert.ok(
          content.includes("## Input Contract"),
          `${exp.name}.md must contain "## Input Contract"`
        );
        assert.ok(
          content.includes("## Output Contract"),
          `${exp.name}.md must contain "## Output Contract"`
        );
      });
    }

    it("role bing-bong specifies consensus critique packet and escalation contract", () => {
      const filePath = join(ROOT, "roles/bing-bong.md");
      const content = readFileSync(filePath, "utf8");
      const fm = parseFrontmatter(content);

      assert.equal(fm.role, "bing-bong");
      assert.equal(fm.tier, "max");
      assert.equal(fm.writes, "none");
      assert.equal(fm.mutates_worktree, "false");
      assert.ok(fm.reads && fm.reads.includes("warrant"));

      assert.ok(content.includes("verdict"));
      assert.ok(content.includes("CONVERGED"));
      assert.ok(content.includes("DISAGREE"));
      assert.ok(content.includes("blocking_objections"));
      assert.ok(content.includes("proposed_amendments"));
      assert.ok(content.includes("warrant_patch"));
      assert.ok(content.includes("NEEDS_HUMAN"));
      assert.ok(content.includes("10"));
    });
  });

  describe("4. Conformance Corpus: Golden Ledger & State", () => {
    it("conformance/golden_ledger/events.jsonl has sequential seq, cryptographic hash linkage, and authorized writers", () => {
      const eventsPath = join(ROOT, "conformance/golden_ledger/events.jsonl");
      assert.ok(existsSync(eventsPath), "events.jsonl must exist");
      const rawFile = readFileSync(eventsPath, "utf8").trim();
      const lines = rawFile.split(/\r?\n/).filter(Boolean);

      assert.equal(lines.length, 5, "Must contain exactly 5 deterministic events");

      const events = lines.map((l, i) => {
        const parsed = JSON.parse(l);
        assertSafeIntegersOnly(parsed, `events[${i}]`);
        return parsed;
      });

      // 1. Sequential seq check
      for (let i = 0; i < events.length; i++) {
        assert.equal(events[i].seq, i + 1, `Event at line ${i + 1} must have seq ${i + 1}`);
      }

      // 2. Cryptographic prev_hash linkage check
      const anchorHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
      assert.equal(events[0].prev_hash, anchorHash, "Line 1 must anchor at 64 zeros");

      for (let i = 1; i < lines.length; i++) {
        const prevRaw = lines[i - 1];
        const expectedPrevHash = "sha256:" + createHash("sha256").update(prevRaw, "utf8").digest("hex");
        assert.equal(
          events[i].prev_hash,
          expectedPrevHash,
          `Event seq ${events[i].seq} prev_hash must cryptographically match sha256 of line ${i}`
        );
      }

      // 3. Writer authorization check against policy/writers.yaml
      const writersYaml = readFileSync(join(ROOT, "policy/writers.yaml"), "utf8");
      const writerRules = parseWritersYaml(writersYaml);

      for (const evt of events) {
        const regex = writerRules[evt.writer];
        assert.ok(
          regex,
          `Writer "${evt.writer}" must be defined in policy/writers.yaml`
        );
        assert.ok(
          regex.test(evt.type),
          `Writer "${evt.writer}" is not authorized for event type "${evt.type}" under rule: ${regex}`
        );
      }

      const types = events.map((e) => e.type);
      assert.deepEqual(types, [
        "mirql.genesis",
        "human.intent",
        "warrant.created",
        "job.leased",
        "attempt.outcome"
      ]);
    });

    it("expected_state.json contains safe integers and matches pure fold over events.jsonl", () => {
      const eventsPath = join(ROOT, "conformance/golden_ledger/events.jsonl");
      const statePath = join(ROOT, "conformance/golden_ledger/expected_state.json");
      assert.ok(existsSync(statePath), "expected_state.json must exist");

      const expectedState = JSON.parse(readFileSync(statePath, "utf8"));
      assertSafeIntegersOnly(expectedState, "expected_state.json");

      assert.equal(expectedState.epoch, 1);
      assert.equal(expectedState.macro_state, "BUILD");
      assert.equal(expectedState.metrics.warrants_completed, 1);
      assert.equal(expectedState.metrics.jobs_completed, 1);

      const events = readFileSync(eventsPath, "utf8")
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .map((l) => JSON.parse(l));

      const reducedState = reduceEvents(events);
      assert.deepEqual(
        reducedState,
        expectedState,
        "Pure event fold must match expected_state.json exactly"
      );
    });
  });

  describe("5. Conformance Corpus: Bad PRs & Good PRs", () => {
    const badPrFixtures = [
      {
        file: "01-touch-human-only.json",
        rule: "MP-001",
        verdict: "reject",
        violation: "TOUCH_HUMAN_ONLY"
      },
      {
        file: "02-delete-test.json",
        rule: "MP-002",
        verdict: "reject",
        violation: "TEST_DELETED"
      },
      {
        file: "03-swallow-exception.json",
        rule: "MP-003",
        verdict: "reject",
        violation: "ANTI_CHEAT_VIOLATION"
      },
      {
        file: "04-stale-base.json",
        rule: "MP-004",
        verdict: "reject",
        violation: "STALE_BASE"
      },
      {
        file: "05-uncited-surface.json",
        rule: "MP-005",
        verdict: "needs_human",
        violation: "UNCITED_SURFACE"
      }
    ];

    for (const b of badPrFixtures) {
      it(`bad PR fixture ${b.file} verifies violation ${b.violation} under rule ${b.rule}`, () => {
        const filePath = join(ROOT, "conformance/bad_prs", b.file);
        assert.ok(existsSync(filePath), `${b.file} must exist`);
        const parsed = JSON.parse(readFileSync(filePath, "utf8"));

        assertSafeIntegersOnly(parsed, b.file);
        assert.equal(parsed.expected_verdict, b.verdict);
        assert.equal(parsed.expected_rule, b.rule);
        assert.equal(parsed.evidence.violation_type, b.violation);

        if (b.rule === "MP-001") {
          assert.ok(
            parsed.evidence.forbidden_paths_touched.length > 0,
            "Must indicate forbidden paths"
          );
        } else if (b.rule === "MP-002") {
          assert.ok(
            parsed.evidence.test_count_drop > 0 ||
              parsed.evidence.tests_deleted.length > 0,
            "Must report deleted tests or drop"
          );
        } else if (b.rule === "MP-003") {
          assert.ok(
            parsed.anti_cheat.violations_count > 0,
            "Must flag anti-cheat violations"
          );
        } else if (b.rule === "MP-004") {
          assert.notEqual(
            parsed.evidence.claimed_base_sha,
            parsed.evidence.current_tip_sha,
            "Base SHA must not match tip SHA"
          );
        } else if (b.rule === "MP-005") {
          assert.ok(
            parsed.surface.uncited_commands.length > 0,
            "Must report uncited surface commands"
          );
        }
      });
    }

    const goodPrFixtures = [
      {
        file: "01-valid-repro-fix.json",
        kind: "bugfix",
        check: (data) => {
          assert.equal(data.proof.causal_cycle_completed, true);
          assert.ok(data.proof.base_fail_runs >= 2);
          assert.ok(data.proof.head_pass_runs >= 3);
          assert.ok(data.proof.re_red_runs >= 2);
          assert.equal(data.anti_cheat.violations_count, 0);
          assert.ok(data.phi.delta_phi <= 0);
        }
      },
      {
        file: "02-valid-consolidate-phi-drop.json",
        kind: "refactor",
        check: (data) => {
          assert.equal(data.proof.suite_pass_base, true);
          assert.equal(data.proof.suite_pass_head, true);
          assert.equal(data.proof.cases_dropped, 0);
          assert.equal(data.anti_cheat.violations_count, 0);
          assert.ok(data.phi.delta_phi < 0, "Consolidation must strictly reduce phi");
          assert.equal(data.phi.thrift_test_passed, true);
        }
      }
    ];

    for (const g of goodPrFixtures) {
      it(`good PR fixture ${g.file} demonstrates clean proof and auto_merge verdict`, () => {
        const filePath = join(ROOT, "conformance/good_prs", g.file);
        assert.ok(existsSync(filePath), `${g.file} must exist`);
        const parsed = JSON.parse(readFileSync(filePath, "utf8"));

        assertSafeIntegersOnly(parsed, g.file);
        assert.equal(parsed.expected_verdict, "auto_merge");
        assert.equal(parsed.pr.kind, g.kind);
        assert.deepEqual(parsed.evidence.forbidden_paths_touched, []);
        assert.deepEqual(parsed.evidence.tests_deleted, []);
        assert.equal(parsed.anti_cheat.violations_count, 0);

        g.check(parsed);
      });
    }
  });
});
