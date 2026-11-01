// tests/topology.test.mjs — Production Topology, Containerization & Sidecar Gates.
// Verifies Dockerfiles, Compose network isolation, LLM Gateway budgeting (Law 1 & 17), and Lifeguard (Law 2).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createLlmGateway,
  WarrantBudgetManager,
  calculateTokenCostMicroUsd,
  DEFAULT_MODEL_PRICING,
  GATEWAY_CODES,
  isSafeNonNegativeInteger,
  LifeguardWatchdog,
  checkProbationStatus,
  validateServiceUnit,
  renderLauncherUnit,
  MANDATORY_SANDBOX_DIRECTIVES,
} from "../packages/daemons/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

describe("Production Containerization & Topology Gates", () => {
  // -------------------------------------------------------------------------
  // 1. Dockerfile Security & Zero-Dependency Specifications
  // -------------------------------------------------------------------------
  describe("1. Dockerfiles Security & Isolation", () => {
    it("Dockerfile.control specifies non-root user, read-only paths, and zero npm install", () => {
      const dockerfilePath = join(ROOT, "deploy", "Dockerfile.control");
      assert.ok(existsSync(dockerfilePath), "deploy/Dockerfile.control must exist");
      const content = readFileSync(dockerfilePath, "utf8");

      assert.match(content, /FROM\s+node:22/i, "Must use Node 22 base");
      assert.match(content, /USER\s+1000/i, "Must run as unprivileged UID 1000");
      assert.doesNotMatch(content, /npm\s+install/i, "Must strictly obey zero-dependency law (no npm install)");
      assert.match(content, /ENTRYPOINT\s+\[.*node.*bin\/mirql\.mjs.*\]/i, "Must invoke bin/mirql.mjs");
    });

    it("Dockerfile.agent specifies unprivileged user, isolated workspace, and no secrets", () => {
      const dockerfilePath = join(ROOT, "deploy", "Dockerfile.agent");
      assert.ok(existsSync(dockerfilePath), "deploy/Dockerfile.agent must exist");
      const content = readFileSync(dockerfilePath, "utf8");

      assert.match(content, /USER\s+1001/i, "Must run as unprivileged agent UID 1001");
      assert.match(content, /WORKDIR\s+\/workspace/i, "Must operate in /workspace");
      assert.doesNotMatch(content, /npm\s+install/i, "No npm install");
      assert.doesNotMatch(content, /keys/i, "Must not copy private keys");
    });

    it("Dockerfile.verify specifies unprivileged user and verification entrypoint", () => {
      const dockerfilePath = join(ROOT, "deploy", "Dockerfile.verify");
      assert.ok(existsSync(dockerfilePath), "deploy/Dockerfile.verify must exist");
      const content = readFileSync(dockerfilePath, "utf8");

      assert.match(content, /USER\s+1002/i, "Must run as unprivileged verify UID 1002");
      assert.match(content, /ENTRYPOINT\s+\[.*node.*bin\/mirql-run\.mjs.*verify.*\]/i, "Must invoke verify entrypoint");
    });

    it("Dockerfile.gateway specifies unprivileged gateway user and exposes port 8080", () => {
      const dockerfilePath = join(ROOT, "deploy", "Dockerfile.gateway");
      assert.ok(existsSync(dockerfilePath), "deploy/Dockerfile.gateway must exist");
      const content = readFileSync(dockerfilePath, "utf8");

      assert.match(content, /USER\s+1003/i, "Must run as unprivileged gateway UID 1003");
      assert.match(content, /EXPOSE\s+8080/i, "Must expose port 8080");
    });
  });

  // -------------------------------------------------------------------------
  // 2. Compose Network & Privilege Isolation
  // -------------------------------------------------------------------------
  describe("2. Docker Compose Network Isolation (Law 1)", () => {
    it("deploy/compose.yaml specifies internal networks and no egress for agent", () => {
      const composePath = join(ROOT, "deploy", "compose.yaml");
      assert.ok(existsSync(composePath), "deploy/compose.yaml must exist");
      const yaml = readFileSync(composePath, "utf8");

      // Verify internal networks
      assert.match(yaml, /control-net:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+internal:\s*true/m);
      assert.match(yaml, /agent-net:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+internal:\s*true/m);
      assert.match(yaml, /gateway-net:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+internal:\s*true/m);

      // Verify verify service has network_mode: "none"
      assert.match(yaml, /verify:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+network_mode:\s*["']none["']/m);

      // Verify agent has cap_drop: ALL and no-new-privileges
      assert.match(yaml, /agent:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+cap_drop:\s*[\r\n]+\s+-\s*ALL/m);
      assert.match(yaml, /agent:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+security_opt:\s*[\r\n]+\s+-\s*no-new-privileges:true/m);
    });

    it("root docker-compose.yml forwarder exists and points to deploy/compose.yaml", () => {
      const rootCompose = join(ROOT, "docker-compose.yml");
      assert.ok(existsSync(rootCompose), "root docker-compose.yml must exist");
      const content = readFileSync(rootCompose, "utf8");
      assert.match(content, /deploy\/compose\.yaml/, "Must reference deploy/compose.yaml");
    });
  });

  // -------------------------------------------------------------------------
  // 3. LLM Gateway & Integer Budget Metering (Law 1 & 17)
  // -------------------------------------------------------------------------
  describe("3. LLM Gateway Integer Budget Metering", () => {
    it("isSafeNonNegativeInteger validates safe integers and rejects floats / negatives / -0", () => {
      assert.equal(isSafeNonNegativeInteger(0), true);
      assert.equal(isSafeNonNegativeInteger(1000), true);
      assert.equal(isSafeNonNegativeInteger(Number.MAX_SAFE_INTEGER), true);

      assert.equal(isSafeNonNegativeInteger(-1), false);
      assert.equal(isSafeNonNegativeInteger(10.5), false);
      assert.equal(isSafeNonNegativeInteger(NaN), false);
      assert.equal(isSafeNonNegativeInteger(Infinity), false);
      assert.equal(isSafeNonNegativeInteger("1000"), false);
      assert.equal(isSafeNonNegativeInteger(-0), false, "-0 must be rejected");
    });

    it("calculateTokenCostMicroUsd calculates integer costs without floating point math", () => {
      const pricing = DEFAULT_MODEL_PRICING["workhorse"]; // input: 300,000 / M, output: 1,200,000 / M
      const cost = calculateTokenCostMicroUsd(1000, 200, pricing);
      // prompt: floor(1000 * 300_000 / 1_000_000) = 300 micro_usd
      // completion: floor(200 * 1_200_000 / 1_000_000) = 240 micro_usd
      // total: 540 micro_usd
      assert.equal(cost, 540);
      assert.equal(Number.isSafeInteger(cost), true);

      // Rejects float inputs
      assert.throws(() => calculateTokenCostMicroUsd(10.5, 20, pricing), TypeError);
    });

    it("WarrantBudgetManager manages preauth, deduction, and exhaustion", () => {
      const mgr = new WarrantBudgetManager();
      const warrantId = "01HWARRANTAAAAAAAAAAAAAAAAA";

      // Preauth 50,000 micro_usd ($0.05)
      const entry = mgr.preauth(warrantId, 50_000, 1);
      assert.equal(entry.budget_micro_usd, 50_000);
      assert.equal(entry.remaining_micro_usd, 50_000);
      assert.equal(entry.spent_micro_usd, 0);

      // Deduct 20,000 micro_usd
      const d1 = mgr.deduct(warrantId, 20_000);
      assert.equal(d1.allowed, true);
      assert.equal(d1.remaining_micro_usd, 30_000);
      assert.equal(d1.spent_micro_usd, 20_000);

      // Deduct another 30,000 micro_usd (remaining reaches 0)
      const d2 = mgr.deduct(warrantId, 30_000);
      assert.equal(d2.allowed, true);
      assert.equal(d2.remaining_micro_usd, 0);

      // Further deduction is blocked with BUDGET_EXHAUSTED
      const d3 = mgr.deduct(warrantId, 1);
      assert.equal(d3.allowed, false);
      assert.equal(d3.reason, "BUDGET_EXHAUSTED");

      // Settlement
      const receipt = mgr.settle(warrantId);
      assert.equal(receipt.spent_micro_usd, 50_000);
      assert.equal(receipt.refund_micro_usd, 0);
    });

    it("HTTP LLM Gateway rejects unauthorized requests, meters valid requests, and trips 402 on budget exhaustion", async () => {
      const gateway = await createLlmGateway({ port: 0 });
      try {
        const baseUrl = `http://127.0.0.1:${gateway.port}`;

        // 1. Health endpoint
        const healthRes = await fetch(`${baseUrl}/health`);
        assert.equal(healthRes.status, 200);
        const healthData = await healthRes.json();
        assert.equal(healthData.ok, true);

        // 2. Preauth a warrant lease with 5,000 micro_usd
        const warrantId = "01HGWTEST00000000000000000";
        const preauthRes = await fetch(`${baseUrl}/v1/warrant/preauth`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            warrant_id: warrantId,
            budget_micro_usd: 5_000,
            epoch: 1,
          }),
        });
        assert.equal(preauthRes.status, 200);
        const preauthData = await preauthRes.json();
        assert.equal(preauthData.remaining_micro_usd, 5_000);

        // 3. Request without warrant ID returns 403
        const unauthRes = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt: "hello" }),
        });
        assert.equal(unauthRes.status, 403);

        // 4. Request with valid warrant ID succeeds and meters budget
        const call1Res = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-mirql-warrant-id": warrantId,
            "x-mirql-cost-micro-usd": "2000",
          },
          body: JSON.stringify({ prompt: "test prompt" }),
        });
        assert.equal(call1Res.status, 200);
        assert.equal(call1Res.headers.get("x-mirql-budget-remaining"), "3000");

        // 5. Another call consuming 2,500 micro_usd
        const call2Res = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-mirql-warrant-id": warrantId,
            "x-mirql-cost-micro-usd": "2500",
          },
          body: JSON.stringify({ prompt: "test prompt 2" }),
        });
        assert.equal(call2Res.status, 200);
        assert.equal(call2Res.headers.get("x-mirql-budget-remaining"), "500");

        // 6. Third call requiring 1,000 micro_usd trips HTTP 402 BUDGET_EXHAUSTED
        const call3Res = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-mirql-warrant-id": warrantId,
            "x-mirql-cost-micro-usd": "1000",
          },
          body: JSON.stringify({ prompt: "test prompt 3" }),
        });
        assert.equal(call3Res.status, 402);
        const call3Data = await call3Res.json();
        assert.equal(call3Data.error, "BUDGET_EXHAUSTED");
        assert.equal(call3Data.code, GATEWAY_CODES.BUDGET_EXHAUSTED);
        assert.equal(call3Data.remaining_micro_usd, 500);

        // 7. Settle warrant and verify refund
        const settleRes = await fetch(`${baseUrl}/v1/warrant/settle`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ warrant_id: warrantId }),
        });
        assert.equal(settleRes.status, 200);
        const settleData = await settleRes.json();
        assert.equal(settleData.spent_micro_usd, 4_500);
        assert.equal(settleData.refund_micro_usd, 500);
      } finally {
        await gateway.close();
      }
    });
  });

  // -------------------------------------------------------------------------
  // 4. Lifeguard Watchdog & Systemd Security (Law 2)
  // -------------------------------------------------------------------------
  describe("4. Lifeguard & Systemd Security Sandboxing (Law 2)", () => {
    it("checkProbationStatus correctly measures elapsed window and trips on expiration", () => {
      const start = 1_000_000;
      const timeout = 1_800_000; // 30m

      // Within window (10m in)
      const s1 = checkProbationStatus({ startTimeMs: start, nowMs: start + 600_000, timeoutMs: timeout });
      assert.equal(s1.ok, true);
      assert.equal(s1.tripped, false);
      assert.equal(s1.elapsedMs, 600_000);
      assert.equal(s1.remainingMs, 1_200_000);

      // Expired (31m in)
      const s2 = checkProbationStatus({ startTimeMs: start, nowMs: start + 1_860_000, timeoutMs: timeout });
      assert.equal(s2.ok, false);
      assert.equal(s2.tripped, true);
      assert.equal(s2.remainingMs, 0);
    });

    it("LifeguardWatchdog disarms cleanly upon verified completion", () => {
      const watchdog = new LifeguardWatchdog({ timeoutMs: 1000 });
      assert.equal(watchdog.check().ok, true);
      watchdog.disarm();
      // Even if time expires, disarmed watchdog reports ok
      assert.equal(watchdog.check(Date.now() + 5000).ok, true);
    });

    it("validateServiceUnit passes on deploy/systemd/mirql-launcher.service", () => {
      const unitPath = join(ROOT, "deploy", "systemd", "mirql-launcher.service");
      assert.ok(existsSync(unitPath), "mirql-launcher.service must exist");
      const content = readFileSync(unitPath, "utf8");

      const res = validateServiceUnit(content);
      assert.equal(res.ok, true, `Validation failed: ${res.errors.join(", ")} missing: ${res.missing.join(", ")}`);
      assert.deepEqual(res.missing, []);
    });

    it("validateServiceUnit rejects units missing mandatory sandbox directives", () => {
      const insecureUnit = `
[Service]
User=root
ExecStart=/bin/sh -c "run"
      `;
      const res = validateServiceUnit(insecureUnit);
      assert.equal(res.ok, false);
      assert.ok(res.missing.includes("ProtectSystem"));
      assert.ok(res.missing.includes("NoNewPrivileges"));
      assert.ok(res.errors.includes("Service unit must not run as root User"));
    });

    it("renderLauncherUnit renders compliant systemd unit with all sandbox directives", () => {
      const unit = renderLauncherUnit({ workingDir: "/opt/mirql", user: "mirql" });
      const res = validateServiceUnit(unit);
      assert.equal(res.ok, true);
    });
  });
});
