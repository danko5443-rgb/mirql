// tests/topology.test.mjs — Production Topology, Containerization & Sidecar Gates.
// Verifies Dockerfiles, Compose network isolation, LLM Gateway budgeting (Law 1 & 17), and Lifeguard (Law 2).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createLlmGateway,
  WarrantBudgetManager,
  calculateTokenCostMicroUsd,
  DEFAULT_MODEL_PRICING,
  GATEWAY_CODES,
  MIN_CALL_COST_MICRO_USD,
  isSafeNonNegativeInteger,
  timingSafeCompare,
  LifeguardWatchdog,
  checkProbationStatus,
  killProcesses,
  killServices,
  executeRollback,
  validateServiceUnit,
  renderLauncherUnit,
  MANDATORY_SANDBOX_DIRECTIVES,
} from "../packages/daemons/index.mjs";
import { touchHeartbeat, runSupervisor, startHeartbeatTicker } from "../packages/run/index.mjs";

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
    it("deploy/compose.yaml specifies internal networks, agent reachability to gateway, and no egress for agent", () => {
      const composePath = join(ROOT, "deploy", "compose.yaml");
      assert.ok(existsSync(composePath), "deploy/compose.yaml must exist");
      const yaml = readFileSync(composePath, "utf8");

      // Verify internal networks
      assert.match(yaml, /control-net:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+internal:\s*true/m);
      assert.match(yaml, /agent-net:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+internal:\s*true/m);
      assert.match(yaml, /gateway-net:\s*[\r\n]+(?:\s+.*[\r\n]+)*?\s+internal:\s*true/m);

      // Verify llm-gateway is on agent-net so agent can reach http://llm-gateway:8080
      assert.match(yaml, /llm-gateway:[\s\S]*?networks:[\s\S]*?-\s*agent-net/m, "llm-gateway must be on agent-net for agent reachability");

      // Verify agent is NOT on egress-net or control-net
      const agentBlock = yaml.match(/agent:\s*[\r\n]+([\s\S]*?)(?=\n\s*[a-z0-9_-]+:|$)/i)?.[1] || "";
      assert.doesNotMatch(agentBlock, /egress-net/, "agent must not have egress network");
      assert.doesNotMatch(agentBlock, /control-net/, "agent must not be on control-net");

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

    it("timingSafeCompare compares strings in constant time and rejects invalid inputs safely", () => {
      assert.equal(timingSafeCompare("secret-token-12345", "secret-token-12345"), true);
      assert.equal(timingSafeCompare("secret-token-12345", "secret-token-wrong"), false);
      assert.equal(timingSafeCompare("short", "longer-token-123"), false);
      assert.equal(timingSafeCompare(null, "token"), false);
      assert.equal(timingSafeCompare("token", undefined), false);
    });

    it("HTTP LLM Gateway enforces min 32-char admin token, constant-time auth, protected warrant lookup, and clamps max_tokens", async () => {
      const adminSecret = "a".repeat(32); // 32 characters
      const gateway = await createLlmGateway({ port: 0, adminToken: adminSecret });
      try {
        const baseUrl = `http://127.0.0.1:${gateway.port}`;
        const warrantId = "01WARRANTPROTECTTEST0000000";

        // Preauth with valid admin token
        const preauthRes = await fetch(`${baseUrl}/v1/warrant/preauth`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${adminSecret}`,
          },
          body: JSON.stringify({
            warrant_id: warrantId,
            budget_micro_usd: 10_000,
          }),
        });
        assert.equal(preauthRes.status, 200);

        // Protected warrant lookup: unauthenticated access rejected with 403 Forbidden
        const unauthLookup = await fetch(`${baseUrl}/v1/warrant/${warrantId}`);
        assert.equal(unauthLookup.status, 403);

        // Access with wrong warrant header is 403 Forbidden
        const wrongLookup = await fetch(`${baseUrl}/v1/warrant/${warrantId}`, {
          headers: { "x-mirql-warrant-id": "wrong-warrant-id" },
        });
        assert.equal(wrongLookup.status, 403);

        // Access with matching warrant header succeeds
        const holderLookup = await fetch(`${baseUrl}/v1/warrant/${warrantId}`, {
          headers: { "x-mirql-warrant-id": warrantId },
        });
        assert.equal(holderLookup.status, 200);
        const holderData = await holderLookup.json();
        assert.equal(holderData.warrant_id, warrantId);

        // Access with admin token succeeds
        const adminLookup = await fetch(`${baseUrl}/v1/warrant/${warrantId}`, {
          headers: { "Authorization": `Bearer ${adminSecret}` },
        });
        assert.equal(adminLookup.status, 200);

        // Omitted max_tokens is automatically clamped to 256
        const completionRes = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-mirql-warrant-id": warrantId,
          },
          body: JSON.stringify({ prompt: "hello, world" }), // omitted max_tokens
        });
        assert.equal(completionRes.status, 200);
        const completionData = await completionRes.json();
        assert.ok(completionData.usage.completion_tokens <= 256);
      } finally {
        await gateway.close();
      }
    });

    it("HTTP LLM Gateway enforces admin auth on preauth/settle, prevents zero-cost bypass, and handles bad inputs safely", async () => {
      const adminToken = "test-admin-token-123-at-least-32-chars-long";
      const gateway = await createLlmGateway({ port: 0, adminToken });
      try {
        const baseUrl = `http://127.0.0.1:${gateway.port}`;

        // 1. Health endpoint
        const healthRes = await fetch(`${baseUrl}/health`);
        assert.equal(healthRes.status, 200);
        const healthData = await healthRes.json();
        assert.equal(healthData.ok, true);

        // 2. Preauth WITHOUT admin token is rejected with 401
        const unauthPreauth = await fetch(`${baseUrl}/v1/warrant/preauth`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ warrant_id: "01W1", budget_micro_usd: 1000 }),
        });
        assert.equal(unauthPreauth.status, 401);

        // 3. Preauth WITH admin token succeeds
        const warrantId = "01HGWTEST00000000000000000";
        const preauthRes = await fetch(`${baseUrl}/v1/warrant/preauth`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${adminToken}`,
          },
          body: JSON.stringify({
            warrant_id: warrantId,
            budget_micro_usd: 500, // Small budget of 500 micro_usd
            epoch: 1,
          }),
        });
        assert.equal(preauthRes.status, 200);
        const preauthData = await preauthRes.json();
        assert.equal(preauthData.remaining_micro_usd, 500);

        // 4. Request without warrant ID returns 403
        const unauthRes = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt: "hello" }),
        });
        assert.equal(unauthRes.status, 403);

        // 5. Zero-cost bypass prevention: caller CANNOT supply zero cost to bypass metering
        // Gateway calculates cost server-side with MIN_CALL_COST_MICRO_USD floor
        const call1Res = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-mirql-warrant-id": warrantId,
            "x-mirql-cost-micro-usd": "0", // Malicious caller attempts 0-cost bypass!
          },
          body: JSON.stringify({ prompt: "test prompt", max_tokens: 50 }),
        });
        assert.equal(call1Res.status, 200);
        const rem1 = parseInt(call1Res.headers.get("x-mirql-budget-remaining"), 10);
        assert.ok(rem1 < 500, "Must have charged server-calculated cost despite caller 0-cost header");

        // 6. Bad input (max_tokens: 1.5) returns 400 and DOES NOT crash process
        const badTokenRes = await fetch(`${baseUrl}/v1/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-mirql-warrant-id": warrantId,
          },
          body: JSON.stringify({ prompt: "test", max_tokens: 1.5 }),
        });
        assert.equal(badTokenRes.status, 400);

        // Gateway remains alive and healthy after bad request
        const healthCheck = await fetch(`${baseUrl}/health`);
        assert.equal(healthCheck.status, 200);

        // 7. Exhaust remaining budget
        let exhausted = false;
        for (let i = 0; i < 5; i++) {
          const res = await fetch(`${baseUrl}/v1/chat/completions`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-mirql-warrant-id": warrantId,
            },
            body: JSON.stringify({ prompt: "consume budget", max_tokens: 200 }),
          });
          if (res.status === 402) {
            exhausted = true;
            const data = await res.json();
            assert.equal(data.error, "BUDGET_EXHAUSTED");
            assert.equal(data.code, GATEWAY_CODES.BUDGET_EXHAUSTED);
            break;
          }
        }
        assert.equal(exhausted, true, "Must have tripped 402 BUDGET_EXHAUSTED");

        // 8. Settle warrant with admin token
        const settleRes = await fetch(`${baseUrl}/v1/warrant/settle`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${adminToken}`,
          },
          body: JSON.stringify({ warrant_id: warrantId }),
        });
        assert.equal(settleRes.status, 200);
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

    it("LifeguardWatchdog executes kill and rollback on timeout expiration (Law 2)", () => {
      const tmp = mkdtempSync(join(tmpdir(), "mirql-lifeguard-test-"));
      try {
        const baseFile = join(tmp, "base_sha");
        writeFileSync(baseFile, "test-target-base-sha-123", "utf8");

        const watchdog = new LifeguardWatchdog({
          repoDir: tmp,
          baseShaFile: baseFile,
          timeoutMs: 1000,
          startTimeMs: Date.now() - 2000, // Started 2s ago, timeout 1s -> already expired!
        });

        const checkRes = watchdog.check();
        assert.equal(checkRes.ok, false);
        assert.equal(checkRes.tripped, true);
        assert.equal(checkRes.reason, "PROBATION_TIMEOUT_EXPIRED");

        // Disarm prevents further trips
        watchdog.disarm();
        assert.equal(watchdog.check().ok, true);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    });

    it("LifeguardWatchdog tracks heartbeat file mtime and trips when heartbeat goes stale", () => {
      const tmp = mkdtempSync(join(tmpdir(), "mirql-lifeguard-hb-"));
      try {
        const hbFile = join(tmp, "heartbeat");
        writeFileSync(hbFile, "alive", "utf8");

        const watchdog = new LifeguardWatchdog({
          repoDir: tmp,
          heartbeatFile: hbFile,
          timeoutMs: 60_000,
          heartbeatTimeoutMs: 500, // 500ms heartbeat timeout
          startTimeMs: Date.now(),
        });

        // Fresh check succeeds
        const c1 = watchdog.check();
        assert.equal(c1.ok, true);

        // Check after heartbeat timeout (600ms in the past) trips
        const c2 = watchdog.check(Date.now() + 600);
        assert.equal(c2.ok, false);
        assert.equal(c2.tripped, true);
        assert.equal(c2.reason, "HEARTBEAT_TIMEOUT_EXPIRED");
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    });

    it("supervisor automatically writes heartbeat and launcher.pid, and lifeguard disarms via disarmFile", () => {
      const tmp = mkdtempSync(join(tmpdir(), "mirql-supervisor-hb-"));
      try {
        const mirqlDir = join(tmp, ".mirql");
        const hbFile = join(mirqlDir, "state", "heartbeat");
        const pidFile = join(mirqlDir, "state", "launcher.pid");
        const disarmFile = join(tmp, "disarm"); // outside mirqlDir (operator controlled)

        // Touch heartbeat directly
        touchHeartbeat(mirqlDir);
        assert.ok(existsSync(hbFile), "Heartbeat file must be created by touchHeartbeat");

        // Run supervisor writes heartbeat and launcher.pid, then cleans up pid on exit
        runSupervisor({
          mirqlDir,
          workspaceDir: tmp,
          warrantId: "01HGWTEST00000000000000000",
          verifyOptions: { workspaceDir: tmp },
          agentOptions: { command: "echo ok" },
          noHeartbeatTicker: true,
        });

        assert.ok(existsSync(hbFile), "Heartbeat file must exist after supervisor run");

        // When launcher PID file does NOT exist (idle between runs), heartbeat timeout does NOT falsely trip
        const idleWatchdog = new LifeguardWatchdog({
          repoDir: tmp,
          heartbeatFile: hbFile,
          killPidFiles: [pidFile],
          disarmFile,
          timeoutMs: 60_000,
          heartbeatTimeoutMs: 100,
          startTimeMs: Date.now() - 500,
        });
        assert.equal(idleWatchdog.check().ok, true, "Idle factory must not trip heartbeat timeout");

        // When launcher PID file exists (active run) and heartbeat is stale, watchdog trips
        // (Use dummy PID 999999 so watchdog does not SIGKILL the test runner process itself!)
        writeFileSync(pidFile, "999999\n", "utf8");
        const activeStaleWatchdog = new LifeguardWatchdog({
          repoDir: tmp,
          heartbeatFile: hbFile,
          killPidFiles: [pidFile],
          disarmFile,
          targetBaseSha: "test-target-sha",
          timeoutMs: 60_000,
          heartbeatTimeoutMs: 100,
          startTimeMs: Date.now() - 500,
        });
        const staleRes = activeStaleWatchdog.check(Date.now() + 200);
        assert.equal(staleRes.ok, false);
        assert.equal(staleRes.tripped, true);
        assert.equal(staleRes.reason, "HEARTBEAT_TIMEOUT_EXPIRED");

        // Creating matching disarm file disarms watchdog
        writeFileSync(disarmFile, "test-target-sha", "utf8");
        const disarmCheck = activeStaleWatchdog.check();
        assert.equal(disarmCheck.ok, true);
        assert.equal(disarmCheck.disarmed, true);
        assert.equal(activeStaleWatchdog.disarmed, true);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    });

    it("startHeartbeatTicker keeps refreshing heartbeat file continuously", async () => {
      const tmp = mkdtempSync(join(tmpdir(), "mirql-ticker-hb-"));
      try {
        const hbFile = join(tmp, "heartbeat");
        writeFileSync(hbFile, "0", "utf8");
        const ticker = startHeartbeatTicker(hbFile, 50);
        assert.ok(ticker);
        try {
          let content = "0";
          const start = Date.now();
          while (Date.now() - start < 3000) {
            await new Promise((done) => setTimeout(done, 50));
            content = readFileSync(hbFile, "utf8").trim();
            if (parseInt(content, 10) > 0) break;
          }
          assert.ok(parseInt(content, 10) > 0, "Heartbeat file must be refreshed by ticker");
        } finally {
          ticker.kill();
        }
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    });

    it("killServices safely attempts service termination without throwing", () => {
      const res = killServices(["nonexistent-mirql-service.service"]);
      assert.ok(Array.isArray(res.killed));
      assert.ok(Array.isArray(res.failed));
    });

    it("validateServiceUnit passes on BOTH deploy/systemd service units with no root permissions", () => {
      for (const unitName of ["mirql-launcher.service", "mirql-lifeguard.service"]) {
        const unitPath = join(ROOT, "deploy", "systemd", unitName);
        assert.ok(existsSync(unitPath), `${unitName} must exist`);
        const content = readFileSync(unitPath, "utf8");

        const res = validateServiceUnit(content);
        assert.equal(res.ok, true, `${unitName} validation failed: ${res.errors.join(", ")} missing: ${res.missing.join(", ")}`);
        assert.deepEqual(res.missing, []);
        assert.deepEqual(res.errors, []);
      }
    });

    it("validateServiceUnit strictly rejects units running as root", () => {
      const insecureUnit = `
[Unit]
Description=insecure

[Service]
User=root
ExecStart=/bin/mirql r supervisor
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
      `;
      const res = validateServiceUnit(insecureUnit);
      assert.equal(res.ok, false);
      assert.ok(res.errors.includes("Service unit must not run as root User"));
    });

    it("renderLauncherUnit renders compliant systemd unit and rejects newline injections", () => {
      const unit = renderLauncherUnit({ workingDir: "/opt/mirql", user: "mirql" });
      const res = validateServiceUnit(unit);
      assert.equal(res.ok, true);

      // Rejects newline injection attempt
      assert.throws(() => renderLauncherUnit({ user: "mirql\nUser=root" }), /newline/);
      assert.throws(() => renderLauncherUnit({ user: "root" }), /root/);
    });
  });
});
