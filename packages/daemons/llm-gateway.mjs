// packages/daemons/llm-gateway.mjs — Zero-dependency LLM Gateway sidecar.
// Enforces Law 1 (two-process privilege split) and Law 17 (integer-only micro_usd budget metering).

import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/** Canonical exit/error codes matching EXIT_CODES. */
export const GATEWAY_CODES = Object.freeze({
  OK: 0,
  DOMAIN_NEGATIVE: 1,
  USAGE_ERROR: 2,
  BUDGET_EXHAUSTED: 7,
});

/** Maximum allowable request body size (10 MB). */
export const MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024;

/** Minimum cost in micro_usd for any inference call (100 micro_usd floor). */
export const MIN_CALL_COST_MICRO_USD = 100;

/** Default model pricing in micro_usd per 1,000,000 tokens (all safe integers). */
export const DEFAULT_MODEL_PRICING = Object.freeze({
  "frontier-deep": { input_per_m: 3_000_000, output_per_m: 15_000_000 },
  "frontier-fast": { input_per_m: 1_000_000, output_per_m: 3_000_000 },
  "workhorse": { input_per_m: 300_000, output_per_m: 1_200_000 },
  "scout": { input_per_m: 50_000, output_per_m: 150_000 },
});

/**
 * Validates that a value is a non-negative safe integer.
 *
 * @param {unknown} n
 * @returns {boolean}
 */
export function isSafeNonNegativeInteger(n) {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
}

/**
 * Calculates token cost in integer micro_usd without floating point math (Law 17).
 *
 * @param {number} promptTokens
 * @param {number} completionTokens
 * @param {{ input_per_m: number, output_per_m: number }} pricing
 * @returns {number}
 */
export function calculateTokenCostMicroUsd(promptTokens, completionTokens, pricing) {
  if (!isSafeNonNegativeInteger(promptTokens) || !isSafeNonNegativeInteger(completionTokens)) {
    throw new TypeError("Token counts must be non-negative safe integers (Law 17)");
  }
  const inputCost = Math.floor((promptTokens * pricing.input_per_m) / 1_000_000);
  const outputCost = Math.floor((completionTokens * pricing.output_per_m) / 1_000_000);
  return inputCost + outputCost;
}

/**
 * In-memory ledger of warrant budget authorizations.
 */
export class WarrantBudgetManager {
  constructor() {
    /** @type {Map<string, { warrant_id: string, budget_micro_usd: number, spent_micro_usd: number, remaining_micro_usd: number, epoch: number, request_count: number, settled: boolean }>} */
    this.warrants = new Map();
  }

  /**
   * Authorizes or tops up budget for a warrant lease.
   *
   * @param {string} warrantId
   * @param {number} budgetMicroUsd
   * @param {number} [epoch=1]
   */
  preauth(warrantId, budgetMicroUsd, epoch = 1) {
    if (typeof warrantId !== "string" || warrantId.trim().length === 0) {
      throw new Error("Invalid warrantId");
    }
    if (!isSafeNonNegativeInteger(budgetMicroUsd)) {
      throw new Error("budget_micro_usd must be a non-negative safe integer (Law 17)");
    }
    if (!isSafeNonNegativeInteger(epoch) || epoch < 1) {
      throw new Error("epoch must be a positive safe integer");
    }

    const existing = this.warrants.get(warrantId);
    if (existing) {
      if (existing.settled) {
        throw new Error(`Warrant ${warrantId} has already been settled`);
      }
      if (existing.budget_micro_usd + budgetMicroUsd > Number.MAX_SAFE_INTEGER) {
        throw new Error("Integer overflow in budget preauth (Law 17)");
      }
      existing.budget_micro_usd += budgetMicroUsd;
      existing.remaining_micro_usd += budgetMicroUsd;
      existing.epoch = epoch;
      return { ...existing };
    }

    const entry = {
      warrant_id: warrantId,
      budget_micro_usd: budgetMicroUsd,
      spent_micro_usd: 0,
      remaining_micro_usd: budgetMicroUsd,
      epoch,
      request_count: 0,
      settled: false,
    };
    this.warrants.set(warrantId, entry);
    return { ...entry };
  }

  /**
   * Retrieves budget status for a warrant.
   *
   * @param {string} warrantId
   */
  get(warrantId) {
    const entry = this.warrants.get(warrantId);
    return entry ? { ...entry } : null;
  }

  /**
   * Attempts to deduct an integer cost from the warrant budget.
   *
   * @param {string} warrantId
   * @param {number} costMicroUsd
   */
  deduct(warrantId, costMicroUsd) {
    if (!isSafeNonNegativeInteger(costMicroUsd) || costMicroUsd <= 0) {
      throw new Error("costMicroUsd must be a positive safe integer (Law 17)");
    }
    const entry = this.warrants.get(warrantId);
    if (!entry) {
      return { allowed: false, reason: "WARRANT_NOT_FOUND" };
    }
    if (entry.settled) {
      return { allowed: false, reason: "WARRANT_SETTLED" };
    }
    if (entry.remaining_micro_usd < costMicroUsd || entry.remaining_micro_usd <= 0) {
      return { allowed: false, reason: "BUDGET_EXHAUSTED", remaining_micro_usd: entry.remaining_micro_usd };
    }

    entry.spent_micro_usd += costMicroUsd;
    entry.remaining_micro_usd -= costMicroUsd;
    entry.request_count += 1;
    return { allowed: true, remaining_micro_usd: entry.remaining_micro_usd, spent_micro_usd: entry.spent_micro_usd };
  }

  /**
   * Settles a warrant lease, preventing further deductions.
   *
   * @param {string} warrantId
   */
  settle(warrantId) {
    const entry = this.warrants.get(warrantId);
    if (!entry) {
      throw new Error(`Warrant ${warrantId} not found`);
    }
    entry.settled = true;
    const refund = entry.remaining_micro_usd;
    entry.remaining_micro_usd = 0;
    return {
      warrant_id: warrantId,
      spent_micro_usd: entry.spent_micro_usd,
      refund_micro_usd: refund,
      request_count: entry.request_count,
    };
  }
}

/**
 * Creates and starts the zero-dependency LLM Gateway HTTP server.
 *
 * @param {object} [options]
 * @param {number} [options.port=0]
 * @param {string} [options.host="127.0.0.1"]
 * @param {string} [options.adminToken]
 * @param {string} [options.upstreamUrl]
 * @returns {Promise<{ server: import("node:http").Server, port: number, manager: WarrantBudgetManager, adminToken: string, close: () => Promise<void> }>}
 */
export function createLlmGateway(options = {}) {
  const manager = new WarrantBudgetManager();
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const adminToken = options.adminToken ?? process.env.GATEWAY_ADMIN_TOKEN ?? "mirql-gateway-admin-secret";
  const upstreamUrl = options.upstreamUrl ?? null;

  const server = createServer(async (req, res) => {
    try {
      // Body collection with strict payload size limit
      let receivedBytes = 0;
      const chunks = [];
      let payloadTooLarge = false;

      for await (const chunk of req) {
        receivedBytes += chunk.length;
        if (receivedBytes > MAX_REQUEST_BODY_BYTES) {
          payloadTooLarge = true;
          break;
        }
        chunks.push(chunk);
      }

      if (payloadTooLarge) {
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "PAYLOAD_TOO_LARGE", code: GATEWAY_CODES.USAGE_ERROR }));
        return;
      }

      const bodyText = Buffer.concat(chunks).toString("utf8");
      let jsonBody = null;
      if (bodyText.length > 0) {
        try {
          jsonBody = JSON.parse(bodyText);
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "INVALID_JSON", code: GATEWAY_CODES.USAGE_ERROR }));
          return;
        }
      }

      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const pathname = url.pathname;

      // Helper for admin auth check
      const checkAdminAuth = () => {
        const authHeader = req.headers["authorization"] ?? "";
        const customToken = req.headers["x-mirql-admin-token"] ?? "";
        const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
        return (bearer === adminToken || customToken === adminToken);
      };

      // Route: GET /health
      if (req.method === "GET" && (pathname === "/health" || pathname === "/v1/health")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, status: "healthy", active_warrants: manager.warrants.size }));
        return;
      }

      // Route: POST /v1/warrant/preauth (Admin only)
      if (req.method === "POST" && pathname === "/v1/warrant/preauth") {
        if (!checkAdminAuth()) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "UNAUTHORIZED_ADMIN", detail: "Admin token required for warrant preauth" }));
          return;
        }
        try {
          if (!jsonBody || typeof jsonBody !== "object") {
            throw new Error("Missing request body");
          }
          const { warrant_id, budget_micro_usd, epoch } = jsonBody;
          const entry = manager.preauth(warrant_id, budget_micro_usd, epoch);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true, ...entry }));
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "PREAUTH_FAILED", detail: err.message, code: GATEWAY_CODES.USAGE_ERROR }));
        }
        return;
      }

      // Route: GET /v1/warrant/:id
      if (req.method === "GET" && pathname.startsWith("/v1/warrant/")) {
        const warrantId = decodeURIComponent(pathname.slice("/v1/warrant/".length));
        const entry = manager.get(warrantId);
        if (!entry) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "WARRANT_NOT_FOUND", warrant_id: warrantId }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, ...entry }));
        return;
      }

      // Route: POST /v1/warrant/settle (Admin only)
      if (req.method === "POST" && pathname === "/v1/warrant/settle") {
        if (!checkAdminAuth()) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "UNAUTHORIZED_ADMIN", detail: "Admin token required for warrant settle" }));
          return;
        }
        try {
          const warrantId = jsonBody?.warrant_id;
          const receipt = manager.settle(warrantId);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true, ...receipt }));
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "SETTLE_FAILED", detail: err.message }));
        }
        return;
      }

      // Route: POST /v1/chat/completions (Metered proxy endpoint)
      if (req.method === "POST" && (pathname === "/v1/chat/completions" || pathname === "/v1/proxy")) {
        const warrantId =
          req.headers["x-mirql-warrant-id"] ??
          jsonBody?.warrant_id;

        if (!warrantId) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            error: "UNAUTHORIZED",
            detail: "Missing x-mirql-warrant-id header or warrant_id field",
            code: 4,
          }));
          return;
        }

        // Validate max_tokens if provided
        if (jsonBody?.max_tokens !== undefined) {
          if (!isSafeNonNegativeInteger(jsonBody.max_tokens) || jsonBody.max_tokens === 0) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              error: "INVALID_MAX_TOKENS",
              detail: "max_tokens must be a positive safe integer",
              code: GATEWAY_CODES.USAGE_ERROR,
            }));
            return;
          }
        }

        // Deterministic server-side cost calculation (Never trust caller-supplied zero costs)
        const tier = DEFAULT_MODEL_PRICING[jsonBody?.model] ?? DEFAULT_MODEL_PRICING["workhorse"];
        const promptEst = Math.max(10, Math.floor(bodyText.length / 4));
        const maxTokens = jsonBody?.max_tokens ?? 256;
        const calculatedCost = calculateTokenCostMicroUsd(promptEst, maxTokens, tier);
        const costMicroUsd = Math.max(MIN_CALL_COST_MICRO_USD, calculatedCost);

        const deduction = manager.deduct(warrantId, costMicroUsd);
        if (!deduction.allowed) {
          res.writeHead(402, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            error: "BUDGET_EXHAUSTED",
            code: GATEWAY_CODES.BUDGET_EXHAUSTED,
            warrant_id: warrantId,
            remaining_micro_usd: deduction.remaining_micro_usd ?? 0,
          }));
          return;
        }

        // If upstream URL is configured, forward the request
        if (upstreamUrl) {
          try {
            const target = new URL(pathname, upstreamUrl);
            const reqFn = target.protocol === "https:" ? httpsRequest : httpRequest;
            const upstreamReq = reqFn(
              target,
              {
                method: "POST",
                headers: {
                  ...req.headers,
                  host: target.host,
                  "content-length": Buffer.byteLength(bodyText),
                },
              },
              (upstreamRes) => {
                res.writeHead(upstreamRes.statusCode || 200, {
                  ...upstreamRes.headers,
                  "x-mirql-budget-remaining": String(deduction.remaining_micro_usd),
                  "x-mirql-cost-micro-usd": String(costMicroUsd),
                });
                upstreamRes.pipe(res);
              },
            );
            upstreamReq.on("error", (upErr) => {
              res.writeHead(502, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "BAD_GATEWAY", detail: upErr.message }));
            });
            upstreamReq.write(bodyText);
            upstreamReq.end();
            return;
          } catch (fwdErr) {
            res.writeHead(502, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "FORWARD_FAILED", detail: fwdErr.message }));
            return;
          }
        }

        // Offline / synthetic completion mode
        res.writeHead(200, {
          "Content-Type": "application/json",
          "x-mirql-budget-remaining": String(deduction.remaining_micro_usd),
          "x-mirql-cost-micro-usd": String(costMicroUsd),
        });

        const responsePayload = {
          id: `chatcmpl-${Date.now()}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: jsonBody?.model ?? "workhorse",
          choices: [
            {
              index: 0,
              message: {
                role: "assistant",
                content: "ok",
              },
              finish_reason: "stop",
            },
          ],
          usage: {
            prompt_tokens: promptEst,
            completion_tokens: Math.min(maxTokens, 16),
            total_tokens: promptEst + Math.min(maxTokens, 16),
          },
          mirql_metering: {
            warrant_id: warrantId,
            charged_micro_usd: costMicroUsd,
            remaining_micro_usd: deduction.remaining_micro_usd,
          },
        };

        res.end(JSON.stringify(responsePayload));
        return;
      }

      // Default 404
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "NOT_FOUND", path: pathname }));
    } catch (unhandledErr) {
      // Top-level fail-safe: never crash Node process
      try {
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "INTERNAL_SERVER_ERROR", detail: unhandledErr.message }));
        }
      } catch {}
    }
  });

  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      const addr = server.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({
        server,
        port: actualPort,
        manager,
        adminToken,
        close: () => new Promise((done) => server.close(done)),
      });
    });
    server.on("error", reject);
  });
}

// CLI entrypoint
if (process.argv[1] && process.argv[1].endsWith("llm-gateway.mjs")) {
  let port = 8080;
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === "--port" && process.argv[i + 1]) {
      port = parseInt(process.argv[++i], 10);
    }
  }
  createLlmGateway({ port, host: "0.0.0.0" }).then(({ port: boundPort }) => {
    process.stdout.write(JSON.stringify({ status: "running", port: boundPort }) + "\n");
  }).catch((err) => {
    process.stderr.write(`Failed to start LLM Gateway: ${err.message}\n`);
    process.exit(1);
  });
}
