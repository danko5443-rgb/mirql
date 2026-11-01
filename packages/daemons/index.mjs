// packages/daemons/index.mjs — Entrypoint for mirql host and sidecar daemons.

export {
  createLlmGateway,
  WarrantBudgetManager,
  calculateTokenCostMicroUsd,
  DEFAULT_MODEL_PRICING,
  GATEWAY_CODES,
  MIN_CALL_COST_MICRO_USD,
  MAX_REQUEST_BODY_BYTES,
  isSafeNonNegativeInteger,
  timingSafeCompare,
} from "./llm-gateway.mjs";

export {
  LifeguardWatchdog,
  checkProbationStatus,
  executeRollback,
  listDestructiblePaths,
  killProcesses,
  killServices,
  DEFAULT_PROBATION_TIMEOUT_MS,
  DEFAULT_HEARTBEAT_TIMEOUT_MS,
} from "./lifeguard.mjs";

export {
  validateServiceUnit,
  renderLauncherUnit,
  MANDATORY_SANDBOX_DIRECTIVES,
} from "./launcher.mjs";
