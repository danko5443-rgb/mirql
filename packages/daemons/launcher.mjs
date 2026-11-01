// packages/daemons/launcher.mjs — Host systemd worker spawner and unit validator.
// Fixed templates only (Law 1, Law 2, Law 8).

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

/** Required systemd security sandboxing directives. */
export const MANDATORY_SANDBOX_DIRECTIVES = Object.freeze([
  "ProtectSystem",
  "ProtectHome",
  "PrivateTmp",
  "NoNewPrivileges",
  "ProtectKernelTunables",
  "ProtectControlGroups",
  "RestrictRealtime",
  "RestrictSUIDSGID",
]);

/**
 * Validates a systemd service unit string against mandatory security sandboxing rules.
 *
 * @param {string} unitContent
 * @returns {{ ok: boolean, missing: string[], errors: string[] }}
 */
export function validateServiceUnit(unitContent) {
  if (typeof unitContent !== "string" || unitContent.trim().length === 0) {
    return { ok: false, missing: [...MANDATORY_SANDBOX_DIRECTIVES], errors: ["Unit content is empty"] };
  }

  const missing = [];
  const errors = [];

  for (const directive of MANDATORY_SANDBOX_DIRECTIVES) {
    const re = new RegExp(`^\\s*${directive}\\s*=`, "m");
    if (!re.test(unitContent)) {
      missing.push(directive);
    }
  }

  // Ensure unprivileged user unless explicitly permitted
  const userMatch = unitContent.match(/^\s*User\s*=\s*([a-zA-Z0-9_-]+)/m);
  if (!userMatch) {
    errors.push("Missing User= directive");
  } else if (userMatch[1] === "root" && !unitContent.includes("mirql-lifeguard")) {
    errors.push("Service unit must not run as root User");
  }

  return {
    ok: missing.length === 0 && errors.length === 0,
    missing,
    errors,
  };
}

/**
 * Renders a canonical mirql launcher service file.
 *
 * @param {object} [options]
 * @param {string} [options.workingDir="/opt/mirql"]
 * @param {string} [options.user="mirql"]
 * @param {string} [options.execStart="/usr/bin/node /opt/mirql/bin/mirql.mjs q daemon"]
 * @returns {string}
 */
export function renderLauncherUnit(options = {}) {
  const workingDir = options.workingDir ?? "/opt/mirql";
  const user = options.user ?? "mirql";
  const execStart = options.execStart ?? "/usr/bin/node /opt/mirql/bin/mirql.mjs q daemon";

  return `[Unit]
Description=mirql Autonomous Factory Launcher
Documentation=https://github.com/ahmed-3m/mirql
After=network.target

[Service]
Type=simple
User=${user}
Group=${user}
WorkingDirectory=${workingDir}
ExecStart=${execStart}
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# Strict security sandbox
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
ReadWritePaths=${workingDir}/.mirql /tmp

# Resource limits
LimitNOFILE=65535
MemoryMax=4G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
`;
}
