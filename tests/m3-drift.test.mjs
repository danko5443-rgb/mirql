// tests/m3-drift.test.mjs — Milestone M3: Claim-Check Drift Sentinel & Surface Lock Verification (Law 12).
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  detectDrift,
  verifyClaimCheck,
  formatDriftEvent,
} from "../packages/run/index.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

describe("Milestone M3: Claim-Check Drift Sentinel & Surface Lock Verification", () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "mirql-m3-test-"));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("1. Baseline Codebase Drift Conformance", () => {
    it("reports zero drift on the active repository", () => {
      const res = detectDrift(ROOT);

      assert.equal(res.ok, true, "Active repo must conform 100% with no drift");
      assert.equal(res.drift_detected, false);
      assert.equal(res.drift_score_bp, 0);
      assert.equal(res.drifts.length, 0);
      assert.ok(res.summary.includes("No drift detected"));
    });
  });

  describe("2. Surface Drift Detection (against surface.lock)", () => {
    it("detects missing surface.lock baseline file", () => {
      const res = detectDrift(tempDir);

      assert.equal(res.ok, false);
      assert.equal(res.drift_detected, true);
      assert.ok(res.drifts.some((d) => d.drift_type === "surface" && d.details.includes("surface.lock")));
    });

    it("detects missing required public binary entrypoint", () => {
      writeFileSync(
        join(tempDir, "surface.lock"),
        JSON.stringify({ v: 1, bins: ["mirql-missing"], schemas: [] }),
        "utf8",
      );
      mkdirSync(join(tempDir, "bin"), { recursive: true });

      const res = detectDrift(tempDir);
      assert.equal(res.ok, false);
      const binDrift = res.drifts.find((d) => d.subsystem === "bin");
      assert.ok(binDrift, "Must flag missing bin");
      assert.equal(binDrift.drift_type, "surface");
      assert.ok(binDrift.details.includes("mirql-missing"));
    });

    it("detects missing public command declared in surface.lock", () => {
      const pkgDir = join(tempDir, "packages", "run");
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(
        join(pkgDir, "index.mjs"),
        `export const SUBCOMMANDS = Object.freeze(["supervisor"]);\n`,
        "utf8",
      );
      writeFileSync(
        join(tempDir, "surface.lock"),
        JSON.stringify({
          v: 1,
          bins: [],
          commands: ["mirql r supervisor", "mirql r missing-cmd"],
          schemas: [],
        }),
        "utf8",
      );

      const res = detectDrift(tempDir);
      assert.equal(res.ok, false);
      assert.ok(res.drifts.some((d) => d.details.includes("mirql r missing-cmd")));
    });
  });

  describe("3. Dependency Creep Detection (Law 0)", () => {
    it("flags unauthorized external dependencies in package.json", () => {
      writeFileSync(
        join(tempDir, "surface.lock"),
        JSON.stringify({ v: 1, bins: [], schemas: [] }),
        "utf8",
      );
      writeFileSync(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "illicit", dependencies: { "lodash": "^4.17.21" } }),
        "utf8",
      );

      const res = detectDrift(tempDir);
      assert.equal(res.ok, false);
      const depDrift = res.drifts.find((d) => d.drift_type === "dependency");
      assert.ok(depDrift, "Must flag dependency drift");
      assert.ok(depDrift.drift_score_bp >= 5000);
      assert.ok(depDrift.details.includes("Law 0 violation"));
    });

    it("flags peerDependencies and optionalDependencies in package.json", () => {
      writeFileSync(
        join(tempDir, "surface.lock"),
        JSON.stringify({ v: 1, bins: [], schemas: [] }),
        "utf8",
      );
      writeFileSync(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "illicit-peers", peerDependencies: { "react": "^18.0.0" } }),
        "utf8",
      );

      const res = detectDrift(tempDir);
      assert.equal(res.ok, false);
      assert.ok(res.drifts.some((d) => d.details.includes("peerDependencies: 1")));
    });
  });

  describe("4. Architectural Boundary Checks", () => {
    it("flags unauthorized bare specifier imports, re-exports, dynamic imports, and require", () => {
      writeFileSync(
        join(tempDir, "surface.lock"),
        JSON.stringify({ v: 1, bins: [], schemas: [] }),
        "utf8",
      );
      writeFileSync(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "test", dependencies: {} }),
        "utf8",
      );

      const pkgDir = join(tempDir, "packages", "sample");
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(
        join(pkgDir, "index.mjs"),
        `// Safe comment mentioning "express"
export * from "lodash";
const chalk = require("chalk");
async function load() { await import("left-pad"); }
import express from "express";
export const x = 1;
`,
        "utf8",
      );

      const res = detectDrift(tempDir);
      assert.equal(res.ok, false);
      const archDrifts = res.drifts.filter((d) => d.drift_type === "architecture");
      assert.ok(archDrifts.some((d) => d.details.includes("lodash")));
      assert.ok(archDrifts.some((d) => d.details.includes("chalk")));
      assert.ok(archDrifts.some((d) => d.details.includes("left-pad")));
      assert.ok(archDrifts.some((d) => d.details.includes("express")));
    });

    it("flags Law 2 privilege boundary leak (unprivileged package importing supervisor)", () => {
      writeFileSync(
        join(tempDir, "surface.lock"),
        JSON.stringify({ v: 1, bins: [], schemas: [] }),
        "utf8",
      );
      writeFileSync(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "test", dependencies: {} }),
        "utf8",
      );

      const mergeproofDir = join(tempDir, "packages", "mergeproof");
      mkdirSync(mergeproofDir, { recursive: true });
      writeFileSync(
        join(mergeproofDir, "index.mjs"),
        `import { getOrGenerateSupervisorKey } from "../run/keys.mjs";\n`,
        "utf8",
      );

      const res = detectDrift(tempDir);
      assert.equal(res.ok, false);
      const leakDrift = res.drifts.find((d) => d.details.includes("Law 2 privilege boundary leak"));
      assert.ok(leakDrift, "Must flag Law 2 privilege boundary leak");
    });
  });

  describe("5. Claim-Check Verification (verifyClaimCheck)", () => {
    it("verifies zero_dependencies claim against active codebase", () => {
      const claim = verifyClaimCheck("zero_dependencies", ROOT);
      assert.equal(claim.verified, true);
      assert.ok(claim.details.includes("zero external dependencies"));
    });

    it("verifies no_surface_drift claim against active codebase", () => {
      const claim = verifyClaimCheck("no_surface_drift", ROOT);
      assert.equal(claim.verified, true);
    });

    it("verifies clean_architecture claim against active codebase", () => {
      const claim = verifyClaimCheck("clean_architecture", ROOT);
      assert.equal(claim.verified, true);
    });
  });

  describe("6. Canonical Event Formatting (formatDriftEvent)", () => {
    it("formats drift.detected event conforming to roles/scout-drift.md contract", () => {
      const mockDrift = {
        ok: false,
        drift_detected: true,
        drift_score_bp: 2500,
        summary: "Surface drift detected",
        drifts: [
          {
            subsystem: "bin",
            drift_type: "surface",
            drift_score_bp: 2500,
            details: "Missing bin/mirql-foo.mjs",
          },
        ],
      };

      const evt = formatDriftEvent(mockDrift, { nowMs: 1700000000000 });
      assert.equal(evt.type, "drift.detected");
      assert.equal(evt.subsystem, "bin");
      assert.equal(evt.payload.drift_type, "surface");
      assert.equal(evt.payload.drift_score_bp, 2500);
      assert.equal(evt.payload.issues_count, 1);
      assert.equal(evt.payload.timestamp_ms, 1700000000000);
    });
  });
});
