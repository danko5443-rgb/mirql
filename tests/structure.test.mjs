// W1 structure gate: zero dependencies, canonical schemas present and
// pinned, every bin executable, and no cross-tool imports between tool
// packages.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");

const SCHEMAS = ["event", "warrant", "job", "outcome"];

/** Required top-level properties, exactly as pinned by work package W1. */
const REQUIRED = {
  event: [
    "v", "id", "tenant_id", "seq", "epoch", "hlc", "ts", "type", "writer",
    "idempotency_key", "prev_hash", "payload", "hash", "sig",
  ],
  warrant: [
    "v", "id", "class", "semantic_fingerprint", "anchors", "evidence",
    "red_check", "scope", "budget_micro_usd", "created_by",
  ],
  job: [
    "v", "id", "tenant_id", "role", "tier", "base_sha", "attempt", "limits",
    "lease", "idempotency_key",
  ],
  outcome: [
    "v", "id", "job_id", "warrant_id", "epoch", "status", "base_sha",
    "head_sha", "tree_hash", "evidence", "anti_cheat", "phi", "surface",
    "thrift", "reconciliation", "cost",
  ],
};

const BINS = [
  "mirql.mjs",
  "mirql-run.mjs",
  "mirql-queue.mjs",
  "mirql-log.mjs",
  "mirql-inbox.mjs",
];

const TOOL_PACKAGES = ["run", "queue", "log", "inbox", "mergeproof"];

/** Spawn `node <binRelPath> <args>` at the repo root. */
function runBin(binRelPath, args) {
  return spawnSync(process.execPath, [join(ROOT, binRelPath), ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30_000,
  });
}

// ---------------------------------------------------------------------------
// Zero-dependency law
// ---------------------------------------------------------------------------

test("package.json declares zero dependencies of any kind", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  for (const field of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    const section = pkg[field];
    assert.ok(
      section === undefined || Object.keys(section).length === 0,
      `package.json must not have ${field} (found ${JSON.stringify(section)})`,
    );
  }
});

// ---------------------------------------------------------------------------
// Canonical schemas
// ---------------------------------------------------------------------------

test("all four canonical schemas exist, parse, and pin their required fields", () => {
  for (const kind of SCHEMAS) {
    const path = join(ROOT, "schemas", `${kind}.schema.json`);
    const schema = JSON.parse(readFileSync(path, "utf8")); // throws if invalid JSON

    assert.equal(schema.$id, `https://mirql.local/schemas/${kind}/v1.json`);
    assert.equal(schema.type, "object");
    assert.deepEqual(schema.required, REQUIRED[kind]);

    const properties = Object.keys(schema.properties ?? {});
    for (const field of REQUIRED[kind]) {
      assert.ok(
        properties.includes(field),
        `${kind}.schema.json: required field "${field}" has no properties entry`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// CLI executables
// ---------------------------------------------------------------------------

test("all five bins exist and answer --help with clean JSON on stdout", () => {
  assert.deepEqual(
    readdirSync(join(ROOT, "bin")).filter((f) => /^mirql.*\.mjs$/.test(f)).sort(),
    [...BINS].sort(),
  );

  const toolNames = { "mirql-run.mjs": "run", "mirql-queue.mjs": "queue", "mirql-log.mjs": "log", "mirql-inbox.mjs": "inbox" };

  for (const bin of BINS) {
    const res = runBin(join("bin", bin), ["--help"]);
    assert.equal(res.status, 0, `${bin} --help exited ${res.status}: ${res.stderr}`);
    assert.equal(res.error, undefined, `${bin} failed to spawn`);

    const doc = JSON.parse(res.stdout); // throws if stdout is not JSON
    assert.equal(doc.tool, toolNames[bin] ?? "mirql", `${bin}: unexpected tool name`);
    if (bin === "mirql.mjs") {
      assert.equal(typeof doc.version, "string");
      assert.equal(doc.usage.length > 0, true);
    } else {
      assert.deepEqual(doc, { tool: toolNames[bin], status: "stub" });
    }
  }
});

test("mirql router maps tools and 1-letter aliases to the stub contract", () => {
  const cases = [
    [["run", "status"], { tool: "run", status: "stub" }],
    [["r", "status"], { tool: "run", status: "stub" }],
    // Arguments after the tool (full name or 1-letter alias) are handed to the
    // tool package: `mirql r bing-bong` must land in packages/run/index.mjs.
    [["run", "bing-bong"], { tool: "run", status: "stub" }],
    [["r", "bing-bong"], { tool: "run", status: "stub" }],
    [["r", "bb"], { tool: "run", status: "stub" }],
    [["queue"], { tool: "queue", status: "stub" }],
    [["q"], { tool: "queue", status: "stub" }],
    [["log"], { tool: "log", status: "stub" }],
    [["l"], { tool: "log", status: "stub" }],
    [["inbox"], { tool: "inbox", status: "stub" }],
    [["i"], { tool: "inbox", status: "stub" }],
    [["mergeproof"], { tool: "mergeproof", status: "stub" }],
    [["m"], { tool: "mergeproof", status: "stub" }],
  ];
  for (const [args, expected] of cases) {
    const res = runBin(join("bin", "mirql.mjs"), args);
    assert.equal(res.status, 0, `mirql ${args.join(" ")} exited ${res.status}`);
    assert.deepEqual(JSON.parse(res.stdout), expected, `mirql ${args.join(" ")}`);
  }
});

test("mirql router reports its version and rejects unknown tools", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

  const version = runBin(join("bin", "mirql.mjs"), ["--version"]);
  assert.equal(version.status, 0);
  assert.deepEqual(JSON.parse(version.stdout), { tool: "mirql", version: pkg.version });

  const unknown = runBin(join("bin", "mirql.mjs"), ["definitely-not-a-tool"]);
  assert.equal(unknown.status, 2); // EXIT_CODES.USAGE_ERROR
  assert.match(unknown.stderr, /unknown_tool/);
});

test("bin entrypoints settle Promise-returning main without ERR_INVALID_ARG_TYPE", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "mirql-bin-async-"));
  try {
    for (const bin of BINS) {
      // Graft the REAL direct-invocation block shipped in bin/<bin> onto an
      // async main() in a fixture entrypoint, so the dispatch code that runs
      // is byte-for-byte the code this repository ships — not a re-creation.
      const source = readFileSync(join(ROOT, "bin", bin), "utf8");
      const markerAt = source.indexOf("function resolveArgv1");
      assert.ok(markerAt >= 0, `${bin}: cannot find resolveArgv1 to extract the dispatch block`);
      const dispatch = source.slice(markerAt);
      assert.ok(
        typeof dispatch === "string" && dispatch.includes("typeof result.then") && dispatch.includes(".catch("),
        `${bin}: direct-invocation block must settle Promise results (async main hardening)`,
      );

      const fixture = [
        "#!/usr/bin/env node",
        `// Auto-generated by tests/structure.test.mjs: dispatch block of bin/${bin} + async main.`,
        'import { realpathSync } from "node:fs";',
        'import { resolve } from "node:path";',
        'import { pathToFileURL } from "node:url";',
        "",
        "// Async stand-in for a tool main() that awaits I/O (e.g. mirql-run",
        "// bing-bong in W3 / mirql-inbox in W4) and resolves to an exit code.",
        "const main = (argv) =>",
        "  new Promise((done, fail) => {",
        "    setImmediate(() => {",
        '      if (argv[0] === "reject") fail(new Error("async failure"));',
        "      else done(Number(argv[0]));",
        "    });",
        "  });",
        "",
        dispatch,
        "",
      ].join("\n");
      const fixturePath = join(tempDir, `fixture-${bin}`);
      writeFileSync(fixturePath, fixture, "utf8");

      // A Promise resolving to a number (exit code 0 or 2) must be honored
      // as the process exit code, without Node crashing on the assignment.
      for (const code of [0, 2]) {
        const res = spawnSync(process.execPath, [fixturePath, String(code)], {
          cwd: ROOT,
          encoding: "utf8",
          timeout: 30_000,
        });
        assert.equal(res.error, undefined, `${bin}: fixture failed to spawn`);
        assert.equal(res.status, code, `${bin}: main() resolving to ${code} exited ${res.status}`);
        assert.doesNotMatch(
          res.stderr,
          /ERR_INVALID_ARG_TYPE/,
          `${bin}: Promise main crashed Node (stderr: ${res.stderr})`,
        );
        assert.equal(res.stderr, "", `${bin}: unexpected stderr for Promise<${code}>`);
      }

      // A rejected Promise must map to JSON-on-stderr + exit code 1.
      const rejected = spawnSync(process.execPath, [fixturePath, "reject"], {
        cwd: ROOT,
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.equal(rejected.status, 1, `${bin}: rejected Promise exited ${rejected.status}`);
      assert.doesNotMatch(
        rejected.stderr,
        /ERR_INVALID_ARG_TYPE/,
        `${bin}: rejected Promise crashed Node (stderr: ${rejected.stderr})`,
      );
      assert.deepEqual(JSON.parse(rejected.stderr), { error: "async failure" });
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Package isolation: no sibling-tool imports
// ---------------------------------------------------------------------------

/** Recursively list .mjs files under `dir`. */
function listMjsFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) found.push(...listMjsFiles(full));
    else if (entry.endsWith(".mjs")) found.push(full);
  }
  return found;
}

/** Extract every static/dynamic import (and require) specifier from source. */
function extractSpecifiers(source) {
  const patterns = [
    /\bfrom\s*["']([^"']+)["']/g, // import ... from "x" / export ... from "x"
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g, // await import("x")
    /\bimport\s*["']([^"']+)["']/g, // side-effect import "x"
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g, // require("x") if any slips in
  ];
  const specs = [];
  for (const re of patterns) {
    for (const match of source.matchAll(re)) specs.push(match[1]);
  }
  return specs;
}

test("tool packages import only from node:* , ../core/, or inside themselves", () => {
  const violations = [];
  const coreDir = join(ROOT, "packages", "core");

  // Core package must never import from sibling tool packages or escape itself.
  const coreFiles = listMjsFiles(coreDir);
  assert.ok(coreFiles.length > 0, "packages/core contains no .mjs files");
  for (const file of coreFiles) {
    const source = readFileSync(file, "utf8");
    for (const spec of extractSpecifiers(source)) {
      if (spec.startsWith("node:")) continue;

      if (spec.startsWith("./") || spec.startsWith("../")) {
        const resolved = resolve(file, "..", spec);
        if (resolved === coreDir || resolved.startsWith(coreDir + sep)) {
          continue;
        }
        violations.push(
          `packages/core/${file.slice(coreDir.length + 1)} imports "${spec}" — escapes packages/core`,
        );
        continue;
      }

      violations.push(
        `packages/core/${file.slice(coreDir.length + 1)} imports bare specifier "${spec}"`,
      );
    }
  }

  for (const tool of TOOL_PACKAGES) {
    const packageDir = join(ROOT, "packages", tool);
    const files = listMjsFiles(packageDir);
    assert.ok(files.length > 0, `packages/${tool} contains no .mjs files`);
    assert.ok(
      files.some((f) => f === join(packageDir, "index.mjs")),
      `packages/${tool}/index.mjs is missing`,
    );

    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const spec of extractSpecifiers(source)) {
        if (spec.startsWith("node:")) continue;

        // Relative imports must resolve inside this package or inside packages/core —
        // resolving with path.resolve first prevents bypasses like "../core/../queue/...".
        if (spec.startsWith("./") || spec.startsWith("../")) {
          const resolved = resolve(file, "..", spec);
          if (
            resolved === packageDir ||
            resolved.startsWith(packageDir + sep) ||
            resolved === coreDir ||
            resolved.startsWith(coreDir + sep)
          ) {
            continue;
          }
          violations.push(
            `packages/${tool}/${file.slice(packageDir.length + 1)} imports "${spec}" — escapes its own package`,
          );
          continue;
        }

        // Anything else is a bare specifier: an external dependency, which is
        // forbidden by the zero-dependency law.
        violations.push(
          `packages/${tool}/${file.slice(packageDir.length + 1)} imports bare specifier "${spec}"`,
        );
      }
    }
  }

  assert.deepEqual(violations, []);
});

test("core and tool package entrypoints all exist", () => {
  assert.equal(statSync(join(ROOT, "packages", "core", "index.mjs")).isFile(), true);
  for (const tool of TOOL_PACKAGES) {
    assert.equal(statSync(join(ROOT, "packages", tool, "index.mjs")).isFile(), true);
  }
});
