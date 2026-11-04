// tests/sandbox-runtime-spawn.test.mjs — Law 8: a worker command reaches the
// container runtime as one argv entry and is never interpreted by a host shell.
//
// The mock runtime records its argv and exits; it never runs the worker command.
// Any marker on disk therefore proves the command ran on the host, outside the
// container.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { EXIT_CODES } from "../packages/core/index.mjs";
import { runAgent, windowsCmdLine } from "../packages/run/agent.mjs";

const windowsOnly = { skip: process.platform !== "win32" && "exercises Windows runtime resolution" };

let envRoot;
const savedEnv = {};

before(() => {
  envRoot = mkdtempSync(join(tmpdir(), "mirql-sb-spawn-env-"));
  for (const key of ["MIRQL_TRUST_ROOT", "HOME", "USERPROFILE"]) savedEnv[key] = process.env[key];
  process.env.MIRQL_TRUST_ROOT = join(envRoot, "trust");
  process.env.HOME = envRoot;
  process.env.USERPROFILE = envRoot;
});

after(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(envRoot, { recursive: true, force: true });
});

const git = (cwd, ...args) => execFileSync("git", args, { cwd, stdio: "ignore" });

function makeWorkspace(parent, plantedFiles = {}) {
  const workspace = join(parent, "workspace");
  mkdirSync(workspace, { recursive: true });
  git(workspace, "init", "-q");
  git(workspace, "config", "user.name", "test");
  git(workspace, "config", "user.email", "test@mirql.local");
  git(workspace, "config", "core.autocrlf", "false");
  writeFileSync(join(workspace, "code.mjs"), "export const value=1;\n");
  for (const [name, body] of Object.entries(plantedFiles)) writeFileSync(join(workspace, name), body);
  git(workspace, "add", "-A");
  git(workspace, "commit", "-q", "-m", "base");
  return workspace;
}

/** Writes the recording mock; returns the source path and the file its argv lands in. */
function writeMockSource(binDir, parent) {
  mkdirSync(binDir, { recursive: true });
  const argsFile = join(parent, "mock-args.json");
  const source = join(binDir, "runtime-mock.mjs");
  writeFileSync(source, [
    'import { writeFileSync } from "node:fs";',
    `writeFileSync(${JSON.stringify(argsFile)}, JSON.stringify(process.argv.slice(2)));`,
    "process.exit(0);",
  ].join("\n"));
  return { source, argsFile };
}

/** A `docker` shim: a batch file on Windows, a shell script elsewhere. */
function makeShimRuntime(parent, binDir = join(parent, "mock-bin")) {
  const { source, argsFile } = writeMockSource(binDir, parent);
  if (process.platform === "win32") {
    writeFileSync(join(binDir, "docker.cmd"), `@node "${source}" %*\r\n`);
  } else {
    writeFileSync(join(binDir, "docker"), `#!/bin/sh\nexec node "${source}" "$@"\n`);
    chmodSync(join(binDir, "docker"), 0o755);
  }
  return { binDir, argsFile };
}

const runInSandbox = (workspace, binDir, command) => runAgent({
  sandbox: "docker",
  image: "mirql-agent-mock:latest",
  cwd: workspace,
  command,
  env: { PATH: `${binDir}${delimiter}${dirname(process.execPath)}` },
});

/** What `sh -c` receives in the container: POSIX hosts prefix a umask for the unprivileged user's output. */
const inContainer = (command) => (process.platform === "win32" ? command : `umask 000; ${command}`);

const hostileCommands = (marker) => [
  `true & echo pwned > "${marker}"`,
  `true && echo pwned > "${marker}"`,
  `true | echo pwned > "${marker}"`,
  `true || echo pwned > "${marker}"`,
  `true ; echo pwned > "${marker}"`,
  `true" & echo pwned > "${marker}" & rem "`,
  `true\\" & echo pwned > "${marker}" & rem "`,
  `^& echo pwned > "${marker}"`,
  `(echo pwned) > "${marker}"`,
  `true & echo pwned > marker`,
];

test("shell metacharacters in a worker command never run on the host and reach the runtime intact", () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-meta-"));
  try {
    const workspace = makeWorkspace(parent);
    const { binDir, argsFile } = makeShimRuntime(parent);
    const marker = join(parent, "host-marker");

    for (const command of hostileCommands(marker)) {
      const res = runInSandbox(workspace, binDir, command);
      assert.equal(existsSync(marker), false, `host shell ran: ${command}`);
      assert.equal(existsSync(join(workspace, "marker")), false, `host shell ran: ${command}`);
      assert.equal(res.ok, true, `${command}: ${JSON.stringify(res)}`);
      assert.deepEqual(JSON.parse(readFileSync(argsFile, "utf8")).slice(-3), ["sh", "-c", inContainer(command)]);
    }
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("variable syntax in a worker command is passed through, not expanded by the host", () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-vars-"));
  try {
    const workspace = makeWorkspace(parent);
    const { binDir, argsFile } = makeShimRuntime(parent);
    const command = 'echo %PATH% !PATH! $PATH `id` a^b "c d" *.mjs e\\ f\\\\';

    const res = runInSandbox(workspace, binDir, command);
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(JSON.parse(readFileSync(argsFile, "utf8")).at(-1), inContainer(command));
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("a runtime shim in a directory with spaces and metacharacters still resolves safely", windowsOnly, () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-dir-"));
  try {
    const workspace = makeWorkspace(parent);
    const { binDir, argsFile } = makeShimRuntime(parent, join(parent, "mock bin (x86) & co"));
    const marker = join(parent, "host-marker");
    const command = `true & echo pwned > "${marker}"`;

    const res = runInSandbox(workspace, binDir, command);
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(existsSync(marker), false);
    assert.equal(JSON.parse(readFileSync(argsFile, "utf8")).at(-1), command);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("a line break is refused for a batch runtime instead of reaching cmd.exe", windowsOnly, () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-newline-"));
  try {
    const workspace = makeWorkspace(parent);
    const { binDir, argsFile } = makeShimRuntime(parent);
    const marker = join(parent, "host-marker");

    const res = runInSandbox(workspace, binDir, `true\necho pwned > "${marker}"`);
    assert.equal(res.ok, false);
    assert.equal(res.exitCode, EXIT_CODES.POLICY_DENIAL);
    assert.equal(res.violation, "SANDBOX_UNAVAILABLE");
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(argsFile), false, "the runtime must not have been started");
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("runtime and shim-child files planted in the workspace are never executed on the host", windowsOnly, () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-plant-"));
  try {
    const marker = join(parent, "host-marker");
    const planted = `@echo pwned > "${marker}"\r\n`;
    const workspace = makeWorkspace(parent, { "docker.cmd": planted, "docker.bat": planted, "node.cmd": planted, "node.bat": planted });
    const { binDir, argsFile } = makeShimRuntime(parent);

    const res = runInSandbox(workspace, binDir, "true");
    assert.equal(existsSync(marker), false, "a workspace file ran on the host");
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(JSON.parse(readFileSync(argsFile, "utf8")).at(-1), "true");
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("a runtime planted in the workspace does not satisfy the lookup when PATH has none", windowsOnly, () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-noruntime-"));
  try {
    const marker = join(parent, "host-marker");
    const workspace = makeWorkspace(parent, { "docker.cmd": `@echo pwned > "${marker}"\r\n` });
    const emptyBin = join(parent, "empty-bin");
    mkdirSync(emptyBin);

    const res = runInSandbox(workspace, emptyBin, "true");
    assert.equal(res.violation, "SANDBOX_UNAVAILABLE");
    assert.equal(existsSync(marker), false);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("an .exe runtime is spawned directly with its argument vector intact", windowsOnly, () => {
  const parent = mkdtempSync(join(tmpdir(), "mirql-sb-exe-"));
  try {
    const workspace = makeWorkspace(parent);
    const binDir = join(parent, "exe-bin");
    const { source, argsFile } = writeMockSource(binDir, parent);
    // A renamed node.exe stands in for docker.exe; the preload records argv and exits.
    copyFileSync(process.execPath, join(binDir, "docker.exe"));
    const marker = join(parent, "host-marker");
    const command = `true & echo pwned > "${marker}"\necho "next line"`;

    const res = runAgent({
      sandbox: "docker",
      cwd: workspace,
      command,
      env: { PATH: binDir, NODE_OPTIONS: `--import=${pathToFileURL(source).href}` },
      allowedEnv: ["NODE_OPTIONS"],
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(existsSync(marker), false);
    assert.deepEqual(JSON.parse(readFileSync(argsFile, "utf8")).slice(-3), ["sh", "-c", command]);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("windowsCmdLine leaves no cmd.exe metacharacter unescaped", () => {
  const line = windowsCmdLine("C:\\Program Files (x86)\\docker.cmd", [
    "run", 'a & b | c > d < e', 'x"y', "%PATH%", "!PATH!", "^", "(z);", "trailing\\", "",
  ]);
  // Remove every caret-escaped character; nothing the shell acts on may remain.
  const bare = line.replace(/\^./g, "");
  assert.doesNotMatch(bare, /[&|<>()%!^"]/);
  assert.ok(line.startsWith("C:\\Program^ Files^ ^(x86^)\\docker.cmd "));
});
