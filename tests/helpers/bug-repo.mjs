// A real repository holding a real bug, and the worker source that fixes it.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { git, initEmptyRepo } from "./git.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

export const REPRODUCER = "tests/repro.test.mjs";
export const FIX = "export function add(a, b) {\n  return a + b;\n}\n";
export const TEST = "import test from 'node:test';\nimport assert from 'node:assert';\nimport { add } from '../src/app.mjs';\ntest('adds', () => assert.equal(add(2, 2), 4));\n";

/** ESM statements that apply the fix. Expects mkdirSync and writeFileSync in scope. */
export const WRITE_FIX = `
writeFileSync("src/app.mjs", ${JSON.stringify(FIX)});
mkdirSync("tests", { recursive: true });
writeFileSync(${JSON.stringify(REPRODUCER)}, ${JSON.stringify(TEST)});
`;

/** Commits the buggy project into `dir` and returns the base commit. */
export function initBugRepo(dir) {
  const files = {
    "package.json": JSON.stringify({ type: "module", scripts: { test: "node --test tests/*.test.mjs" } }),
    "policy/paths.yaml": readFileSync(join(ROOT, "policy", "paths.yaml"), "utf8"),
    ".gitignore": "*.ignored\n",
    "src/app.mjs": "export function add(a, b) {\n  return a - b;\n}\n",
  };
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  initEmptyRepo(dir);
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "base");
  return git(dir, "rev-parse", "HEAD").trim();
}

/** Writes an ESM worker script and returns the shell command that runs it. */
export function writeWorker(path, body) {
  writeFileSync(path, `import { mkdirSync, writeFileSync } from "node:fs";\n${body}`);
  return `"${process.execPath}" "${path}"`;
}
