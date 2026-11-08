// MP-003 ratchet: the repo-wide swallowed-exception count only goes down.
//
// Two fences protect this invariant, deliberately different: the per-PR
// diff-gate scan (ci-evidence.mjs ships the HEAD content of changed .mjs
// files, and the evaluator exempts a `mp-003-allow` marker on catches
// unchanged from base) and THIS repo-wide exact-pin, which counts marked
// sites too — a silence budget that only real removal lowers. Adding an
// unmarked empty catch anywhere in production code fails here, and every
// genuinely handled violation lowers the ceiling for good.
// Lower the number when you fix violations; never raise it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkSwallowedExceptions } from "../packages/core/anti-cheat.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CEILING = 66; // measured 2026-11-07: every silent catch in the tree carries a reason; the count only falls by real handling

function walkJsFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return walkJsFiles(path);
    return path.endsWith(".mjs") ? [path] : [];
  });
}

test("the repo-wide empty-catch count is pinned exactly at its ceiling", () => {
  const perFile = [];
  let total = 0;
  for (const file of [...walkJsFiles(join(ROOT, "packages")), ...walkJsFiles(join(ROOT, "bin")), ...walkJsFiles(join(ROOT, "scripts"))]) {
    const violations = checkSwallowedExceptions(readFileSync(file, "utf8"), file).violations.length;
    if (violations > 0) {
      total += violations;
      perFile.push(`${violations} ${file.slice(ROOT.length + 1)}`);
    }
  }
  assert.ok(
    total === CEILING,
    `MP-003 violation count is ${total}, but CEILING pins it at ${CEILING}.\n` +
      "An empty catch is refused unless it carries `// mp-003-allow: <reason>`.\n" +
      "If it grew: fix the new violations, or annotate them with a real reason.\n" +
      `Current offenders:\n${perFile.sort().join("\n")}\n` +
      `If it dropped: lower CEILING to ${total} so the count can never grow back.`,
  );
});
