// scripts/opencode-run.mjs — Programmatic OpenCode CLI wrapper for dual-model delegation.
import { spawn } from "node:child_process";

const model = process.argv[2] || "zai/glm-5.3";
const prompt = process.argv.slice(3).join(" ");

if (!prompt) {
  process.stderr.write("Usage: node scripts/opencode-run.mjs [model] [prompt...]\n");
  process.exit(1);
}

const args = ["run", "-m", model, "--auto", prompt];
const cp = spawn("opencode.cmd", args, {
  stdio: ["ignore", "inherit", "inherit"],
  shell: true,
});

cp.on("close", (code) => {
  process.exit(code ?? 0);
});
