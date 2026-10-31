// packages/queue — job queue, leases and dispatch.
// W1 ships this as a minimal stub; the W5 work package replaces the body of
// main() with the real CLI. The JSON contract below
// (`{ "tool": "queue", "status": "stub" }`) is what `--help` and `status`
// must emit until then.
import { EXIT_CODES } from "../core/index.mjs";

/** Tool name reported by this package. */
export const TOOL = "queue";

/**
 * CLI entrypoint.
 * @param {string[]} argv - arguments after the program name
 * @returns {number} process exit code (see EXIT_CODES)
 */
export function main(argv = []) {
  void argv; // stub: every invocation reports the stub contract
  process.stdout.write(JSON.stringify({ tool: TOOL, status: "stub" }) + "\n");
  return EXIT_CODES.OK;
}

export default main;
