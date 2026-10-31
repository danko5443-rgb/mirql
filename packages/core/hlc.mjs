/**
 * Hybrid logical clocks (HLC): a total-orderable timestamp that never goes
 * backwards even when wall clocks drift. Used to order events in the ledger
 * across writers without a central clock.
 *
 * An HLC stamp is `{ wall_ms, logical, node }`; stamps compare by wall_ms,
 * then logical, then node id.
 */

/**
 * Produce the next HLC stamp after `prevHlc`.
 *
 * @param {{ wall_ms: number, logical: number, node: string } | null | undefined} prevHlc
 *   The last stamp this node observed (its own or remote). Null/undefined
 *   starts a fresh clock.
 * @param {number} [wallMs] Wall-clock milliseconds (defaults to Date.now()).
 * @param {string} [node] Node identifier (defaults to "local").
 * @returns {{ wall_ms: number, logical: number, node: string }} frozen stamp
 * @throws {RangeError} if wallMs is not a non-negative safe integer.
 */
export function hlcTick(prevHlc, wallMs = Date.now(), node = "local") {
  if (typeof node !== "string" || node.length === 0) {
    throw new TypeError("hlcTick: node must be a non-empty string");
  }
  const wall = Math.floor(Number(wallMs));
  if (!Number.isSafeInteger(wall) || wall < 0) {
    throw new RangeError(
      `hlcTick: wallMs ${wallMs} is not a non-negative safe integer`,
    );
  }

  const prevWall = prevHlc ? prevHlc.wall_ms : 0;
  const wallMsOut = Math.max(prevWall, wall);
  // Same millisecond as the previous tick? Then count logical ticks; a new
  // millisecond resets the counter.
  const logical =
    prevHlc && wallMsOut === prevHlc.wall_ms ? (prevHlc.logical ?? 0) + 1 : 0;

  return Object.freeze({ wall_ms: wallMsOut, logical, node });
}

/**
 * Compare two HLC stamps: by wall_ms, then logical, then node.
 *
 * @param {{ wall_ms: number, logical: number, node: string }} a
 * @param {{ wall_ms: number, logical: number, node: string }} b
 * @returns {-1 | 0 | 1}
 */
export function compareHlc(a, b) {
  if (a.wall_ms !== b.wall_ms) return a.wall_ms < b.wall_ms ? -1 : 1;
  if (a.logical !== b.logical) return a.logical < b.logical ? -1 : 1;
  if (a.node !== b.node) return a.node < b.node ? -1 : 1;
  return 0;
}
