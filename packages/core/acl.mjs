/**
 * Law 3 — Single-Writer ACL.
 *
 * Every ledger event type has an authorized writer namespace permitted to emit
 * it. This table is the canonical grant list; `validateDocument` refuses any
 * event whose (writer.ns, type) pair is not granted here.
 * Note: factory.resumed is dual-writer with tool:queue per documented recovery policy.
 */
export const WRITER_ACL = Object.freeze(
  Object.assign(Object.create(null), {
    /** Queue: jobs, factory bookkeeping, mirql internal state. */
    "tool:queue": /^(job|factory|mirql)\.[a-z_]+$/,
    /** Run supervisor: attempts, probes and warrants it issues. */
    "tool:run_supervisor": /^(attempt|probe|warrant)\.[a-z_]+$/,
    /** Log tool: the append-only ledger itself (both ledger.* and log.* prefixes). */
    "tool:log": /^(ledger|log)\.[a-z_]+$/,
    /** Inbox tool: human-facing events it records. */
    "tool:inbox": /^(human|inbox)\.[a-z_]+$/,
    /** The human owner: direct human intervention (intents, approvals, genesis, halt, resume). */
    "human:owner": /^(human\.[a-z_]+|warrant\.(created|revoked)|mirql\.(genesis|halt|resume)|factory\.resumed|merge\.approved)$/,
    /** The mergeproof notary: verdicts, promotions, and merges. */
    "notary:mergeproof": /^(verdict|promotion)\.[a-z_]+$|^merge\.(?!approved$)[a-z_]+$/,
    /** Lifeguard daemon: out-of-band health, circuit breakers, and rollbacks. */
    "daemon:lifeguard": /^(lifeguard\.[a-z_]+|(promotion|factory|mirql)\.rollback)$/,
  }),
);

/**
 * Checks whether an event type is authorized for the given writer namespace
 * under Law 3 (Single-Writer Discipline).
 *
 * @param {string | null | undefined} writerNs writer namespace (e.g. "tool:queue")
 * @param {string | null | undefined} eventType event type (e.g. "job.enqueued")
 * @returns {boolean} true if authorized, false otherwise
 */
export function canWriteEvent(writerNs, eventType) {
  if (typeof writerNs !== "string" || typeof eventType !== "string") {
    return false;
  }
  const regex = WRITER_ACL[writerNs];
  if (!regex) return false;
  return regex.test(eventType);
}
