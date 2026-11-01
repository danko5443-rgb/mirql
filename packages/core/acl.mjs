/**
 * Law 3 — Single-Writer ACL.
 *
 * Every ledger event type has an authorized writer namespace permitted to emit
 * it. This table is the canonical grant list; `validateDocument` refuses any
 * event whose (writer.ns, type) pair is not granted here.
 */
export const WRITER_ACL = Object.freeze(
  Object.assign(Object.create(null), {
    /** Queue: jobs, factory bookkeeping, mirql internal state. */
    "tool:queue": /^(job|factory|mirql)\.[a-z_]+$/,
    /** Run supervisor: attempts, probes, warrants it issues, and job lifecycle. */
    "tool:run_supervisor": /^(attempt|probe|warrant)\.[a-z_]+$/,
    /** Log tool: the append-only ledger itself (both ledger.* and log.* prefixes). */
    "tool:log": /^(ledger|log)\.[a-z_]+$/,
    /** Inbox tool: human-facing events it records. */
    "tool:inbox": /^(human|inbox)\.[a-z_]+$/,
    /** The human owner, via any medium. */
    "human:owner": /^(?:human\.[a-z_]+|warrant\.(?:created|revoked)|mirql\.(?:genesis|halt|resume)|factory\.resumed)$/,
    /** The mergeproof notary: verdicts, promotions, and merges. */
    "notary:mergeproof": /^(verdict|promotion|merge)\.[a-z_]+$/,
    /** Lifeguard daemon: out-of-band health, circuit breakers, and rollbacks. */
    "daemon:lifeguard": /^(?:lifeguard\.[a-z_]+|(?:promotion|factory|mirql)\.rollback|factory\.resumed|mirql\.resume)$/,
  }),
);

/**
 * May `writerNs` emit an event of type `eventType`?
 *
 * @param {unknown} writerNs e.g. "tool:queue"
 * @param {unknown} eventType e.g. "job.enqueued"
 * @returns {boolean}
 */
export function canWriteEvent(writerNs, eventType) {
  if (typeof writerNs !== "string" || typeof eventType !== "string") {
    return false;
  }
  if (!Object.hasOwn(WRITER_ACL, writerNs)) return false;
  const pattern = WRITER_ACL[writerNs];
  if (!pattern) return false; // unknown writer namespace: deny by default
  return pattern.test(eventType);
}
