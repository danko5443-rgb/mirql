/**
 * Law 3 — Single-Writer ACL.
 *
 * Every ledger event type has exactly one writer namespace permitted to emit
 * it. This table is the canonical grant list; `validateDocument` refuses any
 * event whose (writer.ns, type) pair is not granted here.
 */
export const WRITER_ACL = Object.freeze({
  /** Queue: jobs, factory bookkeeping, mirql internal state. */
  "tool:queue": /^(job|factory|mirql)\.[a-z_]+$/,
  /** Run supervisor: attempts, probes and warrants it issues. */
  "tool:run_supervisor": /^(attempt|probe|warrant)\.[a-z_]+$/,
  /** Log tool: the append-only ledger itself. */
  "tool:log": /^ledger\.[a-z_]+$/,
  /** Inbox tool: human-facing events it records. */
  "tool:inbox": /^human\.[a-z_]+$/,
  /** The human owner, via any medium. */
  "human:owner": /^human\.[a-z_]+$/,
  /** The mergeproof notary: verdicts and promotions. */
  "notary:mergeproof": /^(verdict|promotion)\.[a-z_]+$/,
  /** Lifeguard daemon: may only ever roll things back. */
  "daemon:lifeguard": /^(promotion|factory|mirql)\.rollback$/,
});

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
  const pattern = WRITER_ACL[writerNs];
  if (!pattern) return false; // unknown writer namespace: deny by default
  return pattern.test(eventType);
}
