/**
 * @mirql/core — deterministic primitives for the mirql factory.
 *
 * Public surface (all pure Node.js, zero dependencies):
 * - `EXIT_CODES`            canonical process exit codes
 * - `jcs`                   RFC 8785 canonical JSON + Law 17 integer-only
 * - `sha256`, `jcsHash`     content addressing (`"sha256:<64 hex>"`)
 * - `ulid`, `isValidUlid`, `ULID_ALPHABET`  monotonic ids
 * - `hlcTick`, `compareHlc` hybrid logical clocks
 * - `generateEd25519Keypair`, `computeEventHash`, `signEvent`, `verifyEvent`
 * - `WRITER_ACL`, `canWriteEvent`           Law 3 single-writer grants
 * - `validateDocument`, `loadSchema`, `SCHEMA_KINDS`  canonical contracts
 * - `withLedgerLock`, `acquireLock`, `releaseLock`   multi-process ledger lockfile
 */

export { EXIT_CODES } from "./exit-codes.mjs";
export { jcs } from "./jcs.mjs";
export { sha256, jcsHash } from "./hash.mjs";
export { ulid, isValidUlid, ULID_ALPHABET } from "./ulid.mjs";
export { hlcTick, compareHlc } from "./hlc.mjs";
export {
  generateEd25519Keypair,
  computeEventHash,
  signEvent,
  verifyEvent,
} from "./ed25519.mjs";
export { WRITER_ACL, canWriteEvent } from "./acl.mjs";
export { validateDocument, loadSchema, SCHEMA_KINDS } from "./schema.mjs";
export { withLedgerLock, acquireLock, releaseLock } from "./lock.mjs";
export {
  DEFAULT_HUMAN_ONLY_PATTERNS,
  DEFAULT_HUMAN_APPROVE_PATTERNS,
  normalizePath,
  isPathMatchingPattern,
  loadPathPolicies,
  isHumanOnlyPath,
  isHumanApprovePath,
  extractBalancedBlock,
  isEffectivelyEmpty,
  checkSwallowedExceptions,
  checkTestWeakenings,
} from "./anti-cheat.mjs";

