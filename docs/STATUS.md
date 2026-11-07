# mirql Status Matrix

Honest, per-law and per-tool implementation status (Phase 6.7). This table is
normative for every PR: update it when status changes, and never claim
`Implemented` for a guarantee that is not enforced by code plus a regression
test. "Partial" means the law's mechanism exists but a documented gap remains.

## Table 1 — The 17 Normative Laws (CONSTITUTION.md)

| Law | Name | Status | Code pointers |
|-----|------|--------|---------------|
| Law 1 | Offline Litmus | Implemented | `package.json` (zero dependencies), `tests/structure.test.mjs` (mechanical gates are strictly offline; PR Court LLM review in `scripts/pr-court.mjs` runs out-of-band after mechanical checks and fails closed if unreachable) |
| Law 2 | Lifeguard Law | Implemented | `packages/run/supervisor.mjs`, `tests/lifeguard-rollback.test.mjs` |
| Law 3 | Roles Propose / Tools Author | Implemented | `packages/core/acl.mjs` (`WRITER_ACL`), `packages/core/schema.mjs` (event `writer`), `scripts/pr-court.mjs` (`roles/critic.md`, `roles/advocate.md`, `roles/judge.md` emit JSON proposals; host tool validates, applies, commits, posts, and merges) |
| Law 4 | One Durable Ledger | Implemented | `packages/log/index.mjs`, `packages/core/ledger-verify.mjs` (canonical `GENESIS_PREV_HASH`, `head.json` tail cache with an unkeyed `events_sha256` digest, `verifyChainBeforeAppend` walks the whole chain on every append), all five writers: `packages/run/ledger.mjs`, `packages/queue/ledger.mjs`, `packages/mergeproof/notary.mjs`, `packages/inbox/ledger.mjs` |
| Law 5 | Base-Pinned Mortal Verdicts | Implemented | `packages/mergeproof/evaluator.mjs` (MP-004 `STALE_BASE`), `scripts/pr-court.mjs` (`landCourtMerge` verifies current base tip, green notary on `head_sha`, and `--match-head-commit`) |
| Law 6 | Silence Is Never Consent | Implemented | `packages/mergeproof/evaluator.mjs` (MP-005 `UNCITED_SURFACE`, `MISSING_PHI` fail-closed), `scripts/ci-review-gate.mjs` + `scripts/pr-court.mjs` (malformed/missing LLM output or receipts fail closed) |
| Law 7 | Notary Outside Blast Radius | Implemented | `packages/mergeproof/notary.mjs`, `packages/mergeproof/evaluator.mjs` (`getGitDiffInfo` git cross-check, `LAW_7` fail-closed), `.github/workflows/mergeproof-retrigger.yml` (`base-notary` scripts only; candidate checkout read strictly as text) |
| Law 8 | Speechless Sandboxes | Implemented | `packages/run/agent.mjs` (`buildContainerArgs`: `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, uid 65534; `SANDBOX_UNAVAILABLE` fail-closed), `packages/run/agent-workspace.mjs` (link-safe staging and sync-back; `WORKSPACE_ESCAPE`), `packages/run/verify.mjs` + `packages/mergeproof/evaluator.mjs` (`UNSANDBOXED_EXECUTION`: `sandbox: "none"` never yields `auto_merge`; git-mode verification has no container runner and refuses sandbox requests) |
| Law 9 | N-1 Processes N | Implemented | `packages/queue/index.mjs` (tick/lease pipeline, `withLedgerLock`); multi-node N-1 throughput exercised by `tests/law9-multinode.test.mjs` (child-process nodes drain jobs exactly once, mixed submit/lease/tick races keep one chain, a dead node's stale-epoch outcome is fenced) |
| Law 10 | Ship Invariants Not Features | Implemented | `surface.lock`, `bin/mirql.mjs` (`m check --surface`), `schemas/*.schema.json` |
| Law 11 | No Warrant No Work | Implemented | `packages/core/warrant.mjs` (`requireAuthorizedWarrant`), `packages/queue` (submit/lease gates) |
| Law 12 | The Probe Doctrine | Implemented | `packages/run/supervisor.mjs` (probes), `packages/run/doctor.mjs`, `tests/m5-doctor.test.mjs` |
| Law 13 | Monotone Potential PHI & Thrift Test | Implemented | `packages/run/phi.mjs`, `packages/run/authorized-phi.mjs` (signed cumulative budget), `packages/core/phi-warrant.mjs` + `scripts/ci-phi-warrant.mjs` (the signed budget in CI), `packages/mergeproof/evaluator.mjs` (`LAW_13` rules) |
| Law 14 | Quiescence Is Success | Partial | `packages/run/supervisor.mjs` (idle handling); explicit quiescence accounting is not surfaced as a projection |
| Law 15 | Semantic Identity / Mechanical Location | Implemented | `packages/core/warrant.mjs` (`semantic_fingerprint`, anchors), `tests/law15-identity.test.mjs` (a ledger copied to another path folds identically, and its persisted events and head sidecar never name the ledger's location; the same commit measured through two clones is the same Phi; the real `semantic_fingerprint` returns one id for identical intent and another for changed content — PID use in lock/heartbeat is liveness checking, not identity) |
| Law 16 | GREEN Must Be Causal | Implemented | `packages/run/verify.mjs` (Red-Green-ReRed, coverage, necessity), `packages/mergeproof/evaluator.mjs` (`NO_CAUSAL_PROOF`) |
| Law 17 | Per-Product Tenant Isolation & Integer-Only JCS | Implemented | `packages/core/jcs.mjs` (integer-only RFC 8785), `schemas/event.schema.json` (`tenant_id`) |

## Table 2 — The 5 CLI Tools and their surface-locked commands (`surface.lock`)

| Tool | Bin | Commands |
|------|-----|----------|
| mergeproof | `mirql` (`m`) | `mirql m check` |
| inbox | `mirql-inbox` (`i`) | `mirql i genesis`, `i enroll-key`, `i send`, `i digest`, `i act`, `i approve-merge`, `i protect-key`, `i propose` |
| run | `mirql-run` (`r`) | `mirql r supervisor`, `r agent`, `r verify`, `r probe`, `r bing-bong`, `r phi`, `r drift`, `r mutant`, `r flake`, `r doctor`, `r journey` |
| queue | `mirql-queue` (`q`) | `mirql q tick`, `q submit`, `q status`, `q promote`, `q halt`, `q resume` |
| log | `mirql-log` (`l`) | `mirql l append`, `l view`, `l replay`, `l verify`, `l snapshot` |

All 31 commands above are pinned in `surface.lock`; `mirql m check --surface`
rejects any uncited delta. Schemas pinned: `event/v1`, `warrant/v1`,
`job/v1`, `outcome/v1`.

## Table 3 — Trust Remediation Plan phases (`docs/TRUST-REMEDIATION-PLAN.md`)

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 0 | Fail closed today (no self-reported `auto_merge`, stub exits, suite-pass gate) | Implemented |
| Phase 1 | Trust root out of the agent's reach (external trust root, signed keyring, disposable homes) | Implemented |
| Phase 2 | Human authority is a signature (owner-signed merge approvals, key enrollment) | Implemented |
| Phase 3 | An honest causal proof (Red-Green-ReRed, out-of-band V8 coverage, necessity) | Implemented |
| Phase 4 | Truthful records and a usable Φ (measured SHAs/costs, git-tree Φ, warrant budgets) | Implemented |
| Phase 5 | Real isolation for the agent (container sandbox runner, `sandbox: "none"` gating) | Implemented |
| Phase 6.1 | Canonical ledger primitives (`GENESIS_PREV_HASH`, sidecar, chain verify in core; all five writers — `log`, `run`, `queue`, `notary`, `inbox` — wired to them) | Implemented |
| Phase 6.2 | Verified head sidecar + fail-closed pre-append verification of the whole chain (appends are O(n); `head.json` cannot vouch for earlier lines) | Implemented |
| Phase 6.3 | Stale-lock break hardening in `packages/core/lock.mjs` (atomic rename tombstone + PID/nonce verification) | Implemented |
| Phase 6.4 | MP-003 empty-catch cleanliness (self-check + `// mp-003-allow: <reason>` convention; a marker only exempts a catch unchanged from the asserted `--base`, so a candidate cannot approve its own) | Partial — files touched by Phase 5–6 are clean; a repo-wide sweep remains, and `scripts/ci-evidence.mjs` does not yet supply `sourceCode`, so the CI gate does not run this scan |
| Phase 6.5 | Referee path protection (`policy/paths.yaml` Courthouse Lock in `humanOnly` + engineering paths in `humanApprove` + `roles/judge.md` protected by `AI_REVIEWER_CONFIG_PATTERNS`) | Implemented |
| Phase 6.6 | MP-003/MP-005 documented as lints, optional strengthening | Partial — documented in `packages/core/anti-cheat.mjs`; strengthening open |
| Phase 6.7 | Honest per-law/per-tool status matrix (this document) | Implemented |
| PR Court | 3-Agent PR Court (`Critic` ↔ `Advocate` Ping-Pong → `Judge` in `scripts/pr-court.mjs`, `scripts/ci-review-gate.mjs`, `roles/{critic,advocate,judge}.md`, `.github/workflows/mergeproof-retrigger.yml`, `.github/workflows/mergeproof-review-signal.yml`, `docs/pr-court.md`) | Implemented |
