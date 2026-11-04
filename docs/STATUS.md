# mirql Status Matrix

Honest, per-law and per-tool implementation status (Phase 6.7). This table is
normative for every PR: update it when status changes, and never claim
`Implemented` for a guarantee that is not enforced by code plus a regression
test. "Partial" means the law's mechanism exists but a documented gap remains.

## Table 1 — The 17 Normative Laws (CONSTITUTION.md)

| Law | Name | Status | Code pointers |
|-----|------|--------|---------------|
| Law 1 | Offline Litmus | Implemented | `package.json` (zero dependencies), `tests/structure.test.mjs` |
| Law 2 | Lifeguard Law | Implemented | `packages/run/supervisor.mjs`, `tests/lifeguard-rollback.test.mjs` |
| Law 3 | Roles Propose / Tools Author | Implemented | `packages/core/acl.mjs` (`WRITER_ACL`), `packages/core/schema.mjs` (event `writer`) |
| Law 4 | One Durable Ledger | Implemented | `packages/log/index.mjs`, `packages/core/ledger-verify.mjs` (canonical `GENESIS_PREV_HASH`, O(1) `head.json` sidecar authenticating the full `events.jsonl` via `events_sha256`, `verifyChainBeforeAppend`), all five writers: `packages/run/ledger.mjs`, `packages/queue/ledger.mjs`, `packages/mergeproof/notary.mjs`, `packages/inbox/ledger.mjs` |
| Law 5 | Base-Pinned Mortal Verdicts | Implemented | `packages/mergeproof/evaluator.mjs` (MP-004 `STALE_BASE`) |
| Law 6 | Silence Is Never Consent | Implemented | `packages/mergeproof/evaluator.mjs` (MP-005 `UNCITED_SURFACE`, `MISSING_PHI` fail-closed) |
| Law 7 | Notary Outside Blast Radius | Implemented | `packages/mergeproof/notary.mjs`, `packages/mergeproof/evaluator.mjs` (`getGitDiffInfo` git cross-check, `LAW_7` fail-closed) |
| Law 8 | Speechless Sandboxes | Implemented | `packages/run/agent.mjs` (`buildContainerArgs`: `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, uid 65534; `SANDBOX_UNAVAILABLE` fail-closed), `packages/run/verify.mjs` + `packages/mergeproof/evaluator.mjs` (`UNSANDBOXED_EXECUTION`: `sandbox: "none"` never yields `auto_merge`) |
| Law 9 | N-1 Processes N | Partial | `packages/queue/index.mjs` (tick/lease pipeline, `withLedgerLock`); multi-node N-1 throughput is not yet exercised by tests |
| Law 10 | Ship Invariants Not Features | Implemented | `surface.lock`, `bin/mirql.mjs` (`m check --surface`), `schemas/*.schema.json` |
| Law 11 | No Warrant No Work | Implemented | `packages/core/warrant.mjs` (`requireAuthorizedWarrant`), `packages/queue` (submit/lease gates) |
| Law 12 | The Probe Doctrine | Implemented | `packages/run/supervisor.mjs` (probes), `packages/run/doctor.mjs`, `tests/m5-doctor.test.mjs` |
| Law 13 | Monotone Potential PHI & Thrift Test | Implemented | `packages/run/phi.mjs`, `packages/run/authorized-phi.mjs` (signed cumulative budget), `packages/mergeproof/evaluator.mjs` (`LAW_13` rules) |
| Law 14 | Quiescence Is Success | Partial | `packages/run/supervisor.mjs` (idle handling); explicit quiescence accounting is not surfaced as a projection |
| Law 15 | Semantic Identity / Mechanical Location | Partial | `packages/core/warrant.mjs` (`semantic_fingerprint`, anchors); full mechanical-location resolution pending |
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
| Phase 6.2 | O(1) verified head sidecar + fail-closed pre-append chain verification | Implemented |
| Phase 6.3 | Stale-lock break hardening in `packages/core/lock.mjs` (atomic rename tombstone + PID/nonce verification) | Implemented |
| Phase 6.4 | MP-003 empty-catch cleanliness (self-check + `// mp-003-allow: <reason>` convention) | Partial — files touched by Phase 5–6 are clean; a repo-wide sweep remains |
| Phase 6.5 | Referee path protection (`policy/paths.yaml` `humanOnly`/`humanApprove` coverage) | Implemented |
| Phase 6.6 | MP-003/MP-005 documented as lints, optional strengthening | Partial — documented in `packages/core/anti-cheat.mjs`; strengthening open |
| Phase 6.7 | Honest per-law/per-tool status matrix (this document) | Implemented |
