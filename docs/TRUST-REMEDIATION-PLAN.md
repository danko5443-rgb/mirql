# Trust Remediation Plan

Execution checkpoint on 2 November 2026. Phase 0 code and the original issue fixes have landed.
Item 1.4, disposable worker homes, and the breaker recovery follow-up have also landed.
Item 1.1 is implemented on the external-trust-root branch and requires review.
Item 1.2 is implemented on the signed-key-enrollment branch for review. Item 1.3, Windows ACL enforcement, is implemented on the private-credential-permissions
branch for review. The later authority, proof, telemetry, isolation and consolidation phases remain open. The owner chose
to keep the repository private and leave the unavailable main ruleset requirement open.
The historical status table below records the original audit, rather than current completion.


Goal: make mirql's core promise ("nothing auto-merges without real, unforgeable
proof") true, in that order of priority, before adding any new law or feature.

All `file:line` references are against `main` at `b8ca4f1` (re-checked
2026-11-02, after PRs #19 and #28).

## Status on main (b8ca4f1)

Each exploit was re-run against `main`, not just read.

| Finding | Status | Evidence |
|---------|--------|----------|
| `mirql m check` stub exits 0 | **Fixed** | No input → `USAGE_ERROR`, exit 2. (`m --help` still says `status: stub`.) |
| Forged PR doc auto-merges a protected file | **Open** | `{"proof":{"causal_cycle_completed":true},"phi":{"delta_phi":0}}` touching `packages/core/acl.mjs` → `auto_merge` MP-000, exit 0. So does `suite_pass_base`+`suite_pass_head` = true. In CI the doc is built by `ci-evidence.mjs`, so this hits local/agent use. |
| Tautological reproducer | **Open** | `existsSync` reproducer in git mode → `verified: true`, `auto_merge`. |
| Ledger forged without a keyring | **Open** | `mirql l verify` → `valid: true`, exit 0 (`packages/log/index.mjs:280` trusts the key in the `keyId`). |
| **NEW: the PR controls its own test runner** | **Open, critical** | Simulated CI locally: candidate replaced `scripts/run-tests.mjs` with `process.exit(0)` and truncated `packages/inbox/send.mjs`. Base-notary's `ci-evidence` reported base=true, head=true, ΔΦ=−305 → `m check` = `auto_merge`, exit 0. Real tests on that head: 0 pass, 1 fail. Causes: `.github/workflows/mergeproof.yml:48` runs the **candidate's** runner; `scripts/**` is not protected; `evaluator.mjs:566-569` accepts a suite pass with no causal proof (contradicts Law 16). |
| **NEW: the PR controls its own workflow** | **Open (reasoned, not run)** | `pull_request` runs the PR's copy of `mergeproof.yml`, so a PR can delete the `m check` step. The `humanOnly` rule for `.github/**` is enforced by that same workflow. No `CODEOWNERS`, no ruleset. |
| Causal proof unlocks humanApprove paths | **Open** | `evaluator.mjs:496-501`, `anti-cheat.mjs:207-214`. |
| Fixture mode can return `auto_merge` | **Open** | `verify.mjs:157-167`. |
| Default refs `HEAD~1`, `fullTestCmd` = reproducer, `isTestPath` regex | **Open** | `verify.mjs:224`, `:227`, `:249`. |
| Re-Red repeats Red | **Open** | `verify.mjs:337-339` vs `:408-410`. |
| `warrantId` alone fabricates a `human:owner` warrant | **Open** | `supervisor.mjs:91-103`. |
| Fake SHAs / cost | **Mostly fixed** (#16) | Tree digest and git HEAD are measured; cost is `measured: 0` when unknown. `baseSha` still falls back to `headSha` (`supervisor.mjs:322-325`). |
| ΔΦ always 0 | **Open** | `supervisor.mjs:299-300`: `verified ? realPhi : realPhi`. |
| Keyring auto-enrolment | **Open** | `run/ledger.mjs:130-136`. |
| Agent gets `HOME`/`USERPROFILE`, `shell: true` | **Open** | `agent.mjs:16-17`, `:95`. |
| Four ledger implementations | **Open** | `log/index.mjs`, `run/ledger.mjs`, `inbox/ledger.mjs`, `mergeproof/notary.mjs`. |
| Empty `catch {}` blocks | **Open** | 63 across 11 files (worst: `queue/ledger.mjs`, `run/supervisor.mjs` with 6 each). |

---

Ground rules for every PR in this plan:

1. **Exploit first.** Each PR starts by adding the attack as a failing test in
   `tests/adversarial.test.mjs`. The PR is done when that test passes and no
   other test regresses. (This is the project's own Red → Green rule applied
   to itself.)
2. **No self-reported evidence on the merge path.** Anything the change author
   or agent can write (fixture fields, booleans, Φ values, commands) may be
   *logged*, never *trusted*.
3. **Fail closed when unsure.** Missing data → `needs_human`, never `auto_merge`.
4. **A different reviewer than the implementer**, ideally a human for Phases
   0–2. Agent-reviews-agent rounds are what produced the current gaps.
5. Regex anti-cheat (MP-002..MP-005) is a **lint**, not a security boundary.
   Security comes from Phases 1–3. Docs must say so.

---

## Phase 0 — Fail closed today (½–1 day, one PR)

Stops every confirmed exploit from reaching `auto_merge`, even before the real
fixes land. Expect some conformance fixtures to change expectation.

| # | Gap | Location | Change |
|---|-----|----------|--------|
| 0.0a | **The PR runs its own test runner** | `.github/workflows/mergeproof.yml:48` | Run the head suite with the **base-notary's** runner against the head checkout (`node ../base-notary/scripts/run-tests.mjs --root .`), so the candidate can't swap the runner. Also add `scripts/**` and `bin/**` to `humanOnly` in `policy/paths.yaml`. |
| 0.0b | **Suite pass alone yields `auto_merge`** | `packages/mergeproof/evaluator.mjs:563-569` | A suite pass without `causal_cycle_completed` → `needs_human` (rule `NO_CAUSAL_PROOF`), never `auto_merge`. Law 16 already requires this. Since CI always sends `causal_cycle_completed: false`, CI's best verdict becomes `needs_human` until Phase 3. That is the honest result today. |
| 0.0c | **The PR controls its own workflow** | GitHub settings, `.github/` | Not fixable in code. Add a repository ruleset on `main` that requires the `mergeproof` check, a PR review, and no bypass; add `.github/CODEOWNERS` with `.github/** policy/** scripts/** @ahmed-3m`, and require code-owner review. Done in the GitHub UI by the owner. |
| ~~0.1~~ | ~~`mirql m check` stub exits 0~~ | — | **Fixed on main.** Keep the regression test. Fix the stale `status: stub` in `m --help`. |
| 0.2 | Fixture/doc mode returns `auto_merge` from self-reported `proof.*` | `packages/run/verify.mjs:157-167`; `packages/mergeproof/evaluator.mjs:566-580` via `mirql m check --pr <file>` | A doc that was not built by the notary may only return `verdict:"conformance_pass"` (new verdict). `auto_merge` is reachable **only** from `verifyGitRepository`, or from `m check` when the doc carries a notary signature (Phase 2). Update conformance tests to expect `conformance_pass`. |
| 0.3 | Causal proof or a boolean unlocks humanApprove paths | `packages/mergeproof/evaluator.mjs:496-501`; `packages/run/anti-cheat.mjs:207-214`; `packages/run/verify.mjs:295` | Delete the `hasCausalProof`, `input.human_approved`, `input.human_approval`, `evidence.human_approval` escape hatches. Touching a humanApprove path → always `needs_human` until Phase 2 adds signed approvals. |
| 0.4 | Verifier trusts the key embedded in the event when no keyring exists | `packages/log/index.mjs:280-283` | No keyring → return `null` (verification fails), unless tests pass an explicit `conformance: true` option. `mirql l verify` without a keyring exits non-zero with a clear message. |
| 0.5 | Default refs `HEAD~1`/`HEAD` resolved inside the moved worktree | `packages/run/verify.mjs:224` | `git rev-parse --verify <ref>^{commit}` in `repoDir` before creating the worktree; use the absolute SHAs from then on. |
| 0.6 | `gitWt checkout` results ignored | `packages/run/verify.mjs:337,339,373,408,410` | Check `status`; any non-zero → `reject` with rule `CHECKOUT_FAILED`. |

**Acceptance (adversarial tests that must pass):**
- CI simulation: a head whose `scripts/run-tests.mjs` is `process.exit(0)` and whose real tests fail → head suite fails, verdict not `auto_merge`.
- A PR doc with `suite_pass_base` + `suite_pass_head` and no causal proof → `needs_human`.
- `mirql m check` with no input exits non-zero (already true; keep it).
- Forged one-line PR doc touching `packages/core/acl.mjs` → not `auto_merge`.
- `human_approved: true` on a humanApprove path → `needs_human`.
- Attacker-signed `warrant.created` as `human:owner`, no keyring → `mirql l verify` fails.
- Default refs work on a 2-commit repo.

---

## Phase 1 — Trust root out of the agent's reach (1–2 days)

| # | Gap | Location | Change |
|---|-----|----------|--------|
| 1.1 | `.mirql/` (keys + keyring) defaults to inside the agent workspace | `packages/run/supervisor.mjs:37`, `:540` | Introduce a **trust root** directory, resolved from `MIRQL_TRUST_ROOT` or `~/.mirql-trust/`, refused if it is inside `workspaceDir` or any git worktree (check with `path.relative` + `git rev-parse --show-toplevel`). Machine keys and the keyring move there. The workspace keeps only the event log. |
| 1.2 | Keyring is an editable file; keys auto-enrol | `packages/run/ledger.mjs:120-136` (`getOrGenerateSupervisorKey` keyring sync) | Remove auto-enrolment. Keyring becomes `keyring.json` + `keyring.sig`, signed by the `human:owner` key (already kept outside `.mirql/keys` by `packages/inbox/keys.mjs`). Verifier checks `keyring.sig` against a **pinned** human public key (trust-root config or `--human-key` flag). New command `mirql i enroll-key <ns> <pubkey>` that requires the human key to re-sign. |
| 1.3 | `0o600` is a no-op on Windows | `packages/inbox/keys.mjs` | On `win32`, set an owner-only ACL with `icacls` (or refuse to create keys in a directory readable by other users) and warn loudly if it can't be enforced. |
| 1.4 | Agent env still exports `HOME`/`USERPROFILE` | `packages/run/agent.mjs:16-17` | Point `HOME`/`USERPROFILE` at a fresh temp dir per run. (Real isolation is Phase 5; this just stops casual reads of `~/.ssh` and the trust root.) |

**Acceptance:**
- Adding a key to `keyring.json` by hand → verification fails (bad `keyring.sig`).
- Supervisor refuses a trust root located inside the workspace.
- An agent command `cat $HOME/.ssh/*` (or `type %USERPROFILE%\...`) finds nothing.

---

## Phase 2 — Human authority is a signature, not a field (1–2 days)

| # | Gap | Location | Change |
|---|-----|----------|--------|
| 2.1 | Warrants are schema-checked only; `warrantId` alone fabricates a `human:owner` warrant | `packages/run/supervisor.mjs:91-103` | Remove the fabrication branch. The supervisor accepts a warrant **only** by looking up a `warrant.created` event in the ledger whose signature verifies against the keyring entry for `human:owner`. |
| 2.2 | No signed approval for humanApprove paths | `packages/run/anti-cheat.mjs` MP-005 block | New event type `merge.approved` (schema in `schemas/`, writer ACL: `human:owner` only), binding `{ warrant_id, base_sha, head_sha, tree_sha, paths[] }`. Anti-cheat allows a humanApprove path only if such a verified event exists for the **exact** head/tree SHA. |
| 2.3 | `humanOnly` check runs before the agent, on a caller-supplied list | `packages/run/agent.mjs:77-79` | After the agent runs, compute changed files from git (`git diff --name-status base..HEAD` plus untracked files) and run the humanOnly check on **that** list. Keep the pre-check as an early-out only. |

**Acceptance:**
- `runSupervisor({ warrantId: "x" })` with no ledger warrant → throws.
- An approval signed by any non-human key → `needs_human`.
- An approval for head A doesn't unlock head B.
- An agent that edits `policy/paths.yaml` despite an empty `modifiedFiles` → rejected.

---

## Phase 3 — An honest causal proof (2–4 days)

All in `packages/run/verify.mjs` (`verifyGitRepository`).

| # | Gap | Change |
|---|-----|--------|
| 3.1 | Red-on-base (`:337-339`) and Re-Red (`:408-410`) run the same experiment (base tree + head tests), although the header comment at `:22` says Re-Red reverts the non-test changes | Replace Re-Red with a **necessity check**. For each non-test file the head changed (cap N, e.g. 10; above that, `needs_human`), take the head tree with only that file reverted to base and run the reproducer. At least one revert must turn it red; files whose revert keeps it green are reported as `UNNECESSARY_CHANGE` (lint, or reject for the `surgical` warrant class). Rename evidence fields accordingly; stop calling it a "triple". |
| 3.2 | Reproducer command is caller-supplied (tautology exploit) | The reproducer is a **test file added or changed in the diff**, run by a fixed runner (`node --test <file>`), never an arbitrary shell string. Keep `reproducerCommand` for conformance only. |
| 3.3 | Reproducer needn't touch the fix | Run Green with `NODE_V8_COVERAGE=<tmp>` and require that the reproducer executes at least one changed line in a non-test source file. Zero-dep: parse the V8 coverage JSON, map byte ranges to the diff hunks. No coverage of the change → `REPRODUCER_IRRELEVANT`, reject. |
| 3.4 | `fullTestCmd` defaults to the reproducer (`:227`) | The full suite is the repo's `npm test`, run on head as its own required stage. It must pass. |
| 3.5 | "exit 1 = assertion" is unreliable (`:367`, `:443`, and the copies at `:601`, `:652`, `:709`, `:762`) | Use `--test-reporter=tap` and parse `# fail` / `not ok` plus the presence of an `AssertionError`/`ERR_ASSERTION` in the failure diagnostics. Distinguish assertion failure, crash and timeout explicitly. |
| 3.6 | `isTestPath = /test\|spec/i` (`:249`) | Match a path segment or suffix: `^tests?/`, `/__tests__/`, `\.(test\|spec)\.[cm]?[jt]s$`. Share one helper with `anti-cheat.mjs`. |
| 3.7 | Sync and async `runCheck` are copy-pasted | Keep one async implementation; the sync API wraps it or is dropped. |
| 3.8 | Determinism | Run Red and Green twice each; differing results → `FLAKY_REPRODUCER`, reject. |

**Acceptance:**
- The `src/marker.mjs` tautology reproducer → reject (`REPRODUCER_IRRELEVANT`, or not a test file).
- A PR that adds a real fix plus an unrelated file → `UNNECESSARY_CHANGE` reported.
- A reproducer that throws a `TypeError` on base → `RED_ON_BASE_CRASH`, not "red".
- A flaky reproducer (random pass) → reject.

---

## Phase 4 — Truthful records and a usable Φ (1–2 days)

| # | Gap | Location | Change |
|---|-----|----------|--------|
| 4.1 | `baseSha` falls back to `headSha` (head and tree are now measured, #16) | `packages/run/supervisor.mjs:322-325` | Record the lease-start base from `git rev-parse` when the warrant is leased and pass it through. If unavailable → throw rather than record head as base. |
| ~~4.2~~ | ~~`cost = duration * 10`~~ | — | **Fixed on main** (#16): cost is `{ measured: 0 }` when unknown. |
| 4.3 | ΔΦ is always 0 (`phiAfter = verified ? realPhi : realPhi`) | `packages/run/supervisor.mjs:299-300` | Compute Φ from the **git trees** at base and head (in the verify worktree), not the live workspace. Ignore caller-supplied Φ outside conformance mode. |
| 4.4 | Φ counts tests, and "never increase" blocks all features | `packages/run/phi.mjs`, `CONSTITUTION.md` Law 13 | Constitution amendment: Φ excludes `tests/`, `conformance/`, `*.test.*`. Law 13 becomes "ΔΦ ≤ `warrant.phi_budget`", with budget 0 by default and set by the human in the signed warrant. Consolidator keeps "strictly decreasing". |
| 4.5 | `deltaPhi === undefined` passes | `packages/run/verify.mjs:80-92` | In git mode, undefined ΔΦ → reject (`PHI_UNMEASURED`). |
| 4.6 | Consolidator detected by `author.includes("consolidator")` | `packages/run/verify.mjs:90`; `packages/mergeproof/evaluator.mjs:517` | Derive the role from the warrant's `class` (now signed), not from a string. |

**Acceptance:**
- Ledger `head_sha` equals `git rev-parse HEAD`.
- A feature PR within its warrant budget passes; one over budget is rejected.
- Adding a reproducer test never changes Φ.

---

## Phase 5 — Real isolation for the agent (2–5 days, decision needed)

`packages/run/agent.mjs:95` runs `spawnSync(..., { shell: true })` with the
user's full privileges and network access.

Pick one (recommendation first):

1. **Docker/Podman runner.** Use `--network none`, `--read-only` with a tmpfs workdir, the repo copied in (not bind-mounted), no host home, and a non-root user. Changes come back as a `git bundle`/patch the supervisor applies in its own worktree. Works on Windows via Docker Desktop/WSL2.
2. **Separate OS user** that has no access to the trust root, plus a firewall rule. Weaker, but needs no container runtime.
3. **No isolation, said honestly.** A config `sandbox: "none"` forces every result to `needs_human`. Docs state "trusted agents only".

In all cases: `sandbox: "none"` must never yield `auto_merge`.

**Acceptance:**
- The agent can't read the trust root.
- The agent can't open an outbound socket.
- The agent's edits outside the workspace copy don't reach the host.

---

## Phase 6 — Consolidation and honesty (ongoing, after 0–3)

| # | Item | Change |
|---|------|--------|
| 6.1 | Four ledger implementations (`packages/log`, `run`, `inbox`, `mergeproof/notary.mjs`; `GENESIS_PREV_HASH` duplicated) | One ledger module (keep `packages/log` as canonical, or move it into `packages/core`); the others import it. Every reader verifies signatures and the hash chain. That makes Law 4 true. |
| 6.2 | O(n²) append, no chain check before append | Keep a signed `head` sidecar (last seq + hash). Verify it on open; append in O(1). Run a full `verify` on startup and on demand. |
| 6.3 | Racy stale-lock break in `packages/core/lock.mjs` | Break a stale lock by atomic `rename` to a unique tombstone, then retry `open(wx)`. Only the process whose rename succeeded proceeds. Verify the PID/hostname recorded in the lock. |
| 6.4 | 43 MP-003 violations in 15 files (measured on 4655b81; main has 63 empty `catch {}` blocks, re-measure) (worst: `core/lock.mjs`, `run/anti-cheat.mjs`, `queue/ledger.mjs`, `inbox/keys.mjs`) | Fix them or annotate them with a justified `// mp-003-allow: <reason>`. Add `node scripts/self-check.mjs` to `npm test` so the repo passes its own rules. |
| 6.5 | The referee is editable by agents | Add to `humanOnly`: `packages/run/anti-cheat.mjs`, `packages/run/verify.mjs`, `packages/run/phi.mjs`, `policy/**`, `roles/**` (`scripts/**` and `bin/**` move to Phase 0.0a), `conformance/**`, `schemas/**`. Add to `humanApprove`: modifying an existing file under `tests/**` (adding new test files stays allowed). |
| 6.6 | MP-003/MP-005 are trivially bypassed (`catch(e){ e; }`, early `return;`) | Keep them as lints and document them as such. Optionally strengthen them (a catch must rethrow, log, or return a typed error), but don't spend more effort here than on Phases 1–3. |
| 6.7 | Docs promise Lifeguard, a speechless sandbox, an isolated notary and Sigstore | Add a README "Status" table (implemented / partial / planned) per law and per tool, and keep it updated in each PR. Move unbuilt guarantees into a "Planned" section. |

---

## Order and dependencies

```
Phase 0 ──► Phase 1 ──► Phase 2 ──┐
   │                              ├──► Phase 4 ──► Phase 6
   └────────► Phase 3 ────────────┘
Phase 5 can start after Phase 1, in parallel with 2–4.
```

- **Phase 0 blocks everything** and should land first, on its own.
- Phases 1 and 3 touch different files and can run in parallel.
- Phase 2 needs Phase 1's pinned human key.
- Phase 4.3 needs Phase 3's verify worktree. Phase 4.6 needs Phase 2's signed warrant.

## Definition of done for the whole plan

All exploits from the review are permanent regression tests and pass:

1. stub `mergeproof` exit 0 (fixed on main; keep the test),
2. forged fixture auto-merging a protected file,
3. tautological reproducer,
4. ledger forged without a keyring,
5. a PR that replaces `scripts/run-tests.mjs` with `process.exit(0)` and breaks real code.

And the `main` ruleset (0.0c) is in place, so a PR can't remove the check that judges it.

On top of that:
- An end-to-end test runs a real bug-fix PR through `mirql r` → `mirql m check` → `auto_merge`, with a real Red, Green, necessity and coverage proof, real SHAs, and a ledger that `mirql l verify` accepts against the pinned keyring.
- A human, not an agent, has reviewed Phases 0–2.
