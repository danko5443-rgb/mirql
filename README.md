# mirql

> **m**ergeproof · **i**nbox · **r**un · **q**ueue · **l**og  
> 24/7 Autonomous, Proof-Driven AI Software Factory.

`mirql` is a zero-dependency, pure Node.js factory for autonomous software engineering. Built on strict cryptographic causality, append-only event ledgers, and tamper-resistant test gating, `mirql` ensures that AI coding agents cannot land code without mathematical and behavioral proof.

---

## Architectural Pillars

```text
 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 │    INBOX     │ ──► │    QUEUE     │ ──► │     RUN      │
 │ Human Intent │     │ Warrants &   │     │ Sandboxed    │
 │ & Proposals  │     │ Leases       │     │ Execution    │
 └──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                                  ▼
 ┌──────────────┐                         ┌──────────────┐
 │     LOG      │ ◄────────────────────── │  MERGEPROOF  │
 │ Immutable    │    Proved Outcomes      │ Causal Gate  │
 │ Ledger Fold  │                         │ & Notary     │
 └──────────────┘                         └──────────────┘
```

1. **`m` — mergeproof**: The isolated notary gate. Evaluates candidate pull requests against base branch invariants, requiring causal RED-to-GREEN proofs, potential $\Phi$ within the human-signed allowance, and anti-cheat verification before signing verdicts.
2. **`i` — inbox**: The communication membrane between human operators and autonomous roles. Ingests human intent, digests activity logs, and facilitates 1-tap warrant sign-off.
3. **`r` — run**: The execution engine and supervisor. Spawns workers with a stripped environment and a disposable home directory, with explicit resource budgets and lease timeouts. Workers run as the same OS user: this is not yet an OS sandbox.
4. **`q` — queue**: The deterministic job scheduler. Mints cryptographic warrants, leases jobs to tiered agents (`flash`, `mid`, `max`), and tracks macro-state transitions (`BUILD`, `HARDEN`, `PATROL`, `QUIESCENT`).
5. **`l` — log**: The append-only, tamper-evident cryptographic event ledger. All system state is a pure deterministic fold over immutable ledger events.

---

## The 17 Normative Laws

All operations in `mirql` are strictly governed by [CONSTITUTION.md](CONSTITUTION.md):
- **Law 1: Offline Litmus** — Zero external network dependency during proof gating.
- **Law 2: Lifeguard Law** — Out-of-band kill daemon enforcing budget and lease boundaries.
- **Law 3: Roles Propose / Tools Author** — Agents emit proposals; only host tools author commits.
- **Law 4: One Durable Ledger** — State is a pure fold over append-only events.
- **Law 5: Base-Pinned Mortal Verdicts** — Proofs are pinned to base commit SHA and lease TTL.
- **Law 6: Silence Is Never Consent** — Timeouts and ambiguities always evaluate to refusal.
- **Law 7: Notary Outside Blast Radius** — Notary operates outside worker boundaries.
- **Law 8: Speechless Sandboxes** — The goal is workers with zero network access or ambient credentials. Today only the environment and home directory are isolated; network access and same-user file access remain open until OS isolation lands.
- **Law 9: N-1 Processes N** — Stable version N-1 gates candidate version N.
- **Law 10: Ship Invariants Not Features** — Merges require machine-checked behavioral invariants.
- **Law 11: No Warrant No Work** — Execution prohibited without signed, unexpired warrant.
- **Law 12: The Probe Doctrine** — Continuous monitoring across tests, drift, mutants, complexity, and surface.
- **Law 13: Monotone Potential PHI & Thrift Test** — Production-source potential $\Phi$ may grow only within the warrant's cumulative, human-signed `phi_budget` (absent = 0); refactors must strictly decrease it.
- **Law 14: Quiescence Is Success** — System idles to minimal budget when invariants hold.
- **Law 15: Semantic Identity / Mechanical Location** — Content hashes define entity identity.
- **Law 16: GREEN Must Be Causal** — Passing tests require RED-on-base, GREEN-on-head, and Re-Red confirmation.
- **Law 17: Per-Product Tenant Isolation & Integer-Only JCS** — Zero float numbers; integer micro-units and RFC 8785 JCS.

---

## Baseline CLI Surface

The public surface is strictly locked in [`surface.lock`](surface.lock):

### Mergeproof (`mirql m`)
- `mirql m check` — Run causal proof verification on candidate changes.

### Inbox (`mirql i`)
- `mirql i genesis` — Initialize a new workspace or repository state.
- `mirql i send` — Dispatch instructions or messages to the inbox.
- `mirql i digest` — View pending intents, proposals, and system summaries.
- `mirql i act` — Sign or reject pending warrant proposals.
- `mirql i propose` — Submit a structured change proposal.
- `mirql i protect-key` — Encrypt the owner's private key with a passphrase.

### Run (`mirql r`)
- `mirql r supervisor` — Execute the reactive agent supervisor daemon. Each leased job runs its worker in a disposable checkout of the workspace's committed `HEAD`, so a retry starts from the base commit and your checkout is never touched. A host tool commits the worker's output, then the Git-mode verifier judges that commit against the warrant's scope, its cumulative `phi_budget` and the reproducer the owner signed (`mirql i send --reproducer <test-file>`; without one the attempt ends `NO_REPRODUCER_DECLARED`). An accepted candidate is pinned at `refs/mirql/attempts/<sha>` for you to merge. `mirql i digest` shows the rule behind each outcome.
- `mirql r agent` — Run a worker command with a stripped environment and a disposable home directory (not an OS sandbox).
- `mirql r verify --workspace <repo> --base <ref> --head <ref> --reproducer <changed-test-file>` — Run the measured Git causal checks and the project's full npm test suite. For humanApprove changes, add `--dir <ledger> --warrant-id <id>` to consume an exact owner-signed approval. `--fixture` checks conformance only. Candidate tests execute with a stripped environment and a disposable home directory, but still under the invoking user account; OS isolation remains unfinished. The verifier refuses to run candidate code while the owner key is plaintext (`OWNER_KEY_UNPROTECTED`).
- `mirql r probe` — Run declarative health probes (tests, drift, mutants, complexity, surface).
- `mirql r bing-bong` (alias `mirql r bb`) — Multi-agent frontier consensus loop where 2–3 cross-family agents debate until reaching unanimous `CONVERGED` consensus or escalating to `mirql-inbox` with exit code `10`.

### Queue (`mirql q`)
- `mirql q tick` — Advance queue clock and reap expired leases.
- `mirql q submit` — Enqueue a new warrant for execution.
- `mirql q status` — View active leases, queued warrants, and macro-state.
- `mirql q promote` — Transition system between macro-states (`BUILD`, `HARDEN`, `PATROL`, `QUIESCENT`).
- `mirql q halt` — Halt queue dispatching immediately.
- `mirql q resume` — Resume queue dispatching.

### Log (`mirql l`)
- `mirql l append` — Write an event to the append-only ledger.
- `mirql l view <projection>` — Inspect a ledger projection, such as `job_state`.
- `mirql l replay` — Replay events from genesis to compute current state projection.
- `mirql l verify` — Cryptographically verify ledger hash chains and signatures.
- `mirql l snapshot` — Create a verified compact state checkpoint.

---

## Quickstart

### Prerequisites
- Node.js `>= 22`
- Pure built-in ESM (`node:fs`, `node:path`, `node:test`, `node:assert/strict`)
- Zero external npm dependencies

### Running Conformance Tests
```bash
npm test
```

### Checking Configuration & Surface
Inspect policy files and baseline locks:
- [`policy/mirql.json`](policy/mirql.json) — System budgets, tiers, and macro-state limits.
- [`policy/paths.yaml`](policy/paths.yaml) — Path protection matrix (`humanOnly` vs `humanApprove`).
- [`policy/writers.yaml`](policy/writers.yaml) — Writer namespace authorization regex.
- [`policy/probes.toml`](policy/probes.toml) — Declarative probe thresholds.
- [`surface.lock`](surface.lock) — Baseline command and schema surface lock.

### Trust storage

The owner key signs warrants and merge approvals, so it is encrypted at rest
(scrypt and AES-256-GCM). Genesis requires a passphrase, from
`MIRQL_HUMAN_PASSPHRASE` or `--passphrase`. The flag is visible in process
listings, so prefer the variable. Encrypt an existing key with:

```sh
mirql i protect-key --dir .mirql
```

`mirql r verify` refuses to run candidate code beside a plaintext owner key.
`MIRQL_ALLOW_PLAINTEXT_OWNER_KEY=1` turns that off, and exists for throwaway
test ledgers. Machine keys under `keys/` are still plaintext.

Machine keys, the default human key, and the public keyring live outside the workspace.
Set MIRQL_TRUST_ROOT to an operator-controlled directory, or use the default
~/.mirql-trust. Each ledger receives a separate directory identified by the SHA-256
of its canonical absolute metadata path. Workspaces and Git worktrees are rejected
as credential locations, including paths redirected through symlinks.

The workspace keeps its event log and runtime state. Workspace keyrings are ignored.
Existing ledgers with a workspace keyring are refused with TRUST_MIGRATION_REQUIRED
and the destination path until credentials have been moved.

Before migrating an existing installation, stop its workers. Create the reported
destination with owner-only access, move the existing keys directory there, then
move ledger/keyring.json to keyring.json in that destination. Publish the keyring
last. Retain the workspace event log. Run mirql l verify before resuming work.
Do not initialize fresh keys for an existing ledger. Changing the metadata path
changes its storage identifier, so a relocated ledger needs the same migration.
For an already externalized ledger, move credentials from its previous external
trust directory to the newly reported destination. Loading an existing private
key remains possible; creating a replacement for an initialized ledger is refused.

This storage placement implements trust remediation item 1.1. Signed key enrollment,
Windows ACL enforcement, and worker process isolation remain later plan requirements.

Signed enrollment keeps keyring.json beside keyring.sig and a pinned owner.pub.json
in the external trust directory. Genesis provisions the initial signed registry.
Later machine-key changes require the human private key explicitly. A generated
machine key has no authority until it is enrolled.

```sh
mirql i enroll-key tool:reviewer <public-key> --key <human-key-path> --dir .mirql
```

After migrating an older unsigned registry, add --initialize to authorize its
initial signature with the matching human key. The same flag rebinds migrated
signed storage to its new ledger location using the previous signed contents.
Normal enrollment retries use signed contents to repair an interrupted publication
and discard unsigned edits to the JSON mirror.

Enrollment can add namespaces or repeat an existing registration. Replacing a
namespace key is refused pending a key-rotation policy that preserves verification
of historical ledger entries. Worker isolation remains a separate trust-remediation requirement.

Credential publication creates a private temporary file and writes secret bytes
through its retained file handle. On Windows,
the credential directories and files receive a protected ACL granting FullControl
only to the current user. Existing files owned by another identity are refused.
PowerShell uses the native Windows security APIs in a hidden process. If that
enforcement is unavailable or verification fails, credential publication stops.

Linux and macOS retain owner-only 0700 directories and 0600 files. Publication
uses protected temporary files and atomic replacement. Temporary pathname changes
are detected without redirecting secret writes. Existing unrelated parent
directory permissions are preserved. Existing credentials are checked before use,
and cached checks are invalidated by metadata changes, including NTFS ACL changes.
These file permissions protect against other OS identities. Worker process
isolation remains a separate requirement.


Supervisor execution now requires a human-signed `warrant.created` event in
its ledger. A warrant ID selects existing authority. It cannot create a warrant
or supply its class, scope, or budget. The selected document must match the
signed content hash and the human owner pinned in the external keyring.
Authorization verifies one complete ledger snapshot, including signatures,
writer bindings and the hash chain. Missing, altered, revoked or explicitly
expired grants stop execution before worker dispatch.

Both `mirql i send` and proposal approval issue explicit signed grants.
Queue admission accepts a verified grant once. Historical intent-only warrants
need a new human authorization before execution. `mirql i approve-merge` records
an owner approval bound to the exact base, head, tree, changed paths and warrant.

### Complexity budget (Law 13)

`mirql i send --phi-budget <N>` signs a non-negative integer allowance into the
warrant. Without it the allowance is 0. The allowance is cumulative: every
transition `r verify` accepts under the warrant spends its measured increase,
recorded as a supervisor-signed `warrant.phi_consumed` ledger event. Only
increases are counted. A decrease never refunds the allowance, because an
accepted transition is not proof that it was merged. Re-verifying the same
base/head pair spends nothing extra. The remaining allowance is re-checked
under the ledger lock, so concurrent verifications cannot spend it twice.
Refactor and consolidation warrants must still strictly decrease $\Phi$.

$\Phi$ is measured from immutable Git blobs and counts production source only.
Test and `conformance/` files are exempt only while no production file imports
them, so complexity cannot be hidden behind a test-shaped path. Computed
`import(variable)` specifiers cannot be resolved statically and remain a
residual risk.

The CI notary runs without a ledger, so its allowance is always 0. A pull
request that grows $\Phi$ is rejected in CI, so merging it is a human decision.
GitHub enforces that only when `main` requires the Mergeproof check and agents
use an identity without merge rights; otherwise an agent can merge over red.

The gate runs on `pull_request_target`, so it always uses the base branch's
workflow and a pull request cannot rewrite its own check. A workflow change
first takes effect on the pull requests opened after it lands. A review does
not re-trigger the check: after an AI reviewer approves, re-run the job or add a
label to the pull request.


Worker commands require a readable, committed Git baseline. After execution,
protected-path checks use measured tree changes, staged content, untracked files
(including ignored files), and fingerprints of the physical files captured before
execution. Worker-supplied file lists cannot exempt an edit. Missing or failed
measurement refuses success and preserves worker diagnostics. Git index flags and
clean filters cannot hide changed physical bytes. This guard checks workspace
changes. Process and network isolation remain separate requirements.
