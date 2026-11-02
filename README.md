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

1. **`m` — mergeproof**: The isolated notary gate. Evaluates candidate pull requests against base branch invariants, requiring causal RED-to-GREEN proofs, non-increasing potential $\Phi$, and anti-cheat verification before signing verdicts.
2. **`i` — inbox**: The communication membrane between human operators and autonomous roles. Ingests human intent, digests activity logs, and facilitates 1-tap warrant sign-off.
3. **`r` — run**: The sandboxed execution engine and supervisor. Spawns ephemeral, speechless worker sandboxes with explicit resource budgets and enforces lease timeouts.
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
- **Law 7: Notary Outside Blast Radius** — Notary operates outside worker sandbox boundaries.
- **Law 8: Speechless Sandboxes** — Workers possess zero network access or ambient credentials.
- **Law 9: N-1 Processes N** — Stable version N-1 gates candidate version N.
- **Law 10: Ship Invariants Not Features** — Merges require machine-checked behavioral invariants.
- **Law 11: No Warrant No Work** — Execution prohibited without signed, unexpired warrant.
- **Law 12: The Probe Doctrine** — Continuous monitoring across tests, drift, mutants, complexity, and surface.
- **Law 13: Monotone Potential PHI & Thrift Test** — System potential $\Phi$ must never increase ($\Delta \Phi \le 0$).
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

### Run (`mirql r`)
- `mirql r supervisor` — Execute the reactive agent supervisor daemon.
- `mirql r agent` — Run an ephemeral sandboxed role container.
- `mirql r verify` — Validate local candidate proof artifacts.
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
- `mirql l view` — Stream and inspect ledger events.
- `mirql l replay` — Replay events from genesis to compute current state projection.
- `mirql l verify` — Cryptographically verify ledger hash chains and signatures.
- `mirql l snapshot` — Create a verified compact state checkpoint.

---

## Quickstart

### Prerequisites
- Node.js `>= 18.17`
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

Credential publication now verifies permissions before writing bytes. On Windows,
the credential directories and files receive a protected ACL granting FullControl
only to the current user. Existing files owned by another identity are refused.
PowerShell uses the native Windows security APIs in a hidden process. If that
enforcement is unavailable or verification fails, credential publication stops.

Linux and macOS retain owner-only 0700 directories and 0600 files. Publication
uses protected temporary files and atomic replacement. Existing unrelated parent
directory permissions are preserved. Existing credentials are checked before use,
and cached checks are invalidated by metadata changes, including NTFS ACL changes.
These file permissions protect against other OS identities. Worker process
isolation remains a separate requirement.
