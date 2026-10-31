# ROADMAP: `mirql` Self-Hosting Evolution

This document defines the normative sequence of milestones for `mirql`'s autonomous self-hosting roadmap, from bootstrap initialization through keyless autonomous canary promotion.

---

## Milestone Overview

| Milestone | Code | Focus | Primary Invariant |
|---|---|---|---|
| **M1** | `WAKE` | Event-Driven Wake Rules | Zero unprompted polling; pure event-driven dispatch |
| **M2** | `PHI` | PHI Engine & Ratchets | Monotone potential: $\Phi_{t+1} \le \Phi_t$ |
| **M3** | `DRIFT` | Claim-Check Drift Harness | Zero AST or behavioral drift across transitions |
| **M4** | `MUTANT` | Incremental Mutation & Flake Detector | $\ge 80\%$ mutant kill rate; deterministic test suite |
| **M5** | `DOCTOR` | Doctor & Circuit Breakers | Out-of-band fault detection and autonomous rollback |
| **M6** | `JOURNEY` | Journey Harness & 1-Tap Proposer | High-fidelity user journey replication with 1-tap review |
| **M7** | `CANARY` | Keyless Canary Promotion Gauntlet | Verifiable provenance, zero human friction in safe canary |

---

## Milestone Details

### M1: Event-Driven Wake Rules
- **Objective:** Establish the deterministic event bus, reactive wake rules, and warrant issuance pipeline.
- **Deliverables:**
  - Append-only cryptographic ledger (`mirql l append`, `mirql l replay`).
  - Event-driven reactive supervisor (`mirql r supervisor`) waking workers solely on state changes.
  - Warrant minting and lease lifecycle management (`mirql q tick`, `mirql q submit`).
  - Zero polling overhead: workers sleep until reactive wake conditions are met in the event stream.
- **Invariants & Gates:**
  - Every job execution requires an unexpired warrant (Law 11).
  - All state transitions verifiable via pure ledger fold (Law 4).

### M2: PHI Engine & Ratchets
- **Objective:** Build automated metric collection and strict potential ratchets.
- **Deliverables:**
  - Deterministic metric extractor computing total debt, complexity, and coverage gaps into an integer score $\Phi$.
  - Gating engine rejecting any patch that increases system potential ($\Delta \Phi > 0$).
  - Refactoring thrift verification requiring strictly negative $\Delta \Phi$ for consolidation PRs.
- **Invariants & Gates:**
  - $\Phi_{t+1} \le \Phi_t$ enforced on every merge candidate (Law 13).
  - Integer-only math without floating-point drift (Law 17).

### M3: Claim-Check Drift Harness
- **Objective:** Continuous verification of architectural invariants and AST structural claims.
- **Deliverables:**
  - Static AST analyzer detecting unwanted cross-package coupling and illicit dependency injection.
  - Claim-check verification system: PR claims (e.g. "fixes issue #12 without changing public API") validated mechanically against `surface.lock`.
  - Continuous drift sentinel (`roles/scout-drift.md`).
- **Invariants & Gates:**
  - Public surface delta must be zero unless explicitly cited and approved (Law 12).
  - All drift probes report zero unapproved deviations.

### M4: Incremental Mutation & Flake Detector
- **Objective:** Deep semantic test validation via AST mutation testing and multi-run flake isolation.
- **Deliverables:**
  - Targeted incremental mutation engine generating AST mutants exclusively on changed lines.
  - Flakiness sentinel executing multiple runs against candidate tests to detect non-deterministic outcomes.
  - Automated quarantine mechanism for unmasked flaky tests.
- **Invariants & Gates:**
  - Minimum mutant kill rate $\ge 8000$ basis points (80.00%) on new code.
  - Zero non-deterministic tests admitted to the main branch.

### M5: Doctor & Circuit Breakers
- **Objective:** Autonomous fault detection, health diagnosis, and automated circuit breaking.
- **Deliverables:**
  - Out-of-band diagnostic role (`roles/doctor.md`) evaluating system metrics and error trends.
  - Multi-tier circuit breakers tripping automatically on repeated worker failures or budget exceedance.
  - Safe state transition triggers: `BUILD` $\to$ `HARDEN` $\to$ `QUIESCENT`.
- **Invariants & Gates:**
  - Lifeguard daemon retains unblockable kill authority (Law 2).
  - System converges to quiescence under failure or completion (Law 14).

### M6: Journey Harness & 1-Tap Proposer
- **Objective:** End-to-end user experience simulation and frictionless human collaboration.
- **Deliverables:**
  - User journey simulation harness (`roles/scout-journey.md`) testing CLI workflows end-to-end.
  - 1-tap proposer (`roles/proposer.md`) preparing fully proven, pre-validated proposals for human sign-off.
  - Digest and interactive decision interface (`mirql i digest`, `mirql i act`).
- **Invariants & Gates:**
  - Silence is never consent; 1-tap proposals require affirmative human signature (Law 6).
  - All proposed changes accompanied by verified reproducers (Law 16).

### M7: Keyless Canary Promotion Gauntlet
- **Objective:** Autonomous canary deployment, statistical health verification, and production promotion.
- **Deliverables:**
  - Automated staging deployment pipeline with keyless cryptographic provenance (Sigstore/SLSA).
  - Real-time error rate and latency monitoring during canary phase.
  - Automated canary promotion or instant rollback on statistical anomaly detection.
- **Invariants & Gates:**
  - N-1 supervisor evaluates and promotes version N (Law 9).
  - Complete tamper-evident provenance recorded in durable ledger (Law 4).
