# NOT-ROADMAP: Rejected Anti-Goals & Architectural Prohibitions

This document records architectural proposals, feature ideas, and mechanism requests that have been explicitly evaluated and rejected by the `mirql` core team. 

Any PR or proposal attempting to introduce or facilitate these patterns will be rejected immediately by automated gate rules.

---

## Machine-Readable Rejected Signatures

```json
[
  {
    "id": "nr-0001",
    "reason": "Never auto-approve HUMAN verdicts on timeout",
    "violates_law": "Law 6 (Cryptographic Human Sovereignty / Silence Is Never Consent)",
    "surface_delta": [
      "config:inbox.auto_approve_timeout_s"
    ]
  },
  {
    "id": "nr-0002",
    "reason": "Direct agent git push or branch merge without Notary proof",
    "surface_delta": [
      "agent.capabilities:git_push",
      "agent.capabilities:merge_branch"
    ]
  },
  {
    "id": "nr-0003",
    "reason": "Floating-point currency, budget, or timestamp arithmetic in consensus layers",
    "surface_delta": [
      "schema:float_numbers",
      "policy:fractional_cents"
    ]
  },
  {
    "id": "nr-0004",
    "reason": "Ambient outbound network access inside worker execution sandboxes",
    "surface_delta": [
      "sandbox.network:allow_egress",
      "sandbox.network:unrestricted_dns"
    ]
  },
  {
    "id": "nr-0005",
    "reason": "Bypassing base-fail reproduction (RED-to-GREEN causality requirement)",
    "surface_delta": [
      "verify.flags:skip_base_fail",
      "verify.flags:trust_unreproduced_green"
    ]
  }
]
```

---

## Detailed Rationale

### `nr-0001`: Auto-Approval on Timeout
- **Proposal:** If a PR marked `needs_human` sits in the inbox without human review for more than 24 hours, automatically land it to prevent development bottlenecks.
- **Why Rejected:** Violates **Law 6 (Cryptographic Human Sovereignty / Silence Is Never Consent)**. Unreviewed code cannot earn merge authority by the passage of time. If a human is unresponsive, the system must hold, stall, or cancel the job, never default to landing.

### `nr-0002`: Direct Agent Git Push
- **Proposal:** Allow high-tier agent roles (e.g. `builder` or `orchestrator`) to run `git push origin main` directly if all unit tests pass in their local sandbox.
- **Why Rejected:** Violates **Law 3 (Roles Propose / Tools Author)** and **Law 8 (Speechless Sandboxes)**. Agents propose patches; only the host Notary tool signs commits and performs merges following multi-stage verification.

### `nr-0003`: Floating-Point Financial & Ledger Math
- **Proposal:** Use IEEE 754 standard floats for sub-cent token pricing, micro-USD budgets, and metric ratchets.
- **Why Rejected:** Violates **Law 17 (Per-Product Tenant Isolation & Integer-Only JCS)**. Floating-point arithmetic is inherently non-deterministic across hardware platforms and compilers, introducing consensus splits and ledger divergence. All monetary units must be represented as integer micro-units (`micro_usd`, basis points).

### `nr-0004`: Ambient Network Egress in Sandboxes
- **Proposal:** Allow sandboxes to fetch live external documentation, remote package registries, or cloud APIs during test runs.
- **Why Rejected:** Violates **Law 1 (Offline Litmus)** and **Law 8 (Speechless Sandboxes)**. Proofs must be deterministic and fully reproducible offline. Egress enables exfiltration of prompts/keys and opens the system to external tampering.

### `nr-0005`: Bypassing Red-to-Green Causality
- **Proposal:** Skip running reproduction tests on the base commit if the head test suite passes and code looks correct.
- **Why Rejected:** Violates **Law 16 (GREEN Must Be Causal)**. A test that passes on head might also have passed on base, indicating zero proof that the patch fixed the defect. Only a verified RED $\to$ GREEN transition proves causal remediation.
