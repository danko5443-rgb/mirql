# CONSTITUTION OF MIRQL

> **Status:** Normative · Supreme Law of `mirql`  
> **Applicability:** All autonomous processes, agents, supervisors, notaries, and human operators.  
> **Amendment Procedure:** Modifiable exclusively by `human:owner` under strict ceremony. Autonomous agents are prohibited from altering this file.

---

## Preamble

`mirql` (**m**ergeproof · **i**nbox · **r**un · **q**ueue · **l**og) is an autonomous, 24/7 proof-driven software development factory. The system operates under the foundational premise that generative code models must never be granted unconstrained write or merge authority. Trust is never assumed; every modification must be accompanied by non-repudiable, machine-checked causal proof.

This Constitution establishes the seventeen supreme, normative laws governing all execution, verification, state transitions, and role boundaries within `mirql`.

---

## The 17 Normative Laws

### Law 1: Offline Litmus
All verification gates, proof suites, property checks, and candidate validations must execute in a fully deterministic, completely offline environment. No test, probe, or gate check may depend on ambient network availability, unpinned remote endpoints, or external state. Any proof artifact requiring outbound network access is void and must be rejected immediately.

### Law 2: Lifeguard Law
The safety and quota daemon (`daemon:lifeguard`) executes strictly out-of-band and out-of-process relative to workers and execution runtimes. The Lifeguard possesses unilateral, unalterable kill authority over any process, container, or task that exceeds assigned compute budgets, token limits, runtime leases, or memory ceilings. No worker or supervisor may intercept, mask, or suspend the Lifeguard daemon.

### Law 3: Roles Propose / Tools Author
Large Language Model (LLM) roles—regardless of reasoning capability or model tier—only emit structured proposals, warrants, and candidate patches. LLM roles do not possess filesystem authoring rights, git push capabilities, or ledger commit privileges. All state mutations, git commit creation, and ledger writes are exclusively executed by deterministic, audited host tools.

### Law 4: One Durable Ledger
The sole ground truth of the system is a single, append-only, tamper-evident cryptographic event log. All state at any epoch $t$ is a pure mathematical fold over the ordered sequence of ledger events:
$$\text{State}_t = \text{fold}(\text{Events}_{1 \dots t}, \text{State}_0)$$
No auxiliary database, ephemeral cache, or out-of-band file may hold authoritative state. If an event is not recorded in the ledger, it never occurred.

### Law 5: Base-Pinned Mortal Verdicts
Every verification verdict emitted by the Notary (`notary:mergeproof`) is explicitly pinned to a specific base commit SHA and bounded by an immutable time-to-live (`lease_ttl_ms`). If the base branch tip advances, or if the lease window expires prior to atomic landing, the verdict expires immediately and becomes void. No proof may be applied to a stale base commit.

### Law 6: Silence Is Never Consent
Ambiguity, transport timeouts, empty payloads, malformed outputs, and missing signatures must unconditionally evaluate as a hard refusal (`reject`). The system default is closed. Silence, unresponsiveness, or omission by any agent, supervisor, or human operator can never be construed as approval or progress.

### Law 7: Notary Outside Blast Radius
The Notary verification engine (`mergeproof`) operates in an isolated security boundary physically separated from the execution sandbox of the candidate code. The untrusted code under test must never share memory, execution context, or file access tokens with the Notary. Compromise of the test runner or agent process must not compromise the integrity of the Notary.

### Law 8: Speechless Sandboxes
Sandboxes assigned to agent execution and test reproduction must be speechless: they possess zero ambient credentials, no network interfaces, and no inter-process communication links to other running jobs or outside hosts. Input enters strictly via explicit warrant payload files; output leaves strictly via isolated artifact outputs.

### Law 9: N-1 Processes N
The supervisor and runtime infrastructure running on verified release version $N-1$ evaluate, compile, and gate the candidate changes destined for release version $N$. Self-hosting evolution must proceed incrementally and unidirectionally. A candidate release $N$ cannot bootstrap or gate itself without the prior stable supervisor.

### Law 10: Ship Invariants Not Features
Software features are transient; machine-checked invariants are permanent. No pull request, bugfix, or refactoring candidate may be merged without accompanying machine-executable invariant probes. Capabilities without formal behavioral assertions and regression fences cannot be admitted to the codebase.

### Law 11: No Warrant No Work
No worker node, agent container, or supervisor task may execute instructions, consume tokens, or expend compute cycles without an active, unexpired, cryptographically signed warrant. Every warrant explicitly specifies the originating intent, maximum resource budget, assigned role, and task boundaries.

### Law 12: The Probe Doctrine
Every functional subsystem and public surface interface must be guarded by declarative, continuous probes spanning five dimensions:
1. `tests`: Unit and regression suite determinism.
2. `drift`: Semantic and architectural AST conformance.
3. `mutants`: Mutation testing kill rate and coverage.
4. `complexity`: Cyclomatic complexity and function length ceilings.
5. `surface`: Public API and CLI interface lock enforcement.

### Law 13: Monotone Potential PHI & Thrift Test
System potential $\Phi$ measures production-source complexity and debt. Test files and `conformance/` fixtures do not contribute to the potential; test-gap counts remain separate diagnostics so adding a reproducer never changes $\Phi$.
Every state transition must stay within the complexity allowance the human signed into the warrant. That allowance is cumulative per warrant: it is spent across every accepted transition under the warrant, and it is never re-granted per transition. Only increases spend it:
$$\sum_{i \le t} \max(0,\ \Phi_{i+1} - \Phi_i) \le \text{warrant.phi\_budget}$$
A decrease does not refund the allowance, because a recorded transition is not proof that it was merged. An absent allowance means zero. A caller-supplied number or unsigned document grants no allowance. Refactoring and consolidation tasks must still strictly decrease potential ($\Phi_{t+1} < \Phi_t$), regardless of budget. Superfluous code, redundant dependencies, or complexity above the authorized allowance fails the Thrift Test.

### Law 14: Quiescence Is Success
When all active warrants are completed and all declarative probes report green, the factory must settle into a stable quiescent state. Continuous idle execution, repetitive non-productive polling, or artificial token expenditure is classified as a runaway malfunction. In quiescence, consumption must drop below the defined budget ceiling (`quiescent_max_budget_bp`).

### Law 15: Semantic Identity / Mechanical Location
Entities within `mirql`—including events, warrants, jobs, and proof artifacts—derive their identity entirely from their content hash (SHA-256) and canonical UUID, never from transient mechanical attributes such as local directory paths, git branch names, or host process IDs.

### Law 16: GREEN Must Be Causal
A passing test suite (GREEN) constitutes valid evidence of a fix if and only if causality is established through a strict three-phase cycle:
1. **Red on Base:** The reproducer test is proven to fail against the base branch tip.
2. **Green on Head:** The reproducer test is proven to pass against the candidate patch.
3. **Re-Red Verification:** Reverting the candidate patch while retaining the reproducer test causes the test to fail once more.

### Law 17: Per-Product Tenant Isolation & Integer-Only JCS
All operational and financial metrics, budgets, timestamps, basis points, and token allocations must be represented exclusively as safe integers (`Number.isSafeInteger`). Floating-point arithmetic is strictly forbidden across all policy, consensus, and ledger components. Serialization must adhere strictly to RFC 8785 JSON Canonicalization Scheme (JCS). Multi-tenant assets and operational contexts must maintain cryptographic and spatial separation.

---

## Precedence and Supremacy

Where any configuration, role instruction, prompt template, or runtime parameter contradicts this Constitution, this Constitution shall govern unconditionally.
