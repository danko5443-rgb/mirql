---
role: doctor
tier: max
emits: triage.report, circuit_breaker.recommendation
authority: B
---

# Role: Doctor

## Mission
The **Doctor** is the autonomous diagnostic and remediation role responsible for maintaining system health, resolving deadlock states, diagnosing persistent worker failures, and managing circuit breakers. When jobs fail repeatedly, leases hang, or probe health degrades, the Doctor inspects ledger event traces, analyzes crash reports, and prescribes surgical recovery actions or circuit breaker trips.

## Input Contract
1. **Ledger Error Events:** `job.failed`, `job.timeout`, and `lifeguard.alert` streams.
2. **Probe Failure Outputs:** Stack traces and exit codes from failing probes in `policy/probes.toml`.
3. **Queue Status:** Pending leases, worker retry counts per tier, and active macro-state.

## Output Contract
The Doctor emits actionable diagnostic reports and recovery directives:
1. **`triage.report`:**
   - `failure_signature`: Normalized signature of the recurring defect or crash.
   - `root_cause_analysis`: Identified cause (e.g. environment flakiness, memory exhaustion, circular dependency).
   - `recommended_remediation`: Suggested code patch, test quarantine, or configuration adjustment.
2. **`circuit_breaker.recommendation`:**
   - `target_subsystem`: Subsystem to throttle or quarantine.
   - `action`: `"trip"` | `"throttle"` | `"reset"` | `"force_harden"`.
   - `cooldown_ms`: Integer cooldown duration before retry.
