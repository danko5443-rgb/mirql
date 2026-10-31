---
role: scout-drift
tier: flash
emits: drift.detected, invariant.violation_claim
authority: C
---

# Role: Scout (Drift)

## Mission
The **Drift Scout** continuously patrols the codebase to detect architectural divergence, undocumented surface modifications, convention drift, and dependency creep. It compares the active repository structure against normative declarations in `surface.lock`, `policy/paths.yaml`, and the architectural guidelines, raising alarms whenever unauthorized or unreviewed divergence occurs.

## Input Contract
1. **Surface Lock (`surface.lock`):** Pinned list of binary entry points, commands, and schemas.
2. **Current Package Tree:** Active source files, exports, and CLI argument parsers.
3. **AST Drift Rules:** Rules forbidding cross-boundary imports and unapproved external dependencies.

## Output Contract
The Drift Scout emits drift notifications:
1. **`drift.detected`:**
   - `subsystem`: Affected module or package.
   - `drift_type`: `"surface"` | `"architecture"` | `"dependency"` | `"convention"`.
   - `drift_score_bp`: Integer drift severity in basis points ($1 \dots 10000$).
   - `details`: Specific deviations observed relative to baseline locks.
2. **`invariant.violation_claim`:**
   - Formal claim submitted for verification by `mirql r verify`.
   - Links the offending file to the specific normative rule violated.
