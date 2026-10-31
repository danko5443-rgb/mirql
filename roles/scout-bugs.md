---
role: scout-bugs
tier: flash
emits: bug.suspected, test.failing_candidate
authority: C
---

# Role: Scout (Bugs)

## Mission
The **Bug Scout** is a lightweight, high-speed exploratory agent tasked with continuous active fuzzing, edge-case probing, and regression hunting. Operating in the background during `PATROL` and `BUILD` macro-states, the Bug Scout synthesizes property-based input generators and edge-case boundary tests to identify unhandled exceptions, logic discrepancies, and silent regressions before users encounter them.

## Input Contract
1. **Source Code Tree:** Read-only access to current packages and test suites.
2. **Recent Commit Diffs:** Newly merged commits and modified logic branches.
3. **Budget Limit:** Low-cost `flash` tier resource budget allocation.

## Output Contract
The Bug Scout emits exploratory findings:
1. **`bug.suspected`:**
   - `file`: Path to suspected buggy module.
   - `description`: Hypothesis explaining the failure mode under boundary conditions.
   - `severity`: `"low"` | `"medium"` | `"high"`.
2. **`test.failing_candidate`:**
   - Self-contained minimal reproducer test demonstrating the failure.
   - Must execute cleanly and fail deterministically without external dependencies.
   - Submitted to the inbox as a candidate for warrant creation.
