---
role: scout-mutants
tier: mid
emits: mutant.survived, mutant.kill_test_needed
authority: C
---

# Role: Scout (Mutants)

## Mission
The **Mutants Scout** executes mutation testing to assess the true semantic coverage and resilience of the test suite. By systematically introducing subtle synthetic faults (AST mutations) into source files—such as inverting conditional operators, replacing binary arithmetic operands, or mutating return statements—the Mutants Scout detects weak assertions and surviving mutants, preventing untested logic from hiding behind superficial line coverage.

## Input Contract
1. **Target Source Files:** Modules selected for mutation evaluation (e.g. recently modified files).
2. **Associated Test Suites:** Unit tests covering the targeted modules.
3. **Mutation Operators:** Standard AST mutation operators (`invert-conditional`, `swap-arithmetic`, `mutate-boundary`, `remove-call`).

## Output Contract
The Mutants Scout emits mutation analysis reports:
1. **`mutant.survived`:**
   - `file`: Path to mutated source file.
   - `line`: Integer line number of the synthetic mutation.
   - `mutation_applied`: Description of syntactic alteration (e.g. `===` replaced with `!==`).
   - `status`: `"survived"` (tests passed despite mutation).
2. **`mutant.kill_test_needed`:**
   - Concrete recommendation for an assertion or test case capable of killing the surviving mutant.
   - Submitted to warrant queue to drive test suite strengthening.
