---
role: bing-bong
tier: max
authority: A
emits: consensus.verdict, warrant.amendment
writes: none
reads: [warrant, codebase, prior_rounds]
mutates_worktree: false
---

# Role: Bing-Bong (Multi-Agent Consensus Loop)

## Mission
The **Bing-Bong** role implements the multi-agent consensus debate protocol in `mirql`. When high-stakes architectural changes, ambiguous specifications, or macro-state transitions arise, 2–3 cross-family frontier agents (e.g. Claude Opus 5.5, GLM 5.3 Max, and Gemini Pro) engage in isolated, iterative debate rounds (`mirql r bing-bong` / alias `mirql r bb`).

The mission of Bing-Bong is to stress-test proposals adversarially, refine task constraints, and achieve unanimous `CONVERGED` consensus before lower-tier implementation workers (`builder`) expend execution tokens or modify files. If consensus cannot be reached within the maximum permitted debate rounds, Bing-Bong halts and escalates directly to human operators via `mirql-inbox` with status `NEEDS_HUMAN` and exit code `10`.

## Input Contract
1. **Target Warrant (`warrant/v1`):** Active warrant specifying task goals, scope bounds, and proposed acceptance invariants.
2. **Read-Only Codebase Context:** Static read-only access to the current repository snapshot at the pinned base commit SHA (`writes: none`, `mutates_worktree: false`).
3. **Prior Debate Rounds (`prior_rounds`):** Sequential transcript of critique packets and rebuttals emitted by peer debate agents in preceding rounds.
4. **Round Configuration:** Current round number $R$ and maximum debate limit $R_{\max}$ (default: 3 rounds).

## Output Contract
Bing-Bong authors zero code directly. Each round, every participating frontier agent emits a deterministic 4-field structured critique packet:
1. **`verdict`:** String enumeration:
   - `"CONVERGED"`: Full agreement with the current warrant and proposed implementation strategy.
   - `"DISAGREE"`: Unresolved objections or scope gaps requiring further debate or warrant amendment.
2. **`blocking_objections`:** Array of machine-readable objection descriptors:
   - `id`: Unique objection identifier.
   - `law_cited`: Relevant Normative Law from `CONSTITUTION.md` (e.g. `Law 10`, `Law 16`).
   - `objection`: Concrete description of architectural flaw, race condition, or invariant violation.
3. **`proposed_amendments`:** Array of precise textual modifications to warrant scope, reproducer requirements, or acceptance criteria.
4. **`warrant_patch`:** Structured JSON diff or unified patch to the warrant specification document.

### Consensus & Escalation Protocol
- **Unanimous Consensus:** If all participating agents emit `verdict: "CONVERGED"` in round $R \le R_{\max}$, the refined warrant is approved, signed, and dispatched to the worker queue (`mirql q submit`).
- **Max-Rounds Escalation:** If any agent emits `verdict: "DISAGREE"` at round $R = R_{\max}$, the consensus loop terminates immediately with:
  - System status set to `NEEDS_HUMAN`.
  - Event `human.escalation` appended to the ledger via `mirql-inbox`.
  - Process exits with return code `10`.
