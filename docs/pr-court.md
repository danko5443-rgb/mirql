# PR Court

The PR Court is a three-role LLM review loop run by a deterministic tool from a trusted main checkout. It exists to give pull requests from trusted authors an independent, adversarial review before merge, while keeping every state mutation in deterministic tooling (Constitution Law 3: Roles Propose / Tools Author). The roles only emit JSON proposals; the tool validates, applies, commits, posts, and merges.

## The flow

1. **Critic** (`roles/critic.md`) reviews the diff and emits findings (verdict APPROVE or COMMENT, P1/P2 defects only). External reviewers (coderabbitai, codex-connector) supply findings instead when they are available; the Critic is the independent fallback when they are rate limited or absent.
2. **Advocate** (`roles/advocate.md`) answers each finding: either AGREE_AND_FIX with minimal patches (kept complexity-neutral, `delta_phi <= 0`) or REBUT with evidence. The tool applies valid patches, commits, and pushes them.
3. **Judge** (`roles/judge.md`) rules on every finding — FIXED, OVERRULED_FALSE_POSITIVE, or UNRESOLVED — and issues the terminal verdict: MERGE, REMAND (another round, up to 3), or ESCALATE (a human takes over).
4. **Notary re-run:** after the Judge says MERGE, the full mergeproof notary suite re-runs on the final head. Only a green, base-pinned notary verdict authorizes the actual merge (Law 5: Base-Pinned Mortal Verdicts).
5. **Merge** is executed by the tool, never by an LLM role.

The loop runs at most 3 rounds. Anything still unresolved at round 3 escalates to a human; silence and malformed output are hard refusals everywhere (Law 6: Silence Is Never Consent).

## Courthouse Lock

The court refuses to proceed when the diff touches locked paths: the constitution and roadmap (`CONSTITUTION.md`, `NOT-ROADMAP.md`), policy (`policy/**`), workflow and reviewer config (`.github/**`, `.coderabbit.*`), `AGENTS.md`, `.git`, and `roles/judge.md`. The reason is self-preservation: a PR must not be able to rewrite the rules of the court that judges it, remove its own reviewers, or amend the constitution to permit itself. Changes to those paths always go to a human. The Advocate's patches are under the same lock.

Note the boundary of the lock in "Known limits" below: `scripts/**` and `packages/mergeproof/**` are not locked by the court itself.

## Operator settings

### Repository secrets

- **An LLM key**, one of: `ZAI_API_KEY` (already set), `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`. The court needs at least one to run its roles.
- **`MIRQL_COURT_TOKEN`:** a fine-grained personal access token with `contents:write` on this repository. It exists only so the Advocate's fix commits trigger the notary: pushes made with the built-in `GITHUB_TOKEN` start no workflows, so without a court token the notary would never run on the Advocate's commits. Without it the Advocate never pushes, and every AGREE_AND_FIX escalates to a human instead.

### Repository variables

- **`MIRQL_COURT_AUTO_MERGE=1`:** enables merging. Default is off; with it unset, the court stops at the Judge's verdict and a human lands the PR.
- **`MIRQL_COURT_DISABLED=1`:** halts the court entirely (for incidents or maintenance windows).
- **`MIRQL_LLM_BASE_URL`:** overrides the Z.AI API endpoint (self-hosted or proxied gateway).
- **`MIRQL_CRITIC_MODEL` / `MIRQL_ADVOCATE_MODEL` / `MIRQL_JUDGE_MODEL`:** per-role model overrides — useful for running the Judge on a stronger model than the other roles.
- **`MIRQL_CRITIC_PROVIDER` / `MIRQL_ADVOCATE_PROVIDER` / `MIRQL_JUDGE_PROVIDER`:** per-role provider overrides, one of `zai`, `anthropic`, `openai`, `openrouter`, `gemini` (each requires the matching API key secret).

## Known limits

- **No branch protection.** The repository has no branch protection on its current plan. The court itself checks the Mergeproof Conscience Gate job result before merging, but a person with write access can still merge anything by hand, bypassing the court entirely.
- **Forgeable receipts.** Receipts are authenticated by the `github-actions[bot]` identity, so any workflow on any branch of this repository can forge one. A dedicated GitHub App identity is required before the repo is opened to untrusted pushers.
- **Self-attesting head tests.** `candidate-tests` runs PR code, so `suite_pass_head` can be forged by the PR itself. This is why the court only serves OWNER/MEMBER/COLLABORATOR authors, and why the planned `candidate-tests` move must land before the repository goes public.
- **The Judge is persuadable.** An LLM Judge can be persuaded by a crafted diff. Hazard scanning (injection phrases, trojan unicode, oversized diffs) is only a filter, not a defense.
- **The engine is not locked.** `scripts/**` and `packages/mergeproof/**` are not Courthouse Lock paths, so the court can merge changes to its own engine. `roles/critic.md` and `roles/advocate.md` are likewise unlocked; only `roles/judge.md` is locked.
- **Network-dependent review.** The LLM calls mean the review step depends on the network. The mechanical gates stay offline-measured (Law 1: Offline Litmus) and still fail closed if the LLM step is unreachable.
