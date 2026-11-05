# PR Court

The PR Court is a three-role LLM review loop run by a deterministic tool from a trusted main checkout. It exists to give pull requests from trusted authors an independent, adversarial review before merge, while keeping every state mutation in deterministic tooling (Constitution Law 3: Roles Propose / Tools Author). The roles only emit JSON proposals; the tool validates, applies, commits, posts, and merges.

## The flow

1. **Critic** (`roles/critic.md`) reviews the diff and emits findings (verdict APPROVE or COMMENT, P1/P2 defects only). External reviewers (coderabbitai, codex-connector) supply findings instead when they are available; the Critic is the independent fallback when they are rate limited or absent.
2. **Advocate** (`roles/advocate.md`) answers each finding: either AGREE_AND_FIX with minimal patches (kept complexity-neutral, `delta_phi <= 0`) or REBUT with evidence. The tool applies valid patches, commits, and pushes them.
3. **Judge** (`roles/judge.md`) rules on every finding — FIXED, OVERRULED_FALSE_POSITIVE, or UNRESOLVED — and issues the terminal verdict: MERGE, REMAND (another round, up to 3), or ESCALATE (a human takes over).
4. **Notary check:** after the Judge says MERGE, the tool reads the notary run for the final head. If the gate is not green, it re-runs that run's failed jobs (`gh run rerun --failed`, up to 5 attempts) and waits; a job that already passed is not repeated. Only a green gate on that exact head, measured against the current base tip, authorizes the merge (Law 5: Base-Pinned Mortal Verdicts).
5. **Merge** is executed by the tool, never by an LLM role.

The loop runs at most 3 rounds. Anything still unresolved at round 3 escalates to a human; silence and malformed output are hard refusals everywhere (Law 6: Silence Is Never Consent).

## Courthouse Lock

The Judge refuses to rule (ESCALATE) when the diff touches a locked path: the `humanOnly` list in `policy/paths.yaml` (`CONSTITUTION.md`, `NOT-ROADMAP.md`, `policy/**`, `.github/**`, `roles/judge.md`, `.coderabbit.yaml`, `.coderabbit.yml`, `AGENTS.md`) or any reviewer config file (`AI_REVIEWER_CONFIG_PATTERNS` in `packages/mergeproof/evaluator.mjs`). The reason is self-preservation: a PR must not be able to rewrite the rules of the court that judges it, remove its own reviewers, or amend the constitution to permit itself.

The evaluator enforces this separately: a court receipt (`mirql-judge[bot]`, `mirql-critic[bot]`) never clears MP-001, so changes to those paths always go to a human.

The Advocate's patches are under the same lock. They also cannot touch `package.json`, `.npmrc`, a symlink, or any path with a segment starting with `.git`.

Note the boundary of the lock in "Known limits" below: `scripts/**` and `packages/mergeproof/**` are not locked by the court itself.

## Operator settings

### Repository secrets

- **An LLM key**, one of: `ZAI_API_KEY` (already set), `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`. The court needs at least one to run its roles.
- **`MIRQL_COURT_TOKEN`:** a fine-grained personal access token with `contents:write` on this repository. It exists only so the Advocate's fix commits trigger the notary: pushes made with the built-in `GITHUB_TOKEN` start no workflows, so without a court token the notary would never run on the Advocate's commits. Without it the Advocate never pushes, and every AGREE_AND_FIX escalates to a human instead.

### Repository variables

- **`MIRQL_COURT_AUTO_MERGE=1`:** enables merging. Default is off; with it unset, the court stops at the Judge's verdict and a human lands the PR.
- **`MIRQL_COURT_DISABLED=1`:** halts the court (for incidents or maintenance windows): no role runs and nothing merges. A review signal can still re-run a failed notary gate.
- **`MIRQL_LLM_BASE_URL`:** overrides the Z.AI API endpoint (self-hosted or proxied gateway).
- **`MIRQL_CRITIC_MODEL` / `MIRQL_ADVOCATE_MODEL` / `MIRQL_JUDGE_MODEL`:** per-role model overrides — useful for running the Judge on a stronger model than the other roles.
- **`MIRQL_CRITIC_PROVIDER` / `MIRQL_ADVOCATE_PROVIDER` / `MIRQL_JUDGE_PROVIDER`:** per-role provider overrides, one of `zai`, `anthropic`, `openai`, `openrouter`, `gemini` (each requires the matching API key secret).

### Turning it off

- **Cost:** the court runs on every open PR from a trusted author as soon as this code is on `main` and an LLM key is set. `ZAI_API_KEY` is already set, so it starts spending when it lands, with auto-merge still off. Set `MIRQL_COURT_DISABLED=1` first if that is not wanted yet.
- **Receipts:** remove `mirql-judge[bot]` and `mirql-critic[bot]` from `aiReviewers` in `policy/paths.yaml` and their receipts stop counting as approval, so the PR needs a human again.

## Wake-ups

The court runs as a workflow from `main` (`.github/workflows/mergeproof-retrigger.yml`). A Codex or CodeRabbit comment, a finished notary run, or a manual dispatch wakes it, and each wake-up rereads all state from the API. Review submissions reach it through `.github/workflows/mergeproof-review-signal.yml`. That event runs the PR's own copy of a workflow, so the signal file holds no secrets and `permissions: {}`; its completion fires `workflow_run` in the court workflow.

## Known limits

- **No branch protection.** The repository has no branch protection on its current plan. The court itself checks the Mergeproof Conscience Gate job result before merging, but a person with write access can still merge anything by hand, bypassing the court entirely.
- **Forgeable receipts.** Receipts are authenticated by the `github-actions[bot]` identity, so any workflow on any branch of this repository can forge one. A dedicated GitHub App identity is required before the repo is opened to untrusted pushers.
- **Self-attesting head tests.** `candidate-tests` runs PR code, so `suite_pass_head` can be forged by the PR itself. This is why the court only serves OWNER/MEMBER/COLLABORATOR authors, and why the planned `candidate-tests` move must land before the repository goes public.
- **The Judge is persuadable.** An LLM Judge can be persuaded by a crafted diff. Hazard scanning (injection phrases, trojan unicode, oversized diffs) is only a filter, not a defense.
- **A Critic APPROVE is enough for the gate.** On a `humanApprove` PR, one Critic approval on the exact head turns the Mergeproof check green. It does not make the court merge; only a Judge MERGE does that, but a person may read the green check as a full review.
- **A court merge starts no workflows.** The merge uses `GITHUB_TOKEN`, so a push-triggered workflow would not run on `main` for that commit. No workflow here uses `push` today, so this only matters if one is added.
- **The engine is not locked.** `scripts/**` and `packages/mergeproof/**` are not Courthouse Lock paths, so the court can merge changes to its own engine. `roles/critic.md` and `roles/advocate.md` are likewise unlocked; only `roles/judge.md` is locked.
- **Network-dependent review.** The LLM calls mean the review step depends on the network. The mechanical gates stay offline-measured (Law 1: Offline Litmus) and still fail closed if the LLM step is unreachable.
