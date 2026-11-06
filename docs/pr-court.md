# PR Court

The PR Court is a three-role LLM review loop run by a deterministic tool from a trusted main checkout. It exists to give pull requests from trusted authors an independent, adversarial review before merge, while keeping every state mutation in deterministic tooling (Constitution Law 3: Roles Propose / Tools Author). The roles only emit JSON proposals; the tool validates, applies, commits, posts, and merges.

## The flow

1. **Critic** (`roles/critic.md`) reviews the diff and emits findings (verdict APPROVE or COMMENT, P1/P2 defects only). External reviewers (coderabbitai, codex-connector) supply findings instead when they are available; the Critic is the independent fallback when they are rate limited or absent.
2. **Advocate** (`roles/advocate.md`) answers each finding: either AGREE_AND_FIX with minimal patches (kept within `delta_phi <= phi_allowance`, which is 0 without a signed Phi warrant) or REBUT with evidence. The tool applies valid patches, commits, and pushes them.
3. **Judge** (`roles/judge.md`) rules on every finding — FIXED, OVERRULED_FALSE_POSITIVE, or UNRESOLVED — and issues the terminal verdict: MERGE, REMAND (another round, up to 3), or ESCALATE (a human takes over). A MERGE covers only what the Judge saw: a later reviewer finding reopens the case, and a later CHANGES_REQUESTED holds the merge.
4. **Notary check:** after the Judge says MERGE, the tool reads the notary run for the final head. If the gate is not green, it re-runs that run's failed jobs (`gh run rerun --failed`, up to 5 attempts) and waits; a job that already passed is not repeated. Only a green gate on that exact head, measured against the current base tip, authorizes the merge (Law 5: Base-Pinned Mortal Verdicts).
5. **Merge** is executed by the tool, never by an LLM role.

The loop runs at most 3 rounds. Anything still unresolved at round 3 escalates to a human; silence and malformed output are hard refusals everywhere (Law 6: Silence Is Never Consent).

## Courthouse Lock

The Judge does not rule on a diff that touches a locked path: the `humanOnly` list in `policy/paths.yaml` (`CONSTITUTION.md`, `NOT-ROADMAP.md`, `policy/**`, `.github/**`, `roles/judge.md`, `.coderabbit.yaml`, `.coderabbit.yml`, `AGENTS.md`) or any reviewer config file (`AI_REVIEWER_CONFIG_PATTERNS` in `packages/mergeproof/evaluator.mjs`). The reason is self-preservation: a PR must not be able to rewrite the rules of the court that judges it, remove its own reviewers, or amend the constitution to permit itself.

On such a PR the Critic runs once when no external reviewer has reviewed it, and then the court posts a RECUSE receipt that names the files and the next step (`node scripts/owner-signoff.mjs <pr>`). The Advocate does not run, and the Critic's COMMENT is advisory. A reviewer config file gets a different hint, because no sign-off clears those paths and the owner merges by hand.

The evaluator enforces this separately: a court receipt (`mirql-judge[bot]`, `mirql-critic[bot]`) never clears MP-001, so changes to those paths always go to a human.

The Advocate's patches are under the same lock. They also cannot touch `package.json`, `.npmrc`, a symlink, or any path with a segment starting with `.git`.

Note the boundary of the lock in "Known limits" below: `scripts/**` and `packages/mergeproof/**` are not locked by the court itself.

## RECUSE and ESCALATE

RECUSE means the court declines to rule: a locked path, an untrusted author, or a `delta_phi` above what is left of the owner's signed Phi warrant (0 when there is none). It ends the court's work on that head but says nothing about the PR, so an external approval still clears the review gate. ESCALATE and REMAND are rulings against the PR, and they block the gate even over an external approval.

A diff hazard (an injection phrase, Trojan unicode, or an oversized diff) escalates, because text that could fool the court could fool an external reviewer too. An owner sign-off can still clear it.

A red suite posts no receipt at all, so the court comes back when a re-run turns green.

## Operator settings

### Repository secrets

- **An LLM key**, one of: `ZAI_API_KEY` (already set), `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`. The court needs at least one to run its roles.
- **`MIRQL_COURT_TOKEN`:** a fine-grained personal access token with `contents:write` on this repository. It exists only so the Advocate's fix commits trigger the notary: pushes made with the built-in `GITHUB_TOKEN` start no workflows, so without a court token the notary would never run on the Advocate's commits. Without it the Advocate never pushes, and every AGREE_AND_FIX escalates to a human instead.

### Repository variables

- **`MIRQL_COURT_AUTO_MERGE=1`:** enables merging. Default is off; with it unset, the court stops at the Judge's verdict and a human lands the PR.
- **`MIRQL_PHI_WARRANT`:** the owner's signed Phi warrant, set by `node scripts/phi-warrant.mjs grant`. It is checked against the key pinned in `policy/phi-warrant-key.json` on `main`. Delete the variable to revoke it.
- **`MIRQL_COURT_DISABLED=1`:** halts the court (for incidents or maintenance windows): no role runs and nothing merges. A review signal can still re-run a failed notary gate when the head has an approval or an owner sign-off.
- **`MIRQL_LLM_BASE_URL`:** overrides the Z.AI API endpoint (self-hosted or proxied gateway).
- **`MIRQL_CRITIC_MODEL` / `MIRQL_ADVOCATE_MODEL` / `MIRQL_JUDGE_MODEL`:** per-role model overrides — useful for running the Judge on a stronger model than the other roles. The court enables `thinking: { type: "enabled" }`, `reasoning_effort: "max"`, JSON mode (`max_tokens: 65536`) and streaming for the default Z.AI `glm-5.3` model, so an override runs with that model's own defaults.
- **`MIRQL_CRITIC_PROVIDER` / `MIRQL_ADVOCATE_PROVIDER` / `MIRQL_JUDGE_PROVIDER`:** per-role provider overrides, one of `zai`, `anthropic`, `openai`, `openrouter`, `gemini` (each requires the matching API key secret).

### Turning it off

- **Cost:** the court runs on every open PR from a trusted author as soon as this code is on `main` and an LLM key is set. `ZAI_API_KEY` is already set, so it starts spending when it lands, with auto-merge still off. Set `MIRQL_COURT_DISABLED=1` first if that is not wanted yet.
- **Receipts:** remove `mirql-judge[bot]` and `mirql-critic[bot]` from `aiReviewers` in `policy/paths.yaml` and their receipts stop counting as approval, so the PR needs a human again.

## Wake-ups

The court runs as a workflow from `main` (`.github/workflows/mergeproof-retrigger.yml`). A Codex or CodeRabbit comment, a finished notary run, or a manual dispatch wakes it, and each wake-up rereads all state from the API. Review submissions reach it through `.github/workflows/mergeproof-review-signal.yml`. That event runs the PR's own copy of a workflow, so the signal file holds no secrets and `permissions: {}`; its completion fires `workflow_run` in the court workflow.

## Known limits

- **No branch protection.** The repository has no branch protection on its current plan. The court itself checks the Mergeproof Conscience Gate job result before merging, but a person with write access can still merge anything by hand, bypassing the court entirely.
- **Forgeable receipts.** Receipts are authenticated by the `github-actions[bot]` identity, so any workflow on any branch of this repository can forge one. A dedicated GitHub App identity is required before the repo is opened to untrusted pushers.
- **Self-attesting head tests.** PR code runs in `mergeproof-candidate.yml`, on `pull_request`, so it no longer runs in the base-branch context, but it can still forge `suite_pass_head` by passing its own suite. A forged pass alone stops at `needs_human`, because CI never measures causal proof. The Judge does take the bit as evidence, so a forged pass that gets past the Critic and Judge can land code whose tests fail. This is why the court only serves OWNER/MEMBER/COLLABORATOR authors.
- **A notary re-run does not re-run the tests.** The court's re-run re-reads the candidate suite's result, which is what a sign-off or approval needs. After a flaky failure, re-run `Mergeproof Candidate Suite` first; finishing it does not wake the notary, so re-run the notary's failed jobs after it.
- **The Judge is persuadable.** An LLM Judge can be persuaded by a crafted diff. Hazard scanning (injection phrases, trojan unicode, oversized diffs) is only a filter, not a defense. It does not match the receipt markers or bot commands: those are safe in a diff, because they only count in a comment from the verified bot.
- **A Critic APPROVE is enough for the gate.** On a `humanApprove` PR, one Critic approval on the exact head turns the Mergeproof check green. It does not make the court merge; only a Judge MERGE does that, but a person may read the green check as a full review.
- **A court merge starts no workflows.** The merge uses `GITHUB_TOKEN`, so a push-triggered workflow would not run on `main` for that commit. No workflow here uses `push` today, so this only matters if one is added.
- **The engine is not locked.** `scripts/**` and `packages/mergeproof/**` are not Courthouse Lock paths, so the court can merge changes to its own engine. `roles/critic.md` and `roles/advocate.md` are likewise unlocked; only `roles/judge.md` is locked.
- **Failed model calls are logged without content.** A failed call logs the provider, model, HTTP status or error name, finish reason and character counts. It never logs the reply, which can quote the diff.
- **The Phi warrant is counted from merged history.** Two PRs open at once can each fit what is left, so the second can overspend by up to its own growth; the next PR sees that and stops. Growth merged under an owner sign-off counts as spend too. `roles/judge.md` still says `delta_phi <= 0`, and the tool adds the warrant rule to the Judge's prompt on a run with warranted growth, because a PR touching that file cannot clear the gate. Fold it in the next time the owner edits the file.
- **A failed step leaves a notice, and no verdict.** The Court posts one plain comment per head, role and reason, naming only those three. It carries no receipt marker, so it never counts as approval or as Court state, and it does not wake the Court. The Court retries on its next wake-up, or on `gh workflow run "Mergeproof Court" -f pr_number=<n>`.
- **Time limits are fixed.** A model call gets 12 minutes, and a tick starts no model call that could run past 40 minutes (reason `TICK_BUDGET`). The job limit is 45. Only the default Z.AI model streams, so a slower provider or a model override also hits Node's 5-minute wait for response headers. A call that runs out of time reports `LLM_TIMEOUT`.
- **Network-dependent review.** The LLM calls mean the review step depends on the network. The mechanical gates stay offline-measured (Law 1: Offline Litmus) and still fail closed if the LLM step is unreachable.
