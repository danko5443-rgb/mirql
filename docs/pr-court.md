# PR Court

The PR Court is a three-role LLM review loop run by a deterministic tool from a trusted main checkout. It exists to give pull requests from trusted authors an independent, adversarial review before merge, while keeping every state mutation in deterministic tooling (Constitution Law 3: Roles Propose / Tools Author). The roles only emit JSON proposals; the tool validates, applies, commits, posts, and merges.

## The flow

1. **Critic** (`roles/critic.md`) reviews the diff and emits findings (verdict APPROVE or COMMENT, P1/P2 defects only). External reviewers (coderabbitai, codex-connector) supply findings instead when they are available; the Critic is the independent fallback when they are rate limited or absent.
2. **Advocate** (`roles/advocate.md`) answers each finding: either AGREE_AND_FIX with minimal patches (kept within `delta_phi <= phi_allowance`, which is 0 without a signed Phi warrant) or REBUT with evidence. The tool applies valid patches, commits, and pushes them.
3. **Judge** (`roles/judge.md`) rules on every finding — FIXED, OVERRULED_FALSE_POSITIVE, or UNRESOLVED — and issues the terminal verdict: MERGE, REMAND (another round, up to 3), or ESCALATE (a human takes over). The Judge rules on exactly the findings still open at that head; the prompt names that set explicitly, including the empty case after a base refresh, so a fresh round never echoes the transcript's historical rulings. A MERGE covers only what the Judge saw: a later reviewer finding reopens the case, and a later CHANGES_REQUESTED holds the merge.
4. **Notary check:** after the Judge says MERGE, the tool reads the notary run for the final head. If the gate is not green, it re-runs that run's failed jobs (`gh run rerun --failed`, up to 5 attempts) and waits; a job that already passed is not repeated. Only a green gate on that exact head, measured against the current base tip, authorizes the merge (Law 5: Base-Pinned Mortal Verdicts).
5. **Merge** is executed by the tool, never by an LLM role. The tool then closes the issues the PR links with `Closes #n`, because GitHub left issue 93 open when the court merged PR 94. If that step fails, the merge stands and the run logs a warning. If the merge call fails but the PR turns out merged at the same head (someone merged it by hand at the same moment, as on PR 100), the tool logs `MERGED_ELSEWHERE` and still closes the issues. Any other failure fails the run. A landing that stops short of a merge (`docs/court-landing.md`) posts a `mirql-court-landing:v1` notice on the PR — one per code and head — naming the next step, so a stalled landing never lives only in the run log.

**Fast path.** When the Critic's verdict at the current head is APPROVE with zero findings and no pinned external reviewer finding is outstanding, the Court merges at once: the Advocate and Judge rounds are skipped (one model call instead of three), and the tool itself posts the Judge MERGE receipt — marked `fast_path: true` — so the review gate still clears. Nothing else is bypassed: the merge step waits for the head and base suites to finish green before posting that receipt, the landing then checks the notary gate exactly as a Judge MERGE does, the linked issues still close, and round accounting is unchanged. Any finding — the Critic's, or a pinned bot's whether answered or not — sends the PR back through the Advocate and Judge.

**Single-SHA discipline.** An Advocate push ends the tick at the push. The push invalidates the SHA the Judge would rule on, and the synchronize event starts a fresh cycle — Candidate Suite, Notary, a new Court tick — at the new head, so no Judge call is spent on stale evidence.

The loop runs at most 3 rounds. Anything still unresolved at round 3 escalates to a human; silence and malformed output are hard refusals everywhere (Law 6: Silence Is Never Consent). A missing LLM key is no exception: the tick fails red with a `NO_API_KEY` notice on the PR, because a dead key must not read as a quiet day. Every tick also accounts for its own spend: the provider's token usage per role is logged (`pr-court: tick tokens: {"critic":N,...,"total":N}`) and written to the workflow run summary — integer token counts, never a price guess (Law 17).

## What the roles read

Each role gets the diff, `pr_intent` (the PR's title and body), `linked_issues` (the issues in `Closes #n`, from trusted authors only) and `file_contents` (the head's changed files). A file gets up to 60,000 characters, and the files get whatever is left of 200,000 after the diff, so a big diff shows fewer of them; `partial_files` names anything clipped, refused, deleted or left out. If the linked issues cannot be read, the role still runs, with `linked_issues_unavailable: true`. All of it is fenced as untrusted data. The Advocate also gets the files its findings name, ahead of the others.

The Critic checks each linked requirement and asks whether each new test would fail without its code. It then tries to disprove each candidate finding against the full files before reporting it. The Advocate traces each finding, and its own fix, through the code. The first reply in a tick that fails validation gets one more try; the log records the reply's shape, never its text.

## Courthouse Lock

The Judge does not rule on a diff that touches a locked path: the `humanOnly` list in `policy/paths.yaml` (`CONSTITUTION.md`, `NOT-ROADMAP.md`, `policy/**`, `.github/**`, `roles/judge.md`, `.coderabbit.yaml`, `.coderabbit.yml`, `AGENTS.md`) or any reviewer config file (`AI_REVIEWER_CONFIG_PATTERNS` in `packages/mergeproof/evaluator.mjs`). The reason is self-preservation: a PR must not be able to rewrite the rules of the court that judges it, remove its own reviewers, or amend the constitution to permit itself.

On such a PR the Critic runs once when no external reviewer has reviewed it, and then the court posts a RECUSE receipt that names the files and the next step (`node scripts/owner-signoff.mjs <pr>`). The Advocate does not run, and the Critic's COMMENT is advisory. A reviewer config file gets a different hint, because no sign-off clears those paths and the owner merges by hand.

The evaluator enforces this separately: a court receipt (`mirql-judge[bot]`, `mirql-critic[bot]`) never clears MP-001, so changes to those paths always go to a human.

The Advocate's patches are under the same lock. They also cannot touch `package.json`, `.npmrc`, a symlink, or any path with a segment starting with `.git`.

Note the boundary of the lock in "Known limits" below: `scripts/**` and `packages/mergeproof/**` are not locked by the court itself.

## RECUSE and ESCALATE

RECUSE means the court declines to rule: a locked path, an untrusted author, or a `delta_phi` above what is left of the owner's signed Phi warrant (0 when there is none). It ends the court's work on that head but says nothing about the PR. Clearing the gate afterwards is the owner's act alone: only an owner sign-off clears `MP-001` on a locked path — an external AI approval leaves it `reject` (`TOUCH_HUMAN_ONLY`), it just still satisfies the reviewer requirement for ordinary `humanApprove` paths. ESCALATE and REMAND are rulings against the PR, and they block the gate even over an external approval.

A diff hazard (an injection phrase, Trojan unicode, or an oversized diff) escalates, because text that could fool the court could fool an external reviewer too. An owner sign-off can still clear it.

A red suite posts no receipt at all, so the court comes back when a re-run turns green.

## Operator settings

### Repository secrets

- **At least one LLM key**, any of: `ZAI_API_KEY` (already set), `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`. The roles ride a provider registry with automatic fail-over: a hard failure on one provider — `LLM_HTTP_ERROR` on 401/402/429/5xx, or `LLM_TIMEOUT` — hands the call to the next registry entry that has a key, so one dead key or quota wall degrades to another family instead of failing the tick. A tick ends `ALL_PROVIDERS_FAILED` only when every keyed provider is exhausted; a per-role pin (`MIRQL_<ROLE>_PROVIDER`) keeps one role on one provider and never fails over.
- **`MIRQL_COURT_TOKEN`:** a fine-grained personal access token with `contents:write` on this repository, plus `pull-requests:write` for the Issue Builder and `issues:write` for the Builder's PR-thread lock. It exists so the Advocate's fix commits and the Builder's PRs trigger the notary: pushes and PRs made with the built-in `GITHUB_TOKEN` start no workflows, so without a court token the notary would never run on them. Without it the Advocate never pushes, every AGREE_AND_FIX escalates to a human instead, and the Issue Builder opens nothing.

### Repository variables

- **`MIRQL_COURT_AUTO_MERGE=1`:** enables merging. Default is off; with it unset, the court stops at the Judge's verdict and a human lands the PR.
- **`MIRQL_PHI_WARRANT`:** the owner's signed Phi warrant, set by `node scripts/phi-warrant.mjs grant --budget <n> --per-pr <m>`. One PR may add at most `<m>` of the `<n>` Phi; a larger PR still needs the owner's sign-off, so one PR cannot spend the whole budget. It is checked against the key pinned in `policy/phi-warrant-key.json` on `main`. Delete the variable to revoke it.
- **`MIRQL_COURT_DISABLED=1`:** halts the court (for incidents or maintenance windows): no role runs and nothing merges. A review signal can still re-run a failed notary gate when the head has an approval or an owner sign-off.
- **`MIRQL_BUILDER_DISABLED=1`:** stops the Issue Builder. New issues then open no PRs.
- **`MIRQL_BUILDER_MODEL` / `MIRQL_BUILDER_PROVIDER`:** model and provider overrides for the Builder, like the Court's.
- **`MIRQL_LLM_BASE_URL`:** overrides the Z.AI API endpoint (self-hosted or proxied gateway).
- **`MIRQL_CRITIC_MODEL` / `MIRQL_ADVOCATE_MODEL` / `MIRQL_JUDGE_MODEL`:** per-role model overrides — useful for running the Judge on a stronger model than the other roles. The court enables `thinking: { type: "enabled" }`, `reasoning_effort: "max"`, JSON mode (`max_tokens: 65536`) and streaming for the default Z.AI `glm-5.3` model, so an override runs with that model's own defaults.
- **`MIRQL_CRITIC_PROVIDER` / `MIRQL_ADVOCATE_PROVIDER` / `MIRQL_JUDGE_PROVIDER`:** per-role provider overrides, one of `zai`, `anthropic`, `openai`, `openrouter`, `gemini` (each requires the matching API key secret).

### Turning it off

- **Cost:** the court runs on every open PR from a trusted author as soon as this code is on `main` and an LLM key is set. `ZAI_API_KEY` is already set, so it starts spending when it lands, with auto-merge still off. Set `MIRQL_COURT_DISABLED=1` first if that is not wanted yet.
- **Receipts:** remove `mirql-judge[bot]` and `mirql-critic[bot]` from `aiReviewers` in `policy/paths.yaml` and their receipts stop counting as approval, so the PR needs a human again.

## Wake-ups

The court runs as a workflow from `main` (`.github/workflows/mergeproof-retrigger.yml`). A Codex or CodeRabbit comment, a finished notary run, or a manual dispatch wakes it, and each wake-up rereads all state from the API. Review submissions reach it through `.github/workflows/mergeproof-review-signal.yml`. That event runs the PR's own copy of a workflow, so the signal file holds no secrets and `permissions: {}`; its completion fires `workflow_run` in the court workflow.

## Issue Builder

`.github/workflows/mergeproof-issue-builder.yml` starts the factory one step earlier. When an owner, member or collaborator opens an issue, the Builder (`roles/builder.md`) proposes patches or declines, and `scripts/issue-builder.mjs` validates them, pushes `mirql/issue-<n>` and opens a PR that closes the issue. From there it is an ordinary PR: the gate and the Court decide, and the warrant and the Courthouse Lock apply as usual. A refusal or failure is posted on the issue.

The Builder locks the new PR's conversation the moment it opens it: public users cannot bury the Court's receipts in spam past the API's first comment page, while collaborators and installed Apps — the owner, the Court, the pinned reviewers — can still comment. A refused lock never blocks the PR; the run logs a warning and the PR stays open.

To build an issue that is already open: `gh workflow run "Mergeproof Issue Builder" -f issue_number=<n>`. An issue that already has a `mirql/issue-<n>` branch is skipped.

The Builder gets one attempt, and the job can't run the code it writes, since it holds secrets. If the PR's suite comes back red, the Court posts nothing and the Advocate doesn't run, so the PR waits for a person.

## Known limits

- **No branch protection.** The repository is public and branch rulesets are available on it, but none is configured yet. The court itself checks the Mergeproof Conscience Gate job result before merging, but a person with write access can still merge anything by hand, bypassing the court entirely. A required-checks ruleset with an empty bypass list is on the owner checklist.
- **Forgeable receipts.** Receipts are authenticated by the `github-actions[bot]` identity, so any workflow on any branch of this repository can forge one. A dedicated GitHub App identity is required before the repo is opened to untrusted pushers.
- **Self-attesting head tests.** PR code runs in `mergeproof-candidate.yml`, on `pull_request`, so it no longer runs in the base-branch context, but it can still forge `suite_pass_head` by passing its own suite. A forged pass alone stops at `needs_human`, because CI never measures causal proof. The Judge does take the bit as evidence, so a forged pass that gets past the Critic and Judge can land code whose tests fail. This is why the court only serves OWNER/MEMBER/COLLABORATOR authors.
- **A notary re-run does not re-run the tests.** The court's re-run re-reads the candidate suite's result, which is what a sign-off or approval needs. After a flaky failure, re-run `Mergeproof Candidate Suite` first; finishing it does not wake the notary, so re-run the notary's failed jobs after it.
- **The Judge is persuadable.** An LLM Judge can be persuaded by a crafted diff. Hazard scanning (injection phrases, trojan unicode, oversized diffs) is only a filter, not a defense. It does not match the receipt markers or bot commands: those are safe in a diff, because they only count in a comment from the verified bot.
- **A Critic APPROVE greens nothing by itself.** Only a Judge MERGE receipt on the exact head counts as the court's approval on the gate. A Critic APPROVE is one model call, not a review, so on a `humanApprove` PR it leaves the check red until a ruling lands: the Judge's on a contested PR, or the tool's own `fast_path` receipt on a clean one.
- **A court merge starts no workflows.** The merge uses `GITHUB_TOKEN`, so a push-triggered workflow would not run on `main` for that commit. No workflow here uses `push` today, so this only matters if one is added.
- **The engine is not locked.** `scripts/**` and `packages/mergeproof/**` are not Courthouse Lock paths, so the court can merge changes to its own engine. `roles/critic.md` and `roles/advocate.md` are likewise unlocked; only `roles/judge.md` is locked.
- **Failed model calls are logged without content.** A failed call logs the provider, model, HTTP status or error name, finish reason and character counts. A rejected reply logs its verdict word, its counts and its severity, action or status words. Neither logs the reply's text, which can quote the diff.
- **The Phi warrant is counted from merged history.** Two PRs open at once can each fit what is left, so the second can overspend by up to its own growth; the next PR sees that and stops. Growth merged under an owner sign-off counts as spend too. `roles/judge.md` still says `delta_phi <= 0`, and the tool adds the warrant rule to the Judge's prompt on a run with warranted growth, because a PR touching that file cannot clear the gate. Fold it in the next time the owner edits the file.
- **A failed step leaves a notice, and no verdict.** The Court posts one plain comment per head, role and reason, naming only those three. It carries no receipt marker, so it never counts as approval or as Court state, and it does not wake the Court. The Court retries on its next wake-up, or on `gh workflow run "Mergeproof Court" -f pr_number=<n>`.
- **Time limits are fixed.** A model call gets 12 minutes, and a tick starts no model call that could run past 40 minutes (reason `TICK_BUDGET`). The job limit is 45. Only the default Z.AI model streams, so a slower provider or a model override also hits Node's 5-minute wait for response headers. A call that runs out of time reports `LLM_TIMEOUT`.
- **A real binary file blocks the Court.** The Court diffs with `--text`, so a candidate's `.gitattributes` cannot hide a change as "Binary files differ". A PR that changes a real binary, such as an image, shows its bytes and usually passes the size limit, so the Court refuses it and the owner reviews it. That is on purpose: a NUL-byte test to tell binaries apart can be gamed by a text file holding one NUL, which would put its change back out of sight.
- **Network-dependent review.** The LLM calls mean the review step depends on the network. The mechanical gates stay offline-measured (Law 1: Offline Litmus) and still fail closed if the LLM step is unreachable.
