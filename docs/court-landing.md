# Reading a Court landing

`gh pr checks` does not list Court runs. Use `gh run list --workflow "Mergeproof Court"`. After a Judge MERGE, the run log has `pr-court: landing: <code>`:

| Code | Meaning | Next step |
|---|---|---|
| `MERGED` | The Court merged the PR. | None. |
| `AUTO_MERGE_OFF` | `MIRQL_COURT_AUTO_MERGE` is not `1`. | Owner decides. |
| `NOTARY_BASE_STALE` | The base moved after the notary ran. A re-run keeps the old base. | Push to the PR. |
| `HEAD_MOVED` | The PR closed or has a new head. | Check the PR. |
| `NOTARY_NOT_GREEN` | The gate is not green on this head, or its re-run outlasted the wait. | Read the gate log. |
| `NOTARY_NOT_RERUNNABLE` | The gate has no finished failed run, or used its 5 attempts. | Wait, or push. |
