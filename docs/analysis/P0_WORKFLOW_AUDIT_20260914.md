# P0 workflow audit — 2026-09-14

## Scope and reconciled workspace

Bounded local defensive workflow/checkpoint recovery and publication gates.
Acceptance run: `run_b0b5d9bcb4fe412a88ebc14bd2fe1eab`.
Observed HEAD: `9b3fdad5f37a1252ab21c59cc2a9bf2ac63f59e1`.
At re-entry the previous changes to `ohvul/cli.py`, `ohvul/workflow/fsm.py`,
`tests/test_workflow.py`, and this draft were present. `tests/test_workflow_p0.py`
was absent and was added in this run. The pre-existing dirty
`docs/.obsidian/workspace.json` was not edited. No new commit was observed at
re-entry; this observation is not a guarantee against later external edits.

## Observed commands and results

| Command | Tests run | Passed | Skipped | Exit |
| --- | ---: | ---: | ---: | ---: |
| `python -m unittest tests.test_workflow tests.test_snapshot tests.test_integrity tests.test_checkpoint_link tests.test_verification_gate tests.test_verification_link tests.test_joint_files -q` | 59 | 56 | 3 | 0 |
| `python -m unittest tests.test_workflow_p0 -v` | 15 | 15 | 0 | 0 |
| `python -m unittest discover -s tests -q` | 200 | 196 | 4 | 0 |

TaskQuay command receipts: `op_18d93d3fe493414aabd1c9c290f61511`
and `op_fae8f8c26b584f2893fe47025555c2df`.
The reported total includes skipped tests; skips are not passing tests.
Expected negative-fixture diagnostics (for example `INVALID` and parser errors)
were printed while the suite itself exited successfully.

The previous draft incorrectly labelled a post-edit failure as a baseline and
described expected passes as evidence. Those claims are superseded by this table.
An attempted old-revision comparison was blocked by the tool safety check and
has no execution receipt. The new assertions exercise the previously identified
failure paths on the current code, but an executed old-fails/new-passes comparison
is NOT claimed.

## Fixes and regression coverage

- Recovery uses the same transition gate for direct and helper calls; only
  intake/static_scan are allowed, each recovery consumes exactly one retry,
  exhausted/rejected transitions leave the checkpoint unchanged, stale result
  bindings are cleared, and the source snapshot binding is retained.
- Both supported recovery targets can rerun while retaining task identity and
  cumulative retries. Successful rescans do not embed the prior result digest;
  the saved checkpoint binds the newly written result bytes.
- Failed rescans retain any previous output files without certifying them for
  the new attempt: the checkpoint is blocked with no result digest and the
  latest journal attempt is begin/abort, not committed.
- Source changes during scan or report preparation, and report preparation
  failures, prevent new result/report publication. A report write failure cannot
  produce a success commit even if a result file was already published.
- Boolean retry counters, malformed hexadecimal digests and invalid checkpoint
  persistence are rejected. Report replacement requires --force; conflicting
  engine arguments are rejected before output/checkpoint/journal side effects.

## Acceptance limits and remaining risks

This batch passes the listed local synthetic regressions. It does not prove real
OpenHarmony vulnerabilities, analyzer accuracy, platform impact, or competition
completion. Skipped environment-specific tests remain unverified.

Source rechecking is a before-publication comparison, not an immutable checkout:
change-and-revert and changes after the check remain possible. Multi-file output
publication is not transactional; an uncommitted result can remain after a later
write failure and must be rejected using the checkpoint/journal chain. No stronger
filesystem race or all-or-nothing publication guarantee is claimed.

Next bounded audit: engine_adapter.py -> engine_cli.py -> engine_shards.py,
focusing on execution failures versus clean zero-findings scans, declared and
successful file coverage, snapshot consistency, and preservation of errors and
engine provenance during merging.

## Final integration acceptance in this run

The engine-chain work was subsequently implemented; see
`ENGINE_EXECUTION_AUDIT_20260914.md`. Final receipt:
`op_13d28d6206054651bebb459a6b2ea6b0`.

- `python -m unittest tests.test_workflow_p0 tests.test_engine_execution_contract tests.test_engine_profile_scan -v`:
  37 run, 37 passed, exit 0.
- `python -m unittest discover -s tests -v`:
  220 run, 216 passed, 4 skipped, exit 0.
- `git diff --check`: exit 0 after newline-only cleanup. AST equality was checked
  before/after normalizing the three inherited workflow files.
- All Python source/test hashes and HEAD were unchanged during final test
  execution. HEAD remained `9b3fdad5f37a1252ab21c59cc2a9bf2ac63f59e1`.

The skipped tests all report `symlink unavailable`; they concern checkpoint/link,
scanner and snapshot symbolic-link behavior. No passing result is claimed for
those four tests.

Persisted machine record: `.cache/acceptance_b0b5d9_final.json`.
Full captured logs: `.cache/acceptance_b0b5d9_final_focused.log` and
`.cache/acceptance_b0b5d9_final_full.log`. This final integration result supersedes
earlier unverified or failed attempts, without relabelling those attempts as passes.
