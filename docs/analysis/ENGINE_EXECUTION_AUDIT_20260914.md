# Engine execution and evidence audit — 2026-09-14

## Scope

Workspace: `C:\Projects\LSH`. Work run:
`run_b0b5d9bcb4fe412a88ebc14bd2fe1eab`.
Inspected and changed the adapter -> engine CLI -> shard/profile chain, plus
the main CLI's explicitly requested engine gate. All new analyzer tests use
synthetic local source and mocked analyzer outcomes. No OpenHarmony target,
real Clang/Semgrep process, dependency installation, or remote target was run.

The native Codex agent list request returned `DAEMON_STARTUP_FAILURE` before
inference. Implementation and verification used direct TaskQuay host tools;
this run does not claim a successful Codex agent execution.

## Findings and corrections

| Finding | Correction and tested boundary |
| --- | --- |
| Standalone engine CLI always returned zero, including total analyzer failure. | Completed runs return 0; partial/input-error diagnostic results return 1. Input/argument/publication errors use the CLI error path. An explicitly requested failed engine blocks the main CLI's checkpoint/journal attempt rather than certifying success. |
| File counts came from diagnostics or requested entries, not completed analyses. | Requested, attempted, completed and failed files are separated. A completed zero-diagnostic file counts as analyzed. Unknown coverage is null, not an invented zero. |
| Partial status depended on whether any candidate existed. | Status depends on execution outcomes, independently of candidate count. Per-file outcomes and error reasons are retained. |
| Projection/merge dropped execution failures and replaced engine provenance. | Projection preserves status and structured errors; merging records engine_observations, retains errors and per-engine metadata, and does not mutate its inputs. |
| Engine CLI and shards could bind results only after input changes. | Shards/manifests compare before/after source snapshots; mismatches reject results. Merging rejects mismatched or one-sided snapshot binding. The main CLI supplies its initial snapshot to its base scan. |
| Empty or duplicate/aliased manifests could appear as completed or inflated scans; absolute entries were accepted. | Nonempty distinct input sets are required. Manifest paths must be relative and in-root; invalid input is not sent to the analyzer. Direct source-file CLI arguments may be absolute if they are inside source-root. |
| Engine output could overwrite analyzed source. | Output must be outside source-root, must not alias input metadata, and cannot replace an existing diagnostic output without --force. Default publication uses exclusive creation. |
| Profiles ran Clang even for Semgrep-only selection and ignored declared clang-tidy. | Profiles dispatch only selected engines. clang-static-analyzer and clang-tidy use the shared per-file outcome contract. Semgrep-only selection does not run Clang; Semgrep requires explicit local rules. |
| Embedded Semgrep errors and malformed Clang plist data could lose failure information. | Structured Semgrep errors survive normalization/profile projection. A plist lacking a diagnostics list, invalid diagnostic file references, and contradictory completed-with-errors results are rejected or recorded as errors. |

## Current result contract

`scan.files_requested` counts declared entries; `files_attempted` counts analyzer
attempts; `files_scanned` counts successfully analyzed files, even with no
findings; `files_failed` includes invalid input and failed attempts. There is no
automatic skip mode in this per-file runner; `files_skipped` is zero. These are
per-engine observations, not a claim of whole-platform coverage.

`files_with_findings` is diagnostic location coverage, not analysis coverage.
For imported normalized results without execution coverage, `files_scanned` is
null. Consumers must handle null as unknown. Multi-engine scans preserve
`engine_observations`; unique successful files are counted only when all relevant
per-file records are available. Otherwise aggregate coverage is unknown. Engine
invocation counts are not interchangeable with file counts.

The existing result schema label remains 0.3; these execution metadata fields
are additive, but consumers assuming files_scanned is always an integer must be
updated. Legacy results missing snapshot binding cannot be merged into a bound
run; regenerate results rather than silently supplying a guessed binding.

Status completed describes execution, not vulnerability confirmation or absence.
Findings remain candidates. A standalone failure JSON is diagnostic evidence,
not a successful scan merely because it is syntactically valid JSON.

## Executed regression evidence

Before engine implementation changes:

`python -m unittest tests.test_engine_execution_contract -q`

14 tests ran: 12 assertion failures and 2 errors, exit 1. Receipt:
`op_ad4a8c71f55944d0b1084610dfbe89ac`.
This is an executed before/after regression comparison on synthetic fixtures,
not a claim of reproducing a real target vulnerability.

After corrections the initial 14 tests passed. Further cases were added for
embedded errors, malformed plist, aliased paths, main-CLI abort behavior and
structured profile errors. Current focused command:

`python -m unittest tests.test_workflow_p0 tests.test_engine_execution_contract tests.test_engine_profile_scan -v`

Most recent executed focused result: 37/37 passed. Most recent full command:
`python -m unittest discover -s tests -v`, 220 tests run, 216 passed, 4 skipped.
The four skips report `symlink unavailable`: checkpoint-link input rejection,
checkpoint path rejection, scanner source skipping, and snapshot exclusion.
Those branches have not been verified in this Windows environment.

An initial combined verification returned failure because `git diff --check`
found inherited mixed-line-ending whitespace, although both test commands exited
0. Only the three affected workflow files were normalized to LF; Python ASTs
were checked equal before/after, and the subsequent diff check exited 0.
Final combined verification passed after the newline cleanup. Receipt:
`op_13d28d6206054651bebb459a6b2ea6b0`. Focused: 37/37 passed, exit 0;
full: 220 run, 216 passed, 4 skipped, exit 0; diff check: exit 0.
All Python source/test hashes and HEAD were unchanged during these commands.
The machine record is `.cache/acceptance_b0b5d9_final.json`; complete outputs are
`.cache/acceptance_b0b5d9_final_focused.log` and
`.cache/acceptance_b0b5d9_final_full.log`. These files were written by the actual
verification command, not reconstructed from expected outcomes.

## Remaining limitations / next audit

- Snapshot comparisons are not immutable source capture: change-and-revert,
  filesystem races and changes after the final check are not ruled out.
- Whole-root hashing at shard and manifest boundaries favors correctness here
  but repeats work; measure and optimize this before large-tree performance claims.
- Profile repository provenance validation and compile-argument allowlisting
  are not yet enforced end-to-end. Declared repository commits are not verified
  merely because the content snapshot matches.
- Analyzer version constants still exist in low-level adapters; measured tool
  fingerprints should replace assumed version labels in a later bounded task.
- SARIF and remaining imported metadata validation need further adversarial
  tests. These changes do not constitute a complete audit of every normalizer.
- The built-in text scanner's silent read-error behavior is a separate remaining
  issue; these engine corrections do not imply that scanner has been hardened.
- Hashes and safety labels are not signatures, an enforced network sandbox, or
  evidence of vulnerability validity. Multi-file publication is not transactional.
- No real analyzer coverage, vulnerability precision/recall, OpenHarmony build,
  exploitability, patch effectiveness or platform impact was measured here.

Recommended next bounded task: enforce profile provenance/input contracts and
unify built-in scanner read errors with the explicit execution status contract,
then validate one fixed authorized component with measured tool fingerprints.
