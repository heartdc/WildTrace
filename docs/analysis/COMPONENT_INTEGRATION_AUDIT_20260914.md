# Component integration audit — 2026-09-14

## Scope and acceptance boundaries

Local implementation and integration acceptance: **passed**. Requested real
OpenHarmony component verification: **not run, access blocked**. A TaskQuay
`open_workspace` request for the actual OpenHarmony checkout was blocked by the
tool safety check. No alternate route was used to inspect that checkout. Its
dependency pins, actual build context, and platform impact were not verified.
This record must not be presented as completion of the competition project.

All code changes and local commands used TaskQuay in `C:\Projects\LSH`.
Baseline and final project HEAD: `9b3fdad5f37a1252ab21c59cc2a9bf2ac63f59e1`.
No project commit/reset/checkout, package install, model session, target-code
execution, or remote repository access was performed in this increment.
The integration demo creates commits only in newly created synthetic Git fixtures.

## Implemented changes

`ohvul.profile_capture` captures missing owners of explicitly listed source files
and include directories into a new profile. Existing repository and rule-hash
pins remain constraints; wrong pins are never refreshed to the current state.
Input ownership, clean repository state and tracked target checks reuse the same
byte-bound validation as normal execution. The template and repository state are
rechecked before exclusive publication. Source files and the template are not
modified. Existing outputs, linked paths, and outputs inside the source root are
rejected. A failed write can leave an incomplete new file; that is not an accepted
profile, and the capture receipt is not a multi-file transaction or signature.

Runtime engine versions no longer assume installation versions. Clang observes
`clang_version` in its plist; Semgrep observes the JSON `version`; clang-tidy uses
an explicit version query of the selected executable. Missing/failed observations
remain `unknown`. The `llvm_root` selection is now also passed to clang-tidy.
Commands, return codes, output digests and version observations are retained in
candidate evidence. These are observations, not authenticated binary identities.

Result merging retains `profile_validations` and per-engine observations instead
of dropping profile receipts at the main CLI boundary. Different observed
versions across shards produce an aggregate `unknown`, preserving per-file
versions rather than advertising the first shard's version for the whole run.

`tools/synthetic_static_demo.py` provides an opt-in, reproducible local integration
entry. It rejects existing output directories, Git metadata destinations,
symlinks and junctions before creating fixtures or launching processes.

## Regression evidence

Baseline: `python -m unittest discover -s tests -v` ran 255 tests, exit 0.

Before version fixes, the five new engine-provenance tests produced three
assertion failures and two errors, exit 1. After the initial fix, two additional
tests exposed dropped profile receipts and a misleading single-version label
across heterogeneous shards: one failure and one error, exit 1. Both were fixed.
The new profile capture feature was tested using actual disposable Git repositories.

Final acceptance used `C:\Software\Dev\Miniforge3\python.exe`:

```powershell
python -m unittest tests.test_profile_capture tests.test_engine_provenance tests.test_profile_input_contract tests.test_engine_profile_scan tests.test_engine_adapter tests.test_engine_execution_contract tests.test_workflow_p0 tests.test_synthetic_static_demo -v
python -m unittest discover -s tests -v
python tools/synthetic_static_demo.py --output .cache\component_demo_b1e52a2a_final
git diff --check
```

| Check | Observed result |
| --- | --- |
| Final focused regression | 103 tests, all passed, no skips, exit 0 |
| Final full regression | 277 tests, all passed, no skips, exit 0 |
| Real static integration demo | Passed, exit 0 |
| Source/test/tool hashes before and after acceptance | Identical |
| Project HEAD | Unchanged |
| Out-of-scope Python changes | None observed |
| Existing Obsidian file bytes | Unchanged |
| `git diff --check` | Exit 0 |

The four symlink tests skipped in earlier work ran and passed in this run.
No cause for that environment difference is inferred. A final process polling
call was blocked; the task metadata subsequently confirmed process exit 0, and
the saved acceptance JSON was read successfully. The command was not replayed
to recover its output.

Machine receipt: `.cache/component_b1e52a2a_r2_acceptance.json`.
Complete logs: `.cache/component_b1e52a2a_r2_final_focused.log`,
`.cache/component_b1e52a2a_r2_final_full.log`, and
`.cache/component_b1e52a2a_r2_final_demo.log`.
Earlier red-stage logs remain in `.cache/component_b1e52a2a_versions_red.log`
and `.cache/component_b1e52a2a_merge_red.log`.

## Actual local analyzer run, not mocked

Final fixture directory: `.cache/component_demo_b1e52a2a_final`.
The fixtures contain one explicit null-dereference control, one guarded safe
control, and one separately versioned header dependency. They are synthetic
source code only and were never linked into or run as a target program.

| Engine | Observed version | Unsafe control candidates | Safe control candidates |
| --- | --- | --- | --- |
| Clang Static Analyzer | 22.1.8 | 1 | 0 |
| clang-tidy | 22.1.8 | 1 | 0 |

Both engines analyzed both declared source files. These two observations refer
to the same synthetic defect, not two real vulnerabilities. Semgrep's installed
version query returned 1.177.0, but Semgrep was not run on source in this demo.

The captured profile added the actual header-dependency repository and preserved
the original component pin. Final fixture commits were:

- component: `d2e52e472567ba028ecbbca60b580e092f7e2996`;
- dependency: `2ceacc0e87871535279fd1312500976929437b6d`.

Result, report and journal verification commands each exited 0. Replacing the
component pin with an intentionally wrong value exited 2, produced `blocked`
with no result digest and `begin -> abort`, and published neither a new result
nor a report. Both source fixture repositories remained byte-for-byte unchanged.
The main result retained one profile validation receipt.

The final complete synthetic demo took approximately 13.55 seconds; the main
scan subprocess took approximately 10.96 seconds. These observations include
tool startup and this tiny local fixture; they are not a large-repository
throughput, memory, detection-accuracy or OpenHarmony performance benchmark.

## Detection-quality gaps observed, not hidden by integration acceptance

The full merged report contains **six candidate observations**: four builtin
heuristic findings, one Clang finding and one clang-tidy finding. The builtin
null-dereference regex reports two lines in `component/safe.c`, including a
pointer declaration and an already guarded dereference. Its two `unsafe.c`
observations also include a declaration. Integration success does not make these
heuristics precise and does not justify treating all six observations as defects.

The observed clang-tidy rule `clang-analyzer-core.NullDereference` still has no
CWE mapping in the current builtin map; the original diagnostic and candidate
status are preserved instead of inventing a classification. This is a separate
classification-quality gap from version provenance.

Remaining competition work includes real authorized component validation,
measured candidate quality and deduplication, reproducible target/platform
verification, branch impact and patch validation, and large-input performance.
Profile capture does not discover undeclared transitive or ignored build inputs.
Hashes and before/after checks do not create an immutable filesystem or prove
vulnerability impact. The actual OpenHarmony checkout remains unexamined in
this increment; no platform or competition-completion claim is accepted.
