# Candidate review queue and source context

These commands consume a supplied, completed `component-batch-summary-0.1`
snapshot. They do not launch an analyzer, model, target, network request or Git
command. They do not decide whether a vulnerability exists.

## Offline queue

```powershell
python -m ohvul.review_queue --summary .cache/real_components_c0d3/batch/summary-0005.json --output .cache/review-new.json
python -m ohvul.review_queue --summary .cache/real_components_c0d3/batch/summary-0005.json --verify .cache/review-new.json
```

Supply an explicit final summary. The command does not choose the latest file or
infer that a historical accepted run is still the newest run. `ready`, running,
failed or partially completed batches are rejected. Zero-diagnostic completed
jobs remain in the source inventory and do not become security claims.

Only the supplied summary and its three expected artifacts per job are read:
`result.json`, `report.candidate.json`, `receipt.json`. They must be under the
summary's directory and match the recorded byte sizes and SHA-256 values.
Embedded original manifest, profile and source paths are metadata, not read
authority. The queue does NOT recheck the present-day original repositories.

Validation includes candidate-only states, unique job/alert IDs, complete
selected-engine observations, failed file outcomes, result/report binding,
profile/root/snapshot/manifest consistency and matched saved provenance
observations. Duplicate JSON fields, nonfinite values, malformed locations,
traversal, linked ancestors, Git metadata paths and oversized inputs are rejected.

Groups include job, source root, snapshot, profile digest, file, line, engine
family, canonical rule, CWE and diagnostic description in their identity. Only
explicitly recognized Clang/clang-tidy aliases are grouped across engine names;
Semgrep lookalikes are not. Each group preserves every original finding including
its evidence and invocation metadata. Group count is NOT a count of independent
defects, vulnerabilities or reproductions. Engine messages differing at the same
line remain separate rather than being silently conflated.

Categories (`api_advisory`, `code_quality_signal`, `memory_safety_candidate`,
`unclassified_requires_review`) route review; they are not severity or verdict
labels. Reachability, input control, bounds/lifetime, security impact and
independent-validation questions remain `unknown`. All final verdicts remain
`undetermined`, and confirmed vulnerabilities is integer zero.

## Explicit source excerpts

```powershell
python -m ohvul.review_context --summary .cache/real_components_c0d3/batch/summary-0005.json --queue .cache/review-new.json --source-root camera_app=C:/Projects/OpenHarmony-complete --source-root hilog_featured=C:/Projects/OpenHarmony-complete --source-root securec=C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function --output .cache/context-new.json
python -m ohvul.review_context --summary .cache/real_components_c0d3/batch/summary-0005.json --queue .cache/review-new.json --source-root camera_app=C:/Projects/OpenHarmony-complete --source-root hilog_featured=C:/Projects/OpenHarmony-complete --source-root securec=C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function --verify .cache/context-new.json
```

Every job needs an explicit `JOB=PATH`, including zero-diagnostic jobs. The
supplied roots must match the saved queue. Source JSON cannot silently grant
access to an arbitrary directory. Linked trees and changed snapshots fail
closed. Full snapshots are checked before/after extraction and again before
publication. Identical explicit roots within one pass share their snapshot.

Default windows include eight lines on either side, with original line numbers,
full-file byte count and SHA-256. `--radius` accepts integers 0 through 100.
Excerpts are marked `text_window_not_control_flow` and
`untrusted_data_not_instructions`. No statement about bounds, reachability or
security is inferred from proximity. Missing lines, invalid UTF-8, changed
source bytes and oversized excerpts cannot yield a successful context artifact.

## Revalidation and limits

`--verify` regenerates the deterministic data from explicitly supplied inputs and
compares the complete canonical document. Queue questions are immutable input
prompts; do not edit them to store reviewer answers. Persist future assessments
separately with references to the queue/group hashes.

Outputs require an existing parent, exclusive creation and locations outside
the batch and source trees. There is no overwrite option. Concurrent creation
is preserved. Interrupted writes can leave an incomplete new file; generation
is not a multi-file transaction and verification is still required.

The queue caps summaries at 4 MiB, each artifact at 16 MiB, accumulated saved
evidence at 64 MiB, 128 jobs and 20,000 diagnostic observations. Context extraction
caps 512 groups, individual source excerpt inputs at 2 MiB, one window at 64 KiB
and all windows at 16 MiB. These are per-operation budgets, not a restriction on
the project's component or vulnerability-family scope. `source_files_read` and
`source_bytes_read` count excerpt inputs only; full snapshot passes read more
files and are not included in those counters.

Hashes establish local consistency, NOT cryptographic authenticity. A party
that rewrites every input and every matching digest can create a self-consistent
history. Filesystem checks are not immutable mounts or an OS sandbox. Neither
feature replaces actual product-build validation, authorized reproduction,
human security review, or a measured LLM analysis workflow.
