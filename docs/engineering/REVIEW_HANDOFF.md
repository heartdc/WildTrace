# Offline model-run inspection and evidence handoff

The handoff connects the verified batch, queue, source windows and optional
historical model records. It makes no network request, reads no credential,
executes no suggested commands, and does not change the original candidate queue.

## Failure inspection is not inference acceptance

`ohvul.llm_review --inspect` checks a saved plan, every selected record, the run
summary and the original queue/context/source bindings. It accepts consistent
historical failure records as `bound_incomplete`, not as successful inference.
Its exit code is zero for a consistent inspection and its output explicitly
includes `inference_completed=False` when the run did not complete.

`--verify` remains strict: any failed/rejected/stopped selection returns nonzero.
Neither mode accepts missing records, missing summaries, modified source windows
or invalid request/content/usage bindings. Inspection rechecks actual saved bytes
after reading; even rejected model drafts require an intact transport envelope.
Public transport errors are fixed codes, not arbitrary upstream error bodies.

New plans declare `execution_policy=stop-on-transport-failure-1`. Inspection of
such plans rejects a subsequent call after transport failure. The initial saved
three-403 run predates that policy field; it is inspected as `legacy_unspecified`.
Its bytes are not rewritten and no claim is made that it followed the new policy.

## Evidence tasks

`ohvul.review_handoff` produces one deterministic task for each group and each of
the five existing question IDs: `reachability`, `input_control`,
`bounds_and_lifetime`, `security_impact`, `independent_validation`.

All tasks remain `needs_evidence_or_review`, with answer `unknown` and human
review status `unreviewed`. The module does not implement approvals or automatically
close tasks. A separate evidence-review decision would be required for that.

Successful model drafts contribute separately labeled, untrusted assessments,
reference IDs and requested evidence. Their recommendations do not reprioritize
or remove original candidates. Failed requests, rejected outputs, stopped calls
and groups never selected for a model are retained as different states.

The artifact includes original source/diagnostic reference catalogs, input
digests and explicit run-artifact bindings. Copying the same historical run to
another directory cannot count its calls twice. At most eight explicitly chosen
run directories are read. Input bytes are bounded at 64 MiB and canonical handoff
JSON at 16 MiB. Existing files and source/batch/model-run output trees are protected.
Independent `--verify` regenerates the expected handoff from the original inputs
and rejects altered tasks, deleted groups, changed evidence or invented verdicts.

## Example using the recorded real batch

This command uses historical results and failures; it does not contact the model.
The output file must be new. It remains usable with no `--llm-run`, in which case
all groups are explicitly marked as not requested for model review.

```powershell
python -m ohvul.review_handoff `
  --summary .cache/real_components_c0d3/batch/summary-0005.json `
  --queue .cache/review_33f843/queue.json `
  --context .cache/review_33f843/context.json `
  --source-root camera_app=C:/Projects/OpenHarmony-complete `
  --source-root hilog_featured=C:/Projects/OpenHarmony-complete `
  --source-root securec=C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --llm-run .cache/llm_review_5382/live `
  --output .cache/handoff-new.json
```

To check the file independently, use the same input arguments and replace
`--output .cache/handoff-new.json` with `--verify .cache/handoff-new.json`.
No endpoint, network flag or API key is needed. Recorded paths and current source
snapshots must still match; source changes invalidate the current-source check.

Local hashes establish consistency, not signatures or authentic provider billing.
The file is a review handoff, not a vulnerability report or a control-flow proof.
