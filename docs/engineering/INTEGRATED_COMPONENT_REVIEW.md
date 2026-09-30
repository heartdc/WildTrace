# Integrated static analysis and evidence handoff

This entry point connects existing analysis and review modules. It does not add
another detector, run a model, execute target programs, confirm vulnerabilities,
or submit a report to an external service.

## One command

From the repository root, with the existing WSL compiler and fixed source checkout:

```powershell
python -X utf8 tools/component_review.py --manifest docs/profiles/real_components_integrated_20260915.batch.json --output .cache/integrated-review-new --timeout 120
```

The output must be new and outside all source trees. Nothing is overwritten.
The command runs the batch, verifies its saved result/report/receipt artifacts,
builds the review queue and source windows, and writes the existing evidence
handoff. The final `status.json` says `static_review_ready`, NOT verified
vulnerability or completed competition submission. Runtime verification remains
`not_run`, every evidence question remains open, and no model is invoked.

Generated structure:

```text
batch/summary-NNNN.json
batch/<job>/result.json
batch/<job>/report.candidate.json
batch/<job>/receipt.json
review/queue.json
review/context.json
review/handoff.json
status.json
```

## Versioned selection and evidence

Legacy `component-batch-0.1` manifests keep their existing behavior and saved
review bytes. Version `0.2` requires `analyses` on every job. Supported selections
are `["profile-engines"]`, `["compiler-ast"]`, or both in that order.
`profile-engines` invokes the profile's selected tools; `compiler-ast` uses its
compilation inputs but does NOT invoke the profile's other engines. Selection is
bound in the result, job and receipt; observed engine identities must match.
Compiler stages accept a timeout of 1–120 integer seconds per compiler invocation.
The legacy batch CLI defaults to 300, so specify `--timeout 120` for mixed batches.

Each engine retains its execution outcomes. A failed stage leaves diagnostic
artifacts, but cannot publish a successful candidate report or whole-run review
readiness. Independent later jobs continue; the batch remains nonzero if any
job is incomplete. Files analyzed by multiple engines are not added as unique
coverage. Compiler facts, hashes, source bindings, limits and unknowns survive
the merge, including jobs without compiler candidates.

Queue verification checks saved compiler facts against their per-file digest,
execution and profile records, and checks that compiler candidates were not
dropped or relabelled. The queue retains compiler coverage per source job.
Same-file, same-line calls are linked as related context, NOT as proof that two
diagnostics describe the same defect. Handoff preserves these observations
separately from model proposals and does not close or approve tasks.

Hashes establish local consistency, not signatures or authenticated producers.
Source/configuration semantics, attacker control and runtime behavior still
require review. Header bodies outside the selected compiler scope are not
silently counted as analyzed. Sample profiles remain host-static profiles, not
full product builds.

## Independent offline check

The complete saved delivery can now be checked with the same explicit manifest:

```powershell
python -X utf8 tools/component_review.py --manifest docs/profiles/real_components_integrated_20260915.batch.json --output .cache/integration_2b2e/final/real --verify
```

`STATIC_REVIEW_VERIFIED` means the saved manifest/profile bytes, final batch,
queue, source windows, handoff and readiness receipt agree. Verification reads
fixed artifact names derived from the explicit manifest, never follows paths
suggested by a modified status file, never writes files and never reruns analyzers.
Missing final receipts, changed source/configuration and relabelled runtime or
vulnerability fields are rejected. The original creation mode still rejects
an existing output directory; `--verify` does not enable overwrites.

This command requires the declared source/profile paths to remain available.
It is evidence consistency checking, not fresh compilation, runtime observation,
signature verification or vulnerability confirmation. Separate commands remain
available for diagnosing individual stages:

Use the explicitly saved final summary from this run (not an arbitrary older
summary) with the existing `review_queue --verify`, `review_context --verify`,
and `review_handoff --verify` commands. Source-context verification still requires
explicit `--source-root JOB=PATH` mappings. These operations never call an analyzer
or a model. The script performs all three checks itself before publishing readiness.

## Runtime handoff is a separate gate

The partner's requested runtime-backed case is NOT satisfied by static readiness,
compiler execution, or synthetic fixtures. The product/version matrix, isolated
environment and explicit execution scope, and review/submission owners must be
confirmed in `docs/status/HUMAN_ACTIONS_20260914.md` before that milestone.
