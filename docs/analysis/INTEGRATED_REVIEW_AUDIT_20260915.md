# Mixed static-analysis to review handoff — 2026-09-15

## Scope and collaboration

Starting checkout: `14deaf70188bf6d6d3b9b3fc5bd494cf86c0c7eb`.
The partner feedback was to prioritize a complete case and runtime evidence,
not another scalar-analysis layer. This work connects existing modules.
`clang_facts.py`, `clang_flow.py`, `clang_ranges.py`, and `semantic_rules.py`
remain byte-identical to the starting checkout. No model or target was run.

Version 0.2 batch manifests explicitly select profile engines, compiler AST,
or both. Version 0.1 behavior and historical review bytes remain compatible.
The queue verifies compiler fact/file/profile/diagnostic bindings and retains
per-engine coverage and unknowns. Same-file/line compiler calls are related
observations, not a claim of diagnostic equivalence or proven reachability.
The existing handoff carries these observations without closing tasks.

`tools/component_review.py` is a thin entry point over batch, queue, context,
and handoff. It publishes `static_review_ready` only after saved artifact checks
and source revalidation; failed stages cannot produce that readiness receipt.
Successful sibling diagnostics remain available, and later independent jobs
continue without converting the failed whole batch into success.

## Executed acceptance

- Starting baseline: 691 tests, 687 passed and 4 environment skips.
- Integration/associated final suite: 125 passed, no skips.
- Final full suite: 736 tests, 732 passed and 4 environment skips.
- The added integration module contains 20 tests. The workspace also acquired
  `runtime_evidence.py` and its 25 tests during parallel work; those files were
  preserved, read separately, and included in full-suite acceptance. This work
  does not attribute their implementation to the batch integration patch.
- Legacy `.cache/review_33f843/queue.json` passed its original saved-summary check.
- Actual mixed run completed camera 3, securec 39 and hilog 2 source files using
  CSA, clang-tidy and compiler AST. This is 44 unique selected files, not 132.
- 35 raw diagnostics were retained in 29 review groups; 23 groups have related
  compiler call context. All 145 evidence tasks remain open. Zero confirmed
  vulnerabilities and no runtime execution.
- Full tests and the real run used stable project code and HEAD. Profiles,
  SECURITY.md and artifact hashes remained consistent. Obsidian was unchanged.

The real mixed pipeline command took approximately 380.83 seconds on this run.
That includes provenance checks, compiler work and repeated review validation;
it is not a whole-platform performance benchmark and no peak memory was measured.

## Parallel runtime-record interface

The existing parallel runtime module prepares a case from an explicit candidate
and checks externally supplied build/run/patch/regression records. Its tests use
synthetic operator claims and non-executable fixture artifacts. It neither grants
authorization nor executes a target. Even complete imported records retain
unverified authenticity/execution/effectiveness flags and need human review.
Do not construct another competing runtime-record schema.

An additional attempt to prepare a specific real candidate case was blocked by
the host tool safety check before dispatch. It is not counted as executed or
complete, and no alternative route was used to perform that operation.

## Evidence and remaining gate

`.cache/integration_2b2e/final/acceptance.json` records tests, source hashes,
legacy compatibility, the real run and all pipeline output bindings.
The generated review package is under `final/real/` in that directory.
Post-documentation verification is recorded separately in `postdocs-check.json`.

The partner's runtime-backed case milestone remains open. Static readiness,
compiler execution, synthetic fixtures and imported claims do not substitute
for an actually exercised OpenHarmony case. Product/version, isolated execution
scope and review/submission owners are still pending in HUMAN_ACTIONS.
