# Integer range core and interrupted-run recovery — 2026-09-15

## Scope

Work run `run_ef6abb8e5f1a41aea9700745fbd8eb69` used TaskQuay direct tools in
`C:\Projects\LSH`. LLM integration and network retries remained paused. No
OpenHarmony target program was built as an executable or run; no Codex session
was started. Real Clang syntax/AST extraction is distinct from target execution.

## Interrupted batch reconciliation

The prior run had no active command and no final receipt on reconnection. Its
saved acceptance script was then executed. It passed 116 focused tests, 661 full
tests (657 passed, four symlink-environment skips), compiler contrasts, main-CLI
binding/replay and the 44-file real batch. Its overall receipt initially rejected
the run because an external commit integrated existing tested code during the run.

Commit `a336c65` was compared with the starting `2505c1e`; all tested code bytes
were unchanged. `.cache/range_ef6abb/recovery-acceptance.json` records this explicit
reconciliation. The original `.cache/core_a61e/final/acceptance.json` was retained
without rewriting failure to success. The prior TaskQuay work was then closed.

## New analysis capability

`clang_ranges.py` adds compiler-typed integer domains, arithmetic bounds and
conversion handling. The existing structured visitor in `clang_flow.py` now uses
these intervals for selected pure comparisons, early returns, boolean branches
and joins. Known threshold variables preserve their assignment source evidence.
The scope remains bounded and non-relational. There is no solver, general loop
invariant, heap-capacity inference, virtual dispatch or path-feasibility proof.

`clang_facts.py` exposes per-argument intervals and origins. Memory bounds require
a recognized builtin and a known object. A wholly out-of-extent interval produces
a conditional candidate; an interval overlapping the object extent produces only
`may_exceed_known_object`. Unknowns are retained, not counted as safe. Unsupported
casts cannot be inverted to claim a bound on the original variable. Calls, unknown
stores, increments, loops and cleanup effects invalidate applicable facts.

## Verification

The first 21 new test methods on the original core produced five assertion
failures and eight errors (missing interval capability and fields). That red run
is preserved at `.cache/range_ef6abb/range-red.log`. Thirty dedicated range tests
now cover these cases plus threshold origins, unsigned wrap, signed overflow,
effect invalidation, unrelated checks and exhaustive small integer domains.

The final unified invocation was `op_ac5da9be89c94a3fab6674f8e61b2744` (exit zero):

| Check | Observed result |
| --- | --- |
| Focused regression | 146 passed; no skips |
| Full regression | 691 run, 687 passed, 4 symlink-environment skips |
| Real compiler contrast | 18 positive, 24 negative, 12 unknown/unconfirmed and 3 possible-range controls matched expectations |
| Main CLI and report/checkpoint binding | Passed |
| Independent compiler process normalized replay | Identical fact digests |
| Real inputs, tested source bytes and difference check | Passed; final acceptance HEAD stable |

The contrast suite contains 57 named controls across 59 parsed functions including
helpers. It is development-used, not held out, and is not a real-world accuracy
estimate. No fixture function was executed. No numerical violation is a runtime
reproduction or a confirmed OpenHarmony vulnerability.

## Real component results

| Component | Files completed | Calls carrying integer-range evidence | Candidates |
| --- | ---: | ---: | ---: |
| camera | 3/3 | 1 | 0 |
| securec | 39/39 | 19 | 0 |
| hilog | 2/2 | 0 | 0 |

The 20 range-bearing calls are not 20 memory bugs or 20 resolved safety decisions.
Securec still has 35 unknown memory-extent checks. Current profiles are fixed host
analysis configurations, not complete product builds. Original engine diagnostics
and review artifacts were not rewritten. All new outputs are under the final
directory below. General caller influence and object capacity still need evidence.

## Evidence and remaining work

The final receipt, focused/full logs, real component results and reports, contrast
results and main-CLI artifacts are in `.cache/range_ef6abb/final/`. The script
`.cache/range_ef6abb/accept.py` records actual command exits, hashes, input rechecks,
scope counts, skips and untouched source checks. It uses tested file bytes as its
identity basis and records Git refs separately so commit movement is not hidden.

One ancillary real-evidence preview was blocked by a tool check and not executed;
it is not a validation result. A malformed multi-line shell test wrapper produced
no test files and was not counted as a test run. Subsequent direct test commands
and the final saved acceptance script produced the cited real logs.

Next: integrate compiler/range analysis with the established component and review
pipeline, then add relation/object-capacity summaries and C++/lifetime capability.
Use independent contrasts and real profiles, retaining unknowns and guard failures.
See `docs/status/NEXT_ROADMAP_20260915.md`. No new human input blocks this sequence;
product configuration and isolated runtime authorization affect only their stages.
