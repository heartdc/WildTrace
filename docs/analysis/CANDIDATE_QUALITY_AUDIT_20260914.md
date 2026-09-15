# Candidate quality and CWE mapping audit — 2026-09-14

## Accepted scope and limits

This checkpoint covers local candidate syntax quality, exact CWE mappings,
evidence-bound review observations, regression tests, and the real local Clang
synthetic integration demo. It does not complete the competition project.
The previously blocked OpenHarmony checkout was not accessed by another route.
No OpenHarmony target program, exploit, or external LLM service was executed.

Baseline HEAD: `9b3fdad5f37a1252ab21c59cc2a9bf2ac63f59e1`.
The initial full suite ran 277 tests with exit code 0. Existing project edits
were preserved. No project Git commit, reset, clean, or policy change was made.

## Implemented changes

`ohvul/detect/lexical.py` masks comments, ordinary literals and C++ raw literals
while preserving source line locations. The builtin scanner separates obvious
pointer declaration/multiplication syntax from possible dereference syntax.
It recognizes only narrow direct-return guard forms, such as
`return p ? *p : 0;` and `if (p != 0) return *p;`.

Non-dereference syntax, recognized guards and explicit line-comment suppression
are retained as `rule_observations` with original source evidence, file digest,
column, rule version and `final_verdict=undetermined`. They are not proofs of
code safety or independent human reviews. Strings containing `ohvul:ignore`
cannot suppress scanner output. Unknown control flow, pointer reassignment,
different-pointer guards, macro contexts and volatile/atomic contexts are not
treated as proven non-null. Visible dereferences after control statements are
kept; parenthesized multiplication may therefore still be a candidate.

`ohvul/verify.py` validates observation content and references with the same
evidence mechanism used for findings. New CWE fields are bound to evidence and
checked against the displayed finding; legacy records without that field do not
retroactively gain this stronger binding. Shard merging preserves observations.

The exact `clang-analyzer-core.NullDereference` mapping now produces CWE-476.
Original engine rule names and provenance are retained. The ambiguous
`unix.Malloc` checker no longer automatically implies CWE-416. Engine-reported
CWE identifiers are validated and attributed to `engine_reported`, not to the
builtin map. Unknown checkers remain unclassified. Mapping version is `2`.

## Actual execution evidence

| Stage | Observed result |
| --- | --- |
| Initial new regressions against old implementation | 23 methods; 25 failures and 3 errors including subtests; exit 1 |
| Initial implementation-specific suite | 23 methods passed; exit 0 |
| Intermediate full regression | 293 tests, two failures and one test-import error; exit 1 |
| Corrected implementation, before line-ending cleanup | 104 focused and 304 full tests passed; real demo passed; diff check failed |
| Final accepted focused suite | 104 tests passed, no skips, exit 0 |
| Final accepted full suite | 304 tests passed, no skips, exit 0 |
| Final actual Clang/clang-tidy demo | passed, exit 0 |
| Final diff and source checks | diff check 0; source hashes/HEAD stable; no out-of-scope Python changes; Obsidian unchanged |

The intermediate test-import error was an indentation mistake in an edited
test. Other compatibility failures concerned evidence ordering/counts after
adding observations. They were fixed, not skipped. Three CRLF diff failures
were corrected with byte-hash and AST-equality checks, followed by fresh tests
and a fresh synthetic demo directory. A multiline shell command returned 0
without performing the intended format change; direct file inspection caught
that no-op before acceptance.

Some tool requests were blocked before execution/receipt retrieval. Task state
and persisted logs were reconciled; missing receipts were not counted as passes.

Machine receipt: `.cache/quality_57a_r2_acceptance.json`.
Full logs: `.cache/quality_57a_r2_final_focused.log`,
`.cache/quality_57a_r2_final_full.log`, `.cache/quality_57a_r2_final_demo.log`.
Red-stage log: `.cache/quality_57a_red.log`.

Final entry used: `python .cache/accept_quality_57a.py r2`.
The script selects a new demo directory for each revision; it does not overwrite
an existing demo. Exact subprocess commands, exit codes and log hashes are in
the machine receipt.

## Measured candidate results, not vulnerability accuracy

The unchanged eight-case regression annotations now produce TP=5, FP=0, FN=0
at the **case/CWE candidate-label** level. The historical
`docs/design/rule_benchmark_report.json` remains unchanged at TP=5, FP=2, FN=0.
These tiny, development-used synthetic cases are not an independent held-out
dataset and cannot establish real-world precision, recall or zero false positives.

The real demo uses installed Clang and clang-tidy 22.1.8 on disposable synthetic
sources. No target program is run.

| Source | Unsafe fixture candidates | Safe fixture candidates |
| --- | --- | --- |
| Builtin rule | 1 | 0 |
| Clang Static Analyzer | 1 | 0 |
| clang-tidy | 1 | 0 |

There are three candidate observations of **one known synthetic defect**, not
three independent vulnerabilities or independent reproductions. The prior demo
had two builtin candidates on each control; declaration noise and the narrow
guarded-return false positive are removed. Both real engine findings now carry
CWE-476. Result/report/journal validation passes; a wrong repository pin still
produces a blocked checkpoint, an abort sequence and no successful output.
Confirmed real vulnerabilities in this acceptance remain zero.

Demo evidence: `.cache/quality_demo_57a_final_r2/acceptance.json` and sibling
result, report, checkpoint and logs. Source repositories remain unchanged.

## Remaining work

This lexer is not an AST/CFG, preprocessor, alias analysis, lifetime analysis or
concurrency model. C++ operator overloading, function-pointer declarations,
more complex guards and unevaluated expressions still need compiler-backed
context. Source-authored suppression observations are not trusted reviewer
decisions. Broad memory-copy/length rules remain candidates. Observation volume
and repeated source snapshots require real-scale performance measurements.

Next acceptance should prioritize an accessible, fixed OpenHarmony component,
security-impact triage and authorized independent validation, not another layer
of generic bookkeeping. See the competition readiness record for dependencies
and conditional engineering effort estimates.
