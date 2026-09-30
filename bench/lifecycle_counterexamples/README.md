# Lifecycle (UAF) counter-example corpus

Paired true/false samples for the narrow `compiler.lifetime-*` deleter-sequence
rules in `ohvul/clang_facts.py`. Annotation format mirrors
`bench/engine_counterexamples/cases.json`.

- `candidate` entries must be flagged (CWE-416) when the rules run over a real
  Clang AST of the file; `safe_control` entries must stay silent.
- `lc_cjson_mergepatch_alias_uaf.c` / `lc_cjson_mergepatch_fixed_safe.c` are
  reduced from the pinned public cJSON case (`cases/cjson_merge_alias`,
  commit `388cfc96`) - rule back-validation on a known case, **not** a new
  discovery. The remaining entries are synthetic and exist to measure the
  rule's false-positive guards (fixed ordering, reassignment between, fresh
  local allocations, different pointee types).
- Rule output is candidate-only with `path_feasibility: not_proven`; aliasing
  between two distinct handles is never claimed as proven.
