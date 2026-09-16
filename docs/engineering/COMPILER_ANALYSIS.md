# Compiler-derived analysis core

`ohvul.compiler_analysis` validates a captured profile and invokes the installed
Clang in syntax-only JSON AST mode. It does not build or execute target programs.
The profile supplies compilation arguments, not permission to invoke its other
engines. The Windows bridge uses the existing local WSL toolchain.

## Running and scope

```powershell
python -m ohvul.compiler_analysis `
  --root C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --profile docs/profiles/securec_captured_20260914.json `
  --timeout 120 --output .cache/compiler-securec-new
```

The output directory must be new, with an existing parent, outside the source.
Input errors may be saved diagnostically; only completed analysis publishes a
candidate report. Compiler failure, timeout, budget exhaustion or input mutation
is not clean analysis. The main CLI exposes the same stage with `--compiler-profile`.
Version, tracked-input, include-directory and snapshot checks remain mandatory.
Current host profiles are not complete product builds or arbitrary target/ABI configurations.

The extractor retains main-file function bodies, types and direct declarations.
Large ASTs are streamed with raw hashes, finite budgets and omitted-header counts.
Process-local AST declaration IDs are not persisted as fact identities. Projection
size is not peak process memory; omitted header bodies are not claimed as analyzed.

## Memory and local scalar checks

Recognized memory builtins receive numeric checks only with known array objects,
capacities, offsets and supported integer lengths. Read/write candidates map to
different CWE types and remain conditional on execution. An in-bounds observation
is not a function-level safety verdict.

Analysis version 2 introduced exact values for automatic integer locals: initialization,
direct assignment, compiler-type coercion, dependent scalar expressions and
equal-value branch joins. Declaration identity, not spelling, distinguishes
shadowed variables. Origins retain source locations and values. Optional values
are not used by literal-only callers of `integer()`.

Unknown calls/stores invalidate facts. Nested argument effects do not assume an
evaluation order. Loops discard incoming values rather than inventing invariants;
fresh body assignments can support a subsequent operation. Early returns and
known conditions/short circuits are handled in the supported statement shapes.

Volatile/static/thread-local/atomic values, unknown parameters, unstructured
control, variable-array evaluation and cleanup effects do not inherit stale
initializers. C++ cleanup and unsupported conditional forms are conservative
barriers. Node, depth, binding and origin budgets fail explicitly.

## Bounded integer intervals (analysis version 3)

The current core adds finite intervals for supported integer parameters and local
assignments. Pure comparisons with a known integer refine the true/false branch;
early-return checks constrain the surviving path. Logical conjunction/disjunction
uses intersections/unions rather than selecting a convenient branch. Joins retain
an enclosing interval; only singleton intervals become exact scalar values.

Comparison inversion accepts only value-preserving casts. Narrowing predicates
cannot constrain the original variable. Arithmetic and conversions use the
observed compiler layout: unsigned wrap widens when necessary, while potential
signed overflow remains unknown. Threshold variables retain their assignment
origins as well as the branch location. IDs remain compiler-process independent.

Arguments expose `integer_range` and `range_evidence`. A natural type range alone
does not certify an extent check. Calls, unknown stores, increments, cleanup and
unsupported control remain conservative invalidation barriers. Node/origin and
condition-refinement limits bound this analysis. This is not a relational solver.

For a recognized builtin and a known fixed object, the memory observations are:

| Status | Interpretation |
| --- | --- |
| `within_known_object` | All values in the supported length interval fit this known extent; not a general safety verdict |
| `exceeds_known_object` | All values exceed the known extent if the call executes; emits a candidate, not a confirmed vulnerability |
| `may_exceed_known_object` | The interval overlaps in-bounds and out-of-bounds sizes; retained as a review observation, not a definite finding |
| `unknown` | Missing object, length or applicable evidence; never interpreted as safe |

There is still no general path-feasibility, whole-program call graph, virtual
dispatch, heap/alias/lifetime or exploitability proof. Relations such as
`count <= destination_capacity`, where both are unknown variables, require further
analysis. Header bodies are outside the main-file analysis scope. A checked extent
does not establish object lifetime, caller trust, or the absence of other defects.

## Real compiler contrasts

```powershell
python -X utf8 tools/compiler_core_smoke.py --output .cache/compiler-contrast-new
python -X utf8 -m unittest tests.test_clang_ranges tests.test_clang_scalar_flow tests.test_clang_facts tests.test_clang_stream tests.test_compiler_analysis -v
```

The contrast runner uses a separate synthetic Git workspace, the actual compiler,
result validator and report binder. It never runs fixture functions. Development
positive/negative/unknown cases are not a held-out accuracy benchmark. Consult
the dated audit for final execution results; old failed receipts remain unchanged.
