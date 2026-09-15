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

Analysis version 2 adds exact values for automatic integer locals: initialization,
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

There is still no general interval analysis, path feasibility, whole-program
call graph, virtual dispatch, heap/alias/lifetime or exploitability proof. Unknown
dynamic lengths and effective caller security boundaries still need evidence.

## Real compiler contrasts

```powershell
python -X utf8 tools/compiler_core_smoke.py --output .cache/compiler-contrast-new
python -X utf8 -m unittest tests.test_clang_scalar_flow tests.test_clang_facts tests.test_clang_stream tests.test_compiler_analysis -v
```

The contrast runner uses a separate synthetic Git workspace, the actual compiler,
result validator and report binder. It never runs fixture functions. Development
positive/negative/unknown cases are not a held-out accuracy benchmark. Consult
the dated audit for final execution results; old failed receipts remain unchanged.
