# Fixed-source cJSON MergePatch ownership case

This is a **public-known library regression case**, not a new vulnerability
discovery and not proof that an OpenHarmony product accepts attacker-controlled
calls to this API. Current local status: **prepared and syntax-checked; runtime
not executed**. The tool-side isolation-check invocation was blocked. No alternate
route was used to execute it.

## Reproducible inputs

The source is the clean local OpenHarmony `third_party/cJSON` checkout at
`388cfc96925e4fb41a30735b270736626d26615d`, declaring cJSON 1.7.19. The preparation
tool checks that commit and the recorded raw source digests, makes separate
original/patched copies, retains the upstream license, and never modifies the
original source. Windows CRLF bytes are preserved; the copied patch is narrow.

```powershell
Set-Location C:\Projects\LSH
python -X utf8 tools/cjson_case.py prepare `
  --source C:/Projects/OpenHarmony/third_party/cJSON `
  --output .cache/cjson-case-another
python -X utf8 tools/cjson_case.py verify --output .cache/cjson-case-another
```

`verify` verifies the prepared source package, **not runtime results**. The actual
prepared package from this work is `.cache/cjson-case-6d4f/`.

## Defect and controls

`merge_patch` deletes the target before duplicating a non-object patch. When
that patch is a borrowed target subtree, recursive deletion also frees the patch.
The following duplication reads the stale node. `patch.diff` duplicates first,
then deletes the consumed target. It addresses this non-object branch only.

`poc.c` deliberately does not delete the consumed target or a borrowed patch
after `MergePatch`. This matters: a harness double-delete can itself produce
an AddressSanitizer error without proving a library defect.

| Mode | Relationship | Original expectation | Patched expectation |
| --- | --- | --- | --- |
| subtree | Array patch borrowed from target | Library UAF at duplication | Correct array result |
| scalar-subtree | Scalar patch borrowed from target | Library UAF | Correct number |
| self-array | Patch equals non-object target | Library UAF | Correct array |
| independent | Separately allocated patch | Correct result, no sanitizer error | Same |
| detached | Subtree detached before merge | Correct result, no sanitizer error | Same |
| object-merge | Ordinary independent object patch | Correct merged object | Same |
| object-delete | Ordinary null-member deletion | Correct remaining members | Same |

The last column is a **test expectation**, not an observed outcome. Both public
case-sensitive and case-insensitive entry points are covered in the planned
patched matrix. Three original alias runs and a fresh second build are planned;
these counts are project policy, not competition-specified requirements.

## Execution boundary

The driver's Linux-only `run` mode requires `--execute-authorized`, an already
prepared package and installed bubblewrap/Clang. It must only be invoked where
execution is permitted by both the owner and the execution platform. Preparation
and unit tests never invoke that mode. No fallback to host execution exists.

Before any target runs, the driver checks separate network/PID namespaces and
absence of host home/Windows mounts. It uses fixed compile arguments, read-only
source copies, fresh sandboxes, CPU/wall-clock/output limits and tiny fixed inputs.
It does not download code or accept arbitrary compilation commands. ASan needs
large virtual mappings; no cgroup hard RAM bound is asserted. A namespace setup
is not an immutable VM image or signed execution attestation.

Runtime acceptance requires the expected ASan use-after-free access stack in
`cJSON_Duplicate*` associated with `merge_patch`, plus correctly computed patched
and independent-control outputs. A generic crash, timeout, missing build, or
caller cleanup error is not success. The second build is **not independent human
review**. Runtime logs cannot be fabricated from these expectations.

## Build and product qualification

The observed `BUILD.gn` includes `cJSON_Utils.c` in the `ohos_lite` branch. The
standard branch's named cJSON targets list only `cJSON.c`. Neither fact establishes
actual product reachability; other custom build targets and callers require review.

The public association is CVE-2026-87933 / CWE-416. Upstream PR #1065 describes
the subtree-alias fix; it was open when inspected. This patch must not be called
an upstream released fix or a validated product patch.

Sources: https://github.com/DaveGamble/cJSON/issues/1060 ;
https://github.com/DaveGamble/cJSON/pull/1065 ;
https://vuldb.com/cve/CVE-2026-87933 .
