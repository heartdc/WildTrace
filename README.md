# OpenHarmony code auditing MVP

This repository contains a defensive, local-only source auditing MVP.

## Delivering a source snapshot

`python tools/make_release.py` builds `dist/WildTrace-<tag>.zip` from the committed
tree (`git archive`), appending `frontend/dist` when it has been built so the
workbench can be opened without npm. Ignored paths — `.venv`, `.cache`,
`node_modules`, local scan output — never enter the archive.

Installation and dependency notes live in
[`docs/deliverables/USAGE.md`](docs/deliverables/USAGE.md); the four competition
deliverables (source, technical spec, usage guide, vulnerability report,
performance) are under `docs/deliverables/`, with the report also shipped as PDF.

Code is MIT licensed (`LICENSE`). The patches under `patches/` and
`cases/*/patch.diff` quote upstream projects and stay under their upstream
licences.

## Local web workbench

Run `./Start-Workbench.ps1` on Windows to install and open the local React/FastAPI
workbench. The terminal prints the actual localhost URL (default port 8765).
It connects real cases, offline scans, candidate review, explicit model requests,
cJSON isolated verification, and report exports. See
[workbench setup and demo](docs/engineering/WORKBENCH.md) for environment requirements,
evidence boundaries, test commands, and the recording sequence.

## Phase 1 scope

- Scan a user-provided local source directory.
- Emit candidate findings for manual review.
- Preserve file/line evidence and deterministic line hashes.
- Produce JSON suitable for later evidence and report stages.

The scanner does not execute target code, generate exploit payloads, access remote systems, submit reports, or modify the scanned source tree.

```powershell
python -m ohvul.cli .\path\to\authorized\source --output findings.json
```

Rules are intentionally conservative candidates. They are not vulnerability verdicts.

## Automated analysis pipeline (autopilot v3)

One command turns any C/C++ source tree into a confidence-ranked lead report with
PoC templates:

```powershell
python -m ohvul.autopilot .\authorized-source --output .\autopilot-out [--min-confidence 60] [--joern]
```

Ten analysis layers by default: nine regex pattern families (P1–P3 CJ-FFI specific,
P4–P9 general: unbounded copy, stack overflow, null deref, alloc overflow,
use-after-free, format string) plus cross-function UAF/double-free detection with
positional alias resolution and freed-local tracking. `--joern` adds an eleventh
layer — Joern CPG path-sensitive queries (requires WSL with `/opt/joern`; degrades
to a warning when unavailable). Every finding carries a 0–100 confidence with a
human-readable factor breakdown; leads are not vulnerability verdicts.

Function splitting runs on a length-preserving comment/string mask (an apostrophe
in a comment cannot swallow a function), macro bodies are not parsed as functions,
and each cross-function pattern is emitted once per (callee, variable) — not once
per call site.

Measured on the dsoftbus tree (742K lines): 2466 leads in 217s (historical run
recorded before the cross-UAF dedup tightened counts; the performance deliverable
re-measures). See [TECHNICAL_SPEC §3.8](docs/deliverables/TECHNICAL_SPEC.md).

## Optional LLM PoC generation (hardened)

Upgrade high-confidence leads from TODO-templates to compilable C PoCs:

```powershell
python -m ohvul.llm_poc autopilot-out\findings.json .\authorized-source --output llm_pocs
```

Requires `OSLOVELACE_API_KEY`. Scanned source and findings fields are treated as
untrusted data: `finding['file']` is resolved under the source root only (no
`../` or absolute-path escapes to the remote endpoint), fence sequences are
defused and digest-bound in the prompt, and generated code using dangerous APIs
(`system`/`popen`/`exec*`/`fork`/`curl`…) is rejected before it reaches disk.
Truncated responses never become "validated" PoC files.

Endpoints and models are a closed set (`deepseek-chat`/`deepseek-reasoner` over
`https://api.deepseek.com/v1` is the Chat-Completions channel); redirects are
rejected so an `Authorization` header cannot follow a 3xx off-allowlist.

## PoC verification gate (four gates)

A draft is not evidence until it survives text → compile → run → frame attribution:

```powershell
python -m ohvul.poc_verify llm_pocs --source .\authorized-source `
  --findings autopilot-out\findings.json --output verify `
  --guarded-heap tools\harness          # -Dmalloc=... + quarantined pages
```

- **text** — `classify_poc` marks drafts that redefine the target function as
  `copied_target`; a crash inside the draft's own copy is a tautology and is
  never counted as evidence (same detector the drafting gate uses).
- **compile** — with no `--link`, the link set is inferred from the linker's own
  undefined symbols (≤3 rounds, ≤4 files per round), so a cJSON PoC finds
  `cJSON.c` without being told.
- **run** — UAF/overflow are silent-corruption classes: without a memory checker
  (ASan probe, or the guarded heap) "it did not crash" stays `undetermined`
  instead of being promoted to `refuted`.
- **frame** — a crash inside the library at an unrelated function is
  `wrong_site`, not `confirmed`. Real OHOS `.so` frames come from
  `ohvul.poc_real` / `tools/harness/ohos/run_real.sh` (WSL + musl loader + gdb +
  `llvm-addr2line -i`).

Verdicts: `confirmed` / `wrong_site` / `refuted` / `undetermined`, written to
`verify/poc_verification.json`. See [TECHNICAL_SPEC §3.15](docs/deliverables/TECHNICAL_SPEC.md).

## Version impact matrix and deliverable assembly

```powershell
python -m ohvul.impact_matrix --cases cases --output docs/deliverables/IMPACT_MATRIX
python -m ohvul.vuln_report --cases cases --output docs/deliverables/VULN_REPORT.md --force
python -m ohvul.competition_report --cases cases --output out\report.json --markdown out\report.md
```

The impact matrix joins `kb/third_party_targets` (cvelistV5) by CVE. Current
branch verdicts require per-case `branch_evidence` with a source commit and
evidence reference. Upstream version estimates remain separately visible in
`upstream_predictions`; they do not establish downstream patch or product impact.
Absent branch evidence stays unknown. The workbench reads all 19 case records
and displays delivery gaps separately from vulnerability confirmation.

Deliverables live in `docs/deliverables/` (TECHNICAL_SPEC, VULN_REPORT,
IMPACT_MATRIX, PERFORMANCE, VIDEO_SCRIPT). Toolchain preflight for
demos: `python -m ohvul.toolchain --output preflight.json`.

## Candidate triage

To split a saved scan into deterministic manual-review lanes without invoking a model:

```powershell
python -m ohvul.candidate_triage --result findings.json --output triage.json
python -m ohvul.candidate_triage --result findings.json --verify triage.json
```

The triage file retains every alert and records `confirmed_vulnerabilities: 0`; lane order is a worklist hint, not a severity or exploitability claim.

## Local Clang engine

When an authorized WSL LLVM installation is available, run the adapter on a single file or an explicit relative file list:

```powershell
python -m ohvul.engine_cli .\authorized-source\source.c --source-root .\authorized-source --output engine.json
python -m ohvul.engine_cli --files-from files.txt --source-root .\authorized-source --output engine.json
```

Optional local CVE/CWE matching requires all three values:

```powershell
python -m ohvul.engine_cli .\authorized-source\source.c --source-root .\authorized-source `
  --knowledge-base local-kb.json --component component-name --version 1.0
```

Engine findings remain candidates. Missing build inputs produce `input_error` and must not be interpreted as a clean scan.

The engine CLI returns 0 only for completed execution, 1 for partial/input-error
diagnostic results, and a nonzero argument/publication error otherwise. Output
must be outside the scanned source tree; replacing an existing diagnostic output
requires `--force`. The main CLI blocks successful publication when an explicitly
requested engine fails. Unknown engine file coverage is `null`, not zero; consult
`engine_observations` for per-engine status, file outcomes, and error details.
See [engine execution audit](docs/analysis/ENGINE_EXECUTION_AUDIT_20260914.md).

Candidate benchmark results can be measured after manual annotation:

```powershell
python -m ohvul.engine_benchmark cases.json engine-result.json
```

从已保存结果生成待人工复核草稿：

```powershell
python -m ohvul.engine_benchmark --bootstrap-output cases.json `
  --source-snapshot <sha256> --component <name> --version <version> engine-result.json
```

## Profile provenance and source input contracts

`--engine-profile` requires an `engine-profile-0.1` document with explicit,
nonempty source/repository/engine selections. Every declared repository must be
an actual local Git worktree root at the recorded full commit, with no observed
tracked or untracked changes. Sources and include directories must belong to
declared repositories. Selected target files must be tracked and not hidden by
assume-unchanged/skip-worktree flags. Configured Git filters are rejected; the
provenance check does not recurse into undeclared submodules.

Profile paths must be relative and must not contain symbolic links, junctions,
parent traversal or duplicate aliases. Include paths and macros use their typed
fields. Extra compiler arguments are restricted to a small reviewed subset;
response files, plugins, arbitrary forwarding and output flags are rejected.
The exact profile-byte hash and observed repository checks are emitted as
`profile_validation`; profile bytes and repository state are rechecked after
analysis. These are local observations, not signatures or proof of platform impact.

The standalone `engine_cli --profile` accepts only a Clang-only profile and sources
declared by it. Use the main CLI for profiles selecting multiple engines:

```powershell
python -m ohvul.cli .\authorized-source --engine-profile docs\profiles\securec_captured_20260914.json --output .\out\findings.json
```

Historical camera profile metadata does not bypass these gates. Its dependency
repository declarations must be completed and locally verified before it can be
used with the stricter execution path; this batch did not verify an OpenHarmony checkout.

Eight real profiles live under `docs/profiles/` (schema `engine-profile-0.1`); any of them works as a template.

Capture missing repository pins from the owners of explicitly declared sources
and include directories, without changing any existing commit or rule-hash pin:

```powershell
python -m ohvul.profile_capture --template docs\profiles\securec_captured_20260914.json --source-root .\authorized-source --output out\captured.json
```

The output must be new, outside the source tree, and have an existing parent
directory. There is no force-refresh mode. Wrong existing pins, dirty dependencies,
missing inputs, or changes during capture reject publication. Capture does not
discover undeclared transitive build inputs, execute analyzers, or verify platform
impact. The generated file must pass normal execution-time validation again.

Engine versions are observed from Clang plist, Semgrep JSON, or a clang-tidy
version query, rather than assumed from an installation path. Missing or failed
version observations remain `unknown`. Execution commands, return codes and output
digests are included in candidate evidence; merged results preserve
`profile_validations`. These are content bindings, not binary signatures.

## Opt-in real static-analyzer integration demo

```powershell
python tools/synthetic_static_demo.py --output .cache\synthetic-demo-new
```

This requires the existing WSL Ubuntu LLVM installation used by the adapters. It
creates two disposable local Git repositories in a new output directory, captures
their dependency profile, and runs real Clang and clang-tidy on synthetic unsafe
and safe controls. It verifies the result/report/journal chain and checks that a
wrong repository pin cannot publish a successful result. It never executes the
sample code or modifies project Git, and does not demonstrate an OpenHarmony
vulnerability or establish detection accuracy. Existing output directories are
never replaced. See the [component integration audit](docs/analysis/COMPONENT_INTEGRATION_AUDIT_20260914.md).

## Builtin scanner error handling

The builtin scanner now records read/UTF-8 decode/enumeration errors explicitly.
`files_scanned` counts successful reads and decodes only. Partial/all-failed scans
are `partial`/`input_error`, and the main CLI blocks successful publication.
Directory enumeration failure sets `scope_complete=false` and an unknown
`files_requested` (`null`); `files_discovered` remains the observed count. Skipped
symbolic-link files and directories are listed, not claimed as analyzed. Successful
file records and findings include the SHA-256 of the source bytes actually read.
See [profile and scanner audit](docs/analysis/PROFILE_SCANNER_AUDIT_20260914.md).

## Evidence validation

Candidate quality rules now mask comments and literals and retain narrow syntax
filter decisions in `rule_observations`, with source hashes and an undetermined
verdict. Recognized direct-return guards are not general proofs of safety; macro,
volatile, complex control-flow and alias contexts need further analysis. Unknown
engine checkers keep an unknown CWE. Exact Clang null-dereference aliases use
mapping version 2, and new CWE values are bound to candidate evidence.

The historical eight-case benchmark snapshot is preserved. Current results on
that development-used synthetic set must not be advertised as real-world
vulnerability accuracy. See [candidate quality audit](docs/analysis/CANDIDATE_QUALITY_AUDIT_20260914.md)
and [competition readiness](docs/status/COMPETITION_READINESS_20260914.md).

Saved schema 0.3 results can be checked offline using `python -m ohvul.verify result.json`.
See [evidence contract](docs/engineering/EVIDENCE_VALIDATION.md) for scope and limitations.

## Current offline engineering track

The LLM pause was lifted on 2026-09-16: a bounded online review acceptance
passed through the z.ai Anthropic transport (`glm-5.3`), and `gpt-6-astra`
joined `grok-4.6`/`glm-5.3` on the allowlist for dual-model cross-validation.
The 29-group full review and the dual-model run are still pending execution.
A full code audit on 2026-09-29 closed every P0/P1 finding it raised
(fabricated impact-matrix verdicts, the unwired Joern layer, detection-quality
defects, LLM PoC injection/path-traversal); each fix is pinned by regression
tests. Remaining delivery work: unified performance re-measurement
(`tools/perf_measure.py`), a clean-environment independent rerun, and the demo
video. See [2026-09-22 audit and plan](docs/status/AUDIT_REMAINING_PLAN_20260922.md)
and the CHANGELOG (追加一 to 追加二十) for the remediation record.

`--semantic-files-from` now uses explicit execution records: failed reads do not
count as coverage, and failed execution or a changed file list blocks successful
publication. Semantic execution `completed` is distinct from
`analysis_coverage.status=partial_lexical_analysis`. Preprocessor, type and
control-flow unknowns remain visible; zero candidates is not a safety finding.
Local and caller/parameter observations remain candidate-only with source hashes.
`snprintf` uses the second argument as its size, and complex/ambiguous cases are
not resolved through line proximity or last-definition-wins. Generic length
advisories keep CWE unknown instead of automatically asserting CWE-120.

See [semantic rule contract](docs/engineering/SEMANTIC_RULE_CONTRACT.md),
[measured acceptance](docs/analysis/SEMANTIC_BOUNDARY_AUDIT_20260914.md), and
[current offline roadmap](docs/status/NEXT_ROADMAP_20260914.md).

## Compiler-derived memory analysis

Use `ohvul.compiler_analysis` or the main CLI's `--compiler-profile` for typed
object-size checks and bounded exact local scalar propagation. Unknown effects,
loop state, cleanup and unsupported control flow do not inherit stale values.
This stage invokes a local syntax-only compiler, not a model or target program.
See [compiler analysis](docs/engineering/COMPILER_ANALYSIS.md) and
[current core roadmap](docs/status/NEXT_ROADMAP_20260915.md).

## Optional LLM drafting (online review acceptance passed)

For a local hidden-key prompt and a 300-second optional socket timeout, use
`python -X utf8 tools/llm_local.py plan --output .cache/llm-my-plan`, then
`python -X utf8 tools/llm_local.py run --output .cache/llm-my-live --allow-network`.
Both output directories must be new. See
[complete local instructions](docs/engineering/LLM_LOCAL_OPERATOR.md) before running.
The operator includes verified expanded evidence; plan mode never needs a key.

The optional `ohvul.llm_adapter` reads `OSLOVELACE_API_KEY` only at runtime. Its
default endpoint is `https://oslovelace.com/v1` and its selected provider model
identifier is `grok-4.6`. It rejects redirects, bounds requests/responses, sanitizes
transport errors, and does not retry automatically. Do not place keys in source,
config files, fixtures, logs, or commits. The scanner stays offline by default.

`ohvul.llm_review` now connects the verified batch/queue/source context to
structured, evidence-referenced model proposals. Use `--plan` without network,
`--run --allow-network` for an explicitly authorized bounded selection, and
`--verify` for independent local checks. Model outputs never confirm a
vulnerability, execute tools, remove a candidate or change the FSM. The initial
live requests returned HTTP 403. A later retry was blocked at tool-side credential
input before any API request; it is not evidence of a new provider failure.
A bounded online review acceptance passed on 2026-09-16 via the z.ai Anthropic
transport (`glm-5.3`); `gpt-6-astra` is allowlisted for dual-model
cross-validation. The 29-group full review and the dual-model run are pending.
See [LLM review contract](docs/engineering/LLM_REVIEW.md).

`--inspect` now checks complete historical records, including failed runs, without
calling a model. `bound_incomplete` means records are consistent, not inference
success; `--verify` remains strict. New plans record the stop-after-transport-error
policy, while old records keep their original, explicitly legacy policy status.

`ohvul.review_handoff` combines the verified queue/context and explicitly selected
historical LLM runs into evidence follow-up tasks. All five questions remain open
for every group; model statements are separately cited untrusted proposals, not
facts, commands or automatic approvals. Failed and unselected groups remain visible.
See [handoff commands and independent verification](docs/engineering/REVIEW_HANDOFF.md).

## Explicit multi-component batches

Captured real-source inputs for camera, securec and hilog are in `docs/profiles/`.
They are host static-analysis profiles, not complete OpenHarmony product builds.
Repository pins remain constraints and are checked at execution time.

```powershell
python -m ohvul.component_batch --manifest docs/profiles/real_components_20260914.batch.json --output .cache/preflight-new --preflight-only --timeout 60
python -m ohvul.component_batch --manifest docs/profiles/real_components_20260914.batch.json --output .cache/batch-new --timeout 60
```

The output directory must be new. Preflight `ready` is not analyzed `completed`.
Only the final `summary-NNNN.json` accepts the complete batch; retain per-job
receipts and candidate reports. Failed jobs do not prevent other valid jobs,
but the overall command is nonzero and cannot claim a successful whole batch.
See [batch contract](docs/engineering/COMPONENT_BATCH.md),
[real component audit](docs/analysis/REAL_COMPONENT_BATCH_AUDIT_20260914.md), and
[human decisions and environments](docs/status/HUMAN_ACTIONS_20260914.md).

## Verified candidate review inputs

`ohvul.review_queue` turns an explicitly selected completed batch into a
deterministic review queue. It verifies result/report/receipt hashes, states,
profile and source bindings; all diagnostic observations are retained.
Grouping is for review only, not vulnerability counting.

```powershell
python -m ohvul.review_queue --summary .cache/real_components_c0d3/batch/summary-0005.json --output .cache/review-new.json
python -m ohvul.review_queue --summary .cache/real_components_c0d3/batch/summary-0005.json --verify .cache/review-new.json
```

The optional `ohvul.review_context` requires explicit `--source-root JOB=PATH`
arguments and rechecks source snapshots before/after extracting original-line
text windows. It does not follow source paths from JSON automatically, and no
analyzer, target, network or model is called. Review questions remain unknown.
Output files must be new and outside source/batch directories.
See [review queue and context](docs/engineering/REVIEW_QUEUE.md) for complete
commands and limits, and [measured review integration](docs/analysis/REVIEW_PIPELINE_AUDIT_20260914.md).

## Bounded local evidence expansion

`ohvul.review_evidence` extends verified review windows with bounded lexical
function/macro ranges and same-file call syntax. It keeps original bytes, line
numbers, conditional variants, explicit truncation and the existing handoff task
IDs. It does not run a model or close an evidence task. These associations are
navigation candidates, not AST, control-flow, reachability or vulnerability proof.
Use `--verify` for independent reconstruction from the same explicit source roots.
See [local evidence contract](docs/engineering/LOCAL_EVIDENCE.md),
[measured acceptance](docs/analysis/EVIDENCE_EXPANSION_AUDIT_20260914.md), and
[next roadmap](docs/status/NEXT_ROADMAP_20260914.md).

## Local installation and verification

```powershell
python -m pip install -e . --no-deps
python -m unittest discover -s tests -q
```

No API key is required for scanning or tests. Configure `OSLOVELACE_API_KEY` only when explicitly using the optional drafting adapter.

Profile provenance checks and their tests require a local Git executable. Tests
create temporary synthetic Git repositories; they do not commit the project checkout.
