# Runtime evidence handoff (offline)

`ohvul.runtime_evidence` bridges an existing candidate report to records collected
in a separately authorized environment. It does **not** run targets, execute
commands from JSON, grant permission, verify signatures, or confirm vulnerabilities.
The synthetic harness schema is unchanged and cannot satisfy this real-target gate.

## Prepare a real-source candidate case

```powershell
python -X utf8 -m ohvul.runtime_evidence prepare `
  --result .cache/real_components_c0d3/batch/securec/result.json `
  --report .cache/real_components_c0d3/batch/securec/report.candidate.json `
  --root C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --alert AL-ENG-000008 --output .cache/memcpy-runtime-case.json
```

This explicit example is an API advisory, **not** a confirmed defect or an approved
PoC target. First review the guard, actual object capacity and caller-controlled
input. The case binds the exact result/report bytes, selected diagnostic and
current source snapshot. Its execution authorization and runtime prerequisites
remain pending. Preparation neither mutates the original report nor closes tasks.

## Collect evidence outside this tool

The selected product/configuration, immutable environment/image identity and
specific target execution scope must be confirmed by the project owner. Follow
`SECURITY.md`; source access is not permission to run a target. Do not execute a
candidate just because this module can prepare its case.

After authorization, retain raw configuration, PoC, build logs, execution logs,
environment-reset evidence and (when available) the patch. No credentials belong
in those artifacts. Create a new record for changed inputs; do not edit logs to
make checks pass. Hashes are checked locally, not proof that a producer is honest.

The JSON envelope has **exactly** these fields:

| Field | Contract |
| --- | --- |
| `schema` | `external-runtime-evidence-0.1` |
| `case_id`, `case_sha256` | ID and exact saved case-file SHA-256 |
| `origin` | `real_target` or `synthetic`; synthetic never clears the real-target condition |
| `product` | `name`, `version`, `configuration_sha256` |
| `environment` | `id`, `isolation` (`vm/container/emulator/dedicated_device`), `image_sha256` |
| `authorization` | null while absent; otherwise `reference`, `approved_by`, `environment_id`, `case_id`. Presence is checked, authenticity is not certified. |
| `trigger_definition` | Explicit safety invariant and observed diagnostic to review; a crash alone is not automatically a security vulnerability |
| `configuration`, `poc` | Artifact references |
| `patch` | null, or `artifact` plus changed `source_snapshot_sha256` |
| `runs` | At most 32 explicit run records; empty/partial lists remain incomplete |

Each artifact reference is `{path, sha256, bytes}`. Paths are canonical relative
paths inside the explicitly supplied artifact root. Files are read, never run.
Each artifact is nonempty and at most 8 MiB; all loaded inputs total at most 64 MiB.

Each run has exactly:

```text
id, phase, session_id, operator, environment_id, source_snapshot_sha256,
poc_sha256, build_status, target_executed, status, exit_code,
elapsed_seconds, build_log, log, reset_log
```

`build_status` is `succeeded/failed/not_run`. Phases are `baseline/independent/
patched/regression`. The first three use `triggered/not_triggered`; regression
uses `passed/failed`. All phases may report `build_failed/timeout/environment_failed`.
Successful outcomes require a succeeded build and actual execution **as declared
by the operator**. `not_triggered` and `passed` additionally require exit code 0.
An independent run needs a separate session plus reset-log artifact. Other phases
may use null for `reset_log`. Runtime truth still requires human review.

Completeness policy: at least 3 baseline trigger records, a separate-session
trigger record, patched non-trigger evidence using the same PoC, and functional
regression evidence. **Three repeats is our engineering policy, not a stated
competition rule.** Baseline/independent records must bind the case snapshot;
patched/regression records must bind the declared changed snapshot and patch.
Duplicate run IDs, reusing one log as multiple runs, and hard-link aliases are rejected.

## Import and independently recheck

```powershell
python -X utf8 -m ohvul.runtime_evidence inspect `
  --case .cache/memcpy-runtime-case.json `
  --result .cache/real_components_c0d3/batch/securec/result.json `
  --report .cache/real_components_c0d3/batch/securec/report.candidate.json `
  --root C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --record .cache/operator-runtime-record.json `
  --artifacts-root .cache/operator-runtime-artifacts `
  --output .cache/runtime-review-new.json
```

Repeat the same command with `verify` instead of `inspect` to reconstruct and
compare the saved appendix without execution. Outputs must be new files outside
source and collected-artifact trees; verification never overwrites them.

Exit 0 means records are complete **for human evidence review**, not a confirmed
finding or signed execution. Exit 1 means a consistent incomplete/failure appendix
was retained with named blockers. Exit 2 rejects malformed, changed or unbound
inputs. Build failure and timeout cannot become a successful non-trigger.

You may import baseline evidence before a patch exists. Missing later phases stay
visible; they do not erase the earlier logs. No review is automatically approved.
The importer always returns `confirmed_vulnerabilities=0` and an undetermined
verdict. Even a complete appendix does not prove independent reproduction, patch
effectiveness, product impact, permission authenticity or submission eligibility.

## Test scope

`python -X utf8 -m unittest tests.test_runtime_evidence -v` uses synthetic records
in temporary directories. Fixture `real_target` labels exercise validation paths;
they are **not actual executions or authorizations**. This module adds a missing
handoff interface, not an isolated runtime executor or a W3 vulnerability result.
