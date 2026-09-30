# Component batch runner

`python -m ohvul.component_batch --manifest INPUT.json --output NEW_DIRECTORY`
runs an explicit, serial batch of local component profiles. The manifest is
exactly `component-batch-0.1`:

```json
{
  "schema": "component-batch-0.1",
  "jobs": [
    {"id": "camera", "source_root": "source", "profile": "profiles/camera.json"}
  ]
}
```

Paths are relative to the manifest directory or absolute local paths. IDs are
portable unique names. The complete manifest, every path, alias, output/source
boundary, link/junction ancestor, Git metadata path, existing destination, and
later-job collision are checked before the new output directory is created.
Windows UNC and drive-relative spellings are rejected. A destination is
exclusive and is never overwritten. There is no resume mode, asynchronous
worker, install, network call, target execution, or payload generation.

`--preflight-only` calls `prepare_profile` for each job and writes `ready` or
`blocked`; it never calls an analyzer and returns zero only when every job is
ready. A ready preflight is not a completed scan. Execution calls
`scan_engine_profile`, then validates the result and candidate-only report.
Jobs are independent: a blocked or failed job is retained while other valid
jobs continue. A zero-finding completed execution is valid evidence of that
execution and is not a security claim.

Each job directory contains a diagnostic `receipt.json`, and completed jobs
also contain `result.json` and `report.candidate.json`. The report is always
candidate-only (`confirmed_vulnerabilities: 0`). Partial, timeout, invalid,
binding, analyzer, or publication failures do not receive a successful report
status. An incremental `summary-NNNN.json` records exact manifest/profile/source
hashes, artifact hashes and byte counts, per-engine observations, elapsed times,
counts, and the candidate-only boundary. The final summary is `completed` only
when all jobs completed and their manifest, profile, provenance, source
snapshot, receipts, and artifact bytes still bind to the initial observations.

The receipts and hashes are ordinary local evidence, not signatures. The
runner protects against the races it can observe, but it is not an OS sandbox
and does not provide a multi-file atomic transaction: a process or filesystem
actor can still race between checks and writes, and an interrupted write may
leave an incomplete new artifact. Exclusive creation never replaces an existing
destination, including on POSIX. Such cases remain non-successful and must
be reviewed manually.

`--timeout` is an integer from 1 through 900 seconds, applied per analyzer call,
not an overall batch deadline. `totals` includes jobs, attempted analyses,
completed, ready, blocked, failed and pending jobs; detailed failure statuses
remain in `counts`. Profile reads use the existing bounded profile reader.

Tests use temporary synthetic fixtures and typed mocks. They preserve the
existing profile/result contracts and do not inspect or run an OpenHarmony
tree. All analyzer statuses remain observations; multiple engines are not
counted as multiple confirmed vulnerabilities.

Independent acceptance on 2026-09-14: 31 batch tests passed after the host fixed
the CLI timeout and exclusive publication contracts. Combined focused tests:
90 passed. Full repository suite: 336 run, 332 passed, 4 symlink-unavailable
skips. Real preflight and batch each accepted three explicitly pinned jobs
(44 selected source files); raw diagnostics remain unconfirmed. Evidence and
commands are recorded in `../analysis/REAL_COMPONENT_BATCH_AUDIT_20260914.md`.
