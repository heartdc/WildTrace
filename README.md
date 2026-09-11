# OpenHarmony code auditing MVP

This repository contains a defensive, local-only source auditing MVP.

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

## Evidence validation

Saved schema 0.3 results can be checked offline using `python -m ohvul.verify result.json`.
See [evidence contract](docs/engineering/EVIDENCE_VALIDATION.md) for scope and limitations.
