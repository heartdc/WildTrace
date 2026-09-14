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

## Local Clang engine

When an authorized WSL LLVM installation is available, run the adapter on a single file or an explicit relative file list:

```powershell
python -m ohvul.engine_cli .\source.c --source-root . --output engine.json
python -m ohvul.engine_cli --files-from files.txt --source-root . --output engine.json
```

Optional local CVE/CWE matching requires all three values:

```powershell
python -m ohvul.engine_cli .\source.c --source-root . `
  --knowledge-base local-kb.json --component component-name --version 1.0
```

Engine findings remain candidates. Missing build inputs produce `input_error` and must not be interpreted as a clean scan.

Candidate benchmark results can be measured after manual annotation:

```powershell
python -m ohvul.engine_benchmark cases.json engine-result.json
```

从已保存结果生成待人工复核草稿：

```powershell
python -m ohvul.engine_benchmark --bootstrap-output cases.json `
  --source-snapshot <sha256> --component <name> --version <version> engine-result.json
```

## Evidence validation

Saved schema 0.3 results can be checked offline using `python -m ohvul.verify result.json`.
See [evidence contract](docs/engineering/EVIDENCE_VALIDATION.md) for scope and limitations.

## Optional LLM drafting

The optional `ohvul.llm_adapter` reads `OSLOVELACE_API_KEY` only at runtime. It sends structured candidate evidence for drafting and always returns `final_verdict=undetermined`. Do not place keys in source, config files, fixtures, logs, or commits. Calls are explicit; the scanner does not invoke the network automatically.

## Local installation and verification

```powershell
python -m pip install -e . --no-deps
python -m unittest discover -s tests -q
```

No API key is required for scanning or tests. Configure `OSLOVELACE_API_KEY` only when explicitly using the optional drafting adapter.
