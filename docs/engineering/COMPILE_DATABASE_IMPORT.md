# Compilation argument import

`ohvul.compile_database` converts an explicitly supplied compilation database's
supported `arguments` records into separate existing `engine-profile-0.1` drafts.
It never invokes the recorded compiler, shell command, model or network. This is
an import stage, not compilation, source provenance acceptance or vulnerability
analysis. It retains template repository pins and selected Clang engines.

## Supported subset and failure handling

Each record supplies `directory`, `file` and an explicit `arguments` vector.
`command` and `output` are optional metadata. When both command forms are present,
only `arguments` is consumed; `command_string_ignored` records this choice.
Shell-only records and compiler wrappers are blocked, not guessed or executed.

Working directories, source files and explicit include directories must resolve
inside the independently supplied local source root. Linked ancestors and Git
metadata paths are rejected. Files/includes must exist. One compile input must
match the record's `file`, and exactly one `-c` is required.

Supported analysis arguments are separate or attached `-I`/`-D` and the existing
profile's reviewed option subset. Conflicting/duplicate macros, include aliases,
and multiple language standards are rejected. The template's old include paths,
defines, extra arguments and file list are NOT silently inherited. `-o`, `-MF`,
`-MT`, `-MQ` with separate values, plus `-MD`/`-MMD`/`-MP`, are recorded as excluded
output-only driver options and never executed. Attached output spellings are
unsupported, avoiding confusion with unrelated options such as `-objc...`.

Unknown flags, response files, `-isystem`, sysroot/target options, forced includes,
plugin forwarding, `-x`, and unrepresented optimization settings are currently
blocked. These are importer limitations, not claims that these compiler features
are unsafe in general. Extending support requires preserving their semantics in
the downstream profile/driver contract rather than dropping them to pass parsing.

Every input entry remains visible. Distinct configurations of the same file get
separate profiles. Repeated equivalent configurations are explicitly blocked so
they cannot inflate coverage. A partial import keeps useful drafts and errors,
but does NOT emit a batch that silently leaves out failed entries.

## Outputs and validation

The output directory must be new and outside the source tree. Imported units
produce `unit-*.profile.json`; every completed import writes `summary.json`.
Only all-imported inputs produce `batch.json`. States are `drafts_ready`,
`partial`, or `blocked`; none proves provenance, compilation or platform impact.

The input JSON bytes, template and imported source bytes are rechecked before
publication. Generated drafts are checked before the final summary. A failed or
interrupted write can leave an incomplete new directory: there is no multi-file
filesystem transaction, and independent verification is required.

```powershell
python -m ohvul.compile_database --database <explicit-database.json> --source-root <local-source-root> --template <pinned-profile.json> --output .cache/import-new
python -m ohvul.compile_database --database <explicit-database.json> --source-root <local-source-root> --template <pinned-profile.json> --output .cache/import-new --verify
```

Generation and verification return 0 only for `drafts_ready`, 1 for a consistent
partial/blocked import, and 2 for rejected inputs/outputs. `--verify` re-creates the
expected documents and checks the generated artifact set without running tools.
Output profiles remain subject to `prepare_profile`/`profile_capture` and batch
preflight. An incomplete repository pin set is not silently expanded or bypassed.

For all-imported inputs, the emitted batch is consumable by `component_batch`.
Its normal default is 32 jobs; importing more entries does not automatically
increase the execution budget. Larger batch execution needs an explicit budget.

Limits: database 8 MiB, 2048 records, 512 arguments per record, source 2 MiB per
file/64 MiB cumulative, normalized summary 32 MiB. Include-directory contents,
compiler builtin macros, transitive headers, sysroots and product semantics are
not authenticated by this importer. The current integration test uses a temporary
synthetic Git repository and real existing profile provenance validation, not an
OpenHarmony product build. No genuine product compilation database was analyzed.
