# KV FFI validation approval record

- Scope: local OpenHarmony source-equivalent and, if a complete toolchain becomes available, isolated KV FFI validation.
- Candidates: `kv-ffi-array-validation`, `ipc-cj-array-null-validation`.
- Requested inputs: malformed `CArrEntry`/`CArrStr` array descriptors and one valid control.
- Data boundary: no production database, device, network endpoint, or external submission.
- Source mutation: prohibited; work from a copied source snapshot.
- User authorization: on 2026-09-22 the project owner stated that production-environment use was acceptable, that a test environment was unnecessary, and that full authorization was granted.
- Safety boundary: results remain candidate evidence; no CVE, platform-impact, or disclosure claim may be made without linked-binary reachability and independent review.
- Current execution: only source-equivalent local harnesses have run. No OpenHarmony binary has been executed.
