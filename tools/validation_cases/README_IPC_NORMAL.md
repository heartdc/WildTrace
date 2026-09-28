# Real IPC normal-input check

`ipc_normal_roundtrip.c` loads an existing `libcj_ipc_ffi.z.so` and calls its
exported creation, array-write and array-read functions. It checks arrays of
length 1, 3 and 0 with valid storage. It does not contain an equivalent copy of
the target implementation or establish product impact.

The recorded ABI is from IPC commit
`edc6f3ab59a5b6fbbda92c427e1e4da6f6d64ae3`; inspect the headers before using
another source version. The runner supports the observed OHOS x86_64 / Clang
15.0.4 build layout. It requires an already-built sysroot, libc and dependency
libraries, and does not install tools, alter source, or patch the runtime.

From WSL Ubuntu, with this repository at `/mnt/c/Projects/LSH`:

```sh
bash /mnt/c/Projects/LSH/tools/validation_cases/run_ipc_normal.sh \
  /home/airgap/oh-real-20260925 \
  /home/airgap/oh-real-20260925/out/ffi-direct-min \
  /home/airgap/oh-real-20260925/out/ffi-direct-min/evidence/normal-check-new
```

The third argument must be a new directory with an existing parent. Use a
different name for each observation. The runner saves compiler output, ELF
metadata, input hashes before/after execution, runtime search paths, client
source/binary, and separate build/run exit codes. Runtime execution is bounded
to 30 seconds. Full service warnings remain in `run.log`.

Success requires build/run exit codes of zero and all three `matches=1` lines,
followed by `normal_roundtrip=passed`. A loading failure, timeout or missing
symbol is not a successful function check. Input hashes must remain unchanged.
The hash set covers the target IPC library, libc and caller, not every transitive
library; complete environment reproduction still requires the build tree and
dependency manifest.

## Observed result, September 25, 2026

The repository runner was executed against the local isolated build and passed
all three cases. IPC library SHA-256:
`2bccd55caf31989886225f4a5304b41dd1d291251d95dbec670ac19446352d63`.

That run used a locally fixed base runtime, SHA-256:
`51403d957a03307e80eebbca82387696bfc3ce5634c7fab74df5e1d01eff304c`.
The original base runtime had failed before main. Original binaries, the narrow
runtime patch and earlier failures are preserved separately in
`out/ffi-direct-min/evidence/runtime-init-fix/`.

Thus this is a normal library-level check with a modified base runtime, not
validation of an unmodified official product. Full product services were not
running, including HiLog; related warnings are retained. See
`docs/analysis/REAL_BUILD_PROBE_20260925.md` for the evidence history and remaining
work. Running this check does not automatically change any case verdict.
