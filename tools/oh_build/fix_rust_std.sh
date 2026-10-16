#!/bin/bash
# Stage the ohos Rust std shared libraries into the musl sysroot lib dir.
#
# Why: some CJ FFI root-targets (e.g. av_session) pull Rust components whose
# .so dependencies (libstd.dylib.so et al.) are not in any directory the
# musl loader searches. run_malformed.sh builds library-path.txt from the
# musl sysroot plus discovered .so dirs; the sysroot lib dir is always first,
# so copying the real files there (NOT symlinks — `find -type f` does not
# follow symlinks during discovery) makes them resolvable for every client.
#
# Only host-side loader plumbing is changed; no target library content.
#
# Usage: bash fix_rust_std.sh <oh_root> <out_dir>
set -euo pipefail
[[ $# == 2 ]] || { echo "usage: $0 <oh_root> <out_dir>" >&2; exit 2; }
OH_ROOT=$(realpath -e -- "$1")
O=$(realpath -e -- "$2")
RUST_LIB="$OH_ROOT/prebuilts/rustc/rust-std-nightly-x86_64-unknown-linux-ohos/rust-std-x86_64-unknown-linux-ohos/lib/rustlib/x86_64-unknown-linux-ohos/lib"
SYSROOT_LIB="$O/obj/third_party/musl/usr/lib/x86_64-linux-ohos"
[[ -d "$RUST_LIB" ]] || { echo "missing: $RUST_LIB" >&2; exit 3; }
[[ -d "$SYSROOT_LIB" ]] || { echo "missing: $SYSROOT_LIB (run gn gen first)" >&2; exit 3; }
copied=0
for f in "$RUST_LIB"/*.so; do
    [[ -f "$f" ]] || continue
    cp -- "$f" "$SYSROOT_LIB/"
    copied=$((copied + 1))
done
echo "copied $copied rust std .so files into $SYSROOT_LIB"
test -f "$SYSROOT_LIB/libstd.dylib.so" && echo COPIED_TO_SYSROOT
