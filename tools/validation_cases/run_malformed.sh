#!/usr/bin/env bash
# Compile and run a malformed-input validation client against a real OHOS FFI
# library. Mirrors run_ipc_normal.sh environment discovery; unlike it, a
# non-zero RUN exit code is an observation (candidate crash), not a runner
# failure — it is recorded and the runner exits 0 so evidence capture always
# completes. Build failures remain fatal.
# Usage: bash run_malformed.sh OPENHARMONY_ROOT BUILD_OUTPUT NEW_EVIDENCE_DIRECTORY CLIENT_NAME LIBRARY_REL
#   CLIENT_NAME: ipc_null_bytearray | kv_null_entry
#   LIBRARY_REL: path of the .so under BUILD_OUTPUT
#     ipc: communication/ipc/libcj_ipc_ffi.z.so
#     kv : <discovered by build, see task brief>
set -euo pipefail
if [[ $# != 5 ]]; then
    echo "Usage: bash $0 OPENHARMONY_ROOT BUILD_OUTPUT NEW_EVIDENCE_DIRECTORY CLIENT_NAME LIBRARY_REL" >&2
    exit 2
fi
source_root=$(realpath -e -- "$1")
build_output=$(realpath -e -- "$2")
evidence=$(realpath -m -- "$3")
client_name="$4"
library_rel="$5"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for value in "$source_root" "$build_output" "$evidence"; do
    if [[ "$value" == *:* || "$value" == *$'\n'* ]]; then
        echo "Paths must not contain colon or newline" >&2
        exit 2
    fi
done
llvm="$source_root/prebuilts/clang/ohos/linux-x86_64/llvm"
sysroot="$build_output/obj/third_party/musl"
runtime="$sysroot/usr/lib/x86_64-linux-ohos/libc.so"
library="$build_output/$library_rel"
client="$script_dir/${client_name}.c"
for required in "$llvm/bin/clang" "$llvm/bin/llvm-readelf" "$runtime" "$library" "$client"; do
    test -f "$required" || { echo "Missing: $required" >&2; exit 2; }
done
command -v timeout >/dev/null
mkdir -- "$evidence"
cp -- "$client" "$evidence/client.c"
cp -- "${BASH_SOURCE[0]}" "$evidence/runner.sh"
"$llvm/bin/clang" --version > "$evidence/compiler-version.txt"
"$llvm/bin/llvm-readelf" -h -d --dyn-syms --wide "$library" > "$evidence/target-elf.txt"

libdirs="$sysroot/usr/lib/x86_64-linux-ohos:$llvm/lib/x86_64-linux-ohos:$llvm/lib/clang/15.0.4/lib/x86_64-linux-ohos"
mapfile -t target_dirs < <(find "$build_output" -mindepth 1 -maxdepth 3 \
    \( -path "$build_output/obj" -o -path "$build_output/evidence" \
       -o -path "$build_output/clang_x64" -o -path "$build_output/mingw_x86_64" \
       -o -path "$build_output/ohos_clang_arm64" \) -prune \
    -o -type f -name '*.so' -printf '%h\n' | sort -u)
for directory in "${target_dirs[@]}"; do libdirs+=":$directory"; done
printf '%s\n' "$libdirs" > "$evidence/library-path.txt"
sha256sum -- "$library" "$runtime" "$client" > "$evidence/inputs-before.sha256"
set +e
"$llvm/bin/clang" --target=x86_64-linux-ohos --sysroot="$sysroot" \
    -I"$sysroot/usr/include/x86_64-linux-ohos" "$evidence/client.c" \
    -L"$sysroot/usr/lib/x86_64-linux-ohos" -o "$evidence/client" > "$evidence/build.log" 2>&1
build_status=$?
printf '%s\n' "$build_status" > "$evidence/build.exit"
set -e
if (( build_status != 0 )); then cat "$evidence/build.log"; exit "$build_status"; fi
sha256sum -- "$evidence/client" > "$evidence/client.sha256"
ulimit -c 0
set +e
timeout 30 "$runtime" --library-path "$libdirs" "$evidence/client" "$library" \
    > "$evidence/run.log" 2>&1
run_status=$?
printf '%s\n' "$run_status" > "$evidence/run.exit"
set -e
sha256sum -- "$library" "$runtime" "$client" > "$evidence/inputs-after.sha256"
cmp -- "$evidence/inputs-before.sha256" "$evidence/inputs-after.sha256" || { echo "input hashes changed" >&2; exit 6; }
echo "evidence=$evidence run_exit=$run_status"
echo "interpretation: run_exit in {11(139-128 SIGSEGV),139} => crash case, see run.log last 'case=' marker; 0 => completed_no_crash; 10/11 => env probe failure (KV)"
