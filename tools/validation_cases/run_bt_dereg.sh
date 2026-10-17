#!/usr/bin/env bash
# Compile and run the bluetooth_service DeregisterServerObserver null-observer
# PoC against the real libbluetooth_server.z.so, re-run under gdb, and symbolize
# the fault PC against the unstripped library copy.
#
# Compile flags are extracted from the official ninja command of
# bluetooth_socket_server.o (same toolchain, sysroot, -D_LIBCPP_HAS_MUSL_LIBC,
# -fno-rtti — OH system components are built without RTTI). The stub layer is
# linked statically from the official libbtipc_service.a (the .z.so does not
# export it); the unguarded DeregisterServerObserver override resolves
# dynamically through the exported server vtable, so the crash PC lands inside
# the real libbluetooth_server.z.so.
#
# Usage: bash run_bt_dereg.sh OPENHARMONY_ROOT BUILD_OUTPUT EVIDENCE_DIRECTORY
# A non-zero RUN exit is an observation (candidate crash), not a runner failure.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: bash $0 OPENHARMONY_ROOT BUILD_OUTPUT EVIDENCE_DIRECTORY" >&2
    exit 2
fi
source_root=$(realpath -e -- "$1")
build_output=$(realpath -e -- "$2")
evidence=$(realpath -m -- "$3")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

llvm="$source_root/prebuilts/clang/ohos/linux-x86_64/llvm"
sysroot="$build_output/obj/third_party/musl"
runtime="$sysroot/usr/lib/x86_64-linux-ohos/libc.so"
library="$build_output/communication/bluetooth_service/libbluetooth_server.z.so"
archive="$build_output/obj/foundation/communication/bluetooth_service/services/bluetooth/ipc/libbtipc_service.a"
objfile="$build_output/obj/foundation/communication/bluetooth_service/services/bluetooth/server/src/bluetooth_server/bluetooth_socket_server.o"
client="$script_dir/bt_server_dereg_null.cpp"

for required in "$llvm/bin/clang++" "$llvm/bin/llvm-symbolizer" "$runtime" "$library" "$archive" "$objfile" "$client"; do
    test -f "$required" || { echo "Missing: $required" >&2; exit 2; }
done
command -v timeout >/dev/null
command -v gdb >/dev/null

mkdir -p -- "$evidence"
cp -- "$client" "$evidence/client.cpp"
cp -- "${BASH_SOURCE[0]}" "$evidence/runner.sh"
"$llvm/bin/clang++" --version > "$evidence/compiler-version.txt"
"$llvm/bin/llvm-readelf" -h -d --dyn-syms --wide "$library" > "$evidence/target-elf.txt"
git -C "$source_root/foundation/communication/bluetooth_service" log --oneline -1 \
    > "$evidence/library-git-version.txt" 2>/dev/null || true

# Official include set from the compile command of bluetooth_socket_server.o
inc_list=$(cd "$build_output" && ninja() { :; }; \
    /home/beichen/oh/prebuilts/build-tools/linux-x86/bin/ninja -C "$build_output" -t commands \
    obj/foundation/communication/bluetooth_service/services/bluetooth/server/src/bluetooth_server/bluetooth_socket_server.o 2>/dev/null \
    | grep 'bluetooth_socket_server.cpp' | head -1 | tr ' ' '\n' | grep '^-I' | sed 's/^-I//' || true)
inc_args=(-I"$sysroot/usr/include/x86_64-linux-ohos")
while IFS= read -r d; do
    [ -n "$d" ] || continue
    abs="$d"; case "$d" in /*) ;; *) abs="$build_output/$d";; esac
    [ -d "$abs" ] && inc_args+=("-I$abs")
done <<< "$inc_list"
for d in \
    "$source_root/foundation/communication/ipc/interfaces/innerkits/ipc_core/include" \
    "$source_root/foundation/communication/bluetooth_service/services/bluetooth/ipc/include" \
    "$source_root/foundation/communication/bluetooth_service/services/bluetooth/server/include" \
    "$source_root/foundation/communication/bluetooth/frameworks/inner/ipc/interface" \
    "$source_root/foundation/communication/bluetooth/frameworks/inner/ipc/parcel"; do
    [ -d "$d" ] && inc_args+=("-I$d")
done

deps=(communication/ipc/libipc_single.z.so
      communication/bluetooth_service/libbtservice.z.so
      communication/bluetooth/libbtframework.z.so
      communication/bluetooth/libbtcommon.z.so
      commonlibrary/c_utils/libutils.z.so
      notification/eventhandler/libeventhandler.z.so
      hiviewdfx/hilog/libhilog.so
      hiviewdfx/hisysevent/libhisysevent.z.so
      hiviewdfx/hitrace/libhitrace_meter.so
      systemabilitymgr/samgr/libsamgr_proxy.z.so
      security/access_token/libaccesstoken_sdk.z.so
      ability/ability_base/libbase.z.so
      thirdparty/bounds_checking_function/libsec_shared.z.so)
dep_paths=()
for p in "${deps[@]}"; do [ -f "$build_output/$p" ] && dep_paths+=("$build_output/$p"); done

libcxx_dir="$llvm/lib/x86_64-linux-ohos"
set +e
"$llvm/bin/clang++" --target=x86_64-linux-ohos --sysroot="$sysroot" \
    -std=c++17 -fPIC -fno-rtti -D_LIBCPP_HAS_MUSL_LIBC -Wno-everything \
    "${inc_args[@]}" "$evidence/client.cpp" "$library" "$archive" "${dep_paths[@]}" \
    "-L$libcxx_dir" -lc++ "-L$sysroot/usr/lib/x86_64-linux-ohos" \
    -Wl,--allow-shlib-undefined -o "$evidence/client" > "$evidence/build.log" 2>&1
build_status=$?
printf '%s\n' "$build_status" > "$evidence/build.exit"
set -e
if (( build_status != 0 )); then cat "$evidence/build.log"; exit "$build_status"; fi
sha256sum -- "$evidence/client" > "$evidence/client.sha256"

libdirs="$sysroot/usr/lib/x86_64-linux-ohos:$libcxx_dir:$llvm/lib/clang/15.0.4/lib/x86_64-linux-ohos"
mapfile -t dirs < <(find "$build_output" -mindepth 1 -maxdepth 4 \
    \( -path "$build_output/obj" -o -path "$build_output/clang_x64" -o -path "$build_output/mingw_x86_64" \
       -o -path "$build_output/ohos_clang_arm64" \) -prune \
    -o -type f -name '*.so' -printf '%h\n' | sort -u)
for d in "${dirs[@]}"; do libdirs+=":$d"; done
printf '%s\n' "$libdirs" > "$evidence/library-path.txt"
sha256sum -- "$library" "$runtime" "$client" > "$evidence/inputs-before.sha256"

ulimit -c 0
set +e
timeout 30 "$runtime" --library-path "$libdirs" "$evidence/client" > "$evidence/run.log" 2>&1
run_status=$?
printf '%s\n' "$run_status" > "$evidence/run.exit"
set -e
sha256sum -- "$library" "$runtime" "$client" > "$evidence/inputs-after.sha256"
cmp -- "$evidence/inputs-before.sha256" "$evidence/inputs-after.sha256" || { echo "input hashes changed" >&2; exit 6; }

set +e
timeout 120 gdb -q -batch \
    -ex "set confirm off" -ex "set pagination off" -ex "set auto-load safe-path /" \
    -ex run -ex "printf \"FAULT_PC=%p\\n\", \$pc" \
    -ex "echo ===BT===\n" -ex bt -ex "echo ===MAP===\n" -ex "info proc mappings" \
    --args "$runtime" --library-path "$libdirs" "$evidence/client" > "$evidence/gdb.log" 2>&1
set -e

python3 - "$evidence" "$build_output" "$llvm/bin" <<'PYEOF' > "$evidence/attribution.txt"
import pathlib, re, subprocess, sys
evid, out, llvm = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
log = (evid / "gdb.log").read_text(errors="replace")
m = re.search(r"FAULT_PC=(0x[0-9a-f]+)", log)
if not m:
    print("no FAULT_PC captured"); sys.exit(0)
pc = int(m.group(1), 16)
rows = []
for line in log.splitlines():
    mm = re.match(r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\S+\s+\S+\s+\S+\s*(\S*)", line)
    if mm:
        rows.append((int(mm.group(1), 16), int(mm.group(2), 16), mm.group(3)))
hits = [r for r in rows if r[0] <= pc < r[1]]
print(f"FAULT_PC={hex(pc)}")
for s, e, name in hits:
    print(f"mapped-segment: {hex(s)}-{hex(e)} object={name or '(anon)'}")
for s, e, name in hits:
    if "bluetooth" in name:
        base = min(r[0] for r in rows if r[2] == name)
        offset = pc - base
        print(f"lib={name} base={hex(base)} vaddr_offset={hex(offset)}")
        unstr = out / "lib.unstripped" / pathlib.PurePosixPath(*pathlib.Path(name).parts[-3:])
        target = unstr if unstr.exists() else pathlib.Path(name)
        sym = subprocess.run([str(llvm / "llvm-symbolizer"), f"--obj={target}", "--demangle", hex(offset)],
                             capture_output=True, text=True).stdout
        print(f"symbolized (unstripped {target.name}):")
        print(sym)
        break
PYEOF
cat "$evidence/attribution.txt" 2>/dev/null || true
echo "evidence=$evidence run_exit=$run_status"
echo "interpretation: run_exit in {11(139-128 SIGSEGV),139} => crash case; 0 => completed_no_crash"
echo "attribution: attribution.txt (fault PC -> lib + function + source line)"
