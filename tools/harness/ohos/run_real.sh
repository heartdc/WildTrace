#!/usr/bin/env bash
# Build a draft against the OHOS musl sysroot, run it against the real library,
# and — when it crashes — attribute the frame to a file offset inside that
# library and symbolize it.
#
# Usage:
#   bash run_real.sh OPENHARMONY_ROOT BUILD_OUTPUT CLIENT_C LIBRARY_REL EVIDENCE_DIR \
#                    [SONAME_ALIAS]
# SONAME_ALIAS: a draft that dlopens a guessed soname (very common in generated
# PoCs) finds nothing unless an alias of that name exists on the search path.
# The expected frame is not used here: deciding whether the observed frame is
# the claimed one belongs to the caller, which knows the finding.
#
# Prints one JSON object on stdout:
#   {"built":true,"exit":139,"crashed":true,"address":"0x…","offset":"0x1718a",
#    "rounds":2,"frames":[{"function":"…","file":"…","line":134}]}
#
# Two gdb rounds run with ASLR enabled; "rounds" reports how many produced a
# crash. The caller decides whether the frame is the one the finding claimed.
set -uo pipefail
if [[ $# -lt 5 ]]; then
    echo "Usage: bash $0 OH_ROOT BUILD_OUTPUT CLIENT_C LIBRARY_REL EVIDENCE_DIR" >&2
    exit 2
fi
oh_root=$(realpath -e -- "$1")
build_output=$(realpath -e -- "$2")
client=$(realpath -e -- "$3")
library_rel="$4"
evidence=$(realpath -m -- "$5")

llvm="$oh_root/prebuilts/clang/ohos/linux-x86_64/llvm"
sysroot="$build_output/obj/third_party/musl"
runtime="$sysroot/usr/lib/x86_64-linux-ohos/libc.so"
library="$build_output/$library_rel"
unstripped="$build_output/lib.unstripped/$library_rel"
for required in "$llvm/bin/clang" "$runtime" "$library"; do
    test -f "$required" || { echo "Missing: $required" >&2; exit 2; }
done
mkdir -p "$evidence"
cp -- "$client" "$evidence/draft.c"

libdirs="$sysroot/usr/lib/x86_64-linux-ohos:$llvm/lib/x86_64-linux-ohos:$llvm/lib/clang/15.0.4/lib/x86_64-linux-ohos"
mapfile -t target_dirs < <(find "$build_output" -mindepth 1 -maxdepth 3 \
    \( -path "$build_output/obj" -o -path "$build_output/evidence" \
       -o -path "$build_output/clang_x64" -o -path "$build_output/mingw_x86_64" \
       -o -path "$build_output/ohos_clang_arm64" \) -prune \
    -o -type f -name '*.so' -printf '%h\n' | sort -u)
for directory in "${target_dirs[@]}"; do libdirs+=":$directory"; done
if [[ -n "${6:-}" ]]; then
    alias_dir="$evidence/aliases"
    mkdir -p "$alias_dir"
    ln -sf "$library" "$alias_dir/$6"
    libdirs+=":$alias_dir"
fi

set +e
"$llvm/bin/clang" --target=x86_64-linux-ohos --sysroot="$sysroot" \
    -I"$sysroot/usr/include/x86_64-linux-ohos" "$evidence/draft.c" \
    -L"$sysroot/usr/lib/x86_64-linux-ohos" -o "$evidence/draft" \
    > "$evidence/build.log" 2>&1
build_status=$?
set -e
if (( build_status != 0 )); then
    printf '{"built":false,"exit":%d,"crashed":false,"build_error":%s}\n' \
        "$build_status" "\"$(tail -c 400 "$evidence/build.log" | tr -d '"' | tr '\n' ' ')\""
    exit 0
fi

ulimit -c 0
cd "$evidence" || exit 1
crash_exit=""
for round in 1 2; do
    set +e
    timeout 30 "$runtime" --library-path "$libdirs" "$evidence/draft" \
        > "$evidence/run-round${round}.log" 2>&1
    status=$?
    set -e
    printf '%s\n' "$status" > "$evidence/run-round${round}.exit"
    if [[ "$status" == "139" || "$status" == "11" ]]; then
        crash_exit=$status
        gdb -batch -q \
            -ex "set pagination off" -ex "set confirm off" \
            -ex "set disable-randomization off" -ex "run" \
            -ex "printf \"RIPRAW=%p\\n\", \$rip" \
            -ex "bt 8" -ex "info proc mappings" \
            --args "$runtime" --library-path "$libdirs" "$evidence/draft" \
            > "$evidence/gdb-round${round}.txt" 2>&1
    fi
done

if [[ -z "$crash_exit" ]]; then
    printf '{"built":true,"exit":%s,"crashed":false}\n' \
        "$(cat "$evidence/run-round1.exit")"
    exit 0
fi

# Every round that crashed must agree on the offset, so collect all of them.
offsets=()
rounds=0
frames_file="$evidence/frames.json"
: > "$frames_file"
for round in 1 2; do
    transcript="$evidence/gdb-round${round}.txt"
    [[ -f "$transcript" ]] || continue
    grep -q "Program received signal" "$transcript" || continue
    rounds=$((rounds + 1))
    # r-xp segment of the target library: start <- $1, file offset <- $4
    seg=$(grep -F "$library" "$transcript" | awk '$5=="r-xp"' | head -1)
    [[ -n "$seg" ]] || continue
    seg_start=$(echo "$seg" | awk '{print $1}')
    seg_off=$(echo "$seg" | awk '{print $4}')
    seg_end=$(echo "$seg" | awk '{print $2}')
    # candidates: the faulting instruction, then every return address in bt
    {
        grep -o 'RIPRAW=0x[0-9a-f]*' "$transcript" | cut -d= -f2
        grep -oE '^#[1-7] +0x[0-9a-f]+' "$transcript" | awk '{print $2}'
    } | sort -u > "$evidence/candidates.txt"
    while read -r addr; do
        [[ -z "$addr" ]] && continue
        if (( addr >= seg_start && addr < seg_end )); then
            off=$(printf '0x%x' $(( addr - seg_start + seg_off )))
            offsets+=("$off")
            offset=$off
            break
        fi
    done < "$evidence/candidates.txt"
    if [[ -n "${offset:-}" && -f "$unstripped" ]]; then
        {
            echo "{\"round\": $round, \"offset\": \"$offset\", \"chain\": ["
            "$llvm/bin/llvm-addr2line" -i -f -C -e "$unstripped" "$offset" \
                | paste - - \
                | python3 -c '
import json, sys
rows = [l.rstrip("\n").split("\t") for l in sys.stdin if "\t" in l]
out = []
for func, loc in rows:
    f, _, ln = loc.rpartition(":")
    try:
        line = int(ln)
    except ValueError:
        line = 0
    out.append({"function": func, "file": f, "line": line})
print(",\n".join(json.dumps(o) for o in out))
'
            echo "]}"
        } >> "$frames_file"
    fi
done

if [[ ${#offsets[@]} -eq 0 ]]; then
    printf '{"built":true,"exit":%s,"crashed":true,"offset":"","rounds":%d}\n' \
        "$crash_exit" "$rounds"
    exit 0
fi

unique=$(printf '%s\n' "${offsets[@]}" | sort -u | wc -l)
python3 - "$frames_file" "$crash_exit" "${offsets[-1]}" "$rounds" "$unique" <<'PY'
import json, sys
frames_path, exit_code, offset, rounds, unique = sys.argv[1:6]
chain = []
with open(frames_path, encoding='utf-8', errors='replace') as handle:
    text = handle.read().strip()
if text:
    # the script writes one JSON object per round, concatenated
    decoder = json.JSONDecoder()
    index, entries = 0, []
    while index < len(text):
        obj, index = decoder.raw_decode(text, index)
        entries.append(obj)
        while index < len(text) and text[index] in ' \n\t':
            index += 1
    chain = entries[-1]['chain'] if entries else []
print(json.dumps({
    'built': True,
    'exit': int(exit_code),
    'crashed': True,
    'offset': offset,
    'rounds': int(rounds),
    'offsets_agree': int(unique) == 1,
    'frames': chain,
}))
PY
