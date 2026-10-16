#!/usr/bin/env bash
# Stage real Rust shared-library files in the selected musl sysroot only.
# No target execution, evidence deletion, network access, or automatic retry.
set -euo pipefail
usage() {
  echo "Usage: bash $0 SOURCE_ROOT BUILD_OUTPUT [--apply NEW_BACKUP_DIRECTORY]"
  echo "Optional RUST_LIB_DIR overrides the source Rust library directory."
}
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if [[ $# != 2 && $# != 4 ]]; then usage >&2; exit 2; fi
if [[ $# == 4 && $3 != --apply ]]; then usage >&2; exit 2; fi
source_root=$(realpath -e -- "$1")
build_output=$(realpath -e -- "$2")
rust_dir=$(realpath -e -- "${RUST_LIB_DIR:-$source_root/prebuilts/rustc/rust-std-nightly-x86_64-unknown-linux-ohos/rust-std-x86_64-unknown-linux-ohos/lib/rustlib/x86_64-unknown-linux-ohos/lib}")
sysroot=$(realpath -e -- "$build_output/obj/third_party/musl/usr/lib/x86_64-linux-ohos")
case "$sysroot/" in "$build_output/"*) ;; *) echo 'Sysroot escapes build output' >&2; exit 2;; esac
[[ -f "$rust_dir/libstd.dylib.so" ]] || { echo 'Missing Rust libstd.dylib.so' >&2; exit 1; }
shopt -s nullglob
libraries=("$rust_dir"/*.so)
for library in "${libraries[@]}"; do
  [[ -f "$library" ]] || { echo "Missing link target: $library" >&2; exit 1; }
  name=$(basename -- "$library")
  [[ ! -d "$sysroot/$name" ]] || { echo "Destination is a directory: $name" >&2; exit 1; }
  if [[ -e "$sysroot/$name" && "$library" -ef "$sysroot/$name" ]]; then
    echo "Source and destination alias: $name" >&2; exit 1
  fi
done
if [[ $# == 2 ]]; then
  echo "CHECK_ONLY source=$rust_dir destination=$sysroot files=${#libraries[@]}"
  sha256sum -- "${libraries[@]}"
  exit 0
fi
backup=$(realpath -m -- "$4")
case "$backup/" in "$build_output/"*|"$rust_dir/"*) echo 'Backup must be outside build output and Rust libraries' >&2; exit 2;; esac
[[ ! -e "$backup" && ! -L "$backup" ]] || { echo 'Backup directory already exists' >&2; exit 2; }
mkdir -- "$backup"
mkdir -- "$backup/original"
printf '%s\n' "$sysroot" > "$backup/destination.txt"
: > "$backup/created-files.txt"
# Save all originals before the first replacement. Symlinks are preserved here.
for library in "${libraries[@]}"; do
  name=$(basename -- "$library")
  if [[ -e "$sysroot/$name" || -L "$sysroot/$name" ]]; then
    cp -a -- "$sysroot/$name" "$backup/original/$name"
  else
    printf '%s\n' "$name" >> "$backup/created-files.txt"
  fi
done
sha256sum -- "${libraries[@]}" > "$backup/source-before.sha256"
temporary=''
trap 'if [[ -n "$temporary" ]]; then rm -f -- "$temporary"; fi' EXIT
for library in "${libraries[@]}"; do
  name=$(basename -- "$library")
  temporary=$(mktemp "$sysroot/.rust-stage.XXXXXX")
  cp -L -- "$library" "$temporary"
  chmod --reference="$library" "$temporary"
  # Replacing the directory entry never writes through a destination symlink.
  mv -fT -- "$temporary" "$sysroot/$name"
  temporary=''
  cmp -- "$library" "$sysroot/$name"
  [[ ! -L "$sysroot/$name" ]]
done
sha256sum --check --status "$backup/source-before.sha256"
for library in "${libraries[@]}"; do
  sha256sum -- "$sysroot/$(basename -- "$library")"
done > "$backup/installed.sha256"
echo "COPIED_TO_SYSROOT files=${#libraries[@]} backup=$backup"
