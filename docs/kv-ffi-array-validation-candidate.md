# Candidate: Distributed KV FFI array validation

Status: `candidate`, `undetermined`; no target execution has been performed.

## Evidence

- Conversion: `foundation/distributeddatamgr/kv_store/frameworks/cj/src/distributed_kv_store_impl.cpp:373-382`
- Entry point: `foundation/distributeddatamgr/kv_store/frameworks/cj/src/distributed_kv_store_ffi.cpp:135-142`
- Public C ABI declaration: `foundation/distributeddatamgr/kv_store/frameworks/cj/include/distributed_kv_store_ffi.h:52`
- Input type: `foundation/distributeddatamgr/kv_store/frameworks/cj/include/distributed_kv_store_impl.h:107-110`

`CArrEntry` contains a raw `CEntry *head` and signed `int64_t size`. `CArrayEntryToEntries` copies `size` into `arrSize` and loops from zero to `arrSize`, dereferencing `cArrEntry.head[i]` without checking `head`, rejecting negative or unreasonably large sizes, or proving that the pointed-to array contains `size` elements. The FFI wrapper forwards the struct directly to `CJSingleKVStore::PutBatch`.

The analogous `CArrStrToVectorKey` path at lines 423-431 and `CArrStrToVectorString` path at lines 532-540 have the same shape and feed `DeleteBatch`, backup, and sync operations.

## Impact hypothesis

A caller able to invoke the C ABI with `{head = NULL, size = 1}` may cause a null-pointer crash. A forged large positive size may cause out-of-bounds reads or resource exhaustion. This is currently a hypothesis: the reachability of malformed structs from supported Cangjie/runtime bindings and the process boundary must be established before assigning CWE-476/CWE-125 or claiming a platform vulnerability.

## Safe verification plan

1. Build the smallest authorized FFI/library harness with AddressSanitizer or an equivalent crash detector.
2. Obtain a valid store handle through the supported setup path.
3. Call `FfiOHOSDistributedKVStoreSingleKVStorePutBatch` with `{nullptr, 1}` and record return/crash behavior.
4. Repeat with `{nullptr, -1}` and a one-element valid array to separate null, negative-size, and normal behavior.
5. Do not use a large allocation or cross-device service until the null/negative cases are understood.

No PoC, target execution, external submission, or patch is included in this candidate record.

## Build readiness check

The available `OpenHarmony-complete` snapshot has component `BUILD.gn` files but no root `.gn`; its `build/build_scripts/build.sh` therefore stops before generating a build. The Windows host has no `gn`, `hb`, or OpenHarmony clang toolchain, and the WSL environment has neither `gn` nor `clang++`. The four source/header inputs were copied with SHA-256 hashes to `.cache/oh-kv-candidate-backup-20260922` before any verification attempt. Runtime verification remains pending a complete OpenHarmony checkout/build toolchain.

## Source-equivalent reproduction

Because the snapshot cannot produce an OpenHarmony binary, a small harness copied the conversion function verbatim and linked only local type stubs. It was compiled with MinGW-w64 g++ 16.1.0. The result is recorded in `.cache/kv-ffi-equivalent/result.json`:

| Input | Result |
|---|---|
| `CArrEntry{head=null,size=1}` | Windows access violation (`0xC0000005`) |
| `CArrEntry{head=null,size=-1}` | returns normally through an empty loop |
| one valid element | returns normally |

This confirms the memory-unsafe behavior of the copied function, but it is not a linked OpenHarmony binary and does not establish caller reachability or platform impact. A second run with WSL Clang 21.1.8 and `-fsanitize=address,undefined` reports a zero-page SEGV for both null-head inputs, with stacks ending in `CArrayEntryToEntries` and `CArrStrToVectorKey`; negative-size and valid controls return normally. The candidate remains unconfirmed at platform level.

The parallel `CArrStrToVectorKey` conversion at lines 423-431 was tested with the same three inputs. `CArrStr{head=null,size=1}` also exits with `0xC0000005`, while a negative size and one valid string return normally. This strengthens the defect-family evidence across `PutBatch` and `DeleteBatch` without changing the platform-level status.
