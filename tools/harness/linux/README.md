# Guarded heap for prebuilt `.so` targets (Linux)

`tools/harness/guarded_heap.c` (the Windows one) works by renaming `malloc` at
the preprocessor level, which needs the target's sources. OpenHarmony FFI
libraries ship as compiled `.so`, so here the interposition happens at load
time instead.

```bash
gcc -shared -fPIC -O2 -o guarded_heap.so guarded_heap.c -ldl

# normal control run
./poc /path/to/libcj_ipc_ffi.z.so

# guarded run: any read of released memory faults
LD_PRELOAD=./guarded_heap.so ./poc /path/to/libcj_ipc_ffi.z.so
```

Expect the guarded run to die with SIGSEGV (exit 139) where the plain run
either passes or silently returns garbage. **Both results are needed** — a
crash only under the harness is the signal; a crash in both is an ordinary bug
that did not need help.

## When to prefer AddressSanitizer

If the target can be rebuilt, use ASan instead: it has a shadow map, per-byte
granularity and readable reports.

```bash
clang -fsanitize=address -g poc.c -o poc && ./poc
```

Use this harness only when the `.so` is prebuilt and cannot be recompiled.

## Limits

- allocations above 64 KiB fall through to the real allocator, so a large-buffer
  overflow is not caught by this harness;
- the quarantine is a fixed 65536-entry table (a PoC leaks those pages);
- only the four standard names are interposed: a target that calls `mmap`,
  `operator new` or a bundled allocator directly is not covered;
- interposing hides real allocator reuse, so timing and memory use differ from a
  normal run — do not use these numbers in a performance claim.
