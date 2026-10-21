/* Guarded heap: a library-agnostic use-after-free detector for Windows builds.
 *
 * ASan is not available for the mingw target (the runtime is missing:
 * `undefined symbol: __asan_report_load8`), and lld rejects `--wrap`, so the
 * remaining portable hook is the preprocessor: compile the library and the PoC
 * with
 *
 *     -include guarded_heap.h
 *     -Dmalloc=wt_guard_malloc -Dfree=wt_guard_free
 *     -Drealloc=wt_guard_realloc -Dcalloc=wt_guard_calloc
 *
 * and link guarded_heap.c alongside them. Every allocation the code under test
 * makes through the standard names then lands on its own page(s), and every
 * free turns those pages into PAGE_NOACCESS *without recycling the address*,
 * so reading a released object faults instead of silently seeing a fresh one.
 *
 * That last part matters: a naive VirtualFree hands the same address back on
 * the next allocation, and a use-after-free then runs to completion against
 * garbage-but-valid memory (observed on CVE-2026-87933 before the quarantine
 * was added).
 *
 * Nothing here is specific to any one library. The target only has to be built
 * from C sources next to the PoC.
 */
#ifndef WILDTRACE_GUARDED_HEAP_H
#define WILDTRACE_GUARDED_HEAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* When the compiler is invoked with `-Dmalloc=wt_guard_malloc`, the <stdlib.h>
 * declaration inside each translation unit is rewritten to these prototypes,
 * so declaration and definition always agree. */
void *wt_guard_malloc(size_t size);
void wt_guard_free(void *pointer);
void *wt_guard_realloc(void *pointer, size_t size);
void *wt_guard_calloc(size_t count, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* WILDTRACE_GUARDED_HEAP_H */
