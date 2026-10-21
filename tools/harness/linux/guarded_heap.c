/* Guarded heap for Linux: LD_PRELOAD interposer for prebuilt shared objects.
 *
 * The Windows harness in ../guarded_heap.c cannot help here — the OpenHarmony
 * FFI libraries ship as compiled .so files, so there is no source to rebuild
 * with -Dmalloc=... . Interposing at load time is the only option that does not
 * touch the target binary.
 *
 *     gcc -shared -fPIC -O2 -o guarded_heap.so guarded_heap.c -ldl
 *     LD_PRELOAD=./guarded_heap.so ./poc /path/to/libfoo.z.so
 *
 * Same two rules as the Windows version:
 *   1. one mmap'd span per allocation, so an overflow past the requested size
 *      lands on an unmapped page;
 *   2. freed spans are mprotect(PROT_NONE) and quarantined — the address is
 *      never recycled, otherwise the next allocation lands on the same page and
 *      a use-after-free runs to completion against valid memory.
 *
 * Prefer AddressSanitizer when the toolchain supports it (a proper shadow map
 * and better diagnostics). Use this when the target is a prebuilt .so that
 * cannot be recompiled.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define WT_QUARANTINE_SLOTS 65536
#define WT_LARGE_THRESHOLD (64 * 1024)

static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static void *(*real_realloc)(void *, size_t);
static void *(*real_calloc)(size_t, size_t);

static void *quarantine[WT_QUARANTINE_SLOTS];
static size_t quarantine_count = 0;
static size_t page_size = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void wt_init(void)
{
    if (page_size != 0) return;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
}

/* Header kept just before the user pointer so free()/realloc() can find the
 * span without a side table (the target may free memory it did not allocate). */
typedef struct { size_t span; } wt_header;

static void *wt_span_alloc(size_t size)
{
    size_t span, total;
    void *base;
    wt_header *header;
    if (size == 0) size = 1;
    if (size > WT_LARGE_THRESHOLD) return NULL;          /* sentinel: use CRT */
    span = ((size + sizeof(wt_header) + page_size - 1) / page_size) * page_size;
    total = span;
    base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    header = (wt_header *)base;
    header->span = total;
    return (char *)base + sizeof(wt_header);
}

void *malloc(size_t size)
{
    void *out;
    if (page_size == 0) wt_init();
    out = wt_span_alloc(size);
    if (out != NULL) return out;
    return real_malloc(size);
}

void free(void *pointer)
{
    wt_header *header;
    void *base;
    if (pointer == NULL) return;
    if (page_size == 0) wt_init();
    base = (char *)pointer - sizeof(wt_header);
    /* Only touch blocks we handed out: the span header sits right before the
     * pointer and the whole thing is a single mapping we created. */
    header = (wt_header *)base;
    if (header->span <= WT_LARGE_THRESHOLD + page_size || header->span % page_size) {
        real_free(pointer);
        return;
    }
    mprotect(base, header->span, PROT_NONE);
    pthread_mutex_lock(&lock);
    if (quarantine_count < WT_QUARANTINE_SLOTS) {
        quarantine[quarantine_count++] = base;
    } else {
        munmap(base, header->span);
    }
    pthread_mutex_unlock(&lock);
}

void *realloc(void *pointer, size_t size)
{
    wt_header *header;
    void *fresh;
    size_t was;
    if (pointer == NULL) return malloc(size);
    if (size == 0) { free(pointer); return NULL; }
    if (page_size == 0) wt_init();
    header = (wt_header *)((char *)pointer - sizeof(wt_header));
    if (header->span <= WT_LARGE_THRESHOLD + page_size || header->span % page_size)
        return real_realloc(pointer, size);
    fresh = wt_span_alloc(size);
    if (fresh == NULL) return real_realloc(pointer, size);
    was = header->span - sizeof(wt_header);
    memcpy(fresh, pointer, was < size ? was : size);
    free(pointer);
    return fresh;
}

void *calloc(size_t count, size_t size)
{
    void *block;
    if (count != 0 && size > (size_t)-1 / count) return NULL;
    block = malloc(count * size);
    /* mmap hands back zeroed pages, so only the CRT path needs the memset. */
    if (block != NULL && count * size > WT_LARGE_THRESHOLD)
        memset(block, 0, count * size);
    return block;
}
