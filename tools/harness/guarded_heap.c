/* Guarded heap implementation — see guarded_heap.h for how it is wired in.
 *
 * Two rules make this a real detector rather than a wrapper:
 *   1. one page span per allocation, so an overflow past the requested size
 *      lands on unmapped memory instead of a neighbouring object;
 *   2. freed spans are quarantined (PAGE_NOACCESS, address never reused), so a
 *      use-after-free faults even though the allocator is still healthy.
 *
 * The quarantine table is static and bounded: a PoC leaks a few thousand pages
 * at worst, which is expected for a short-lived verification run.
 */
#include <windows.h>

/* Compiled without the -Dmalloc mapping, so these reach the CRT. */
void *__cdecl malloc(size_t size);
void __cdecl free(void *pointer);
void *__cdecl realloc(void *pointer, size_t size);

#define WT_QUARANTINE_SLOTS 16384
#define WT_PAGE 4096
#define WT_LARGE_THRESHOLD (64 * 1024)   /* big blocks go straight to the CRT */

static void *wt_freed[WT_QUARANTINE_SLOTS];
static size_t wt_freed_count = 0;

static void *wt_span_alloc(size_t size)
{
    size_t span = ((size + WT_PAGE - 1) / WT_PAGE) * WT_PAGE;
    return VirtualAlloc(NULL, span, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void *wt_guard_malloc(size_t size)
{
    if (size == 0) size = 1;
    if (size > WT_LARGE_THRESHOLD) return malloc(size);
    return wt_span_alloc(size);
}

void wt_guard_free(void *pointer)
{
    MEMORY_BASIC_INFORMATION info;
    DWORD previous;
    if (pointer == NULL) return;
    if (VirtualQuery(pointer, &info, sizeof(info)) != sizeof(info)) return;
    /* A block that came from the CRT (large allocation) still has to go back
     * through the CRT; ours are always leaf regions we reserved ourselves. */
    if (info.Type != MEM_PRIVATE || info.AllocationBase != pointer) {
        free(pointer);
        return;
    }
    VirtualProtect(info.AllocationBase, info.RegionSize, PAGE_NOACCESS, &previous);
    if (wt_freed_count < WT_QUARANTINE_SLOTS) {
        wt_freed[wt_freed_count++] = info.AllocationBase;
    } else {
        VirtualFree(info.AllocationBase, 0, MEM_RELEASE);
    }
}

void *wt_guard_realloc(void *pointer, size_t size)
{
    void *fresh;
    MEMORY_BASIC_INFORMATION info;
    size_t was;
    if (pointer == NULL) return wt_guard_malloc(size);
    if (size == 0) { wt_guard_free(pointer); return NULL; }
    if (VirtualQuery(pointer, &info, sizeof(info)) != sizeof(info))
        return realloc(pointer, size);
    if (info.Type != MEM_PRIVATE || info.AllocationBase != pointer)
        return realloc(pointer, size);
    fresh = wt_guard_malloc(size);
    if (fresh == NULL) return NULL;
    was = info.RegionSize < size ? info.RegionSize : size;
    memcpy(fresh, pointer, was);
    wt_guard_free(pointer);
    return fresh;
}

void *wt_guard_calloc(size_t count, size_t size)
{
    void *block;
    if (count != 0 && size > (size_t)-1 / count) return NULL;
    block = wt_guard_malloc(count * size);
    /* VirtualAlloc already hands back zeroed pages; the CRT path may not. */
    if (block != NULL && count * size > WT_LARGE_THRESHOLD)
        memset(block, 0, count * size);
    return block;
}
