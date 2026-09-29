/* Malformed-input client for the OpenHarmony x86_64 CJ HiAppEvent AddWatcher ABI.
 * ABI source: hiviewdfx_hiappevent frameworks/cj/ffi/include/common.h
 *   CWatcher { char* name; CTriggerCondition; CArrAppEventFilter; callback×2 }
 *   CArrAppEventFilter { CAppEventFilter* head; int64_t size; }
 *   CAppEventFilter { char* domain; CArrUI32 eventTypes; CArrString names; }
 * Candidate under test: FfiOHOSHiAppEventAddWatcher → nested filter loop
 *   for(i < filters.size) { for(j < head[i].names.size) { head[i].names.head[j] } }
 *   — triple unprotected: outer head, inner names.head, eventTypes.head + shift UB.
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  valid: 1 filter with valid domain+1 name+1 type     control
 *   1  filters.head=NULL, size=1                           outer null (first crash layer)
 *   2  head valid, domain valid, names.head=NULL, names.size=1   inner null (second layer)
 *   3  head valid, eventTypes.head=NULL, size=1, type=100        shift UB (BIT_MASK << 100)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { uint32_t *head; int64_t size; } CArrUI32;
typedef struct { char **head; int64_t size; } CArrString;
typedef struct {
    char *domain;
    CArrUI32 eventTypes;
    CArrString names;
} CAppEventFilter;
typedef struct { CAppEventFilter *head; int64_t size; } CArrAppEventFilter;
typedef struct { int row; int size; int timeOut; } CTriggerCondition;
typedef struct {
    char *name;
    CTriggerCondition triggerCondition;
    CArrAppEventFilter appEventFilters;
    void (*callbackOnTriggerRef)(int, int, int64_t);
    void (*callbackOnReceiveRef)(char *, void *);
} CWatcher;
typedef struct { int64_t code; int64_t data; } RetDataI64;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

static void dummy_trigger(int a, int b, int64_t c) { (void)a; (void)b; (void)c; }
static void dummy_receive(char *a, void *b) { (void)a; (void)b; }

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    RetDataI64 (*add_watcher)(CWatcher) =
        (RetDataI64 (*)(CWatcher))dlsym(library, "FfiOHOSHiAppEventAddWatcher");
    if (!add_watcher) { fputs("missing AddWatcher export\n", stderr); return 4; }

    /* Case 0: valid */
    uint32_t types0[] = { 1 };
    char *names0[] = { (char *)"event_name" };
    CAppEventFilter f0 = {
        .domain = (char *)"validation.domain",
        .eventTypes = { types0, 1 },
        .names = { names0, 1 },
    };
    CWatcher w0 = {
        .name = (char *)"validation_watcher",
        .triggerCondition = { 1, 1, 0 },
        .appEventFilters = { &f0, 1 },
        .callbackOnTriggerRef = dummy_trigger,
        .callbackOnReceiveRef = dummy_receive,
    };

    /* Case 1: outer head = NULL, size = 1 */
    CWatcher w1 = w0;
    w1.appEventFilters.head = NULL;
    w1.appEventFilters.size = 1;

    /* Case 2: inner names.head = NULL, names.size = 1 */
    CAppEventFilter f2 = f0;
    f2.names.head = NULL;
    f2.names.size = 1;
    CWatcher w2 = w0;
    w2.appEventFilters.head = &f2;

    /* Case 3: eventTypes.head = NULL + shift UB attempt (type value 100) */
    CAppEventFilter f3 = f0;
    f3.eventTypes.head = NULL;
    f3.eventTypes.size = 1;
    CWatcher w3 = w0;
    w3.appEventFilters.head = &f3;

    const struct { CWatcher *w; const char *name; } cases[] = {
        { &w0, "valid_control" },
        { &w1, "outer_head_null_candidate" },
        { &w2, "inner_names_null_candidate" },
        { &w3, "eventtypes_null_shift_ub_variant" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start\n", k, cases[k].name);
        RetDataI64 ret = add_watcher(*cases[k].w);
        printf("case=%zu name=%s done code=%lld data=%lld\n", k, cases[k].name,
               (long long)ret.code, (long long)ret.data);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
