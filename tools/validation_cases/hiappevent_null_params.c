/* Malformed-input client for the OpenHarmony x86_64 CJ HiAppEvent exported ABI.
 * ABI source: hiviewdfx_hiappevent frameworks/cj/ffi/src/hiappevent_ffi.cpp
 * Candidate under test: AddParams2EventPack (:139) enters head+i loop without
 * checking head for null. FfiOHOSHiAppEventSetEventParam (:416) passes directly.
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  head=valid 1 param, size=1     control: normal int32 param
 *   1  head=NULL, size=1              candidate: null head with positive size
 *   2  head=NULL, size=5              variant: larger size
 *   3  head=valid, size=0             zero size (loop skips → expect safe)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { int8_t valueType; char *key; void *value; int64_t size; } CParameters;
typedef struct { CParameters *head; int64_t size; } CArrParameters;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    /* FFI export: int32_t FfiOHOSHiAppEventSetEventParam(
     *     CArrParameters eventParams, char* domain, char* name) */
    int32_t (*set_param)(CArrParameters, char *, char *) =
        (int32_t (*)(CArrParameters, char *, char *))dlsym(library,
            "FfiOHOSHiAppEventSetEventParam");
    if (!set_param) { fputs("missing HiAppEvent export\n", stderr); return 4; }

    int32_t valid_val = 42;
    CParameters p0 = { 1 /*INT32_VALUE*/, "k0", &valid_val, 0 };

    const struct { CArrParameters params; const char *name; } cases[] = {
        { { &p0, 1 },        "valid_control" },
        { { NULL, 1 },        "null_head_size1_candidate" },
        { { NULL, 5 },        "null_head_size5_variant" },
        { { &p0, 0 },         "valid_head_size0_control" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld\n", k, cases[k].name,
               (void *)cases[k].params.head, (long long)cases[k].params.size);
        int32_t rc = set_param(cases[k].params, (char *)"validation.domain",
                               (char *)"validation_event");
        printf("case=%zu name=%s done rc=%d\n", k, cases[k].name, rc);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
