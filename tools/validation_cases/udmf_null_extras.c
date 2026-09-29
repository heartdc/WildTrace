/* Malformed-input client for the OpenHarmony x86_64 CJ UDMF exported ABI.
 * ABI source: udmf interfaces/cj/include/unified_data_ffi.h
 *   CUnifiedDataProperties { CArrParameters extras; char* tag; int64_t timestamp; int32_t shareOptions; }
 *   CArrParameters { CParameters* head; int64_t size; }
 * Candidate under test: SetDataParameters (unified_data_parameter_parse.cpp:158)
 * enters head+i loop without checking head for null.
 * Prerequisite: FfiUDMFUnifiedDataConstructor() must return a valid id.
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  extras{valid 1 param, size=1}   control
 *   1  extras{head=NULL, size=3}       candidate: null head + positive size
 *   2  extras{head=NULL, size=0}       zero size control
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { int8_t valueType; char *key; void *value; int64_t size; } CParameters;
typedef struct { CParameters *head; int64_t size; } CArrParameters;
typedef struct {
    CArrParameters extras;
    char *tag;
    int64_t timestamp;
    int32_t shareOptions;
} CUnifiedDataProperties;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    int64_t (*constructor)(void) =
        (int64_t (*)(void))dlsym(library, "FfiUDMFUnifiedDataConstructor");
    void (*set_props)(int64_t, CUnifiedDataProperties) =
        (void (*)(int64_t, CUnifiedDataProperties))dlsym(library, "FfiUDMFSetProperties");
    if (!constructor || !set_props) { fputs("missing UDMF export\n", stderr); return 4; }

    puts("stage=env_probe start");
    int64_t data_id = constructor();
    printf("stage=env_probe constructor id=%lld\n", (long long)data_id);
    if (data_id <= 0) { puts("stage=env_probe failed"); return 10; }
    puts("stage=env_probe ok");

    CParameters valid_param = { 1 /*I32_TYPE*/, "k0", NULL, 0 };
    int32_t valid_val = 42;
    valid_param.value = &valid_val;

    const struct {
        CUnifiedDataProperties props;
        const char *name;
    } cases[] = {
        { { { &valid_param, 1 }, NULL, 0, 1 }, "valid_control" },
        { { { NULL, 3 }, NULL, 0, 1 },          "null_head_size3_candidate" },
        { { { NULL, 0 }, NULL, 0, 1 },          "null_head_size0_control" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld\n", k, cases[k].name,
               (void *)cases[k].props.extras.head,
               (long long)cases[k].props.extras.size);
        set_props(data_id, cases[k].props);
        printf("case=%zu name=%s done\n", k, cases[k].name);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
