/* Malformed-input client for the OpenHarmony x86_64 CJ UDMF exported ABI.
 * ABI source: udmf interfaces/cj/include/unified_data_impl.h
 *   CParameters { int8_t valueType; char* key; void* value; int64_t size; }
 *   CArrParameters { CParameters* head; int64_t size; }
 *   CUnifiedDataProperties { CArrParameters extras; char* tag; int64_t timestamp; int32_t shareOptions; }
 * Type codes (interfaces/cj/src/unified_data_parameter_parse.cpp:34-39):
 *   I32_TYPE=0 I64_TYPE=1 DOUBLE_TYPE=2 BOOL_TYPE=3 STR_TYPE=4 UINT8_ARRAY_TYPE=5
 *
 * Candidate A (stale, expected falsified on this snapshot):
 *   SetDataParameters enters head+i loop — current code guards head==nullptr
 *   (unified_data_parameter_parse.cpp SetDataParameters first if-statement).
 * Candidate B (under test, expected crash):
 *   FfiUDMFSetProperties -> prop->tag = Utils::MallocCString(properties.tag)
 *   (interfaces/cj/src/unified_data_ffi.cpp FfiUDMFSetProperties body);
 *   MallocCString takes const std::string& (interfaces/cj/src/utils.cpp:18),
 *   so tag==NULL constructs std::string(nullptr) -> strlen(NULL) SIGSEGV.
 *   Note FfiUDMFGetProperties returns tag=nullptr for an empty stored tag,
 *   i.e. the getter's own output is not valid setter input (round-trip crash).
 * Prerequisite: FfiUDMFUnifiedDataConstructor() must return a valid id.
 * No target implementation is copied into this client.
 *
 * Case matrix (sequential single process; the crash case is placed last so
 * earlier cases' done-markers give crash attribution):
 *   0  extras{valid 1 param I32, size=1} + tag="rt-tag"   control
 *   1  extras{head=NULL, size=3}          + tag="rt-tag"  stale candidate
 *   2  extras{head=NULL, size=0}          + tag="rt-tag"  zero-size control
 *   3  extras{valid 1 param I32, size=1}  + tag=NULL      candidate B
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

    CParameters valid_param = { 0 /*I32_TYPE*/, "k0", NULL, 0 };
    int32_t valid_val = 42;
    valid_param.value = &valid_val;

    const struct {
        CUnifiedDataProperties props;
        const char *name;
    } cases[] = {
        { { { &valid_param, 1 },  "rt-tag", 0, 1 }, "valid_control" },
        { { { NULL, 3 },           "rt-tag", 0, 1 }, "null_head_size3_stale_candidate" },
        { { { NULL, 0 },           "rt-tag", 0, 1 }, "null_head_size0_control" },
        { { { &valid_param, 1 },  NULL,     0, 1 }, "null_tag_candidate" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p tag=%s size=%lld\n", k, cases[k].name,
               (void *)cases[k].props.extras.head,
               cases[k].props.tag ? cases[k].props.tag : "(null)",
               (long long)cases[k].props.extras.size);
        set_props(data_id, cases[k].props);
        printf("case=%zu name=%s done\n", k, cases[k].name);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
