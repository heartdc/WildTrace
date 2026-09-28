/* Malformed-input client for the OpenHarmony x86_64 CJ IPC exported ABI.
 * ABI source: IPC interfaces/innerkits/cj/include/ipc_utils_ffi.h and ipc_ffi.h
 * at edc6f3ab59a5b6fbbda92c427e1e4da6f6d64ae3 (same as ipc_normal_roundtrip.c).
 * Candidate under test: CJ_WriteByteArray iterates value.data for a positive
 * len without checking data for null (message_sequence_impl.cpp).
 * No target implementation is copied into this client.
 *
 * Case matrix (each prints start/done markers unbuffered so run.log pinpoints
 * the failing case even on a raw crash):
 *   0  data=NULL, len=0    control: loop body never runs, expect no crash
 *   1  data=NULL, len=1    the candidate: expected zero-page read per source
 *   2  data=NULL, len=64   variant with larger len
 *   3  data=valid, len=1   post-crash control (skipped only if earlier case died)
 * Either outcome of case 1/2 is a valid experiment result: a crash
 * (SIGSEGV, run exit 139) confirms the candidate at real-library level; a
 * returned error code (printed as write_error) disproves reachability of the
 * unguarded loop in this build. Do not interpret anything without the log.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct { int8_t *data; uint32_t len; } CJByteArray;
_Static_assert(sizeof(void *) == 8, "x86_64 caller required");
_Static_assert(offsetof(CJByteArray, len) == 8 && sizeof(CJByteArray) == 16,
               "unexpected array ABI");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }
    int64_t (*create)(void) = (int64_t (*)(void))dlsym(library, "FfiRpcMessageSequenceImplCreate");
    void (*write_array)(int64_t, CJByteArray, int32_t *) =
        (void (*)(int64_t, CJByteArray, int32_t *))dlsym(library, "FfiRpcMessageSequenceImplWriteByteArray");
    if (!create || !write_array) { fputs("missing IPC export\n", stderr); return 4; }

    int8_t valid = 7;
    const struct { int8_t *data; uint32_t len; const char *name; } cases[] = {
        { NULL, 0, "null_len0_control" },
        { NULL, 1, "null_len1_candidate" },
        { NULL, 64, "null_len64_variant" },
        { &valid, 1, "valid_len1_postcontrol" },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start\n", k, cases[k].name);
        int64_t id = create();
        printf("case=%zu create_id=%lld\n", k, (long long)id);
        if (id <= 0) { printf("case=%zu create_failed\n", k); return 5; }
        int32_t error = -1;
        CJByteArray input = { cases[k].data, cases[k].len };
        printf("case=%zu calling write_array data=%p len=%u\n", k,
               (void *)input.data, input.len);
        write_array(id, input, &error);
        printf("case=%zu name=%s done write_error=%d\n", k, cases[k].name, error);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
