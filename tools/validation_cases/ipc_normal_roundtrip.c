/* Normal-input client for the OpenHarmony x86_64 CJ IPC exported ABI.
 * ABI source: IPC interfaces/innerkits/cj/include/ipc_utils_ffi.h and ipc_ffi.h
 * at edc6f3ab59a5b6fbbda92c427e1e4da6f6d64ae3.
 * No target implementation is copied into this client.
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
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }
    int64_t (*create)(void) = (int64_t (*)(void))dlsym(library, "FfiRpcMessageSequenceImplCreate");
    void (*write_array)(int64_t, CJByteArray, int32_t *) =
        (void (*)(int64_t, CJByteArray, int32_t *))dlsym(library, "FfiRpcMessageSequenceImplWriteByteArray");
    CJByteArray (*read_array)(int64_t, int32_t *) =
        (CJByteArray (*)(int64_t, int32_t *))dlsym(library, "FfiRpcMessageSequenceImplReadByteArray");
    if (!create || !write_array || !read_array) {
        fputs("missing IPC export\n", stderr);
        return 4;
    }
    int8_t values[] = {42, -7, 0};
    const uint32_t lengths[] = {1, 3, 0};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        int64_t id = create();
        if (id <= 0) return 5;
        int32_t error = 0;
        CJByteArray input = {values, lengths[i]};
        write_array(id, input, &error);
        printf("length=%u write_error=%d\n", input.len, error);
        if (error) return 6;
        CJByteArray output = read_array(id, &error);
        int matches = error == 0 && output.len == input.len;
        if (output.len && !output.data) matches = 0;
        if (matches) {
            for (uint32_t n = 0; n < input.len; ++n)
                if (output.data[n] != input.data[n]) matches = 0;
        }
        printf("length=%u read_length=%u read_error=%d matches=%d\n",
               input.len, output.len, error, matches);
        free(output.data);
        if (!matches) return 7;
    }
    puts("normal_roundtrip=passed");
    return 0;
}
