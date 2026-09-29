/* Malformed-input client for the OpenHarmony x86_64 CJ AppAccount exported ABI.
 * ABI source: account_os_account frameworks/appaccount/cj/include/appaccount_defination.h
 *   CVerifyCredentialOptions { char* credentialType; char* credential; CArrParameters parameters; }
 *   CArrParameters { CParameters* head; int64_t size; }
 *   CParameters { int8_t valueType; char* key; void* value; int64_t size; }
 * Candidate under test: SetDataParameters (appaccount_parameter_parse.cpp:163)
 * enters head+i loop without checking head for null.
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  head=valid 1 param, size=1     control: normal dispatch
 *   1  head=NULL, size=5              candidate: null head with positive size
 *   2  head=valid, size=-1            negative size variant (loop skips → safe or UB)
 *   3  head=NULL, size=0              zero size (for loop skips → expect safe)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { int8_t valueType; char *key; void *value; int64_t size; } CParameters;
typedef struct { CParameters *head; int64_t size; } CArrParameters;
typedef struct { char *credentialType; char *credential; CArrParameters parameters; } CVerifyCredentialOptions;
/* CAuthCallback is a function pointer table; pass NULL-filled struct */
typedef struct { void *onResult; void *onRequestRedirected; void *onRequestContinued; } CAuthCallbackStub;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    /* FFI export: int32_t FfiAppAccountAppAccountManagerVerifyCredential(
     *     int id, char *name, char *owner, CAuthCallback callbackId,
     *     CVerifyCredentialOptions cOptions) */
    int32_t (*verify_cred)(int, char *, char *, CAuthCallbackStub, CVerifyCredentialOptions) =
        (int32_t (*)(int, char *, char *, CAuthCallbackStub, CVerifyCredentialOptions))
        dlsym(library, "FfiAppAccountAppAccountManagerVerifyCredential");
    if (!verify_cred) { fputs("missing AppAccount export\n", stderr); return 4; }

    CAuthCallbackStub cb = { NULL, NULL, NULL };
    CParameters valid_param = { 1 /*I32_TYPE*/, "k0", NULL, 0 }; /* value=NULL is ok for scalar type? let's set */
    int32_t valid_val = 42;
    valid_param.value = &valid_val;

    const struct {
        CVerifyCredentialOptions opts;
        const char *name;
    } cases[] = {
        { { NULL, NULL, { &valid_param, 1 } }, "valid_control" },
        { { NULL, NULL, { NULL, 5 } },           "null_head_size5_candidate" },
        { { NULL, NULL, { &valid_param, -1 } },  "neg_size_variant" },
        { { NULL, NULL, { NULL, 0 } },           "null_head_size0_control" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld\n", k, cases[k].name,
               (void *)cases[k].opts.parameters.head,
               (long long)cases[k].opts.parameters.size);
        int32_t rc = verify_cred(1, (char *)"validation_acct", (char *)"validation_owner",
                                 cb, cases[k].opts);
        printf("case=%zu name=%s done rc=%d\n", k, cases[k].name, rc);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
