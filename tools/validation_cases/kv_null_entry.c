/* Malformed-input client for the OpenHarmony x86_64 CJ KV-store exported ABI.
 * ABI source: kv_store frameworks/cj/include/distributed_kv_store_ffi.h and
 * distributed_kv_store_impl.h at master (CArrEntry{CEntry* head; int64_t size},
 * CEntry{char* key; ValueType value}).
 * Candidate under test: PutBatch conversion dereferences head while size>0
 * without a null/negative check (distributed_kv_store_impl.cpp).
 * No target implementation is copied into this client.
 *
 * Stage 0 is an environment probe: CreateKVManager/GetKVStore must succeed in
 * the isolated runtime before PutBatch is reachable. If stage 0 fails, record
 * the error and STOP — that is an isolation limit, not a case verdict.
 * Case matrix once a store exists:
 *   0  head=NULL, size=0      control (empty batch, expect no crash)
 *   1  head=NULL, size=1      candidate: null head with positive size
 *   2  head=NULL, size=-1     negative-size variant
 *   3  head=valid, size=1     post control (one real entry)
 * Either outcome of case 1/2 is a valid result (crash vs returned error).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *key; int32_t tag; double num; char *str; int32_t boolean; } ValueTypeStub;
typedef struct { char *key; ValueTypeStub value; } CEntryStub;
typedef struct { CEntryStub *head; int64_t size; } CArrEntryStub;

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    int64_t (*create_manager)(const char *, int32_t *) =
        (int64_t (*)(const char *, int32_t *))dlsym(library, "FfiOHOSDistributedKVStoreCreateKVManager");
    int64_t (*get_store)(int64_t, const char *, const char *, int32_t *) =
        (int64_t (*)(int64_t, const char *, const char *, int32_t *))dlsym(library, "FfiOHOSDistributedKVStoreGetKVStore");
    int32_t (*put_batch)(int64_t, CArrEntryStub) =
        (int32_t (*)(int64_t, CArrEntryStub))dlsym(library, "FfiOHOSDistributedKVStoreSingleKVStorePutBatch");
    int32_t (*close_store)(int64_t, const char *, const char *) =
        (int32_t (*)(int64_t, const char *, const char *))dlsym(library, "FfiOHOSDistributedKVStoreCloseKVStore");
    if (!create_manager || !get_store || !put_batch) {
        fputs("missing KV export\n", stderr);
        return 4;
    }

    puts("stage=env_probe start");
    int32_t err = 0;
    int64_t manager = create_manager("ohos.validation.case", &err);
    printf("stage=env_probe create_manager id=%lld err=%d\n", (long long)manager, err);
    if (manager <= 0) { puts("stage=env_probe failed: isolated runtime cannot create manager"); return 10; }
    int64_t store = get_store(manager, "ohos.validation.case", "malformed_store", &err);
    printf("stage=env_probe get_store id=%lld err=%d\n", (long long)store, err);
    if (store <= 0) { puts("stage=env_probe failed: isolated runtime cannot create store"); return 11; }
    puts("stage=env_probe ok");

    /* ValueType layout here is a stub; for null-head cases the conversion
     * never dereferences entries, so candidate verdicts do not depend on it.
     * Case 3 is a best-effort control only. */
    ValueTypeStub v = { 0 };
    CEntryStub one = { "k0", v };
    const struct { CEntryStub *head; int64_t size; const char *name; } cases[] = {
        { NULL, 0, "null_size0_control" },
        { NULL, 1, "null_size1_candidate" },
        { NULL, -1, "null_sizeneg_variant" },
        { &one, 1, "valid_size1_postcontrol" },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld\n", k, cases[k].name,
               (void *)cases[k].head, (long long)cases[k].size);
        CArrEntryStub batch = { cases[k].head, cases[k].size };
        int32_t rc = put_batch(store, batch);
        printf("case=%zu name=%s done rc=%d\n", k, cases[k].name, rc);
    }
    if (close_store) close_store(manager, "ohos.validation.case", "malformed_store");
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
