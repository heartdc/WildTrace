/* Malformed-input client for the OpenHarmony x86_64 CJ Bluetooth BLE exported ABI.
 * ABI source: communication_bluetooth frameworks/cj/ble/include/bluetooth_ble_ffi.h
 *   NativeScanFilter { 12 fields incl CArrUI8 }; CArrNativeScanFilter { head; size; }
 * Candidate under test: CheckBleScanParams (:221) does
 *   uint32_t length = static_cast<uint32_t>(filters.size);
 *   for (uint32_t i = 0; i < length; i++) { filters.head[i]; }
 * — head not checked for null; negative size becomes huge uint32 → massive OOB loop.
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  head=valid empty filter, size=1  control
 *   1  head=NULL, size=1                candidate: null head + positive size
 *   2  head=NULL, size=-1               candidate: negative size → uint32 huge loop
 *   3  head=valid, size=0               zero size (loop skips → expect safe)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Minimal NativeScanFilter stub (only layout matters, not content) */
typedef struct { uint8_t *head; int64_t size; } CArrUI8;
typedef struct {
    char *deviceId; char *name; char *serviceUuid; char *serviceUuidMask;
    char *serviceSolicitationUuid; char *serviceSolicitationUuidMask;
    CArrUI8 serviceData; CArrUI8 serviceDataMask;
    uint16_t manufactureId;
    CArrUI8 manufactureData; CArrUI8 manufactureDataMask;
} NativeScanFilter;
typedef struct { NativeScanFilter *head; int64_t size; } CArrNativeScanFilter;
typedef struct { int32_t interval; int32_t dutyType; int32_t matchMode; } NativeScanOptions;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    /* FFI export: void FfiBluetoothBleStartBleScan(
     *     CArrNativeScanFilter filters, NativeScanOptions *options, int32_t *errCode) */
    void (*start_scan)(CArrNativeScanFilter, NativeScanOptions *, int32_t *) =
        (void (*)(CArrNativeScanFilter, NativeScanOptions *, int32_t *))dlsym(library,
            "FfiBluetoothBleStartBleScan");
    if (!start_scan) { fputs("missing Bluetooth BLE export\n", stderr); return 4; }

    NativeScanFilter valid_filter = { 0 }; /* all-null/zero = match everything */
    NativeScanOptions opts = { 0 };

    const struct { CArrNativeScanFilter filters; const char *name; } cases[] = {
        { { &valid_filter, 1 },  "valid_control" },
        { { NULL, 1 },            "null_head_size1_candidate" },
        { { NULL, -1 },           "null_head_negsize_uint32_variant" },
        { { &valid_filter, 0 },   "valid_head_size0_control" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld\n", k, cases[k].name,
               (void *)cases[k].filters.head, (long long)cases[k].filters.size);
        int32_t err = 0;
        start_scan(cases[k].filters, &opts, &err);
        printf("case=%zu name=%s done err=%d\n", k, cases[k].name, err);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
