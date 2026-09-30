/* Functional negative controls for the pinned securec memcpy_s API.
 * These are NOT vulnerability PoCs. All allocated objects are large enough
 * for the documented writes, including error-path resets. Execute only in an
 * explicitly authorized validation environment. Syntax checks do not execute.
 */
#include <stddef.h>
#include <stdio.h>
#include "securec.h"

static int bytes_equal(const unsigned char *data, size_t start, size_t end,
                       unsigned char expected)
{
    size_t i;
    for (i = start; i < end; ++i) {
        if (data[i] != expected) return 0;
    }
    return 1;
}

static int record(const char *id, int pass)
{
    printf("{\"case_id\":\"%s\",\"kind\":\"functional_control\","
           "\"passed\":%s,\"counts_as_vulnerability\":false}\n",
           id, pass ? "true" : "false");
    return pass ? 0 : 1;
}

int main(void)
{
    unsigned char src[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char bounded[8] = {90, 90, 90, 90, 90, 90, 90, 90};
    unsigned char range[8] = {90, 90, 90, 90, 90, 90, 90, 90};
    unsigned char nullsrc[8] = {90, 90, 90, 90, 90, 90, 90, 90};
    unsigned char overlap[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char zero[8] = {90, 90, 90, 90, 90, 90, 90, 90};
    errno_t code;
    int failures = 0;

    fputs("CASE_START securec-memcpy-controls cases=6\n", stderr);

    code = memcpy_s(bounded, 4, src, 4);
    failures += record("bounded-copy", code == EOK && bounded[0] == 1 &&
        bounded[1] == 2 && bounded[2] == 3 && bounded[3] == 4 &&
        bytes_equal(bounded, 4, 8, 90));

    /* count exceeds destMax but NOT the allocated source or destination. */
    code = memcpy_s(range, 4, src, 5);
    failures += record("reject-count-and-reset", code == ERANGE_AND_RESET &&
        bytes_equal(range, 0, 4, 0) && bytes_equal(range, 4, 8, 90));

    code = memcpy_s(nullsrc, 4, NULL, 1);
    failures += record("reject-null-source-and-reset", code == EINVAL_AND_RESET &&
        bytes_equal(nullsrc, 0, 4, 0) && bytes_equal(nullsrc, 4, 8, 90));

    code = memcpy_s(NULL, 4, src, 1);
    failures += record("reject-null-destination", code == EINVAL);

    code = memcpy_s(overlap, sizeof overlap, overlap + 1, 3);
    /* Pinned-implementation observation, not a portable overlap guarantee. */
    failures += record("implementation-overlap-reset", code == EOVERLAP_AND_RESET &&
        bytes_equal(overlap, 0, sizeof overlap, 0));

    code = memcpy_s(zero, 4, src, 0);
    failures += record("zero-count-no-copy", code == EOK &&
        bytes_equal(zero, 0, sizeof zero, 90));

    printf("{\"kind\":\"functional_control_summary\",\"cases\":6,"
           "\"failures\":%d,\"confirmed_vulnerabilities\":0}\n", failures);
    return failures == 0 ? 0 : 1;
}
