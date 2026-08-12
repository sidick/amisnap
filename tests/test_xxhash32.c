/* test_xxhash32.c -- XXH32 vectors, verified against the reference
 * implementation (python-xxhash, which wraps Cyan4973/xxHash itself)
 * before being recorded here -- not transcribed from memory. Lengths are
 * chosen to cover every code path: empty, the <16-byte tail-only path
 * (1 and 3 bytes), a 39-byte input (two 16-byte stripes + a 4-byte lane
 * + 3 trailing bytes), and a 101-byte binary ramp with a non-zero seed.
 */
#include <string.h>

#include "test.h"
#include "xxhash32.h"

void run_xxhash32_tests(void)
{
    static const char spam[] = "Nobody inspects the spammish repetition";
    uint8_t ramp[101];
    size_t i;

    for (i = 0; i < sizeof(ramp); i++)
        ramp[i] = (uint8_t)i;

    TEST_CHECK(amisnap_xxh32("", 0, 0) == 0x02CC5D05u);
    TEST_CHECK(amisnap_xxh32("a", 1, 0) == 0x550D7456u);
    TEST_CHECK(amisnap_xxh32("abc", 3, 0) == 0x32D153FFu);
    TEST_CHECK(amisnap_xxh32(spam, strlen(spam), 0) == 0xE2293B2Fu);
    TEST_CHECK(amisnap_xxh32(spam, strlen(spam), 2654435761u) == 0xC9E89E68u);
    TEST_CHECK(amisnap_xxh32(ramp, sizeof(ramp), 0) == 0x1A20E95Bu);
    TEST_CHECK(amisnap_xxh32(ramp, sizeof(ramp), 42) == 0x2F072667u);
}
