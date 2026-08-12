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

    /* Streaming API (amisnap_repo_writer_file_chunked()'s own E_XHASH
     * needs this -- format.md's E_XHASH is one value for the whole
     * logical file, not per chunk, so it has to be accumulated across
     * however the caller happens to split its Read() calls). No
     * separate reference vectors for this path -- cross-checked
     * against the already-vector-verified one-shot function above, at
     * update() split sizes chosen to land differently relative to the
     * algorithm's own 16-byte stripe boundary each time (1: every call
     * is sub-block; 3: never divides 16 evenly; 7: same; 16: exactly
     * one stripe per call; 17: one stripe plus a byte spanning into
     * the next call's buffer). */
    {
        static const size_t splits[] = {1, 3, 7, 16, 17, 40};
        size_t si;

        /* Empty input via streaming: no update() calls at all. */
        {
            amisnap_xxh32_state s;
            amisnap_xxh32_init(&s, 0);
            TEST_CHECK(amisnap_xxh32_digest(&s) == amisnap_xxh32("", 0, 0));
        }

        for (si = 0; si < sizeof(splits) / sizeof(splits[0]); si++) {
            size_t chunk = splits[si];
            amisnap_xxh32_state s_spam0, s_spam_seed, s_ramp0, s_ramp42;
            size_t off;

            amisnap_xxh32_init(&s_spam0, 0);
            amisnap_xxh32_init(&s_spam_seed, 2654435761u);
            for (off = 0; off < strlen(spam); off += chunk) {
                size_t n = chunk;
                if (off + n > strlen(spam)) n = strlen(spam) - off;
                amisnap_xxh32_update(&s_spam0, spam + off, n);
                amisnap_xxh32_update(&s_spam_seed, spam + off, n);
            }
            TEST_CHECK(amisnap_xxh32_digest(&s_spam0) == amisnap_xxh32(spam, strlen(spam), 0));
            TEST_CHECK(amisnap_xxh32_digest(&s_spam_seed)
                       == amisnap_xxh32(spam, strlen(spam), 2654435761u));

            amisnap_xxh32_init(&s_ramp0, 0);
            amisnap_xxh32_init(&s_ramp42, 42);
            for (off = 0; off < sizeof(ramp); off += chunk) {
                size_t n = chunk;
                if (off + n > sizeof(ramp)) n = sizeof(ramp) - off;
                amisnap_xxh32_update(&s_ramp0, ramp + off, n);
                amisnap_xxh32_update(&s_ramp42, ramp + off, n);
            }
            TEST_CHECK(amisnap_xxh32_digest(&s_ramp0) == amisnap_xxh32(ramp, sizeof(ramp), 0));
            TEST_CHECK(amisnap_xxh32_digest(&s_ramp42) == amisnap_xxh32(ramp, sizeof(ramp), 42));
        }
    }
}
