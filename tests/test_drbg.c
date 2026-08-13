/* test_drbg.c -- HMAC-DRBG (SHA-256) tests.
 *
 * The known-answer vectors are produced by an independent Python
 * HMAC-DRBG-over-SHA256 reference (hmac/hashlib, mirroring SP 800-90A
 * 10.1.2), so this is a genuine cross-implementation check, not a
 * self-consistency snapshot -- same structure as sibling AmiAuth's
 * tests/test_drbg.c. Plus structural properties: determinism, seed
 * independence, reseed effect, and distribution.
 */
#include <string.h>

#include "test.h"
#include "drbg.h"

static int hex_eq(const uint8_t *buf, size_t len, const char *hex)
{
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return 0;
        if (buf[i] != (uint8_t)v) return 0;
    }
    return hex[len * 2] == '\0';
}

static void seed_0_to_31(uint8_t seed[32])
{
    int i;
    for (i = 0; i < 32; i++) seed[i] = (uint8_t)i;
}

void run_drbg_tests(void)
{
    uint8_t seed[32];
    uint8_t out[64], out2[64];
    amisnap_drbg_state st, st2;

    /* --- Known-answer (Python HMAC-DRBG-SHA256 oracle, seed = 00 01 .. 1f) --- */
    seed_0_to_31(seed);
    amisnap_drbg_init(&st, seed, sizeof seed);
    amisnap_drbg_generate(&st, out, 64);
    TEST_CHECK(hex_eq(out, 64,
        "3226437dd9f98b17591aad731383303213439f64d029a5764e84e36256ddeb7"
        "9e2d0f9bbbac0520ef7319ac9509d6e04759f5c7bb2324f9c0c61e4869cd2f2a8"));

    /* Second draw: state has advanced, so a different block. */
    amisnap_drbg_generate(&st, out, 16);
    TEST_CHECK(hex_eq(out, 16, "8bec53ca34d241938d1dc9ae54c03b1f"));

    /* --- Determinism: same seed -> same stream. --- */
    seed_0_to_31(seed);
    amisnap_drbg_init(&st, seed, sizeof seed);
    amisnap_drbg_generate(&st, out, 64);
    amisnap_drbg_init(&st2, seed, sizeof seed);
    amisnap_drbg_generate(&st2, out2, 64);
    TEST_CHECK(memcmp(out, out2, 64) == 0);

    /* --- Seed independence: a different seed -> a different, known stream. --- */
    amisnap_drbg_init(&st2, (const uint8_t *)"amisnap", 7);
    amisnap_drbg_generate(&st2, out2, 8);
    TEST_CHECK(hex_eq(out2, 8, "699dd5f63d36ee99"));
    TEST_CHECK(memcmp(out, out2, 8) != 0);         /* differs from the 0..1f stream */

    /* --- Reseed changes the stream. --- */
    seed_0_to_31(seed);
    amisnap_drbg_init(&st, seed, sizeof seed);
    amisnap_drbg_reseed(&st, (const uint8_t *)"\xaa\xbb\xcc\xdd", 4);
    amisnap_drbg_generate(&st, out2, 64);
    TEST_CHECK(memcmp(out, out2, 64) != 0);

    /* --- Distribution sanity: a large draw is non-degenerate. --- */
    {
        static uint8_t big[4096];
        int seen[256];
        int i, distinct = 0, nonzero = 0;
        memset(seen, 0, sizeof seen);
        seed_0_to_31(seed);
        amisnap_drbg_init(&st, seed, sizeof seed);
        amisnap_drbg_generate(&st, big, sizeof big);
        for (i = 0; i < (int)sizeof big; i++) {
            if (!seen[big[i]]) { seen[big[i]] = 1; distinct++; }
            if (big[i]) nonzero++;
        }
        TEST_CHECK(distinct == 256);               /* every byte value appears */
        TEST_CHECK(nonzero > 4000);                /* not a run of zeros */
    }
}
