/* test_blake2s.c -- BLAKE2s-256 vectors, verified against Python's
 * hashlib.blake2s (the reference libb2/RFC 7693 implementation) before
 * being recorded here -- not transcribed from memory. Covers: empty
 * input, a partial block, a message crossing the 64-byte block boundary
 * (43 bytes: exercises final() padding on a non-block-aligned tail; 101
 * bytes: exercises one full compress() plus a second, partial one), both
 * unkeyed (amisnap_blake2s256) and keyed (init_key, exercising the
 * key-block prepend and non-zero key_length parameter byte) modes, and
 * a keyed message that itself is exactly one full block (65 bytes with
 * a 32-byte key block prepended -- boundary case for the streaming
 * update() path).
 */
#include <string.h>

#include "blake2s.h"
#include "test.h"

static int hex_eq32(const uint8_t *buf, const char *hex)
{
    static const char H[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < 32; i++) {
        if (hex[i * 2] != H[buf[i] >> 4] || hex[i * 2 + 1] != H[buf[i] & 0x0f])
            return 0;
    }
    return hex[64] == '\0';
}

void run_blake2s_tests(void)
{
    uint8_t out[32];
    uint8_t ramp101[101], ramp65[65], key32[32];
    size_t i;
    amisnap_blake2s_ctx ctx;

    for (i = 0; i < sizeof(ramp101); i++)
        ramp101[i] = (uint8_t)i;
    for (i = 0; i < sizeof(ramp65); i++)
        ramp65[i] = (uint8_t)i;
    for (i = 0; i < sizeof(key32); i++)
        key32[i] = (uint8_t)i;

    /* Unkeyed, one-shot convenience API. */
    amisnap_blake2s256("", 0, out);
    TEST_CHECK(hex_eq32(out, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"));

    amisnap_blake2s256("abc", 3, out);
    TEST_CHECK(hex_eq32(out, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));

    amisnap_blake2s256("The quick brown fox jumps over the lazy dog", 43, out);
    TEST_CHECK(hex_eq32(out, "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"));

    amisnap_blake2s256(ramp101, sizeof(ramp101), out);
    TEST_CHECK(hex_eq32(out, "e3e3c4aa3acbbc85332af9d564bc24165e1687f6b1adcbfae77a8f03c72ac28c"));

    /* Keyed (MAC mode), streaming API. */
    amisnap_blake2s_init_key(&ctx, 32, key32, 32);
    amisnap_blake2s_final(&ctx, out);
    TEST_CHECK(hex_eq32(out, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"));

    amisnap_blake2s_init_key(&ctx, 32, key32, 32);
    amisnap_blake2s_update(&ctx, "abc", 3);
    amisnap_blake2s_final(&ctx, out);
    TEST_CHECK(hex_eq32(out, "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65"));

    amisnap_blake2s_init_key(&ctx, 32, key32, 32);
    amisnap_blake2s_update(&ctx, ramp65, sizeof(ramp65));
    amisnap_blake2s_final(&ctx, out);
    TEST_CHECK(hex_eq32(out, "21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"));

    /* Streaming API must match the one-shot API for the same input,
     * fed in multiple update() calls to exercise buffering. */
    amisnap_blake2s_init(&ctx, 32);
    amisnap_blake2s_update(&ctx, ramp101, 50);
    amisnap_blake2s_update(&ctx, ramp101 + 50, sizeof(ramp101) - 50);
    amisnap_blake2s_final(&ctx, out);
    {
        uint8_t oneshot[32];
        amisnap_blake2s256(ramp101, sizeof(ramp101), oneshot);
        TEST_CHECK(memcmp(out, oneshot, 32) == 0);
    }

    /* Bad outlen/keylen are rejected, not silently clamped. */
    TEST_CHECK(amisnap_blake2s_init(&ctx, 0) != 0);
    TEST_CHECK(amisnap_blake2s_init(&ctx, 33) != 0);
    TEST_CHECK(amisnap_blake2s_init_key(&ctx, 32, key32, 33) != 0);
}
