/* test_hmac_sha256.c -- HMAC-SHA256 vectors (RFC 4231), the SHA-256
 * subset of sibling AmiAuth's tests/test_hmac.c. */
#include <string.h>

#include "test.h"
#include "hmac_sha256.h"

static int hex_eq32(const uint8_t *buf, const char *hex)
{
    size_t i;
    for (i = 0; i < AMISNAP_SHA256_DIGEST_SIZE; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return 0;
        if (buf[i] != (uint8_t)v) return 0;
    }
    return hex[AMISNAP_SHA256_DIGEST_SIZE * 2] == '\0';
}

void run_hmac_sha256_tests(void)
{
    uint8_t mac[AMISNAP_SHA256_DIGEST_SIZE];
    uint8_t key[131];
    uint8_t data[50];

    /* RFC 4231 case 1: key = 0x0b x20, data = "Hi There". */
    memset(key, 0x0b, 20);
    amisnap_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, mac);
    TEST_CHECK(hex_eq32(mac,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    /* RFC 4231 case 2: key = "Jefe" (shorter than block). */
    amisnap_hmac_sha256((const uint8_t *)"Jefe", 4,
                         (const uint8_t *)"what do ya want for nothing?", 28, mac);
    TEST_CHECK(hex_eq32(mac,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    /* RFC 4231 case 3: key = 0xaa x20, data = 0xdd x50. */
    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    amisnap_hmac_sha256(key, 20, data, 50, mac);
    TEST_CHECK(hex_eq32(mac,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));

    /* RFC 4231 case 6: key = 0xaa x131 (longer than the block size). */
    memset(key, 0xaa, 131);
    amisnap_hmac_sha256(key, 131,
                         (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First",
                         54, mac);
    TEST_CHECK(hex_eq32(mac,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

    /* Streaming update() matches the one-shot result. */
    {
        amisnap_hmac_sha256_ctx ctx;
        memset(key, 0x0b, 20);
        amisnap_hmac_sha256_init(&ctx, key, 20);
        amisnap_hmac_sha256_update(&ctx, "Hi ", 3);
        amisnap_hmac_sha256_update(&ctx, "There", 5);
        amisnap_hmac_sha256_final(&ctx, mac);
        TEST_CHECK(hex_eq32(mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }
}
