/* test_pbkdf2.c -- PBKDF2-HMAC-SHA256 vectors, independently computed
 * with Python's hashlib.pbkdf2_hmac('sha256', ...) and cross-checked
 * against `openssl kdf -kdfopt digest:SHA256 ... PBKDF2` before being
 * recorded here, per house rule (never transcribed from memory -- and
 * no RFC ships SHA-256 PBKDF2 vectors the way RFC 6070 does for SHA-1,
 * so this cross-implementation check stands in for a published vector
 * set). Same case shapes as sibling AmiAuth's tests/test_pbkdf2.c
 * (RFC 6070): c=1, c=2, the calibration-scale c=4096 case, a
 * multi-block dkLen, and embedded NUL bytes in password/salt. */
#include "test.h"
#include "pbkdf2.h"

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

void run_pbkdf2_tests(void)
{
    uint8_t dk[40];

    /* c = 1, dkLen = 32 */
    amisnap_pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                (const uint8_t *)"salt", 4, 1, dk, 32);
    TEST_CHECK(hex_eq(dk, 32,
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));

    /* c = 2, dkLen = 32 */
    amisnap_pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                (const uint8_t *)"salt", 4, 2, dk, 32);
    TEST_CHECK(hex_eq(dk, 32,
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"));

    /* c = 4096, dkLen = 32 (the calibration-scale case) */
    amisnap_pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                (const uint8_t *)"salt", 4, 4096, dk, 32);
    TEST_CHECK(hex_eq(dk, 32,
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));

    /* Longer inputs, dkLen = 40 -- spans two SHA-256 output blocks. */
    amisnap_pbkdf2_hmac_sha256((const uint8_t *)"passwordPASSWORDpassword", 24,
                                (const uint8_t *)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                                4096, dk, 40);
    TEST_CHECK(hex_eq(dk, 40,
        "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"));

    /* Embedded NUL bytes in password and salt (dkLen = 16). */
    amisnap_pbkdf2_hmac_sha256((const uint8_t *)"pass\0word", 9,
                                (const uint8_t *)"sa\0lt", 5, 4096, dk, 16);
    TEST_CHECK(hex_eq(dk, 16, "89b69d0516f829893c696226650a8687"));
}
