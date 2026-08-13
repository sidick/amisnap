/* pbkdf2.c -- PBKDF2-HMAC-SHA256 (RFC 2898 Sec 5.2). Adapted from
 * sibling AmiAuth v1.0's src/core/pbkdf2.c (see pbkdf2.h for why
 * SHA-256 here vs AmiAuth's SHA-1). Validated against RFC 6070-style
 * vectors, independently reproduced with Python's hashlib.pbkdf2_hmac,
 * in tests/test_pbkdf2.c.
 */
#include <string.h>

#include "pbkdf2.h"
#include "hmac_sha256.h"

/* One derived block: T_i = U_1 ^ U_2 ^ ... ^ U_c, where
 *   U_1 = HMAC(P, S || INT_BE32(i)),  U_n = HMAC(P, U_{n-1}). */
static void pbkdf2_block(const uint8_t *pass, size_t passlen,
                         const uint8_t *salt, size_t saltlen,
                         uint32_t iterations, uint32_t blockidx,
                         uint8_t out[AMISNAP_SHA256_DIGEST_SIZE])
{
    uint8_t idx[4];
    uint8_t u[AMISNAP_SHA256_DIGEST_SIZE];
    uint8_t t[AMISNAP_SHA256_DIGEST_SIZE];
    amisnap_hmac_sha256_ctx c;
    uint32_t n;
    int i;

    idx[0] = (uint8_t)(blockidx >> 24);
    idx[1] = (uint8_t)(blockidx >> 16);
    idx[2] = (uint8_t)(blockidx >>  8);
    idx[3] = (uint8_t)(blockidx);

    /* U_1 = HMAC(P, S || idx) -- streamed to avoid concatenating into a buffer. */
    amisnap_hmac_sha256_init(&c, pass, passlen);
    amisnap_hmac_sha256_update(&c, salt, saltlen);
    amisnap_hmac_sha256_update(&c, idx, sizeof(idx));
    amisnap_hmac_sha256_final(&c, u);
    memcpy(t, u, AMISNAP_SHA256_DIGEST_SIZE);

    for (n = 1; n < iterations; n++) {
        amisnap_hmac_sha256(pass, passlen, u, AMISNAP_SHA256_DIGEST_SIZE, u);
        for (i = 0; i < AMISNAP_SHA256_DIGEST_SIZE; i++) t[i] ^= u[i];
    }

    memcpy(out, t, AMISNAP_SHA256_DIGEST_SIZE);

    memset(idx, 0, sizeof(idx));
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    memset(&c, 0, sizeof(c));
}

void amisnap_pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen,
                                 const uint8_t *salt, size_t saltlen,
                                 uint32_t iterations,
                                 uint8_t *out, size_t outlen)
{
    uint8_t block[AMISNAP_SHA256_DIGEST_SIZE];
    uint32_t blockidx = 1;
    size_t got = 0;

    if (!out) return;
    if (iterations == 0) iterations = 1;

    while (got < outlen) {
        size_t n = outlen - got < AMISNAP_SHA256_DIGEST_SIZE
                 ? outlen - got : AMISNAP_SHA256_DIGEST_SIZE;
        pbkdf2_block(pass, passlen, salt, saltlen, iterations, blockidx, block);
        memcpy(out + got, block, n);
        got += n;
        blockidx++;
    }

    memset(block, 0, sizeof(block));
}
