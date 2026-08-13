/* hmac_sha256.c -- HMAC-SHA256 (RFC 2104), vendored from sibling
 * AmiAuth v1.0's src/core/hmac.c (see hmac_sha256.h for why only the
 * SHA-256 variant is carried over). Validated against RFC 4231 vectors
 * in tests/test_hmac_sha256.c.
 */
#include <string.h>

#include "hmac_sha256.h"

void amisnap_hmac_sha256_init(amisnap_hmac_sha256_ctx *ctx, const uint8_t *key, size_t keylen)
{
    uint8_t k[AMISNAP_SHA256_BLOCK_SIZE];
    uint8_t ipad[AMISNAP_SHA256_BLOCK_SIZE];
    size_t i;

    if (!ctx) return;

    /* K' = key, zero-padded to the block size; keys longer than a block are
     * first hashed down. */
    memset(k, 0, sizeof(k));
    if (keylen > AMISNAP_SHA256_BLOCK_SIZE) {
        amisnap_sha256(key, keylen, k);
    } else if (keylen) {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < AMISNAP_SHA256_BLOCK_SIZE; i++) {
        ipad[i]      = k[i] ^ 0x36;
        ctx->opad[i] = k[i] ^ 0x5c;
    }

    amisnap_sha256_init(&ctx->inner);
    amisnap_sha256_update(&ctx->inner, ipad, AMISNAP_SHA256_BLOCK_SIZE);

    memset(k, 0, sizeof(k));
    memset(ipad, 0, sizeof(ipad));
}

void amisnap_hmac_sha256_update(amisnap_hmac_sha256_ctx *ctx, const void *data, size_t len)
{
    if (!ctx) return;
    amisnap_sha256_update(&ctx->inner, data, len);
}

void amisnap_hmac_sha256_final(amisnap_hmac_sha256_ctx *ctx, uint8_t out[AMISNAP_SHA256_DIGEST_SIZE])
{
    uint8_t inner[AMISNAP_SHA256_DIGEST_SIZE];
    amisnap_sha256_ctx outer;

    if (!ctx || !out) return;

    amisnap_sha256_final(&ctx->inner, inner);          /* SHA256((K'^ipad) || msg) */
    amisnap_sha256_init(&outer);
    amisnap_sha256_update(&outer, ctx->opad, AMISNAP_SHA256_BLOCK_SIZE);
    amisnap_sha256_update(&outer, inner, AMISNAP_SHA256_DIGEST_SIZE);
    amisnap_sha256_final(&outer, out);                 /* SHA256((K'^opad) || inner) */

    /* opad is K'^0x5c -- trivially invertible to the key -- and this runs on
     * machines with no memory protection: scrub everything. A finalised ctx
     * is dead; every caller re-inits before reuse. */
    memset(inner, 0, sizeof(inner));
    memset(&outer, 0, sizeof(outer));
    memset(ctx, 0, sizeof(*ctx));
}

void amisnap_hmac_sha256(const uint8_t *key, size_t keylen,
                          const uint8_t *msg, size_t msglen,
                          uint8_t out[AMISNAP_SHA256_DIGEST_SIZE])
{
    amisnap_hmac_sha256_ctx ctx;
    amisnap_hmac_sha256_init(&ctx, key, keylen);
    amisnap_hmac_sha256_update(&ctx, msg, msglen);
    amisnap_hmac_sha256_final(&ctx, out);
}
