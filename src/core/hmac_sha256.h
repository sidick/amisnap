/* hmac_sha256.h -- HMAC-SHA256 (RFC 2104), vendored from sibling
 * AmiAuth v1.0's src/core/hmac.c (RFC-verified there against RFC 4231;
 * see CLAUDE.md "Crypto ... is vendored from sibling AmiAuth v1.0 ...
 * don't reimplement"). Only the SHA-256 variant is carried over --
 * AmiAuth's HMAC-SHA1/SHA512 forms have no AmiSnap use (the repository
 * KDF is PBKDF2-HMAC-SHA256 per docs/format.md, not SHA-1) and vendoring
 * the unused hash flavours would violate the CPU-budget "never
 * mandatory" rule for code nobody calls on a 68020.
 */
#ifndef AMISNAP_HMAC_SHA256_H
#define AMISNAP_HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

typedef struct {
    amisnap_sha256_ctx inner;
    uint8_t opad[AMISNAP_SHA256_BLOCK_SIZE];
} amisnap_hmac_sha256_ctx;

void amisnap_hmac_sha256_init(amisnap_hmac_sha256_ctx *ctx, const uint8_t *key, size_t keylen);
void amisnap_hmac_sha256_update(amisnap_hmac_sha256_ctx *ctx, const void *data, size_t len);
void amisnap_hmac_sha256_final(amisnap_hmac_sha256_ctx *ctx, uint8_t out[AMISNAP_SHA256_DIGEST_SIZE]);

/* One-shot convenience wrapper over the streaming API. */
void amisnap_hmac_sha256(const uint8_t *key, size_t keylen,
                          const uint8_t *msg, size_t msglen,
                          uint8_t out[AMISNAP_SHA256_DIGEST_SIZE]);

#endif /* AMISNAP_HMAC_SHA256_H */
