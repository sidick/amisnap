/* sha256.h -- SHA-256 (FIPS 180-4), vendored from sibling AmiAuth v1.0
 * (src/core/sha256.c there; RFC-verified, OpenSSL-differential-fuzzed).
 * AmiSnap's only use is as HMAC-SHA256's inner hash for the phase-4
 * repository KDF (PBKDF2-HMAC-SHA256, docs/format.md "Encryption") --
 * content addressing stays BLAKE2s/xxHash32 per the CPU-budget rule.
 */
#ifndef AMISNAP_SHA256_H
#define AMISNAP_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define AMISNAP_SHA256_DIGEST_SIZE 32
#define AMISNAP_SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t count;               /* total bytes processed */
    uint8_t  buf[AMISNAP_SHA256_BLOCK_SIZE];
    size_t   buflen;              /* bytes currently in buf */
} amisnap_sha256_ctx;

void amisnap_sha256_init(amisnap_sha256_ctx *ctx);
void amisnap_sha256_update(amisnap_sha256_ctx *ctx, const void *data, size_t len);
void amisnap_sha256_final(amisnap_sha256_ctx *ctx, uint8_t out[AMISNAP_SHA256_DIGEST_SIZE]);

/* One-shot convenience wrapper. */
void amisnap_sha256(const void *data, size_t len, uint8_t out[AMISNAP_SHA256_DIGEST_SIZE]);

#endif /* AMISNAP_SHA256_H */
