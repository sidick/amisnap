/* blake2s.h -- BLAKE2s (RFC 7693), the integrity hash AmiSnap uses for
 * content addressing and manifest verification (docs/proposal.md "CPU
 * budget": computed once per new/changed file, never on every scan).
 *
 * Only BLAKE2s-256 (32-byte digest) ships as the convenience one-shot;
 * the streaming context and init_key() exist because the repository
 * format's phase-4 encrypted tier (docs/implementation-plan.md, "Phase
 * 4") authenticates ciphertext with a keyed BLAKE2s MAC, reusing this
 * same primitive rather than adding a second one.
 */
#ifndef AMISNAP_BLAKE2S_H
#define AMISNAP_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

#define AMISNAP_BLAKE2S_OUTBYTES 32
#define AMISNAP_BLAKE2S_BLOCKBYTES 64
#define AMISNAP_BLAKE2S_KEYBYTES 32

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[AMISNAP_BLAKE2S_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
} amisnap_blake2s_ctx;

/* outlen: 1..32. Returns 0 on success, -1 on a bad outlen. */
int amisnap_blake2s_init(amisnap_blake2s_ctx *ctx, size_t outlen);

/* Keyed hash (MAC mode): keylen must be 0..32. Returns 0 on success, -1
 * on a bad outlen/keylen. */
int amisnap_blake2s_init_key(amisnap_blake2s_ctx *ctx, size_t outlen,
                              const void *key, size_t keylen);

void amisnap_blake2s_update(amisnap_blake2s_ctx *ctx, const void *in, size_t inlen);

/* Writes ctx->outlen bytes to out. The context is consumed -- do not
 * update() or final() again without re-initializing. */
void amisnap_blake2s_final(amisnap_blake2s_ctx *ctx, void *out);

/* One-shot BLAKE2s-256 (unkeyed): out must hold 32 bytes. This is the
 * repository format's content-address hash. */
void amisnap_blake2s256(const void *data, size_t len, uint8_t out[AMISNAP_BLAKE2S_OUTBYTES]);

#endif /* AMISNAP_BLAKE2S_H */
