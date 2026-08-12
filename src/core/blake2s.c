/* blake2s.c -- portable BLAKE2s (RFC 7693), implemented from the RFC's
 * own pseudocode (section 3: G, F/compress, and the parameter-block
 * layout in section 2.5). Little-endian byte packing throughout, correct
 * on both the big-endian 68k target and little-endian CI hosts. Verified
 * against Python's hashlib.blake2s (itself the reference libb2/RFC
 * implementation) in tests/test_blake2s.c -- vectors computed there, not
 * transcribed from memory.
 */
#include <string.h>

#include "blake2s.h"

static const uint32_t IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const uint8_t SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define G(r, i, a, b, c, d)                                            \
    do {                                                               \
        a = a + b + m[SIGMA[r][2 * i + 0]];                            \
        d = rotr32(d ^ a, 16);                                         \
        c = c + d;                                                     \
        b = rotr32(b ^ c, 12);                                         \
        a = a + b + m[SIGMA[r][2 * i + 1]];                            \
        d = rotr32(d ^ a, 8);                                          \
        c = c + d;                                                     \
        b = rotr32(b ^ c, 7);                                          \
    } while (0)

/* Compresses one 64-byte block. `last` is nonzero for the final block. */
static void compress(amisnap_blake2s_ctx *ctx, const uint8_t block[AMISNAP_BLAKE2S_BLOCKBYTES])
{
    uint32_t m[16];
    uint32_t v[16];
    int i, r;

    for (i = 0; i < 16; i++)
        m[i] = load_le32(block + i * 4);

    for (i = 0; i < 8; i++)
        v[i] = ctx->h[i];
    for (i = 0; i < 8; i++)
        v[8 + i] = IV[i];

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0];
    v[15] ^= ctx->f[1];

    for (r = 0; r < 10; r++) {
        G(r, 0, v[0], v[4], v[ 8], v[12]);
        G(r, 1, v[1], v[5], v[ 9], v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[ 8], v[13]);
        G(r, 7, v[3], v[4], v[ 9], v[14]);
    }

    for (i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void increment_counter(amisnap_blake2s_ctx *ctx, uint32_t inc)
{
    ctx->t[0] += inc;
    if (ctx->t[0] < inc)
        ctx->t[1]++;
}

static int init_common(amisnap_blake2s_ctx *ctx, size_t outlen, size_t keylen)
{
    uint8_t param[32];
    int i;

    if (outlen == 0 || outlen > AMISNAP_BLAKE2S_OUTBYTES)
        return -1;
    if (keylen > AMISNAP_BLAKE2S_KEYBYTES)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->outlen = outlen;

    /* Parameter block (RFC 7693 section 2.5), all defaults (fanout=1,
     * depth=1, everything else zero) except digest_length and key_length. */
    memset(param, 0, sizeof(param));
    param[0] = (uint8_t)outlen;       /* digest_length */
    param[1] = (uint8_t)keylen;       /* key_length */
    param[2] = 1;                     /* fanout */
    param[3] = 1;                     /* depth */

    for (i = 0; i < 8; i++)
        ctx->h[i] = IV[i] ^ load_le32(param + i * 4);

    return 0;
}

int amisnap_blake2s_init(amisnap_blake2s_ctx *ctx, size_t outlen)
{
    return init_common(ctx, outlen, 0);
}

int amisnap_blake2s_init_key(amisnap_blake2s_ctx *ctx, size_t outlen,
                              const void *key, size_t keylen)
{
    uint8_t block[AMISNAP_BLAKE2S_BLOCKBYTES];

    if (keylen > AMISNAP_BLAKE2S_KEYBYTES)
        return -1;
    if (init_common(ctx, outlen, keylen) != 0)
        return -1;

    if (keylen > 0) {
        memset(block, 0, sizeof(block));
        memcpy(block, key, keylen);
        amisnap_blake2s_update(ctx, block, sizeof(block));
    }
    return 0;
}

void amisnap_blake2s_update(amisnap_blake2s_ctx *ctx, const void *in, size_t inlen)
{
    const uint8_t *p = (const uint8_t *)in;

    while (inlen > 0) {
        size_t left = AMISNAP_BLAKE2S_BLOCKBYTES - ctx->buflen;
        size_t take = inlen < left ? inlen : left;

        memcpy(ctx->buf + ctx->buflen, p, take);
        ctx->buflen += take;
        p += take;
        inlen -= take;

        /* Only compress a full buffered block once we know more data
         * follows -- the very last block must go through final() with
         * f[0] set, never here, even if it lands exactly on 64 bytes. */
        if (ctx->buflen == AMISNAP_BLAKE2S_BLOCKBYTES && inlen > 0) {
            increment_counter(ctx, AMISNAP_BLAKE2S_BLOCKBYTES);
            compress(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void amisnap_blake2s_final(amisnap_blake2s_ctx *ctx, void *out)
{
    uint8_t hash[32];
    size_t i;

    increment_counter(ctx, (uint32_t)ctx->buflen);
    ctx->f[0] = 0xFFFFFFFFu;

    memset(ctx->buf + ctx->buflen, 0, AMISNAP_BLAKE2S_BLOCKBYTES - ctx->buflen);
    compress(ctx, ctx->buf);

    for (i = 0; i < 8; i++)
        store_le32(hash + i * 4, ctx->h[i]);

    memcpy(out, hash, ctx->outlen);
}

void amisnap_blake2s256(const void *data, size_t len, uint8_t out[AMISNAP_BLAKE2S_OUTBYTES])
{
    amisnap_blake2s_ctx ctx;

    amisnap_blake2s_init(&ctx, AMISNAP_BLAKE2S_OUTBYTES);
    amisnap_blake2s_update(&ctx, data, len);
    amisnap_blake2s_final(&ctx, out);
}
