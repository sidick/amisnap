/* xxhash32.c -- portable XXH32 (Yann Collet's xxHash, 32-bit variant),
 * implemented from the published specification
 * (https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md).
 * Byte-wise little-endian reads: correct on both the big-endian 68k
 * target and little-endian CI hosts, and the compiler folds them on
 * platforms where it matters. Verified against the reference vectors in
 * tests/test_xxhash32.c.
 */
#include "xxhash32.h"

#define PRIME1 2654435761u
#define PRIME2 2246822519u
#define PRIME3 3266489917u
#define PRIME4  668265263u
#define PRIME5  374761393u

static uint32_t rotl32(uint32_t x, unsigned r)
{
    return (x << r) | (x >> (32 - r));
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t round32(uint32_t acc, uint32_t lane)
{
    return rotl32(acc + lane * PRIME2, 13) * PRIME1;
}

uint32_t amisnap_xxh32(const void *data, size_t len, uint32_t seed)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *end = p + len;
    uint32_t h;

    if (len >= 16) {
        uint32_t acc1 = seed + PRIME1 + PRIME2;
        uint32_t acc2 = seed + PRIME2;
        uint32_t acc3 = seed;
        uint32_t acc4 = seed - PRIME1;
        const uint8_t *limit = end - 16;

        do {
            acc1 = round32(acc1, read_le32(p));
            acc2 = round32(acc2, read_le32(p + 4));
            acc3 = round32(acc3, read_le32(p + 8));
            acc4 = round32(acc4, read_le32(p + 12));
            p += 16;
        } while (p <= limit);

        h = rotl32(acc1, 1) + rotl32(acc2, 7) + rotl32(acc3, 12) + rotl32(acc4, 18);
    } else {
        h = seed + PRIME5;
    }

    h += (uint32_t)len;

    /* Guarded on len (not just relying on p==end already making both
     * loops no-ops): repo.c legitimately calls this with data=NULL,
     * len=0 for a zero-byte file (repo.h's own documented contract),
     * and merely computing `p + 4` against a NULL `p` inside the while
     * condition -- even though the loop would run zero iterations
     * anyway -- is undefined behaviour in C regardless of whether the
     * result is used. Found live via UBSan while adding the streaming
     * counterpart below, not something either of these one-shot loops
     * had ever been exercised under a sanitizer with a NULL input
     * before. */
    if (len > 0) {
        while (p + 4 <= end) {
            h = rotl32(h + read_le32(p) * PRIME3, 17) * PRIME4;
            p += 4;
        }
        while (p < end) {
            h = rotl32(h + (uint32_t)(*p) * PRIME5, 11) * PRIME1;
            p++;
        }
    }

    h ^= h >> 15;
    h *= PRIME2;
    h ^= h >> 13;
    h *= PRIME3;
    h ^= h >> 16;
    return h;
}

/* Streaming counterpart -- see xxhash32.h's own header comment for
 * why this exists and how it's verified (cross-checked against the
 * one-shot function above at many split points, not a second set of
 * external reference vectors). Same published spec, same round32/
 * rotl32/read_le32 helpers; the only real difference from the one-shot
 * function is carrying up to 15 leftover bytes (`buf`/`buf_len`)
 * across update() calls, since a chunk boundary can land anywhere. */

void amisnap_xxh32_init(amisnap_xxh32_state *s, uint32_t seed)
{
    s->seed = seed;
    s->acc1 = seed + PRIME1 + PRIME2;
    s->acc2 = seed + PRIME2;
    s->acc3 = seed;
    s->acc4 = seed - PRIME1;
    s->total_len = 0;
    s->buf_len = 0;
}

void amisnap_xxh32_update(amisnap_xxh32_state *s, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t i;

    s->total_len += len;

    if (s->buf_len + len < 16) {
        for (i = 0; i < len; i++) s->buf[s->buf_len + i] = p[i];
        s->buf_len += len;
        return;
    }

    if (s->buf_len > 0) {
        size_t fill = 16 - s->buf_len;
        for (i = 0; i < fill; i++) s->buf[s->buf_len + i] = p[i];
        s->acc1 = round32(s->acc1, read_le32(s->buf));
        s->acc2 = round32(s->acc2, read_le32(s->buf + 4));
        s->acc3 = round32(s->acc3, read_le32(s->buf + 8));
        s->acc4 = round32(s->acc4, read_le32(s->buf + 12));
        p += fill;
        len -= fill;
        s->buf_len = 0;
    }

    while (len >= 16) {
        s->acc1 = round32(s->acc1, read_le32(p));
        s->acc2 = round32(s->acc2, read_le32(p + 4));
        s->acc3 = round32(s->acc3, read_le32(p + 8));
        s->acc4 = round32(s->acc4, read_le32(p + 12));
        p += 16;
        len -= 16;
    }

    if (len > 0) {
        for (i = 0; i < len; i++) s->buf[i] = p[i];
        s->buf_len = len;
    }
}

uint32_t amisnap_xxh32_digest(const amisnap_xxh32_state *s)
{
    uint32_t h;
    const uint8_t *p = s->buf;
    const uint8_t *end = s->buf + s->buf_len;

    if (s->total_len >= 16) {
        h = rotl32(s->acc1, 1) + rotl32(s->acc2, 7) + rotl32(s->acc3, 12) + rotl32(s->acc4, 18);
    } else {
        h = s->seed + PRIME5;
    }

    h += (uint32_t)s->total_len;

    while (p + 4 <= end) {
        h = rotl32(h + read_le32(p) * PRIME3, 17) * PRIME4;
        p += 4;
    }
    while (p < end) {
        h = rotl32(h + (uint32_t)(*p) * PRIME5, 11) * PRIME1;
        p++;
    }

    h ^= h >> 15;
    h *= PRIME2;
    h ^= h >> 13;
    h *= PRIME3;
    h ^= h >> 16;
    return h;
}
