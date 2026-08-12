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
