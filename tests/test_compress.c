/* test_compress.c -- the OBJCOMP=1 object frame (compress.h,
 * docs/format.md "Content objects").
 *
 * The interop vectors below were produced by reference implementations
 * outside this codebase, per the repo rule (verify against a real
 * reference, never transcribe from memory): the LZ4 block stream by
 * python-lz4 4.4.5 (lz4.block.compress(msg, store_size=False), lz4
 * library 1.9.4) and the zlib stream by CPython's zlib
 * (zlib.compress(msg, 6), zlib 1.2.12) -- both decoding here proves
 * the vendored decoders read what standard tooling writes. The reverse
 * direction (standard tooling reading what AmiSnap writes) is asserted
 * by the Python reference-reader cross-check, not here. */
#include <stdlib.h>
#include <string.h>

#include "compress.h"
#include "test.h"

static const char MSG[] =
    "the quick brown fox jumps over the lazy dog, "
    "the quick brown fox jumps again";
#define MSG_LEN (sizeof MSG - 1) /* 76 */

/* lz4.block.compress(MSG, store_size=False), python-lz4 4.4.5 */
static const uint8_t LZ4_REF[] = {
    0xf0, 0x10, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b,
    0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20,
    0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20,
    0x1f, 0x00, 0x91, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67,
    0x2c, 0x0e, 0x00, 0x0f, 0x2d, 0x00, 0x03, 0x50, 0x61, 0x67, 0x61,
    0x69, 0x6e
};

/* zlib.compress(MSG, 6), CPython / zlib 1.2.12 */
static const uint8_t ZLIB_REF[] = {
    0x78, 0x9c, 0x2b, 0xc9, 0x48, 0x55, 0x28, 0x2c, 0xcd, 0x4c, 0xce,
    0x56, 0x48, 0x2a, 0xca, 0x2f, 0xcf, 0x53, 0x48, 0xcb, 0xaf, 0x50,
    0xc8, 0x2a, 0xcd, 0x2d, 0x28, 0x56, 0xc8, 0x2f, 0x4b, 0x2d, 0x52,
    0x28, 0x01, 0x4a, 0xe7, 0x24, 0x56, 0x55, 0x2a, 0xa4, 0xe4, 0xa7,
    0xeb, 0x80, 0x79, 0xd8, 0x15, 0x27, 0xa6, 0x27, 0x66, 0xe6, 0x01,
    0x00, 0x33, 0xec, 0x1b, 0xe8
};

/* Hand-assemble a frame around a reference payload. */
static void build_frame(amisnap_buf *f, uint8_t alg, uint64_t usize,
                        const uint8_t *payload, size_t paylen)
{
    uint8_t hdr[AMISNAP_FRAME_HDR_SIZE];

    amisnap_buf_init(f);
    hdr[0] = alg;
    amisnap_put_be64(hdr + 1, usize);
    TEST_CHECK(amisnap_buf_bytes(f, hdr, sizeof hdr) == AMISNAP_OK);
    TEST_CHECK(amisnap_buf_bytes(f, payload, paylen) == AMISNAP_OK);
}

static void decode_reference_streams(void)
{
    amisnap_buf f, out;

    build_frame(&f, AMISNAP_COMP_LZ4, MSG_LEN, LZ4_REF, sizeof LZ4_REF);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out) == AMISNAP_OK);
    TEST_CHECK(out.len == MSG_LEN && memcmp(out.data, MSG, MSG_LEN) == 0);
    amisnap_buf_free(&out);
    amisnap_buf_free(&f);

    build_frame(&f, AMISNAP_COMP_ZLIB, MSG_LEN, ZLIB_REF, sizeof ZLIB_REF);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out) == AMISNAP_OK);
    TEST_CHECK(out.len == MSG_LEN && memcmp(out.data, MSG, MSG_LEN) == 0);
    amisnap_buf_free(&out);
    amisnap_buf_free(&f);
}

static void round_trip(uint8_t alg, const uint8_t *data, size_t len,
                       uint8_t expect_alg)
{
    amisnap_buf f, out;

    TEST_CHECK(amisnap_frame_encode(alg, data, len, &f) == AMISNAP_OK);
    TEST_CHECK(f.len >= AMISNAP_FRAME_HDR_SIZE);
    TEST_CHECK(f.data[0] == expect_alg);
    TEST_CHECK(amisnap_get_be64(f.data + 1) == (uint64_t)len);
    /* the whole point of the fallback: a frame is never larger than
     * stored-plus-header */
    TEST_CHECK(f.len <= AMISNAP_FRAME_HDR_SIZE + len);

    TEST_CHECK(amisnap_frame_decode(f.data, f.len, (uint64_t)len, &out) == AMISNAP_OK);
    TEST_CHECK(out.len == len && (len == 0 || memcmp(out.data, data, len) == 0));
    amisnap_buf_free(&out);
    amisnap_buf_free(&f);
}

static void round_trips(void)
{
    /* Deterministic pseudo-random bytes (xorshift32): incompressible,
     * so LZ4/ZLIB preference must fall back to STORED. */
    uint8_t noise[4096];
    uint8_t runs[100000];
    uint32_t x = 0x12345678u;
    size_t i;

    for (i = 0; i < sizeof noise; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        noise[i] = (uint8_t)x;
    }
    /* Highly compressible: long runs with a slow drift. */
    for (i = 0; i < sizeof runs; i++)
        runs[i] = (uint8_t)(i >> 10);

    round_trip(AMISNAP_COMP_STORED, (const uint8_t *)MSG, MSG_LEN, AMISNAP_COMP_STORED);
    round_trip(AMISNAP_COMP_LZ4, (const uint8_t *)MSG, MSG_LEN, AMISNAP_COMP_LZ4);
    round_trip(AMISNAP_COMP_ZLIB, (const uint8_t *)MSG, MSG_LEN, AMISNAP_COMP_ZLIB);

    round_trip(AMISNAP_COMP_LZ4, runs, sizeof runs, AMISNAP_COMP_LZ4);
    round_trip(AMISNAP_COMP_ZLIB, runs, sizeof runs, AMISNAP_COMP_ZLIB);

    /* Incompressible input: preference falls back to STORED. */
    round_trip(AMISNAP_COMP_LZ4, noise, sizeof noise, AMISNAP_COMP_STORED);
    round_trip(AMISNAP_COMP_ZLIB, noise, sizeof noise, AMISNAP_COMP_STORED);

    /* Empty input never dispatches a compressor. */
    round_trip(AMISNAP_COMP_LZ4, noise, 0, AMISNAP_COMP_STORED);
    round_trip(AMISNAP_COMP_ZLIB, noise, 0, AMISNAP_COMP_STORED);
}

static void error_cases(void)
{
    amisnap_buf f, out;

    /* Unknown preference refused at encode time. */
    TEST_CHECK(amisnap_frame_encode(0x7f, (const uint8_t *)MSG, MSG_LEN, &f)
               == AMISNAP_ERR_MALFORMED);

    /* Unknown alg in a frame: refuse-loudly class. */
    build_frame(&f, 0x7f, MSG_LEN, (const uint8_t *)MSG, MSG_LEN);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out)
               == AMISNAP_ERR_CRITICAL_TAG);
    amisnap_buf_free(&f);

    /* usize disagreeing with the manifest's expected size. */
    build_frame(&f, AMISNAP_COMP_STORED, MSG_LEN + 1, (const uint8_t *)MSG, MSG_LEN);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out)
               == AMISNAP_ERR_MALFORMED);
    amisnap_buf_free(&f);

    /* Stored payload shorter than usize claims. */
    build_frame(&f, AMISNAP_COMP_STORED, MSG_LEN, (const uint8_t *)MSG, MSG_LEN - 1);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out)
               == AMISNAP_ERR_MALFORMED);
    amisnap_buf_free(&f);

    /* Truncated: shorter than the header itself. */
    TEST_CHECK(amisnap_frame_decode((const uint8_t *)"\x01", 1, 0, &out)
               == AMISNAP_ERR_MALFORMED);

    /* Corrupt compressed payload must not decode. */
    build_frame(&f, AMISNAP_COMP_LZ4, MSG_LEN, ZLIB_REF, sizeof ZLIB_REF);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out)
               == AMISNAP_ERR_MALFORMED);
    amisnap_buf_free(&f);
    build_frame(&f, AMISNAP_COMP_ZLIB, MSG_LEN, LZ4_REF, sizeof LZ4_REF);
    TEST_CHECK(amisnap_frame_decode(f.data, f.len, MSG_LEN, &out)
               == AMISNAP_ERR_MALFORMED);
    amisnap_buf_free(&f);
}

void run_compress_tests(void)
{
    decode_reference_streams();
    round_trips();
    error_cases();
}
