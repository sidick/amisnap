/* compress.c -- OBJCOMP=1 object frame encode/decode (see compress.h
 * and docs/format.md "Content objects"). */
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "compress.h"
#include "lz4.h"
#include "miniz.h"

/* One deflate level for every zlib frame AmiSnap writes: miniz's
 * default (6), the ratio/CPU balance zlib itself defaults to. A user
 * who picked ZLIB over LZ4 chose ratio over CPU already; a per-run
 * level knob can be added later without any format impact (the frame
 * doesn't record the level -- no deflate decoder needs it). */
#define FRAME_ZLIB_LEVEL MZ_DEFAULT_LEVEL

static int frame_header(amisnap_buf *out, uint8_t alg, uint64_t usize)
{
    uint8_t hdr[AMISNAP_FRAME_HDR_SIZE];

    hdr[0] = alg;
    amisnap_put_be64(hdr + 1, usize);
    return amisnap_buf_bytes(out, hdr, sizeof hdr);
}

static int frame_stored(const uint8_t *data, size_t len, amisnap_buf *out)
{
    int rc = frame_header(out, AMISNAP_COMP_STORED, (uint64_t)len);

    if (rc != AMISNAP_OK)
        return rc;
    return amisnap_buf_bytes(out, data, len);
}

int amisnap_frame_encode(uint8_t alg, const uint8_t *data, size_t len,
                         amisnap_buf *out)
{
    uint8_t *tmp;
    size_t csize;
    int rc;

    amisnap_buf_init(out);

    switch (alg) {
    case AMISNAP_COMP_STORED:
        return frame_stored(data, len, out);

    case AMISNAP_COMP_LZ4: {
        int bound, written;

        if (len > (size_t)LZ4_MAX_INPUT_SIZE)
            return AMISNAP_ERR_TOO_LONG;
        if (len == 0)
            return frame_stored(data, len, out);
        bound = LZ4_compressBound((int)len);
        tmp = malloc((size_t)bound);
        if (tmp == NULL)
            return AMISNAP_ERR_NOMEM;
        written = LZ4_compress_default((const char *)data, (char *)tmp,
                                       (int)len, bound);
        if (written <= 0 || (size_t)written >= len) {
            free(tmp);
            return frame_stored(data, len, out);
        }
        csize = (size_t)written;
        break;
    }

    case AMISNAP_COMP_ZLIB: {
        mz_ulong bound, dlen;

        if ((mz_ulong)len != len)
            return AMISNAP_ERR_TOO_LONG;
        if (len == 0)
            return frame_stored(data, len, out);
        bound = mz_compressBound((mz_ulong)len);
        tmp = malloc((size_t)bound);
        if (tmp == NULL)
            return AMISNAP_ERR_NOMEM;
        dlen = bound;
        if (mz_compress2(tmp, &dlen, data, (mz_ulong)len,
                         FRAME_ZLIB_LEVEL) != MZ_OK ||
            (size_t)dlen >= len) {
            free(tmp);
            return frame_stored(data, len, out);
        }
        csize = (size_t)dlen;
        break;
    }

    default:
        return AMISNAP_ERR_MALFORMED;
    }

    rc = frame_header(out, alg, (uint64_t)len);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_bytes(out, tmp, csize);
    free(tmp);
    if (rc != AMISNAP_OK)
        amisnap_buf_free(out);
    return rc;
}

int amisnap_frame_decode(const uint8_t *data, size_t len,
                         uint64_t expected_usize, amisnap_buf *out)
{
    const uint8_t *payload;
    size_t paylen, usize;
    uint8_t alg;

    amisnap_buf_init(out);

    if (len < AMISNAP_FRAME_HDR_SIZE)
        return AMISNAP_ERR_MALFORMED;
    alg = data[0];
    if (amisnap_get_be64(data + 1) != expected_usize)
        return AMISNAP_ERR_MALFORMED;
    if ((uint64_t)(size_t)expected_usize != expected_usize)
        return AMISNAP_ERR_NOMEM; /* > SIZE_MAX: undecodable on this host */
    usize = (size_t)expected_usize;
    payload = data + AMISNAP_FRAME_HDR_SIZE;
    paylen = len - AMISNAP_FRAME_HDR_SIZE;

    switch (alg) {
    case AMISNAP_COMP_STORED:
        if (paylen != usize)
            return AMISNAP_ERR_MALFORMED;
        return amisnap_buf_bytes(out, payload, paylen);

    case AMISNAP_COMP_LZ4: {
        int decoded;

        if (paylen > (size_t)INT_MAX || usize > (size_t)INT_MAX)
            return AMISNAP_ERR_MALFORMED;
        out->data = malloc(usize ? usize : 1);
        if (out->data == NULL)
            return AMISNAP_ERR_NOMEM;
        out->cap = usize ? usize : 1;
        decoded = LZ4_decompress_safe((const char *)payload,
                                      (char *)out->data,
                                      (int)paylen, (int)usize);
        if (decoded < 0 || (size_t)decoded != usize) {
            amisnap_buf_free(out);
            return AMISNAP_ERR_MALFORMED;
        }
        out->len = usize;
        return AMISNAP_OK;
    }

    case AMISNAP_COMP_ZLIB: {
        mz_ulong dlen;

        if ((mz_ulong)usize != usize || (mz_ulong)paylen != paylen)
            return AMISNAP_ERR_MALFORMED;
        out->data = malloc(usize ? usize : 1);
        if (out->data == NULL)
            return AMISNAP_ERR_NOMEM;
        out->cap = usize ? usize : 1;
        dlen = (mz_ulong)usize;
        if (mz_uncompress(out->data, &dlen, payload,
                          (mz_ulong)paylen) != MZ_OK ||
            (size_t)dlen != usize) {
            amisnap_buf_free(out);
            return AMISNAP_ERR_MALFORMED;
        }
        out->len = usize;
        return AMISNAP_OK;
    }

    default:
        return AMISNAP_ERR_CRITICAL_TAG;
    }
}
