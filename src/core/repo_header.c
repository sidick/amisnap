/* repo_header.c -- see repo_header.h. Tags mirror docs/format.md's
 * "Repository header" section exactly; keep the two in sync when
 * either changes (same rule manifest.c's own header states).
 */
#include <string.h>

#include "repo_header.h"

#define REC_REPO_TAG     0x8001u

#define TAG_REPO_ID      0x8010u
#define TAG_CIPHER       0x8011u
#define TAG_CHUNK_SIZE   0x0012u
#define TAG_KDF          0x8013u
#define TAG_WRAPPED_KEY  0x8014u
#define TAG_FORMAT_APP   0x0015u
#define TAG_OBJCOMP      0x8016u
#define TAG_COMP_PREF    0x0017u

int amisnap_repo_header_encode(const amisnap_repo_header *hdr, amisnap_buf *out)
{
    amisnap_buf body;
    int rc;

    if (hdr->cipher == 0) {
        if (hdr->salt || hdr->wrapped_key)
            return AMISNAP_ERR_MALFORMED;
    } else {
        if (!hdr->salt || !hdr->wrapped_key)
            return AMISNAP_ERR_MALFORMED;
        if (hdr->salt_len > 0xFFFFu)
            return AMISNAP_ERR_TOO_LONG;
    }
    if (hdr->has_format_app && hdr->format_app_len > 0xFFFFu)
        return AMISNAP_ERR_TOO_LONG;
    if (hdr->objcomp != AMISNAP_OBJCOMP_RAW &&
        hdr->objcomp != AMISNAP_OBJCOMP_FRAMED)
        return AMISNAP_ERR_MALFORMED;

    amisnap_buf_init(&body);

    rc = amisnap_buf_field(&body, TAG_REPO_ID, hdr->repo_id, AMISNAP_REPO_ID_SIZE);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field_u8(&body, TAG_CIPHER, hdr->cipher);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field_u8(&body, TAG_OBJCOMP, hdr->objcomp);
    if (rc == AMISNAP_OK && hdr->has_comp_pref)
        rc = amisnap_buf_field_u8(&body, TAG_COMP_PREF, hdr->comp_pref);
    if (rc == AMISNAP_OK && hdr->has_chunk_size)
        rc = amisnap_buf_field_u32(&body, TAG_CHUNK_SIZE, hdr->chunk_size);

    if (rc == AMISNAP_OK && hdr->cipher != 0) {
        amisnap_buf kdfbuf;
        uint8_t itersbuf[4], saltlenbuf[2];

        amisnap_buf_init(&kdfbuf);
        rc = amisnap_buf_bytes(&kdfbuf, &hdr->kdf_id, 1);
        if (rc == AMISNAP_OK) {
            amisnap_put_be32(itersbuf, hdr->kdf_iters);
            rc = amisnap_buf_bytes(&kdfbuf, itersbuf, sizeof(itersbuf));
        }
        if (rc == AMISNAP_OK) {
            amisnap_put_be16(saltlenbuf, (uint16_t)hdr->salt_len);
            rc = amisnap_buf_bytes(&kdfbuf, saltlenbuf, sizeof(saltlenbuf));
        }
        if (rc == AMISNAP_OK)
            rc = amisnap_buf_bytes(&kdfbuf, hdr->salt, hdr->salt_len);
        if (rc == AMISNAP_OK)
            rc = amisnap_buf_field(&body, TAG_KDF, kdfbuf.data, kdfbuf.len);
        amisnap_buf_free(&kdfbuf);

        if (rc == AMISNAP_OK)
            rc = amisnap_buf_field(&body, TAG_WRAPPED_KEY, hdr->wrapped_key,
                                    AMISNAP_WRAPPED_KEY_SIZE);
    }

    if (rc == AMISNAP_OK && hdr->has_format_app)
        rc = amisnap_buf_field_string(&body, TAG_FORMAT_APP,
                                       hdr->format_app, hdr->format_app_len);

    if (rc != AMISNAP_OK) { amisnap_buf_free(&body); return rc; }

    amisnap_buf_init(out);
    rc = amisnap_write_header(out, AMISNAP_FTYPE_REPO, 0);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field(out, REC_REPO_TAG, body.data, body.len);
    amisnap_buf_free(&body);
    if (rc != AMISNAP_OK) amisnap_buf_free(out);
    return rc;
}

static int decode_kdf(const uint8_t *val, size_t vlen, amisnap_repo_header *out)
{
    const uint8_t *p = val;
    size_t left = vlen;
    uint16_t saltlen;

    if (left < 1) return AMISNAP_ERR_MALFORMED;
    out->kdf_id = p[0];
    p += 1; left -= 1;

    if (left < 4) return AMISNAP_ERR_MALFORMED;
    out->kdf_iters = amisnap_get_be32(p);
    p += 4; left -= 4;

    if (left < 2) return AMISNAP_ERR_MALFORMED;
    saltlen = amisnap_get_be16(p);
    p += 2; left -= 2;

    if (left != saltlen) return AMISNAP_ERR_MALFORMED;
    out->salt = p;
    out->salt_len = saltlen;
    return AMISNAP_OK;
}

int amisnap_repo_header_decode(const uint8_t *data, size_t len, amisnap_repo_header *out)
{
    size_t body_start;
    uint16_t hdr_flags;
    amisnap_cursor c;
    amisnap_cursor rc_cursor;
    uint16_t rec_tag;
    const uint8_t *rec_val;
    size_t rec_vlen;
    int rc;
    int have_id = 0, have_cipher = 0, have_kdf = 0, have_wrapped = 0;

    memset(out, 0, sizeof(*out));

    rc = amisnap_read_header(data, len, AMISNAP_FTYPE_REPO, &hdr_flags, &body_start);
    if (rc != AMISNAP_OK) return rc;

    amisnap_cursor_init(&c, data + body_start, len - body_start);

    rc = amisnap_cursor_field(&c, &rec_tag, &rec_val, &rec_vlen);
    if (rc == 0) return AMISNAP_ERR_MISSING_FIELD;
    if (rc < 0) return rc;
    if (rec_tag != REC_REPO_TAG) return AMISNAP_ERR_MISSING_FIELD;

    amisnap_cursor_init(&rc_cursor, rec_val, rec_vlen);

    /* REC_REPO is the only top-level record this file has (format.md
     * "Repository header": "exactly one") -- nothing may follow it. */
    {
        uint16_t extra_tag;
        const uint8_t *extra_val;
        size_t extra_vlen;
        int r = amisnap_cursor_field(&c, &extra_tag, &extra_val, &extra_vlen);
        if (r != 0) return r < 0 ? r : AMISNAP_ERR_MALFORMED;
    }
    for (;;) {
        uint16_t tag;
        const uint8_t *val;
        size_t vlen;
        int r = amisnap_cursor_field(&rc_cursor, &tag, &val, &vlen);

        if (r == 0) break;
        if (r < 0) return r;

        switch (tag) {
        case TAG_REPO_ID:
            if (vlen != AMISNAP_REPO_ID_SIZE) return AMISNAP_ERR_MALFORMED;
            memcpy(out->repo_id, val, AMISNAP_REPO_ID_SIZE);
            have_id = 1;
            break;
        case TAG_CIPHER:
            rc = amisnap_decode_u8(val, vlen, &out->cipher);
            if (rc != AMISNAP_OK) return rc;
            if (out->cipher != 0 && out->cipher != 1) return AMISNAP_ERR_CRITICAL_TAG;
            have_cipher = 1;
            break;
        case TAG_OBJCOMP:
            rc = amisnap_decode_u8(val, vlen, &out->objcomp);
            if (rc != AMISNAP_OK) return rc;
            if (out->objcomp != AMISNAP_OBJCOMP_RAW &&
                out->objcomp != AMISNAP_OBJCOMP_FRAMED)
                return AMISNAP_ERR_CRITICAL_TAG;
            break;
        case TAG_COMP_PREF:
            rc = amisnap_decode_u8(val, vlen, &out->comp_pref);
            if (rc != AMISNAP_OK) return rc;
            out->has_comp_pref = 1;
            break;
        case TAG_CHUNK_SIZE:
            rc = amisnap_decode_u32(val, vlen, &out->chunk_size);
            if (rc != AMISNAP_OK) return rc;
            out->has_chunk_size = 1;
            break;
        case TAG_KDF:
            rc = decode_kdf(val, vlen, out);
            if (rc != AMISNAP_OK) return rc;
            have_kdf = 1;
            break;
        case TAG_WRAPPED_KEY:
            if (vlen != AMISNAP_WRAPPED_KEY_SIZE) return AMISNAP_ERR_MALFORMED;
            out->wrapped_key = val;
            have_wrapped = 1;
            break;
        case TAG_FORMAT_APP: {
            const uint8_t *str;
            size_t strlen_;
            rc = amisnap_decode_string(val, vlen, &str, &strlen_);
            if (rc != AMISNAP_OK) return rc;
            out->format_app = str;
            out->format_app_len = strlen_;
            out->has_format_app = 1;
            break;
        }
        default:
            if (tag & AMISNAP_TAG_CRITICAL) return AMISNAP_ERR_CRITICAL_TAG;
            break;
        }
    }

    if (!have_id || !have_cipher) return AMISNAP_ERR_MISSING_FIELD;
    if (out->cipher != 0 && (!have_kdf || !have_wrapped)) return AMISNAP_ERR_MISSING_FIELD;
    if (out->cipher == 0 && (have_kdf || have_wrapped)) return AMISNAP_ERR_MALFORMED;

    return AMISNAP_OK;
}
