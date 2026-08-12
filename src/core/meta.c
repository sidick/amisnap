/* meta.c -- see meta.h. Field tags mirror docs/format.md's REC_ENTRY
 * table exactly; keep the two in sync when either changes. */
#include <string.h>

#include "meta.h"

#define TAG_E_PATH    0x8040u
#define TAG_E_TYPE    0x8041u
#define TAG_E_PROT    0x8042u
#define TAG_E_DATE    0x8043u
#define TAG_E_COMMENT 0x0044u
#define TAG_E_OWNER   0x0045u
#define TAG_E_SIZE    0x8046u
#define TAG_E_CONTENT 0x8047u
#define TAG_E_LINK    0x8048u
#define TAG_E_XHASH   0x0049u

int amisnap_meta_encode_entry(amisnap_buf *out, const amisnap_entry_meta *e)
{
    amisnap_buf body;
    uint8_t datebuf[12];
    uint8_t ownerbuf[4];
    int rc = AMISNAP_OK;
    size_t i;

    amisnap_buf_init(&body);

    if (e->path_len > 0xFFFFu) { rc = AMISNAP_ERR_TOO_LONG; goto done; }
    if (e->has_comment && e->comment_len > 0xFFFFu) { rc = AMISNAP_ERR_TOO_LONG; goto done; }
    if (e->has_link && e->link_len > 0xFFFFu) { rc = AMISNAP_ERR_TOO_LONG; goto done; }

    rc = amisnap_buf_field_string(&body, TAG_E_PATH, e->path, e->path_len);
    if (rc != AMISNAP_OK) goto done;

    rc = amisnap_buf_field_u8(&body, TAG_E_TYPE, e->type);
    if (rc != AMISNAP_OK) goto done;

    rc = amisnap_buf_field_u32(&body, TAG_E_PROT, e->prot);
    if (rc != AMISNAP_OK) goto done;

    amisnap_put_be32(datebuf, e->date_days);
    amisnap_put_be32(datebuf + 4, e->date_mins);
    amisnap_put_be32(datebuf + 8, e->date_ticks);
    rc = amisnap_buf_field(&body, TAG_E_DATE, datebuf, sizeof(datebuf));
    if (rc != AMISNAP_OK) goto done;

    if (e->has_comment) {
        rc = amisnap_buf_field_string(&body, TAG_E_COMMENT, e->comment, e->comment_len);
        if (rc != AMISNAP_OK) goto done;
    }

    if (e->has_owner) {
        amisnap_put_be16(ownerbuf, e->uid);
        amisnap_put_be16(ownerbuf + 2, e->gid);
        rc = amisnap_buf_field(&body, TAG_E_OWNER, ownerbuf, sizeof(ownerbuf));
        if (rc != AMISNAP_OK) goto done;
    }

    if (e->has_size) {
        rc = amisnap_buf_field_u64(&body, TAG_E_SIZE, e->size);
        if (rc != AMISNAP_OK) goto done;
    }

    for (i = 0; i < e->content_count; i++) {
        uint8_t refbuf[40];
        memcpy(refbuf, e->content[i].hash, 32);
        amisnap_put_be64(refbuf + 32, e->content[i].size);
        rc = amisnap_buf_field(&body, TAG_E_CONTENT, refbuf, sizeof(refbuf));
        if (rc != AMISNAP_OK) goto done;
    }

    if (e->has_link) {
        rc = amisnap_buf_field_string(&body, TAG_E_LINK, e->link, e->link_len);
        if (rc != AMISNAP_OK) goto done;
    }

    if (e->has_xhash) {
        rc = amisnap_buf_field_u32(&body, TAG_E_XHASH, e->xhash);
        if (rc != AMISNAP_OK) goto done;
    }

    rc = amisnap_buf_field(out, AMISNAP_REC_ENTRY_TAG, body.data, body.len);

done:
    amisnap_buf_free(&body);
    return rc;
}

int amisnap_meta_decode_entry(const uint8_t *value, size_t valuelen,
                               amisnap_entry_meta *out,
                               amisnap_content_ref *content_storage, size_t content_cap)
{
    amisnap_cursor c;
    uint16_t tag;
    const uint8_t *fval;
    size_t flen;
    int rc;
    int have_path = 0, have_type = 0, have_prot = 0, have_date = 0;

    memset(out, 0, sizeof(*out));
    out->content = content_storage;

    amisnap_cursor_init(&c, value, valuelen);

    while ((rc = amisnap_cursor_field(&c, &tag, &fval, &flen)) == 1) {
        switch (tag) {
        case TAG_E_PATH:
            rc = amisnap_decode_string(fval, flen, &out->path, &out->path_len);
            if (rc != AMISNAP_OK) return rc;
            have_path = 1;
            break;
        case TAG_E_TYPE:
            rc = amisnap_decode_u8(fval, flen, &out->type);
            if (rc != AMISNAP_OK) return rc;
            have_type = 1;
            break;
        case TAG_E_PROT:
            rc = amisnap_decode_u32(fval, flen, &out->prot);
            if (rc != AMISNAP_OK) return rc;
            have_prot = 1;
            break;
        case TAG_E_DATE:
            if (flen != 12) return AMISNAP_ERR_MALFORMED;
            out->date_days = amisnap_get_be32(fval);
            out->date_mins = amisnap_get_be32(fval + 4);
            out->date_ticks = amisnap_get_be32(fval + 8);
            have_date = 1;
            break;
        case TAG_E_COMMENT:
            rc = amisnap_decode_string(fval, flen, &out->comment, &out->comment_len);
            if (rc != AMISNAP_OK) return rc;
            out->has_comment = 1;
            break;
        case TAG_E_OWNER:
            if (flen != 4) return AMISNAP_ERR_MALFORMED;
            out->uid = amisnap_get_be16(fval);
            out->gid = amisnap_get_be16(fval + 2);
            out->has_owner = 1;
            break;
        case TAG_E_SIZE:
            rc = amisnap_decode_u64(fval, flen, &out->size);
            if (rc != AMISNAP_OK) return rc;
            out->has_size = 1;
            break;
        case TAG_E_CONTENT:
            if (flen != 40) return AMISNAP_ERR_MALFORMED;
            if (out->content_count >= content_cap) return AMISNAP_ERR_MALFORMED;
            memcpy(content_storage[out->content_count].hash, fval, 32);
            content_storage[out->content_count].size = amisnap_get_be64(fval + 32);
            out->content_count++;
            break;
        case TAG_E_LINK:
            rc = amisnap_decode_string(fval, flen, &out->link, &out->link_len);
            if (rc != AMISNAP_OK) return rc;
            out->has_link = 1;
            break;
        case TAG_E_XHASH:
            rc = amisnap_decode_u32(fval, flen, &out->xhash);
            if (rc != AMISNAP_OK) return rc;
            out->has_xhash = 1;
            break;
        default:
            if (tag & AMISNAP_TAG_CRITICAL)
                return AMISNAP_ERR_CRITICAL_TAG;
            /* unknown, non-critical: skip, per format.md "TLV encoding" */
            break;
        }
    }
    if (rc != 0) /* AMISNAP_ERR_TRUNCATED, propagated as-is */
        return rc;

    if (!have_path || !have_type || !have_prot || !have_date)
        return AMISNAP_ERR_MISSING_FIELD;

    if (out->type == AMISNAP_ETYPE_FILE) {
        if (!out->has_size)
            return AMISNAP_ERR_MISSING_FIELD;
        if (out->size > 0 && out->content_count == 0)
            return AMISNAP_ERR_MISSING_FIELD;
    } else if (out->type == AMISNAP_ETYPE_SOFTLINK || out->type == AMISNAP_ETYPE_HARDLINK) {
        if (!out->has_link)
            return AMISNAP_ERR_MISSING_FIELD;
    }

    return AMISNAP_OK;
}
