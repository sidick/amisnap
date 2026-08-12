/* manifest.c -- see manifest.h. Record/field tags mirror docs/format.md's
 * "Manifest" section exactly; keep the two in sync when either changes. */
#include <stdlib.h>
#include <string.h>

#include "blake2s.h"
#include "manifest.h"

#define REC_SNAP_TAG   0x8002u
#define REC_VOLUME_TAG 0x8003u
#define REC_END_TAG    0x8005u

#define TAG_CREATED    0x8020u
#define TAG_HOSTNAME   0x0021u
#define TAG_TOOLVER    0x0022u
#define TAG_SNAP_COMMENT 0x0023u

#define TAG_VOL_ROOT    0x8030u
#define TAG_VOL_NAME    0x0031u
#define TAG_VOL_DOSTYPE 0x0032u
#define TAG_VOL_CREATED 0x0033u
#define TAG_VOL_CAPS    0x0034u

#define TAG_END_COUNT 0x8050u
#define TAG_END_HASH  0x8051u

/* ---------------------------------------------------------------- writer */

void amisnap_manifest_writer_init(amisnap_manifest_writer *w)
{
    amisnap_buf_init(&w->body);
    w->entry_count = 0;
    w->have_snap = 0;
    w->error = AMISNAP_OK;
}

void amisnap_manifest_writer_free(amisnap_manifest_writer *w)
{
    amisnap_buf_free(&w->body);
}

static int encode_snap_body(amisnap_buf *body, const amisnap_snap_meta *snap)
{
    uint8_t datebuf[12];
    int rc;

    if ((snap->has_hostname && snap->hostname_len > 0xFFFFu) ||
        (snap->has_toolver && snap->toolver_len > 0xFFFFu) ||
        (snap->has_comment && snap->comment_len > 0xFFFFu))
        return AMISNAP_ERR_TOO_LONG;

    amisnap_put_be32(datebuf, snap->created_days);
    amisnap_put_be32(datebuf + 4, snap->created_mins);
    amisnap_put_be32(datebuf + 8, snap->created_ticks);
    rc = amisnap_buf_field(body, TAG_CREATED, datebuf, sizeof(datebuf));
    if (rc != AMISNAP_OK) return rc;

    if (snap->has_hostname) {
        rc = amisnap_buf_field_string(body, TAG_HOSTNAME, snap->hostname, snap->hostname_len);
        if (rc != AMISNAP_OK) return rc;
    }
    if (snap->has_toolver) {
        rc = amisnap_buf_field_string(body, TAG_TOOLVER, snap->toolver, snap->toolver_len);
        if (rc != AMISNAP_OK) return rc;
    }
    if (snap->has_comment) {
        rc = amisnap_buf_field_string(body, TAG_SNAP_COMMENT, snap->comment, snap->comment_len);
        if (rc != AMISNAP_OK) return rc;
    }
    return AMISNAP_OK;
}

int amisnap_manifest_writer_snap(amisnap_manifest_writer *w, const amisnap_snap_meta *snap)
{
    amisnap_buf body;
    int rc;

    if (w->error != AMISNAP_OK) return w->error;
    if (w->have_snap) { w->error = AMISNAP_ERR_MALFORMED; return w->error; }

    amisnap_buf_init(&body);
    rc = encode_snap_body(&body, snap);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field(&w->body, REC_SNAP_TAG, body.data, body.len);
    amisnap_buf_free(&body);

    if (rc != AMISNAP_OK) { w->error = rc; return rc; }
    w->have_snap = 1;
    return AMISNAP_OK;
}

static int encode_volume_body(amisnap_buf *body, const amisnap_volume_meta *vol)
{
    int rc;

    if (vol->vol_root_len > 0xFFFFu) return AMISNAP_ERR_TOO_LONG;
    if (vol->has_name && vol->name_len > 0xFFFFu) return AMISNAP_ERR_TOO_LONG;

    rc = amisnap_buf_field_string(body, TAG_VOL_ROOT, vol->vol_root, vol->vol_root_len);
    if (rc != AMISNAP_OK) return rc;

    if (vol->has_name) {
        rc = amisnap_buf_field_string(body, TAG_VOL_NAME, vol->name, vol->name_len);
        if (rc != AMISNAP_OK) return rc;
    }
    if (vol->has_dostype) {
        rc = amisnap_buf_field_u32(body, TAG_VOL_DOSTYPE, vol->dostype);
        if (rc != AMISNAP_OK) return rc;
    }
    if (vol->has_created) {
        uint8_t datebuf[12];
        amisnap_put_be32(datebuf, vol->created_days);
        amisnap_put_be32(datebuf + 4, vol->created_mins);
        amisnap_put_be32(datebuf + 8, vol->created_ticks);
        rc = amisnap_buf_field(body, TAG_VOL_CREATED, datebuf, sizeof(datebuf));
        if (rc != AMISNAP_OK) return rc;
    }
    if (vol->has_caps) {
        uint8_t capsbuf[4];
        amisnap_put_be16(capsbuf, vol->maxnamelen);
        amisnap_put_be16(capsbuf + 2, vol->caps_flags);
        rc = amisnap_buf_field(body, TAG_VOL_CAPS, capsbuf, sizeof(capsbuf));
        if (rc != AMISNAP_OK) return rc;
    }
    return AMISNAP_OK;
}

int amisnap_manifest_writer_volume(amisnap_manifest_writer *w, const amisnap_volume_meta *vol)
{
    amisnap_buf body;
    int rc;

    if (w->error != AMISNAP_OK) return w->error;
    if (!w->have_snap) { w->error = AMISNAP_ERR_MISSING_FIELD; return w->error; }

    amisnap_buf_init(&body);
    rc = encode_volume_body(&body, vol);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field(&w->body, REC_VOLUME_TAG, body.data, body.len);
    amisnap_buf_free(&body);

    if (rc != AMISNAP_OK) w->error = rc;
    return rc;
}

int amisnap_manifest_writer_entry(amisnap_manifest_writer *w, const amisnap_entry_meta *entry)
{
    int rc;

    if (w->error != AMISNAP_OK) return w->error;
    if (!w->have_snap) { w->error = AMISNAP_ERR_MISSING_FIELD; return w->error; }

    rc = amisnap_meta_encode_entry(&w->body, entry);
    if (rc != AMISNAP_OK) { w->error = rc; return rc; }

    w->entry_count++;
    return AMISNAP_OK;
}

int amisnap_manifest_writer_finish(amisnap_manifest_writer *w, amisnap_buf *out)
{
    uint8_t countbuf[4], hashbuf[32];
    amisnap_buf endbody;
    int rc;

    if (w->error != AMISNAP_OK) return w->error;
    if (!w->have_snap) return AMISNAP_ERR_MISSING_FIELD;

    amisnap_buf_init(out);
    rc = amisnap_write_header(out, AMISNAP_FTYPE_MANIFEST, 0);
    if (rc != AMISNAP_OK) return rc;
    rc = amisnap_buf_bytes(out, w->body.data, w->body.len);
    if (rc != AMISNAP_OK) return rc;

    /* Hash covers exactly [header .. body], everything written to
     * `out` so far -- REC_END hasn't been appended yet. */
    amisnap_blake2s256(out->data, out->len, hashbuf);
    amisnap_put_be32(countbuf, (uint32_t)w->entry_count);

    amisnap_buf_init(&endbody);
    rc = amisnap_buf_field(&endbody, TAG_END_COUNT, countbuf, sizeof(countbuf));
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field(&endbody, TAG_END_HASH, hashbuf, sizeof(hashbuf));
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field(out, REC_END_TAG, endbody.data, endbody.len);
    amisnap_buf_free(&endbody);

    return rc;
}

/* ---------------------------------------------------------------- reader */

static int decode_snap(const uint8_t *value, size_t valuelen, amisnap_snap_meta *out)
{
    amisnap_cursor c;
    uint16_t tag;
    const uint8_t *fval;
    size_t flen;
    int rc;
    int have_created = 0;

    memset(out, 0, sizeof(*out));
    amisnap_cursor_init(&c, value, valuelen);

    while ((rc = amisnap_cursor_field(&c, &tag, &fval, &flen)) == 1) {
        switch (tag) {
        case TAG_CREATED:
            if (flen != 12) return AMISNAP_ERR_MALFORMED;
            out->created_days = amisnap_get_be32(fval);
            out->created_mins = amisnap_get_be32(fval + 4);
            out->created_ticks = amisnap_get_be32(fval + 8);
            have_created = 1;
            break;
        case TAG_HOSTNAME:
            rc = amisnap_decode_string(fval, flen, &out->hostname, &out->hostname_len);
            if (rc != AMISNAP_OK) return rc;
            out->has_hostname = 1;
            break;
        case TAG_TOOLVER:
            rc = amisnap_decode_string(fval, flen, &out->toolver, &out->toolver_len);
            if (rc != AMISNAP_OK) return rc;
            out->has_toolver = 1;
            break;
        case TAG_SNAP_COMMENT:
            rc = amisnap_decode_string(fval, flen, &out->comment, &out->comment_len);
            if (rc != AMISNAP_OK) return rc;
            out->has_comment = 1;
            break;
        default:
            if (tag & AMISNAP_TAG_CRITICAL) return AMISNAP_ERR_CRITICAL_TAG;
            break;
        }
    }
    if (rc != 0) return rc;
    if (!have_created) return AMISNAP_ERR_MISSING_FIELD;
    return AMISNAP_OK;
}

static int decode_volume(const uint8_t *value, size_t valuelen, amisnap_volume_meta *out)
{
    amisnap_cursor c;
    uint16_t tag;
    const uint8_t *fval;
    size_t flen;
    int rc;
    int have_root = 0;

    memset(out, 0, sizeof(*out));
    amisnap_cursor_init(&c, value, valuelen);

    while ((rc = amisnap_cursor_field(&c, &tag, &fval, &flen)) == 1) {
        switch (tag) {
        case TAG_VOL_ROOT:
            rc = amisnap_decode_string(fval, flen, &out->vol_root, &out->vol_root_len);
            if (rc != AMISNAP_OK) return rc;
            have_root = 1;
            break;
        case TAG_VOL_NAME:
            rc = amisnap_decode_string(fval, flen, &out->name, &out->name_len);
            if (rc != AMISNAP_OK) return rc;
            out->has_name = 1;
            break;
        case TAG_VOL_DOSTYPE:
            rc = amisnap_decode_u32(fval, flen, &out->dostype);
            if (rc != AMISNAP_OK) return rc;
            out->has_dostype = 1;
            break;
        case TAG_VOL_CREATED:
            if (flen != 12) return AMISNAP_ERR_MALFORMED;
            out->created_days = amisnap_get_be32(fval);
            out->created_mins = amisnap_get_be32(fval + 4);
            out->created_ticks = amisnap_get_be32(fval + 8);
            out->has_created = 1;
            break;
        case TAG_VOL_CAPS:
            if (flen != 4) return AMISNAP_ERR_MALFORMED;
            out->maxnamelen = amisnap_get_be16(fval);
            out->caps_flags = amisnap_get_be16(fval + 2);
            out->has_caps = 1;
            break;
        default:
            if (tag & AMISNAP_TAG_CRITICAL) return AMISNAP_ERR_CRITICAL_TAG;
            break;
        }
    }
    if (rc != 0) return rc;
    if (!have_root) return AMISNAP_ERR_MISSING_FIELD;
    return AMISNAP_OK;
}

static int decode_end(const uint8_t *value, size_t valuelen, uint32_t *count, uint8_t hash[32])
{
    amisnap_cursor c;
    uint16_t tag;
    const uint8_t *fval;
    size_t flen;
    int rc;
    int have_count = 0, have_hash = 0;

    amisnap_cursor_init(&c, value, valuelen);

    while ((rc = amisnap_cursor_field(&c, &tag, &fval, &flen)) == 1) {
        if (tag == TAG_END_COUNT) {
            rc = amisnap_decode_u32(fval, flen, count);
            if (rc != AMISNAP_OK) return rc;
            have_count = 1;
        } else if (tag == TAG_END_HASH) {
            if (flen != 32) return AMISNAP_ERR_MALFORMED;
            memcpy(hash, fval, 32);
            have_hash = 1;
        } else if (tag & AMISNAP_TAG_CRITICAL) {
            return AMISNAP_ERR_CRITICAL_TAG;
        }
    }
    if (rc != 0) return rc;
    if (!have_count || !have_hash) return AMISNAP_ERR_MISSING_FIELD;
    return AMISNAP_OK;
}

int amisnap_manifest_decode(const uint8_t *data, size_t len, const amisnap_manifest_visitor *visitor)
{
    size_t body_start;
    uint16_t hdr_flags;
    amisnap_cursor c;
    amisnap_content_ref *scratch;
    int seen_snap = 0, seen_end = 0;
    size_t entry_count = 0;
    int rc;

    rc = amisnap_read_header(data, len, AMISNAP_FTYPE_MANIFEST, &hdr_flags, &body_start);
    if (rc != AMISNAP_OK) return rc;

    scratch = (amisnap_content_ref *)malloc(AMISNAP_MANIFEST_MAX_CONTENT_REFS * sizeof(*scratch));
    if (!scratch) return AMISNAP_ERR_NOMEM;

    amisnap_cursor_init(&c, data + body_start, len - body_start);

    for (;;) {
        size_t rec_start = body_start + c.pos;
        uint16_t tag;
        const uint8_t *val;
        size_t vlen;
        int r = amisnap_cursor_field(&c, &tag, &val, &vlen);

        if (r == 0) break;
        if (r < 0) { rc = r; goto out; }

        if (!seen_snap && tag != REC_SNAP_TAG) { rc = AMISNAP_ERR_MISSING_FIELD; goto out; }
        if (seen_end) { rc = AMISNAP_ERR_MALFORMED; goto out; } /* nothing may follow REC_END */

        switch (tag) {
        case REC_SNAP_TAG: {
            amisnap_snap_meta snap;
            if (seen_snap) { rc = AMISNAP_ERR_MALFORMED; goto out; }
            rc = decode_snap(val, vlen, &snap);
            if (rc != AMISNAP_OK) goto out;
            seen_snap = 1;
            if (visitor->on_snap) {
                rc = visitor->on_snap(visitor->user, &snap);
                if (rc != 0) goto out;
            }
            break;
        }
        case REC_VOLUME_TAG: {
            amisnap_volume_meta vol;
            rc = decode_volume(val, vlen, &vol);
            if (rc != AMISNAP_OK) goto out;
            if (visitor->on_volume) {
                rc = visitor->on_volume(visitor->user, &vol);
                if (rc != 0) goto out;
            }
            break;
        }
        case AMISNAP_REC_ENTRY_TAG: {
            amisnap_entry_meta entry;
            rc = amisnap_meta_decode_entry(val, vlen, &entry, scratch, AMISNAP_MANIFEST_MAX_CONTENT_REFS);
            if (rc != AMISNAP_OK) goto out;
            entry_count++;
            if (visitor->on_entry) {
                rc = visitor->on_entry(visitor->user, &entry);
                if (rc != 0) goto out;
            }
            break;
        }
        case REC_END_TAG: {
            uint32_t end_count;
            uint8_t end_hash[32], computed[32];

            rc = decode_end(val, vlen, &end_count, end_hash);
            if (rc != AMISNAP_OK) goto out;
            if (end_count != (uint32_t)entry_count) { rc = AMISNAP_ERR_MALFORMED; goto out; }

            amisnap_blake2s256(data, rec_start, computed);
            if (memcmp(computed, end_hash, 32) != 0) { rc = AMISNAP_ERR_HASH_MISMATCH; goto out; }

            seen_end = 1;
            break;
        }
        default:
            if (tag & AMISNAP_TAG_CRITICAL) { rc = AMISNAP_ERR_CRITICAL_TAG; goto out; }
            break;
        }
    }

    rc = (!seen_snap || !seen_end) ? AMISNAP_ERR_MISSING_FIELD : AMISNAP_OK;

out:
    free(scratch);
    return rc;
}
