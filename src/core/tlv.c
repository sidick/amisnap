/* tlv.c -- see tlv.h. */
#include <stdlib.h>
#include <string.h>

#include "tlv.h"

void amisnap_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

void amisnap_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

void amisnap_put_be64(uint8_t *p, uint64_t v)
{
    amisnap_put_be32(p, (uint32_t)(v >> 32));
    amisnap_put_be32(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}

uint16_t amisnap_get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t amisnap_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t amisnap_get_be64(const uint8_t *p)
{
    return ((uint64_t)amisnap_get_be32(p) << 32) | amisnap_get_be32(p + 4);
}

void amisnap_buf_init(amisnap_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void amisnap_buf_free(amisnap_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

int amisnap_buf_bytes(amisnap_buf *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t newcap = b->cap ? b->cap * 2 : 256;
        uint8_t *newdata;

        while (newcap < b->len + n)
            newcap *= 2;

        newdata = (uint8_t *)realloc(b->data, newcap);
        if (!newdata)
            return AMISNAP_ERR_NOMEM;
        b->data = newdata;
        b->cap = newcap;
    }
    if (n > 0) {
        memcpy(b->data + b->len, p, n);
        b->len += n;
    }
    return AMISNAP_OK;
}

int amisnap_buf_field(amisnap_buf *b, uint16_t tag, const void *value, size_t valuelen)
{
    uint8_t hdr[6];
    int rc;

    amisnap_put_be16(hdr, tag);
    amisnap_put_be32(hdr + 2, (uint32_t)valuelen);

    rc = amisnap_buf_bytes(b, hdr, sizeof(hdr));
    if (rc != AMISNAP_OK)
        return rc;
    return amisnap_buf_bytes(b, value, valuelen);
}

int amisnap_buf_field_u8(amisnap_buf *b, uint16_t tag, uint8_t v)
{
    return amisnap_buf_field(b, tag, &v, 1);
}

int amisnap_buf_field_u16(amisnap_buf *b, uint16_t tag, uint16_t v)
{
    uint8_t tmp[2];
    amisnap_put_be16(tmp, v);
    return amisnap_buf_field(b, tag, tmp, sizeof(tmp));
}

int amisnap_buf_field_u32(amisnap_buf *b, uint16_t tag, uint32_t v)
{
    uint8_t tmp[4];
    amisnap_put_be32(tmp, v);
    return amisnap_buf_field(b, tag, tmp, sizeof(tmp));
}

int amisnap_buf_field_u64(amisnap_buf *b, uint16_t tag, uint64_t v)
{
    uint8_t tmp[8];
    amisnap_put_be64(tmp, v);
    return amisnap_buf_field(b, tag, tmp, sizeof(tmp));
}

int amisnap_buf_field_string(amisnap_buf *b, uint16_t tag, const void *p, size_t len)
{
    amisnap_buf tmp;
    uint8_t lenbuf[2];
    int rc;

    if (len > 0xFFFFu)
        return AMISNAP_ERR_TOO_LONG;

    amisnap_buf_init(&tmp);
    amisnap_put_be16(lenbuf, (uint16_t)len);

    rc = amisnap_buf_bytes(&tmp, lenbuf, sizeof(lenbuf));
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_bytes(&tmp, p, len);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_field(b, tag, tmp.data, tmp.len);

    amisnap_buf_free(&tmp);
    return rc;
}

void amisnap_cursor_init(amisnap_cursor *c, const uint8_t *data, size_t len)
{
    c->data = data;
    c->len = len;
    c->pos = 0;
}

int amisnap_cursor_field(amisnap_cursor *c, uint16_t *tag, const uint8_t **value, size_t *valuelen)
{
    uint32_t vlen;

    if (c->pos == c->len)
        return 0;
    if (c->len - c->pos < 6)
        return AMISNAP_ERR_TRUNCATED;

    *tag = amisnap_get_be16(c->data + c->pos);
    vlen = amisnap_get_be32(c->data + c->pos + 2);

    if (c->len - c->pos - 6 < vlen)
        return AMISNAP_ERR_TRUNCATED;

    *value = c->data + c->pos + 6;
    *valuelen = vlen;
    c->pos += 6 + vlen;
    return 1;
}

int amisnap_decode_string(const uint8_t *value, size_t valuelen,
                           const uint8_t **str, size_t *strlen)
{
    uint16_t declared;

    if (valuelen < 2)
        return AMISNAP_ERR_MALFORMED;

    declared = amisnap_get_be16(value);
    if ((size_t)declared + 2 != valuelen)
        return AMISNAP_ERR_MALFORMED;

    *str = value + 2;
    *strlen = declared;
    return AMISNAP_OK;
}

int amisnap_decode_u8(const uint8_t *value, size_t valuelen, uint8_t *out)
{
    if (valuelen != 1)
        return AMISNAP_ERR_MALFORMED;
    *out = value[0];
    return AMISNAP_OK;
}

int amisnap_decode_u16(const uint8_t *value, size_t valuelen, uint16_t *out)
{
    if (valuelen != 2)
        return AMISNAP_ERR_MALFORMED;
    *out = amisnap_get_be16(value);
    return AMISNAP_OK;
}

int amisnap_decode_u32(const uint8_t *value, size_t valuelen, uint32_t *out)
{
    if (valuelen != 4)
        return AMISNAP_ERR_MALFORMED;
    *out = amisnap_get_be32(value);
    return AMISNAP_OK;
}

int amisnap_decode_u64(const uint8_t *value, size_t valuelen, uint64_t *out)
{
    if (valuelen != 8)
        return AMISNAP_ERR_MALFORMED;
    *out = amisnap_get_be64(value);
    return AMISNAP_OK;
}
