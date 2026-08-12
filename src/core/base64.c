/* base64.c -- see base64.h. */
#include "base64.h"

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int amisnap_base64_encode(amisnap_buf *out, const void *data_v, size_t len)
{
    const unsigned char *data = (const unsigned char *)data_v;
    size_t i;
    int rc;

    for (i = 0; i + 3 <= len; i += 3) {
        unsigned char group[4];
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];

        group[0] = (unsigned char)alphabet[(v >> 18) & 0x3F];
        group[1] = (unsigned char)alphabet[(v >> 12) & 0x3F];
        group[2] = (unsigned char)alphabet[(v >> 6) & 0x3F];
        group[3] = (unsigned char)alphabet[v & 0x3F];
        rc = amisnap_buf_bytes(out, group, 4);
        if (rc != AMISNAP_OK) return rc;
    }

    if (len - i == 1) {
        unsigned char group[4];
        uint32_t v = (uint32_t)data[i] << 16;

        group[0] = (unsigned char)alphabet[(v >> 18) & 0x3F];
        group[1] = (unsigned char)alphabet[(v >> 12) & 0x3F];
        group[2] = '=';
        group[3] = '=';
        rc = amisnap_buf_bytes(out, group, 4);
        if (rc != AMISNAP_OK) return rc;
    } else if (len - i == 2) {
        unsigned char group[4];
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);

        group[0] = (unsigned char)alphabet[(v >> 18) & 0x3F];
        group[1] = (unsigned char)alphabet[(v >> 12) & 0x3F];
        group[2] = (unsigned char)alphabet[(v >> 6) & 0x3F];
        group[3] = '=';
        rc = amisnap_buf_bytes(out, group, 4);
        if (rc != AMISNAP_OK) return rc;
    }

    return AMISNAP_OK;
}
