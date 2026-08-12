/* test_tlv.c -- the shared TLV primitives (tlv.h): big-endian scalar
 * packing, the growable write buffer, and the read cursor's contracts
 * for clean-end / truncation / string malformation.
 */
#include <string.h>

#include "test.h"
#include "tlv.h"

void run_tlv_tests(void)
{
    amisnap_buf b;
    amisnap_cursor c;
    uint16_t tag;
    const uint8_t *val;
    size_t vlen;
    uint8_t tmp[8];

    /* Big-endian scalar packing round-trips and matches the wire byte
     * order explicitly (not just get(put(x))==x, which a byte-order
     * bug on both sides could still pass). */
    amisnap_put_be16(tmp, 0x1234);
    TEST_CHECK(tmp[0] == 0x12 && tmp[1] == 0x34);
    TEST_CHECK(amisnap_get_be16(tmp) == 0x1234);

    amisnap_put_be32(tmp, 0x89ABCDEFu);
    TEST_CHECK(tmp[0] == 0x89 && tmp[1] == 0xAB && tmp[2] == 0xCD && tmp[3] == 0xEF);
    TEST_CHECK(amisnap_get_be32(tmp) == 0x89ABCDEFu);

    amisnap_put_be64(tmp, 0x0102030405060708ull);
    TEST_CHECK(tmp[0] == 0x01 && tmp[7] == 0x08);
    TEST_CHECK(amisnap_get_be64(tmp) == 0x0102030405060708ull);

    /* Empty buffer: a cursor over it reports a clean end immediately. */
    amisnap_buf_init(&b);
    amisnap_cursor_init(&c, b.data, b.len);
    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 0);
    amisnap_buf_free(&b);

    /* Round-trip a handful of fields of every shape through one buffer. */
    amisnap_buf_init(&b);
    TEST_CHECK(amisnap_buf_field_u8(&b, 0x0001, 0x42) == AMISNAP_OK);
    TEST_CHECK(amisnap_buf_field_u32(&b, 0x0002, 0xCAFEBABEu) == AMISNAP_OK);
    TEST_CHECK(amisnap_buf_field_string(&b, 0x0003, "hello", 5) == AMISNAP_OK);
    TEST_CHECK(amisnap_buf_field_string(&b, 0x0004, "", 0) == AMISNAP_OK);

    amisnap_cursor_init(&c, b.data, b.len);

    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
    TEST_CHECK(tag == 0x0001 && vlen == 1 && val[0] == 0x42);

    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
    {
        uint32_t v;
        TEST_CHECK(tag == 0x0002);
        TEST_CHECK(amisnap_decode_u32(val, vlen, &v) == AMISNAP_OK && v == 0xCAFEBABEu);
    }

    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
    {
        const uint8_t *s;
        size_t slen;
        TEST_CHECK(tag == 0x0003);
        TEST_CHECK(amisnap_decode_string(val, vlen, &s, &slen) == AMISNAP_OK);
        TEST_CHECK(slen == 5 && memcmp(s, "hello", 5) == 0);
    }

    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
    {
        const uint8_t *s;
        size_t slen;
        TEST_CHECK(tag == 0x0004);
        TEST_CHECK(amisnap_decode_string(val, vlen, &s, &slen) == AMISNAP_OK && slen == 0);
    }

    /* Clean end after the last field, not a truncation error. */
    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 0);
    amisnap_buf_free(&b);

    /* Truncation: a 6-byte header with no value bytes following. */
    amisnap_buf_init(&b);
    {
        uint8_t hdr[6];
        amisnap_put_be16(hdr, 1);
        amisnap_put_be32(hdr + 2, 10); /* claims 10 value bytes that never arrive */
        TEST_CHECK(amisnap_buf_bytes(&b, hdr, sizeof(hdr)) == AMISNAP_OK);
    }
    amisnap_cursor_init(&c, b.data, b.len);
    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == AMISNAP_ERR_TRUNCATED);
    amisnap_buf_free(&b);

    /* Truncation: fewer than 6 bytes total (a partial header). */
    amisnap_buf_init(&b);
    TEST_CHECK(amisnap_buf_bytes(&b, "\x00\x01\x00", 3) == AMISNAP_OK);
    amisnap_cursor_init(&c, b.data, b.len);
    TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == AMISNAP_ERR_TRUNCATED);
    amisnap_buf_free(&b);

    /* A malformed string: declared length longer than the field's own
     * value bytes. */
    {
        uint8_t bad[4];
        const uint8_t *s;
        size_t slen;
        amisnap_put_be16(bad, 100); /* claims 100 bytes follow; only 2 more present */
        bad[2] = 'x'; bad[3] = 'y';
        TEST_CHECK(amisnap_decode_string(bad, sizeof(bad), &s, &slen) == AMISNAP_ERR_MALFORMED);
    }

    /* A string field over the 65535-byte limit is rejected before any
     * bytes are written -- b is untouched. */
    {
        amisnap_buf b2;
        static uint8_t huge[70000];
        amisnap_buf_init(&b2);
        TEST_CHECK(amisnap_buf_field_string(&b2, 1, huge, sizeof(huge)) == AMISNAP_ERR_TOO_LONG);
        TEST_CHECK(b2.len == 0);
        amisnap_buf_free(&b2);
    }
}
