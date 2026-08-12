/* test_meta.c -- REC_ENTRY encode/decode. Fixed vectors for readability
 * (one of each entry shape: empty dir, small file with one content
 * ref, chunked file with several refs, softlink, hardlink, and every
 * optional field both present and absent), plus a seeded random
 * property test: N random entries survive encode->decode bit-for-bit
 * (implementation-plan.md Phase 1 item 2's round-trip requirement).
 *
 * rand()/srand() with a fixed seed, not amitools/Workflow's banned
 * Math.random() -- this is plain host C, reproducibility here just
 * means picking one seed and keeping it, which a fixed srand() gives.
 */
#include <stdlib.h>
#include <string.h>

#include "meta.h"
#include "test.h"
#include "tlv.h"

static int entries_equal(const amisnap_entry_meta *a, const amisnap_entry_meta *b)
{
    size_t i;

    if (a->path_len != b->path_len || memcmp(a->path, b->path, a->path_len) != 0)
        return 0;
    if (a->type != b->type) return 0;
    if (a->prot != b->prot) return 0;
    if (a->date_days != b->date_days || a->date_mins != b->date_mins || a->date_ticks != b->date_ticks)
        return 0;

    if (a->has_comment != b->has_comment) return 0;
    if (a->has_comment && (a->comment_len != b->comment_len ||
                            memcmp(a->comment, b->comment, a->comment_len) != 0))
        return 0;

    if (a->has_owner != b->has_owner) return 0;
    if (a->has_owner && (a->uid != b->uid || a->gid != b->gid))
        return 0;

    if (a->has_size != b->has_size) return 0;
    if (a->has_size && a->size != b->size) return 0;

    if (a->content_count != b->content_count) return 0;
    for (i = 0; i < a->content_count; i++) {
        if (memcmp(a->content[i].hash, b->content[i].hash, 32) != 0) return 0;
        if (a->content[i].size != b->content[i].size) return 0;
    }

    if (a->has_link != b->has_link) return 0;
    if (a->has_link && (a->link_len != b->link_len ||
                         memcmp(a->link, b->link, a->link_len) != 0))
        return 0;

    if (a->has_xhash != b->has_xhash) return 0;
    if (a->has_xhash && a->xhash != b->xhash) return 0;

    return 1;
}

/* Encodes e, decodes the result, and checks the round trip. Returns
 * the decoded copy's content_count via *out_content_count for callers
 * that want to inspect further (all current callers just check
 * entries_equal). */
static int roundtrip(const amisnap_entry_meta *e)
{
    amisnap_buf buf;
    amisnap_cursor c;
    uint16_t tag;
    const uint8_t *val;
    size_t vlen;
    amisnap_entry_meta decoded;
    amisnap_content_ref storage[64];
    int rc, ok;

    amisnap_buf_init(&buf);
    rc = amisnap_meta_encode_entry(&buf, e);
    if (rc != AMISNAP_OK) { amisnap_buf_free(&buf); return 0; }

    amisnap_cursor_init(&c, buf.data, buf.len);
    rc = amisnap_cursor_field(&c, &tag, &val, &vlen);
    if (rc != 1 || tag != AMISNAP_REC_ENTRY_TAG) { amisnap_buf_free(&buf); return 0; }

    rc = amisnap_meta_decode_entry(val, vlen, &decoded, storage, 64);
    ok = (rc == AMISNAP_OK) && entries_equal(e, &decoded);

    /* The whole buffer is exactly the one REC_ENTRY field -- nothing
     * trailing, nothing short. */
    ok = ok && (amisnap_cursor_field(&c, &tag, &val, &vlen) == 0);

    amisnap_buf_free(&buf);
    return ok;
}

void run_meta_tests(void)
{
    amisnap_entry_meta e;
    amisnap_content_ref refs[3];
    int i;

    /* An empty directory: only the always-required fields. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Work/Projects";
    e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0x0000000Eu; /* rwed active-low, all clear */
    e.date_days = 12345; e.date_mins = 600; e.date_ticks = 30;
    TEST_CHECK(roundtrip(&e));

    /* Root entry: empty path is legal (format.md E_PATH: "Empty = the
     * root itself"). */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"";
    e.path_len = 0;
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0x0000000Fu;
    e.date_days = 1; e.date_mins = 0; e.date_ticks = 0;
    TEST_CHECK(roundtrip(&e));

    /* A small file, every optional field present: comment, owner,
     * one content ref, xhash. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"S/Startup-Sequence";
    e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0x00000000u;
    e.date_days = 16000; e.date_mins = 59; e.date_ticks = 1;
    e.has_comment = 1;
    e.comment = (const uint8_t *)"boot script";
    e.comment_len = strlen((const char *)e.comment);
    e.has_owner = 1; e.uid = 1; e.gid = 100;
    e.has_size = 1; e.size = 512;
    memset(refs[0].hash, 0xAB, 32);
    refs[0].size = 512;
    e.content = refs; e.content_count = 1;
    e.has_xhash = 1; e.xhash = 0xDEADBEEFu;
    TEST_CHECK(roundtrip(&e));

    /* A chunked file: several content refs, no optional metadata. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Video/Big.mov";
    e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0x00000000u;
    e.date_days = 16000; e.date_mins = 0; e.date_ticks = 0;
    e.has_size = 1; e.size = 3 * 8388608u;
    for (i = 0; i < 3; i++) {
        memset(refs[i].hash, (uint8_t)(i + 1), 32);
        refs[i].size = 8388608u;
    }
    e.content = refs; e.content_count = 3;
    TEST_CHECK(roundtrip(&e));

    /* A zero-byte file: E_SIZE present, no content refs required. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"empty.txt";
    e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0;
    e.date_days = 1; e.date_mins = 1; e.date_ticks = 1;
    e.has_size = 1; e.size = 0;
    TEST_CHECK(roundtrip(&e));

    /* Softlink and hardlink. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Link/ToDevs";
    e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_SOFTLINK;
    e.prot = 0;
    e.date_days = 1; e.date_mins = 0; e.date_ticks = 0;
    e.has_link = 1;
    e.link = (const uint8_t *)"DEVS:";
    e.link_len = strlen((const char *)e.link);
    TEST_CHECK(roundtrip(&e));

    e.type = AMISNAP_ETYPE_HARDLINK;
    e.link = (const uint8_t *)"S/Startup-Sequence";
    e.link_len = strlen((const char *)e.link);
    TEST_CHECK(roundtrip(&e));

    /* Explicit absent-vs-empty: a zero-length comment is a comment
     * (has_comment=1, len=0), distinct from no comment at all -- both
     * must round-trip distinguishably (format.md E_COMMENT). */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"noted";
    e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0;
    e.date_days = 1; e.date_mins = 0; e.date_ticks = 0;
    e.has_size = 1; e.size = 0;
    e.has_comment = 1;
    e.comment = (const uint8_t *)"";
    e.comment_len = 0;
    TEST_CHECK(roundtrip(&e));

    /* --- Error paths --- */

    /* A missing required field (E_DATE dropped) is rejected. */
    {
        amisnap_buf body, wrapped;
        amisnap_entry_meta decoded;
        amisnap_content_ref storage[4];
        amisnap_cursor c;
        uint16_t tag;
        const uint8_t *val;
        size_t vlen;

        amisnap_buf_init(&body);
        TEST_CHECK(amisnap_buf_field_string(&body, 0x8040, "x", 1) == AMISNAP_OK); /* E_PATH */
        TEST_CHECK(amisnap_buf_field_u8(&body, 0x8041, AMISNAP_ETYPE_DIR) == AMISNAP_OK); /* E_TYPE */
        TEST_CHECK(amisnap_buf_field_u32(&body, 0x8042, 0) == AMISNAP_OK); /* E_PROT */
        /* E_DATE (0x8043) deliberately omitted */

        amisnap_buf_init(&wrapped);
        TEST_CHECK(amisnap_buf_field(&wrapped, AMISNAP_REC_ENTRY_TAG, body.data, body.len) == AMISNAP_OK);

        amisnap_cursor_init(&c, wrapped.data, wrapped.len);
        TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
        TEST_CHECK(amisnap_meta_decode_entry(val, vlen, &decoded, storage, 4) == AMISNAP_ERR_MISSING_FIELD);

        amisnap_buf_free(&body);
        amisnap_buf_free(&wrapped);
    }

    /* An unknown critical tag (high bit set) is refused, never
     * silently ignored (format.md "TLV encoding"). */
    {
        amisnap_buf body, wrapped;
        amisnap_entry_meta decoded;
        amisnap_content_ref storage[4];
        amisnap_cursor c;
        uint16_t tag;
        const uint8_t *val;
        size_t vlen;

        amisnap_buf_init(&body);
        TEST_CHECK(amisnap_buf_field_string(&body, 0x8040, "x", 1) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_field_u8(&body, 0x8041, AMISNAP_ETYPE_DIR) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_field_u32(&body, 0x8042, 0) == AMISNAP_OK);
        {
            uint8_t datebuf[12] = { 0 };
            TEST_CHECK(amisnap_buf_field(&body, 0x8043, datebuf, sizeof(datebuf)) == AMISNAP_OK);
        }
        /* A made-up future critical tag this decoder can't know. */
        TEST_CHECK(amisnap_buf_field_u8(&body, 0x8FFF, 0) == AMISNAP_OK);

        amisnap_buf_init(&wrapped);
        TEST_CHECK(amisnap_buf_field(&wrapped, AMISNAP_REC_ENTRY_TAG, body.data, body.len) == AMISNAP_OK);

        amisnap_cursor_init(&c, wrapped.data, wrapped.len);
        TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
        TEST_CHECK(amisnap_meta_decode_entry(val, vlen, &decoded, storage, 4) == AMISNAP_ERR_CRITICAL_TAG);

        amisnap_buf_free(&body);
        amisnap_buf_free(&wrapped);
    }

    /* An unknown NON-critical tag is skipped, and decode still
     * succeeds. */
    {
        amisnap_buf body, wrapped;
        amisnap_entry_meta decoded;
        amisnap_content_ref storage[4];
        amisnap_cursor c;
        uint16_t tag;
        const uint8_t *val;
        size_t vlen;

        amisnap_buf_init(&body);
        TEST_CHECK(amisnap_buf_field_string(&body, 0x8040, "x", 1) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_field_u8(&body, 0x8041, AMISNAP_ETYPE_DIR) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_field_u32(&body, 0x8042, 0) == AMISNAP_OK);
        {
            uint8_t datebuf[12] = { 0 };
            TEST_CHECK(amisnap_buf_field(&body, 0x8043, datebuf, sizeof(datebuf)) == AMISNAP_OK);
        }
        TEST_CHECK(amisnap_buf_field_u8(&body, 0x0FFF, 0) == AMISNAP_OK); /* unknown, non-critical */

        amisnap_buf_init(&wrapped);
        TEST_CHECK(amisnap_buf_field(&wrapped, AMISNAP_REC_ENTRY_TAG, body.data, body.len) == AMISNAP_OK);

        amisnap_cursor_init(&c, wrapped.data, wrapped.len);
        TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
        TEST_CHECK(amisnap_meta_decode_entry(val, vlen, &decoded, storage, 4) == AMISNAP_OK);

        amisnap_buf_free(&body);
        amisnap_buf_free(&wrapped);
    }

    /* A file with size > 0 but zero content refs is rejected -- data
     * that claims to exist but has nowhere to read it from. */
    {
        amisnap_buf body, wrapped;
        amisnap_entry_meta decoded;
        amisnap_content_ref storage[4];
        amisnap_cursor c;
        uint16_t tag;
        const uint8_t *val;
        size_t vlen;

        amisnap_buf_init(&body);
        TEST_CHECK(amisnap_buf_field_string(&body, 0x8040, "x", 1) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_field_u8(&body, 0x8041, AMISNAP_ETYPE_FILE) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_field_u32(&body, 0x8042, 0) == AMISNAP_OK);
        {
            uint8_t datebuf[12] = { 0 };
            TEST_CHECK(amisnap_buf_field(&body, 0x8043, datebuf, sizeof(datebuf)) == AMISNAP_OK);
        }
        TEST_CHECK(amisnap_buf_field_u64(&body, 0x8046, 1024) == AMISNAP_OK); /* E_SIZE, no E_CONTENT */

        amisnap_buf_init(&wrapped);
        TEST_CHECK(amisnap_buf_field(&wrapped, AMISNAP_REC_ENTRY_TAG, body.data, body.len) == AMISNAP_OK);

        amisnap_cursor_init(&c, wrapped.data, wrapped.len);
        TEST_CHECK(amisnap_cursor_field(&c, &tag, &val, &vlen) == 1);
        TEST_CHECK(amisnap_meta_decode_entry(val, vlen, &decoded, storage, 4) == AMISNAP_ERR_MISSING_FIELD);

        amisnap_buf_free(&body);
        amisnap_buf_free(&wrapped);
    }

    /* A path over 65535 bytes is rejected by the encoder outright
     * (format.md "Limits"). */
    {
        static uint8_t huge_path[70000];
        memset(huge_path, 'a', sizeof(huge_path));
        memset(&e, 0, sizeof(e));
        e.path = huge_path;
        e.path_len = sizeof(huge_path);
        e.type = AMISNAP_ETYPE_DIR;
        e.date_days = 1;
        {
            amisnap_buf buf;
            amisnap_buf_init(&buf);
            TEST_CHECK(amisnap_meta_encode_entry(&buf, &e) == AMISNAP_ERR_TOO_LONG);
            amisnap_buf_free(&buf);
        }
    }

    /* --- Property test: random entries round-trip exactly. --- */
    {
        static uint8_t pathbuf[256], commentbuf[256], linkbuf[256];
        amisnap_content_ref rrefs[8];
        int n;

        srand(0xA51Du);

        for (n = 0; n < 500; n++) {
            int plen, clen, llen, nrefs, j;

            memset(&e, 0, sizeof(e));

            plen = rand() % 200;
            for (j = 0; j < plen; j++)
                pathbuf[j] = (uint8_t)(1 + (rand() % 255)); /* never a NUL */
            e.path = pathbuf;
            e.path_len = (size_t)plen;

            e.type = (uint8_t)(1 + (rand() % 4));
            e.prot = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
            e.date_days = (uint32_t)rand();
            e.date_mins = (uint32_t)(rand() % 1440);
            e.date_ticks = (uint32_t)(rand() % 3000);

            if (rand() % 2) {
                e.has_comment = 1;
                clen = rand() % 200;
                for (j = 0; j < clen; j++)
                    commentbuf[j] = (uint8_t)(rand() % 256);
                e.comment = commentbuf;
                e.comment_len = (size_t)clen;
            }

            if (rand() % 2) {
                e.has_owner = 1;
                e.uid = (uint16_t)rand();
                e.gid = (uint16_t)rand();
            }

            if (e.type == AMISNAP_ETYPE_FILE) {
                e.has_size = 1;
                nrefs = rand() % 9;
                if (nrefs == 0) {
                    e.size = 0;
                } else {
                    uint64_t total = 0;
                    for (j = 0; j < nrefs; j++) {
                        int k;
                        for (k = 0; k < 32; k++)
                            rrefs[j].hash[k] = (uint8_t)rand();
                        rrefs[j].size = 1 + (uint32_t)(rand() % 100000);
                        total += rrefs[j].size;
                    }
                    e.content = rrefs;
                    e.content_count = (size_t)nrefs;
                    e.size = total;
                }
            } else if (e.type == AMISNAP_ETYPE_SOFTLINK || e.type == AMISNAP_ETYPE_HARDLINK) {
                e.has_link = 1;
                llen = 1 + (rand() % 200);
                for (j = 0; j < llen; j++)
                    linkbuf[j] = (uint8_t)(1 + (rand() % 255));
                e.link = linkbuf;
                e.link_len = (size_t)llen;
            }

            if (rand() % 2) {
                e.has_xhash = 1;
                e.xhash = (uint32_t)rand();
            }

            if (!roundtrip(&e)) {
                TEST_CHECK(0); /* fprintf-free failure report: TEST_CHECK's own file:line pinpoints n via re-run */
                break;
            }
        }
    }
}
