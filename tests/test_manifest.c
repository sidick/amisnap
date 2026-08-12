/* test_manifest.c -- the whole-manifest codec (manifest.h): builds a
 * small but representative manifest (REC_SNAP, two REC_VOLUME sections,
 * a handful of REC_ENTRY records, REC_END) with the writer, decodes it
 * with the visitor API, and checks every field survives; then a battery
 * of corruption cases proving decode's integrity guarantees (format.md
 * "A manifest without a valid REC_END is not a snapshot") are real,
 * not just described.
 */
#include <string.h>

#include "manifest.h"
#include "test.h"

typedef struct {
    int snap_seen;
    amisnap_snap_meta snap;
    int volume_count;
    amisnap_volume_meta volumes[4];
    int entry_count;
    amisnap_entry_meta entries[8];
    /* entries[] borrow into the decode buffer for path/comment/link,
     * but content refs are decode-scratch that gets reused per entry
     * -- copy them out so the test can check them after decode
     * returns. */
    amisnap_content_ref entry_content_copy[8][4];
} collected;

static void on_snap(void *user, const amisnap_snap_meta *snap)
{
    collected *c = (collected *)user;
    c->snap_seen = 1;
    c->snap = *snap;
}

static void on_volume(void *user, const amisnap_volume_meta *vol)
{
    collected *c = (collected *)user;
    if (c->volume_count < 4)
        c->volumes[c->volume_count++] = *vol;
}

static void on_entry(void *user, const amisnap_entry_meta *entry)
{
    collected *c = (collected *)user;
    if (c->entry_count < 8) {
        int i = c->entry_count++;
        c->entries[i] = *entry;
        for (size_t k = 0; k < entry->content_count && k < 4; k++)
            c->entry_content_copy[i][k] = entry->content[k];
        c->entries[i].content = c->entry_content_copy[i]; /* re-point past the reused scratch */
    }
}

static void build_sample(amisnap_manifest_writer *w)
{
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    amisnap_content_ref ref;

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 17000; snap.created_mins = 720; snap.created_ticks = 5;
    snap.has_hostname = 1;
    snap.hostname = (const uint8_t *)"A1200"; snap.hostname_len = 5;
    snap.has_toolver = 1;
    snap.toolver = (const uint8_t *)"AmiSnap 0.1"; snap.toolver_len = 11;
    TEST_CHECK(amisnap_manifest_writer_snap(w, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    vol.has_name = 1; vol.name = (const uint8_t *)"Work"; vol.name_len = 4;
    vol.has_dostype = 1; vol.dostype = 0x444F5307u; /* "DOS\7" */
    vol.has_caps = 1; vol.maxnamelen = 107; vol.caps_flags = AMISNAP_VOLCAP_OWNER | AMISNAP_VOLCAP_COMMENT;
    TEST_CHECK(amisnap_manifest_writer_volume(w, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)""; e.path_len = 0; /* the volume root itself */
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0x0Fu;
    e.date_days = 17000; e.date_mins = 0; e.date_ticks = 0;
    TEST_CHECK(amisnap_manifest_writer_entry(w, &e) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"S/Startup-Sequence"; e.path_len = 18;
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0;
    e.date_days = 17000; e.date_mins = 1; e.date_ticks = 0;
    e.has_size = 1; e.size = 100;
    memset(ref.hash, 0x11, 32); ref.size = 100;
    e.content = &ref; e.content_count = 1;
    TEST_CHECK(amisnap_manifest_writer_entry(w, &e) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"DH1:Backup"; vol.vol_root_len = 10;
    TEST_CHECK(amisnap_manifest_writer_volume(w, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)""; e.path_len = 0;
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0;
    e.date_days = 17000; e.date_mins = 0; e.date_ticks = 0;
    TEST_CHECK(amisnap_manifest_writer_entry(w, &e) == AMISNAP_OK);
}

void run_manifest_tests(void)
{
    amisnap_manifest_writer w;
    amisnap_buf out;
    collected c;
    amisnap_manifest_visitor v;

    memset(&c, 0, sizeof(c));
    memset(&v, 0, sizeof(v));
    v.user = &c;
    v.on_snap = on_snap;
    v.on_volume = on_volume;
    v.on_entry = on_entry;

    /* --- Happy path: build, encode, decode, verify every field. --- */
    amisnap_manifest_writer_init(&w);
    build_sample(&w);
    TEST_CHECK(amisnap_manifest_writer_finish(&w, &out) == AMISNAP_OK);
    amisnap_manifest_writer_free(&w);

    TEST_CHECK(amisnap_manifest_decode(out.data, out.len, &v) == AMISNAP_OK);

    TEST_CHECK(c.snap_seen);
    TEST_CHECK(c.snap.created_days == 17000 && c.snap.created_mins == 720 && c.snap.created_ticks == 5);
    TEST_CHECK(c.snap.has_hostname && c.snap.hostname_len == 5 && memcmp(c.snap.hostname, "A1200", 5) == 0);
    TEST_CHECK(c.snap.has_toolver && memcmp(c.snap.toolver, "AmiSnap 0.1", 11) == 0);
    TEST_CHECK(!c.snap.has_comment);

    TEST_CHECK(c.volume_count == 2);
    TEST_CHECK(c.volumes[0].vol_root_len == 5 && memcmp(c.volumes[0].vol_root, "Work:", 5) == 0);
    TEST_CHECK(c.volumes[0].has_dostype && c.volumes[0].dostype == 0x444F5307u);
    TEST_CHECK(c.volumes[0].has_caps && c.volumes[0].maxnamelen == 107);
    TEST_CHECK(c.volumes[0].caps_flags == (AMISNAP_VOLCAP_OWNER | AMISNAP_VOLCAP_COMMENT));
    TEST_CHECK(c.volumes[1].vol_root_len == 10 && memcmp(c.volumes[1].vol_root, "DH1:Backup", 10) == 0);
    TEST_CHECK(!c.volumes[1].has_name && !c.volumes[1].has_dostype);

    TEST_CHECK(c.entry_count == 3);
    TEST_CHECK(c.entries[0].path_len == 0 && c.entries[0].type == AMISNAP_ETYPE_DIR);
    TEST_CHECK(c.entries[1].path_len == 18 && memcmp(c.entries[1].path, "S/Startup-Sequence", 18) == 0);
    TEST_CHECK(c.entries[1].content_count == 1 && c.entries[1].content[0].hash[0] == 0x11);
    TEST_CHECK(c.entries[2].path_len == 0 && c.entries[2].type == AMISNAP_ETYPE_DIR);

    amisnap_buf_free(&out);

    /* --- Corruption: flip a byte inside the manifest body -> END_HASH
     * mismatch, not silently accepted. --- */
    {
        amisnap_manifest_writer w2;
        amisnap_buf out2;

        amisnap_manifest_writer_init(&w2);
        build_sample(&w2);
        TEST_CHECK(amisnap_manifest_writer_finish(&w2, &out2) == AMISNAP_OK);
        amisnap_manifest_writer_free(&w2);

        out2.data[20] ^= 0xFF; /* well inside the header/body, before REC_END */
        TEST_CHECK(amisnap_manifest_decode(out2.data, out2.len, &v) == AMISNAP_ERR_HASH_MISMATCH);
        amisnap_buf_free(&out2);
    }

    /* --- Corruption: truncate the buffer right before REC_END --
     * decode must refuse (no REC_END = "not a snapshot"), not return
     * partial success. --- */
    {
        amisnap_manifest_writer w3;
        amisnap_buf out3, truncated;

        amisnap_manifest_writer_init(&w3);
        build_sample(&w3);
        TEST_CHECK(amisnap_manifest_writer_finish(&w3, &out3) == AMISNAP_OK);
        amisnap_manifest_writer_free(&w3);

        /* Re-encode without ever calling finish's REC_END append: reuse
         * out3's body length before REC_END by re-deriving it isn't
         * straightforward from outside, so instead just truncate the
         * finished buffer's tail -- still exercises "no valid REC_END". */
        amisnap_buf_init(&truncated);
        TEST_CHECK(amisnap_buf_bytes(&truncated, out3.data, out3.len > 10 ? out3.len - 10 : 0) == AMISNAP_OK);
        {
            int rc = amisnap_manifest_decode(truncated.data, truncated.len, &v);
            TEST_CHECK(rc == AMISNAP_ERR_MISSING_FIELD || rc == AMISNAP_ERR_TRUNCATED ||
                       rc == AMISNAP_ERR_MALFORMED || rc == AMISNAP_ERR_HASH_MISMATCH);
        }
        amisnap_buf_free(&truncated);
        amisnap_buf_free(&out3);
    }

    /* --- A manifest that is only a header (no records at all): no
     * REC_SNAP, no REC_END -- rejected. --- */
    {
        amisnap_buf hdr_only;
        amisnap_buf_init(&hdr_only);
        TEST_CHECK(amisnap_write_header(&hdr_only, AMISNAP_FTYPE_MANIFEST, 0) == AMISNAP_OK);
        TEST_CHECK(amisnap_manifest_decode(hdr_only.data, hdr_only.len, &v) == AMISNAP_ERR_MISSING_FIELD);
        amisnap_buf_free(&hdr_only);
    }

    /* --- Wrong ftype (a repository header's ftype=1) is refused. --- */
    {
        amisnap_buf wrong;
        amisnap_buf_init(&wrong);
        TEST_CHECK(amisnap_write_header(&wrong, AMISNAP_FTYPE_REPO, 0) == AMISNAP_OK);
        TEST_CHECK(amisnap_manifest_decode(wrong.data, wrong.len, &v) == AMISNAP_ERR_MALFORMED);
        amisnap_buf_free(&wrong);
    }

    /* --- Writer misuse is rejected, not silently tolerated: calling
     * volume/entry before snap, or snap twice. --- */
    {
        amisnap_manifest_writer w4;
        amisnap_volume_meta vol;
        amisnap_snap_meta snap;

        memset(&vol, 0, sizeof(vol));
        vol.vol_root = (const uint8_t *)"X:"; vol.vol_root_len = 2;

        amisnap_manifest_writer_init(&w4);
        TEST_CHECK(amisnap_manifest_writer_volume(&w4, &vol) == AMISNAP_ERR_MISSING_FIELD);
        amisnap_manifest_writer_free(&w4);

        memset(&snap, 0, sizeof(snap));
        amisnap_manifest_writer_init(&w4);
        TEST_CHECK(amisnap_manifest_writer_snap(&w4, &snap) == AMISNAP_OK);
        TEST_CHECK(amisnap_manifest_writer_snap(&w4, &snap) == AMISNAP_ERR_MALFORMED);
        amisnap_manifest_writer_free(&w4);
    }
}
