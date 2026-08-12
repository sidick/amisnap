/* test_index.c -- amisnap_index_build/lookup, and the change-detection
 * policy (amisnap_index_unchanged) from implementation-plan.md's
 * "Decisions since the proposal": the archive bit as corroboration
 * only, never sole evidence.
 */
#include <string.h>

#include "index.h"
#include "manifest.h"
#include "test.h"

static amisnap_buf build_sample_manifest(void)
{
    amisnap_manifest_writer w;
    amisnap_snap_meta snap;
    amisnap_entry_meta e;
    amisnap_content_ref ref;
    amisnap_buf out;

    amisnap_manifest_writer_init(&w);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 5000;
    TEST_CHECK(amisnap_manifest_writer_snap(&w, &snap) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"S/Startup-Sequence"; e.path_len = 18;
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = AMISNAP_FIBF_ARCHIVE; /* archived, everything else clear */
    e.date_days = 5000; e.date_mins = 100; e.date_ticks = 3;
    e.has_size = 1; e.size = 42;
    memset(ref.hash, 0xAA, 32); ref.size = 42;
    e.content = &ref; e.content_count = 1;
    TEST_CHECK(amisnap_manifest_writer_entry(&w, &e) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Work"; e.path_len = 4;
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0;
    e.date_days = 5000; e.date_mins = 0; e.date_ticks = 0;
    TEST_CHECK(amisnap_manifest_writer_entry(&w, &e) == AMISNAP_OK);

    TEST_CHECK(amisnap_manifest_writer_finish(&w, &out) == AMISNAP_OK);
    amisnap_manifest_writer_free(&w);
    return out;
}

void run_index_tests(void)
{
    amisnap_buf mf;
    amisnap_index idx;
    const amisnap_entry_meta *found;
    amisnap_entry_meta last, cur;

    mf = build_sample_manifest();
    TEST_CHECK(amisnap_index_build(mf.data, mf.len, &idx) == AMISNAP_OK);
    amisnap_buf_free(&mf); /* index owns its own copy -- this must be safe to free */

    TEST_CHECK(idx.count == 2);

    found = amisnap_index_lookup(&idx, (const uint8_t *)"S/Startup-Sequence", 18);
    TEST_CHECK(found != NULL);
    TEST_CHECK(found->has_size && found->size == 42);
    TEST_CHECK(found->content_count == 1 && found->content[0].hash[0] == 0xAA);

    found = amisnap_index_lookup(&idx, (const uint8_t *)"Work", 4);
    TEST_CHECK(found != NULL && found->type == AMISNAP_ETYPE_DIR);

    TEST_CHECK(amisnap_index_lookup(&idx, (const uint8_t *)"NoSuchPath", 10) == NULL);
    /* A prefix match is not a match -- "S/Startup" must not hit the
     * "S/Startup-Sequence" entry. */
    TEST_CHECK(amisnap_index_lookup(&idx, (const uint8_t *)"S/Startup", 9) == NULL);

    /* --- amisnap_index_unchanged --- */

    /* No prior entry at all: always "examine". */
    memset(&cur, 0, sizeof(cur));
    cur.type = AMISNAP_ETYPE_FILE;
    cur.prot = AMISNAP_FIBF_ARCHIVE;
    TEST_CHECK(amisnap_index_unchanged(NULL, &cur) == 0);

    /* Baseline: identical file, archive bit set -- skip. */
    memset(&last, 0, sizeof(last));
    last.type = AMISNAP_ETYPE_FILE;
    last.prot = 0; /* archive bit clear in the stored record -- irrelevant, see below */
    last.date_days = 100; last.date_mins = 2; last.date_ticks = 3;
    last.has_size = 1; last.size = 1000;

    cur = last;
    cur.prot = AMISNAP_FIBF_ARCHIVE; /* only the live archive bit differs, and it's SET */
    TEST_CHECK(amisnap_index_unchanged(&last, &cur) == 1);

    /* The archive bit is genuinely not compared against `last` -- a
     * stored record that already had it set behaves identically. */
    last.prot = AMISNAP_FIBF_ARCHIVE;
    TEST_CHECK(amisnap_index_unchanged(&last, &cur) == 1);
    last.prot = 0;

    /* Archive bit currently CLEAR: examine, even though every other
     * field is identical -- this is the one condition that overrides
     * an otherwise-perfect metadata match (the whole point of the
     * policy: a rewrite-then-restore-datestamp trick still clears the
     * bit). */
    cur.prot = 0;
    TEST_CHECK(amisnap_index_unchanged(&last, &cur) == 0);
    cur.prot = AMISNAP_FIBF_ARCHIVE;

    /* Type changed: examine. */
    {
        amisnap_entry_meta c2 = cur;
        c2.type = AMISNAP_ETYPE_DIR;
        TEST_CHECK(amisnap_index_unchanged(&last, &c2) == 0);
    }

    /* A non-archive protection bit differs (e.g. write-protect
     * toggled): examine. */
    {
        amisnap_entry_meta c2 = cur;
        c2.prot |= 0x02u; /* FIBF_WRITE-ish bit, anything other than the archive bit */
        TEST_CHECK(amisnap_index_unchanged(&last, &c2) == 0);
    }

    /* Datestamp differs (any of the three fields): examine. */
    { amisnap_entry_meta c2 = cur; c2.date_days++; TEST_CHECK(amisnap_index_unchanged(&last, &c2) == 0); }
    { amisnap_entry_meta c2 = cur; c2.date_mins++; TEST_CHECK(amisnap_index_unchanged(&last, &c2) == 0); }
    { amisnap_entry_meta c2 = cur; c2.date_ticks++; TEST_CHECK(amisnap_index_unchanged(&last, &c2) == 0); }

    /* Size differs: examine. */
    { amisnap_entry_meta c2 = cur; c2.size++; TEST_CHECK(amisnap_index_unchanged(&last, &c2) == 0); }

    /* Comment: absent-vs-present, and content, both matter. */
    {
        amisnap_entry_meta l2 = last, c2 = cur;
        c2.has_comment = 1;
        c2.comment = (const uint8_t *)"new note";
        c2.comment_len = 8;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 0); /* last has none, current does */

        l2.has_comment = 1;
        l2.comment = (const uint8_t *)"old note";
        l2.comment_len = 8;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 0); /* both have one, different text */

        l2.comment = (const uint8_t *)"new note";
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 1); /* identical comment: unchanged */
    }

    /* Owner: absent-vs-present, and uid/gid, both matter. */
    {
        amisnap_entry_meta l2 = last, c2 = cur;
        c2.has_owner = 1; c2.uid = 1; c2.gid = 2;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 0);

        l2.has_owner = 1; l2.uid = 1; l2.gid = 2;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 1);

        l2.gid = 3;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 0);
    }

    /* Links: target text matters; size/content are irrelevant for
     * this type. */
    {
        amisnap_entry_meta l2, c2;
        memset(&l2, 0, sizeof(l2));
        l2.type = AMISNAP_ETYPE_SOFTLINK;
        l2.date_days = 1;
        l2.has_link = 1; l2.link = (const uint8_t *)"DEVS:"; l2.link_len = 5;

        c2 = l2;
        c2.prot = AMISNAP_FIBF_ARCHIVE;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 1);

        c2.link = (const uint8_t *)"S:"; c2.link_len = 2;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 0);
    }

    /* Directories: size is simply not part of the comparison. */
    {
        amisnap_entry_meta l2, c2;
        memset(&l2, 0, sizeof(l2));
        l2.type = AMISNAP_ETYPE_DIR;
        l2.date_days = 1;
        c2 = l2;
        c2.prot = AMISNAP_FIBF_ARCHIVE;
        TEST_CHECK(amisnap_index_unchanged(&l2, &c2) == 1);
    }

    amisnap_index_free(&idx);
}
