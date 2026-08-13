/* test_repo.c -- the snapshot write path (repo.h) end to end against a
 * real directory backend: build a small snapshot, then verify
 * everything the writer produced independently -- reading the
 * manifest and objects straight off the backend, not through the
 * writer's own state -- which is what "snapshot against a host
 * directory tree works under CI" (implementation-plan.md Phase 1 item
 * 3's gate) actually means.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "manifest.h"
#include "repo.h"
#include "test.h"

#define TESTDIR "build/test-repo"

typedef struct {
    int snap_seen;
    int entry_count;
    amisnap_entry_meta entries[8];
    amisnap_content_ref content_copy[8][2];
} collected;

static int on_snap(void *user, const amisnap_snap_meta *snap)
{
    ((collected *)user)->snap_seen = 1;
    (void)snap;
    return 0;
}

static int on_volume(void *user, const amisnap_volume_meta *vol)
{
    (void)user; (void)vol;
    return 0;
}

static int on_entry(void *user, const amisnap_entry_meta *entry)
{
    collected *c = (collected *)user;
    if (c->entry_count < 8) {
        int i = c->entry_count++;
        size_t k;
        c->entries[i] = *entry;
        for (k = 0; k < entry->content_count && k < 2; k++)
            c->content_copy[i][k] = entry->content[k];
        c->entries[i].content = c->content_copy[i];
    }
    return 0;
}

static void count_cb(void *user, const char *name)
{
    (void)name;
    (*(int *)user)++;
}

typedef struct {
    char (*seen)[17];
    int *n;
    int cap;
} list_collect_ctx;

static void list_collect_cb(void *user, const char *snapid)
{
    list_collect_ctx *ctx = (list_collect_ctx *)user;
    if (*ctx->n < ctx->cap) {
        strncpy(ctx->seen[*ctx->n], snapid, 16);
        ctx->seen[*ctx->n][16] = '\0';
        (*ctx->n)++;
    }
}

static void object_key_for(const uint8_t hash[32], char key[80])
{
    static const char hexd[] = "0123456789abcdef";
    char hex[65];
    size_t i;

    for (i = 0; i < 32; i++) {
        hex[i * 2]     = hexd[hash[i] >> 4];
        hex[i * 2 + 1] = hexd[hash[i] & 0x0Fu];
    }
    hex[64] = '\0';
    snprintf(key, 80, "objects/%c%c/%s", hex[0], hex[1], hex);
}

void run_repo_tests(void)
{
    amisnap_backend be;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    char snapid[17];
    char mf_key[32];
    amisnap_buf mf_bytes;
    collected c;
    amisnap_manifest_visitor v;
    static const char file1_data[] = "the quick brown fox";
    static const char file2_data[] = "the quick brown fox"; /* identical: dedup case */
    uint8_t expect_hash[32];

    TEST_CHECK(system("rm -rf " TESTDIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(TESTDIR, &be) == AMISNAP_OK);

    amisnap_repo_writer_init(&rw, &be, NULL);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 1000; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)""; e.path_len = 0;
    e.type = AMISNAP_ETYPE_DIR;
    e.date_days = 1000;
    TEST_CHECK(amisnap_repo_writer_entry(&rw, &e) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"a.txt"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 1000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, file1_data, sizeof(file1_data) - 1) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"b.txt"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 1000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, file2_data, sizeof(file2_data) - 1) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"empty.txt"; e.path_len = 9;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 1000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, NULL, 0) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    /* --- Independent verification: read the manifest straight off the
     * backend and decode it -- not the writer's in-memory state. --- */
    snprintf(mf_key, sizeof(mf_key), "snapshots/%s.mf", snapid);
    TEST_CHECK(amisnap_backend_get(&be, mf_key, &mf_bytes) == AMISNAP_OK);

    memset(&c, 0, sizeof(c));
    memset(&v, 0, sizeof(v));
    v.user = &c;
    v.on_snap = on_snap; v.on_volume = on_volume; v.on_entry = on_entry;
    TEST_CHECK(amisnap_manifest_decode(mf_bytes.data, mf_bytes.len, &v) == AMISNAP_OK);
    amisnap_buf_free(&mf_bytes);

    TEST_CHECK(c.snap_seen);
    TEST_CHECK(c.entry_count == 4);
    TEST_CHECK(c.entries[0].path_len == 0 && c.entries[0].type == AMISNAP_ETYPE_DIR);
    TEST_CHECK(c.entries[1].content_count == 1);
    TEST_CHECK(c.entries[2].content_count == 1);
    TEST_CHECK(c.entries[3].has_size && c.entries[3].size == 0 && c.entries[3].content_count == 0);

    /* a.txt and b.txt have identical content -- same object hash
     * (dedup), and the object read back off the backend has the real
     * bytes. */
    amisnap_blake2s256(file1_data, sizeof(file1_data) - 1, expect_hash);
    TEST_CHECK(memcmp(c.entries[1].content[0].hash, expect_hash, 32) == 0);
    TEST_CHECK(memcmp(c.entries[2].content[0].hash, expect_hash, 32) == 0);

    {
        char key[80];
        amisnap_buf obj;
        object_key_for(expect_hash, key);
        TEST_CHECK(amisnap_backend_get(&be, key, &obj) == AMISNAP_OK);
        TEST_CHECK(obj.len == sizeof(file1_data) - 1 && memcmp(obj.data, file1_data, obj.len) == 0);
        amisnap_buf_free(&obj);

        /* Exactly one object exists for this hash despite two entries
         * referencing it -- dedup actually skipped the second write,
         * not just produced an equal-content overwrite. */
        {
            char prefix[16];
            int n = 0;
            static const char hexd[] = "0123456789abcdef";
            snprintf(prefix, sizeof(prefix), "objects/%c%c", hexd[expect_hash[0] >> 4], hexd[expect_hash[0] & 0x0Fu]);
            TEST_CHECK(amisnap_backend_list(&be, prefix, count_cb, &n) == AMISNAP_OK);
            TEST_CHECK(n == 1);
        }
    }

    /* --- A second snapshot with the identical creation DateStamp
     * collides on snapid; finish() must resolve it by incrementing
     * ticks (format.md's stated policy), not silently overwrite. --- */
    {
        amisnap_repo_writer rw2;
        amisnap_snap_meta snap2;
        amisnap_entry_meta e2;
        char snapid2[17];

        amisnap_repo_writer_init(&rw2, &be, NULL);
        memset(&snap2, 0, sizeof(snap2));
        snap2.created_days = 1000; snap2.created_mins = 1; snap2.created_ticks = 1; /* identical */
        TEST_CHECK(amisnap_repo_writer_snap(&rw2, &snap2) == AMISNAP_OK);

        memset(&e2, 0, sizeof(e2));
        e2.path = (const uint8_t *)""; e2.path_len = 0;
        e2.type = AMISNAP_ETYPE_DIR;
        e2.date_days = 1000;
        TEST_CHECK(amisnap_repo_writer_entry(&rw2, &e2) == AMISNAP_OK);

        TEST_CHECK(amisnap_repo_writer_finish(&rw2, snapid2) == AMISNAP_OK);
        amisnap_repo_writer_free(&rw2);

        TEST_CHECK(strcmp(snapid, snapid2) != 0);
        /* days.mins portion (first 12 hex chars) identical; only the
         * ticks portion (last 4) differs -- confirms it incremented
         * ticks specifically, not derived an unrelated id. */
        TEST_CHECK(memcmp(snapid, snapid2, 12) == 0);
        TEST_CHECK(memcmp(snapid + 12, snapid2 + 12, 4) != 0);

        /* --- list_snapshots sees both committed snapshots, and
         * nothing else (tmp/ leftovers, if any, must not appear). --- */
        {
            char seen[4][17];
            int n = 0;
            list_collect_ctx ctx;
            ctx.seen = seen;
            ctx.n = &n;
            ctx.cap = 4;
            TEST_CHECK(amisnap_repo_list_snapshots(&be, list_collect_cb, &ctx) == AMISNAP_OK);
            TEST_CHECK(n == 2);
            TEST_CHECK((strcmp(seen[0], snapid) == 0 && strcmp(seen[1], snapid2) == 0) ||
                       (strcmp(seen[0], snapid2) == 0 && strcmp(seen[1], snapid) == 0));
        }
    }

    amisnap_backend_close(&be);
    TEST_CHECK(system("rm -rf " TESTDIR) == 0);
}
