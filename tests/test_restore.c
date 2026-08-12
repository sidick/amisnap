/* test_restore.c -- amisnap_restore_manifest() against real directory
 * backends (repo source and restore destination are two separate
 * amisnap_backend_dir instances, exactly like a real restore-to-
 * alternate-path run).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "manifest.h"
#include "repo.h"
#include "restore.h"
#include "test.h"

#define REPODIR "build/test-restore-repo"
#define DESTDIR "build/test-restore-dest"

static amisnap_buf build_and_commit(amisnap_backend *repo, char snapid_out[17])
{
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    static const char root_data[] = "root file";
    static const char sub_data[] = "nested file content";
    amisnap_buf mf;

    amisnap_repo_writer_init(&rw, repo);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 2000; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    /* root dir */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)""; e.path_len = 0;
    e.type = AMISNAP_ETYPE_DIR; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_entry(&rw, &e) == AMISNAP_OK);

    /* a file directly under the root */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"root.txt"; e.path_len = 8;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, root_data, sizeof(root_data) - 1) == AMISNAP_OK);

    /* an empty subdirectory -- restore must create it even though no
     * file ever writes into it. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Empty"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_DIR; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_entry(&rw, &e) == AMISNAP_OK);

    /* a subdirectory with a file in it */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Sub"; e.path_len = 3;
    e.type = AMISNAP_ETYPE_DIR; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_entry(&rw, &e) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Sub/nested.txt"; e.path_len = 14;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, sub_data, sizeof(sub_data) - 1) == AMISNAP_OK);

    /* a zero-byte file */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Sub/empty.txt"; e.path_len = 13;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, NULL, 0) == AMISNAP_OK);

    /* a softlink -- deliberately unsupported by restore right now;
     * confirms it's skipped and counted, not crashed on or dropped
     * silently. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"LinkToWork"; e.path_len = 10;
    e.type = AMISNAP_ETYPE_SOFTLINK; e.date_days = 2000;
    e.has_link = 1; e.link = (const uint8_t *)"Work:"; e.link_len = 5;
    TEST_CHECK(amisnap_repo_writer_entry(&rw, &e) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid_out) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    {
        char key[32];
        snprintf(key, sizeof(key), "snapshots/%s.mf", snapid_out);
        TEST_CHECK(amisnap_backend_get(repo, key, &mf) == AMISNAP_OK);
    }
    return mf;
}

typedef struct {
    amisnap_backend *dest;
    size_t count;
    int sub_children_existed;
} meta_cb_ctx;

static int path_is(const amisnap_entry_meta *entry, const char *s)
{
    size_t len = strlen(s);
    return entry->path_len == len && memcmp(entry->path, s, len) == 0;
}

/* Regression check for the real bug the real-FFS Copperline harness found
 * (implementation-plan.md item 8's real-FFS follow-up, 2026-08-12): real
 * AmigaDOS filesystems update a directory's own datestamp (and evidently
 * its protection) whenever an entry is later created inside it, so a
 * directory's metadata must not be applied until every entry -- including
 * its own children -- already exists at `dest`. Confirms this by checking
 * "Sub"'s two children already exist at the moment "Sub" itself is handed
 * to the callback; under the old immediately-after-mkcol() ordering this
 * would be false (Sub/nested.txt and Sub/empty.txt are later entries in
 * the same manifest, not yet restored when "Sub" was created). */
static void record_entry_restored(void *user, const amisnap_entry_meta *entry)
{
    meta_cb_ctx *ctx = (meta_cb_ctx *)user;

    ctx->count++;
    if (path_is(entry, "Sub")) {
        ctx->sub_children_existed =
            amisnap_backend_exists(ctx->dest, "Sub/nested.txt") == 1 &&
            amisnap_backend_exists(ctx->dest, "Sub/empty.txt") == 1;
    }
}

void run_restore_tests(void)
{
    amisnap_backend repo, dest;
    amisnap_buf mf;
    char snapid[17];
    amisnap_restore_result result;

    TEST_CHECK(system("rm -rf " REPODIR " " DESTDIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(REPODIR, &repo) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_dir_open(DESTDIR, &dest) == AMISNAP_OK);

    mf = build_and_commit(&repo, snapid);

    /* --- Full restore --- */
    TEST_CHECK(amisnap_restore_manifest(&repo, &dest, mf.data, mf.len, NULL, &result) == AMISNAP_OK);
    TEST_CHECK(result.files_written == 3); /* root.txt, Sub/nested.txt, Sub/empty.txt */
    TEST_CHECK(result.dirs_created == 3);  /* "", Empty, Sub */
    TEST_CHECK(result.links_skipped == 1);
    TEST_CHECK(result.entries_skipped == 0);
    TEST_CHECK(result.bytes_written == 9 + 19); /* "root file" + "nested file content" */

    {
        amisnap_buf got;
        TEST_CHECK(amisnap_backend_get(&dest, "root.txt", &got) == AMISNAP_OK);
        TEST_CHECK(got.len == 9 && memcmp(got.data, "root file", 9) == 0);
        amisnap_buf_free(&got);

        TEST_CHECK(amisnap_backend_get(&dest, "Sub/nested.txt", &got) == AMISNAP_OK);
        TEST_CHECK(got.len == 19 && memcmp(got.data, "nested file content", 19) == 0);
        amisnap_buf_free(&got);

        TEST_CHECK(amisnap_backend_get(&dest, "Sub/empty.txt", &got) == AMISNAP_OK);
        TEST_CHECK(got.len == 0);
        amisnap_buf_free(&got);

        /* The empty directory really was created, not just implied
         * by some other file's parent-dir side effect. */
        TEST_CHECK(amisnap_backend_exists(&dest, "Empty") == 1);

        /* The softlink target was never written as a file. */
        TEST_CHECK(amisnap_backend_exists(&dest, "LinkToWork") == 0);
    }

    /* --- on_entry_restored (the Amiga metadata hook) fires only after
     * every entry's content/container already exists -- see
     * record_entry_restored's own comment above for why this matters. --- */
    {
        amisnap_backend dest6;
        amisnap_restore_options opts6;
        amisnap_restore_result r6;
        meta_cb_ctx ctx;

        TEST_CHECK(system("rm -rf " DESTDIR "6") == 0);
        TEST_CHECK(amisnap_backend_dir_open(DESTDIR "6", &dest6) == AMISNAP_OK);

        memset(&ctx, 0, sizeof(ctx));
        ctx.dest = &dest6;

        memset(&opts6, 0, sizeof(opts6));
        opts6.on_entry_restored = record_entry_restored;
        opts6.user = &ctx;

        TEST_CHECK(amisnap_restore_manifest(&repo, &dest6, mf.data, mf.len, &opts6, &r6) == AMISNAP_OK);
        /* every non-link entry: "", root.txt, Empty, Sub, Sub/nested.txt, Sub/empty.txt */
        TEST_CHECK(ctx.count == 6);
        TEST_CHECK(ctx.sub_children_existed == 1);

        amisnap_backend_close(&dest6);
        TEST_CHECK(system("rm -rf " DESTDIR "6") == 0);
    }

    /* --- Subtree restore: only "Sub" and its contents --- */
    {
        amisnap_backend dest2;
        amisnap_restore_options opts;
        amisnap_restore_result r2;

        TEST_CHECK(system("rm -rf " DESTDIR "2") == 0);
        TEST_CHECK(amisnap_backend_dir_open(DESTDIR "2", &dest2) == AMISNAP_OK);

        memset(&opts, 0, sizeof(opts));
        opts.subtree_prefix = (const uint8_t *)"Sub";
        opts.subtree_prefix_len = 3;

        TEST_CHECK(amisnap_restore_manifest(&repo, &dest2, mf.data, mf.len, &opts, &r2) == AMISNAP_OK);
        TEST_CHECK(r2.dirs_created == 1);   /* "Sub" itself */
        TEST_CHECK(r2.files_written == 2);  /* Sub/nested.txt, Sub/empty.txt */
        /* everything else ("", root.txt, Empty, LinkToWork) is outside
         * the subtree and must be skipped, not restored. */
        TEST_CHECK(r2.entries_skipped == 4);
        TEST_CHECK(amisnap_backend_exists(&dest2, "root.txt") == 0);
        TEST_CHECK(amisnap_backend_exists(&dest2, "Sub/nested.txt") == 1);

        /* A prefix that only looks similar ("Su") must not match --
         * component-boundary correctness. */
        {
            amisnap_backend dest3;
            amisnap_restore_options opts3;
            amisnap_restore_result r3;
            TEST_CHECK(system("rm -rf " DESTDIR "3") == 0);
            TEST_CHECK(amisnap_backend_dir_open(DESTDIR "3", &dest3) == AMISNAP_OK);
            memset(&opts3, 0, sizeof(opts3));
            opts3.subtree_prefix = (const uint8_t *)"Su";
            opts3.subtree_prefix_len = 2;
            TEST_CHECK(amisnap_restore_manifest(&repo, &dest3, mf.data, mf.len, &opts3, &r3) == AMISNAP_OK);
            TEST_CHECK(r3.dirs_created == 0 && r3.files_written == 0);
            amisnap_backend_close(&dest3);
            TEST_CHECK(system("rm -rf " DESTDIR "3") == 0);
        }

        amisnap_backend_close(&dest2);
        TEST_CHECK(system("rm -rf " DESTDIR "2") == 0);
    }

    /* --- A missing object aborts the restore, reported via the
     * return code (implementation-plan.md principle 1: a data-losing
     * bug is fatal -- restore must not silently produce a partial
     * tree with no indication anything went wrong). --- */
    {
        amisnap_backend dest4;
        amisnap_restore_result r4;
        char objkey[AMISNAP_OBJECT_KEY_LEN];
        uint8_t hash[32];
        static const char root_data[] = "root file";

        amisnap_blake2s256(root_data, sizeof(root_data) - 1, hash);
        amisnap_repo_object_key(hash, objkey);
        TEST_CHECK(amisnap_backend_remove(&repo, objkey) == AMISNAP_OK);

        TEST_CHECK(system("rm -rf " DESTDIR "4") == 0);
        TEST_CHECK(amisnap_backend_dir_open(DESTDIR "4", &dest4) == AMISNAP_OK);
        TEST_CHECK(amisnap_restore_manifest(&repo, &dest4, mf.data, mf.len, NULL, &r4) == AMISNAP_ERR_NOT_FOUND);
        amisnap_backend_close(&dest4);
        TEST_CHECK(system("rm -rf " DESTDIR "4") == 0);

        /* Restore that object so later assertions in this function
         * (none currently, but future edits) aren't left with a
         * corrupted fixture repo. */
        TEST_CHECK(amisnap_backend_put(&repo, objkey, root_data, sizeof(root_data) - 1) == AMISNAP_OK);
    }

    /* --- A corrupted object (bytes don't match its declared hash)
     * aborts with AMISNAP_ERR_HASH_MISMATCH, never gets written out. --- */
    {
        amisnap_backend dest5;
        amisnap_restore_result r5;
        char objkey[AMISNAP_OBJECT_KEY_LEN];
        uint8_t hash[32];
        static const char sub_data[] = "nested file content";

        amisnap_blake2s256(sub_data, sizeof(sub_data) - 1, hash);
        amisnap_repo_object_key(hash, objkey);
        /* Same length as the real content (so the length check alone
         * wouldn't catch it) but different bytes. */
        TEST_CHECK(amisnap_backend_put(&repo, objkey, "XXXXXXXXXXXXXXXXXXX", 19) == AMISNAP_OK);

        TEST_CHECK(system("rm -rf " DESTDIR "5") == 0);
        TEST_CHECK(amisnap_backend_dir_open(DESTDIR "5", &dest5) == AMISNAP_OK);
        TEST_CHECK(amisnap_restore_manifest(&repo, &dest5, mf.data, mf.len, NULL, &r5) == AMISNAP_ERR_HASH_MISMATCH);
        /* The corrupted file itself must never have been written. */
        TEST_CHECK(amisnap_backend_exists(&dest5, "Sub/nested.txt") == 0);
        amisnap_backend_close(&dest5);
        TEST_CHECK(system("rm -rf " DESTDIR "5") == 0);
    }

    amisnap_buf_free(&mf);
    amisnap_backend_close(&repo);
    amisnap_backend_close(&dest);
    TEST_CHECK(system("rm -rf " REPODIR " " DESTDIR) == 0);
}
