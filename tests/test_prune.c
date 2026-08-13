/* test_prune.c -- amisnap_prune_execute() (prune.h) against a real
 * directory backend: two snapshots sharing one deduplicated object,
 * each with one object unique to itself, plus a stray tmp/ leftover
 * simulating an interrupted run. Confirms mark-and-sweep keeps exactly
 * what's still referenced and nothing else -- format.md's "Prune"
 * section, checked end to end rather than trusted from reading the
 * code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "prune.h"
#include "repo.h"
#include "test.h"

#define REPODIR "build/test-prune-repo"

static char *g_snapid_a;
static char *g_snapid_b;

static char snapid_a_buf[17];
static char snapid_b_buf[17];

/* commit_snapshot writes one snapshot with two files: "shared.txt"
 * (identical bytes across both calls -- dedup must land on the same
 * object) and "only<tag>.txt" (unique bytes per call). snap.created_*
 * must differ between the two calls, or amisnap_repo_writer_finish's
 * own id-collision bump would silently make them adjacent ticks --
 * still two real snapshots either way, but distinct days keeps this
 * test's intent obvious to a reader. */
static void commit_snapshot(amisnap_backend *repo, uint32_t days, const char *tag,
                             char snapid_out[17])
{
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    char unique_data[32];
    char path[32];

    amisnap_repo_writer_init(&rw, repo, NULL);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = days; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"shared.txt"; e.path_len = 10;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = days;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "same bytes", 10) == AMISNAP_OK);

    snprintf(path, sizeof(path), "only%s.txt", tag);
    snprintf(unique_data, sizeof(unique_data), "unique to %s", tag);
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)path; e.path_len = strlen(path);
    e.type = AMISNAP_ETYPE_FILE; e.date_days = days;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, unique_data, strlen(unique_data)) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid_out) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);
}

static int count_snapshots_cb_n;
static void count_snapshots_cb(void *user, const char *snapid)
{
    (void)user; (void)snapid;
    count_snapshots_cb_n++;
}

void run_prune_tests(void)
{
    amisnap_backend repo;
    amisnap_prune_result result;
    const char *delete_ids[1];
    char obj_shared[AMISNAP_OBJECT_KEY_LEN];
    char obj_only_a[AMISNAP_OBJECT_KEY_LEN];
    char obj_only_b[AMISNAP_OBJECT_KEY_LEN];
    uint8_t hash[32];

    g_snapid_a = snapid_a_buf;
    g_snapid_b = snapid_b_buf;

    TEST_CHECK(system("rm -rf " REPODIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(REPODIR, &repo) == AMISNAP_OK);

    commit_snapshot(&repo, 2000, "a", g_snapid_a);
    commit_snapshot(&repo, 2001, "b", g_snapid_b);

    /* Recompute the three objects' own keys independently of the
     * writer, the same way the format.md disaster-recovery reader
     * would: hash the plaintext ourselves, don't trust repo.c's own
     * bookkeeping for what this test is checking. */
    {
        amisnap_blake2s256("same bytes", 10, hash);
        amisnap_repo_object_key(hash, obj_shared);
        amisnap_blake2s256("unique to a", 11, hash);
        amisnap_repo_object_key(hash, obj_only_a);
        amisnap_blake2s256("unique to b", 11, hash);
        amisnap_repo_object_key(hash, obj_only_b);
    }

    TEST_CHECK(amisnap_backend_exists(&repo, obj_shared) == 1);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_only_a) == 1);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_only_b) == 1);

    /* A stray tmp/ leftover, simulating an interrupted run -- prune
     * must sweep it even though nothing ever referenced it. */
    TEST_CHECK(amisnap_backend_put(&repo, "tmp/orphan", "x", 1) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_exists(&repo, "tmp/orphan") == 1);

    /* --- Prune snapshot A. "shared.txt"'s object must survive (B
     * still references it); "onlyA.txt"'s object must not. --- */
    delete_ids[0] = g_snapid_a;
    TEST_CHECK(amisnap_prune_execute(&repo, NULL, delete_ids, 1, &result) == AMISNAP_OK);
    TEST_CHECK(result.snapshots_deleted == 1);
    TEST_CHECK(result.objects_deleted == 1); /* only "onlyA.txt"'s object */
    TEST_CHECK(result.tmp_deleted == 1);

    TEST_CHECK(amisnap_backend_exists(&repo, obj_shared) == 1);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_only_a) == 0);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_only_b) == 1);
    TEST_CHECK(amisnap_backend_exists(&repo, "tmp/orphan") == 0);

    /* Snapshot A itself is gone; B remains and is the only one listed. */
    {
        char key[64];
        snprintf(key, sizeof(key), "snapshots/%s.mf", g_snapid_a);
        TEST_CHECK(amisnap_backend_exists(&repo, key) == 0);
        snprintf(key, sizeof(key), "snapshots/%s.mf", g_snapid_b);
        TEST_CHECK(amisnap_backend_exists(&repo, key) == 1);
    }
    count_snapshots_cb_n = 0;
    TEST_CHECK(amisnap_repo_list_snapshots(&repo, count_snapshots_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(count_snapshots_cb_n == 1);

    /* --- A repeat prune of the same (now-gone) id is a harmless no-op,
     * not an error -- amisnap_backend_remove's own AMISNAP_ERR_NOT_FOUND
     * must not abort the call. --- */
    TEST_CHECK(amisnap_prune_execute(&repo, NULL, delete_ids, 1, &result) == AMISNAP_OK);
    TEST_CHECK(result.snapshots_deleted == 0);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_shared) == 1);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_only_b) == 1);

    /* --- Pruning every remaining snapshot leaves an empty repository:
     * every object gone, nothing left referenced. --- */
    delete_ids[0] = g_snapid_b;
    TEST_CHECK(amisnap_prune_execute(&repo, NULL, delete_ids, 1, &result) == AMISNAP_OK);
    TEST_CHECK(result.snapshots_deleted == 1);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_shared) == 0);
    TEST_CHECK(amisnap_backend_exists(&repo, obj_only_b) == 0);
    count_snapshots_cb_n = 0;
    TEST_CHECK(amisnap_repo_list_snapshots(&repo, count_snapshots_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(count_snapshots_cb_n == 0);

    amisnap_backend_close(&repo);
    TEST_CHECK(system("rm -rf " REPODIR) == 0);
}
