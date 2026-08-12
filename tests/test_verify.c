/* test_verify.c -- amisnap_verify_manifest() (repo.h): structural
 * (existence only) and full (re-hash) modes, against a real directory
 * backend.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "repo.h"
#include "test.h"

#define REPODIR "build/test-verify-repo"

void run_verify_tests(void)
{
    amisnap_backend repo;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_entry_meta e;
    amisnap_content_ref ref2;
    char snapid[17];
    char mf_key[32];
    amisnap_buf mf;
    amisnap_verify_result result;
    static const char data1[] = "some file content here";
    static const char data2[] = "a second, different file";
    uint8_t hash2[32];
    char key2[AMISNAP_OBJECT_KEY_LEN];

    TEST_CHECK(system("rm -rf " REPODIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(REPODIR, &repo) == AMISNAP_OK);

    amisnap_repo_writer_init(&rw, &repo);
    memset(&snap, 0, sizeof(snap));
    snap.created_days = 3000; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"a.txt"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 3000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, data1, sizeof(data1) - 1) == AMISNAP_OK);

    /* A second file whose content is written directly (bypassing the
     * writer's own dedup path) so this test can corrupt/delete it
     * independently of a.txt below. */
    amisnap_blake2s256(data2, sizeof(data2) - 1, hash2);
    amisnap_repo_object_key(hash2, key2);
    TEST_CHECK(amisnap_backend_put(&repo, key2, data2, sizeof(data2) - 1) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"b.txt"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 3000;
    e.has_size = 1; e.size = sizeof(data2) - 1;
    memcpy(ref2.hash, hash2, 32); ref2.size = sizeof(data2) - 1;
    e.content = &ref2; e.content_count = 1;
    TEST_CHECK(amisnap_manifest_writer_entry(&rw.mw, &e) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    snprintf(mf_key, sizeof(mf_key), "snapshots/%s.mf", snapid);
    TEST_CHECK(amisnap_backend_get(&repo, mf_key, &mf) == AMISNAP_OK);

    /* --- Healthy repository: both modes report zero problems. --- */
    TEST_CHECK(amisnap_verify_manifest(&repo, mf.data, mf.len, 0, &result) == AMISNAP_OK);
    TEST_CHECK(result.objects_checked == 2);
    TEST_CHECK(result.objects_missing == 0);
    TEST_CHECK(result.objects_corrupt == 0);

    TEST_CHECK(amisnap_verify_manifest(&repo, mf.data, mf.len, 1, &result) == AMISNAP_OK);
    TEST_CHECK(result.objects_checked == 2);
    TEST_CHECK(result.objects_missing == 0);
    TEST_CHECK(result.objects_corrupt == 0);

    /* --- Delete b.txt's object: structural mode catches it via
     * existence alone. --- */
    TEST_CHECK(amisnap_backend_remove(&repo, key2) == AMISNAP_OK);

    TEST_CHECK(amisnap_verify_manifest(&repo, mf.data, mf.len, 0, &result) == AMISNAP_OK);
    TEST_CHECK(result.objects_checked == 2);
    TEST_CHECK(result.objects_missing == 1);
    TEST_CHECK(result.objects_corrupt == 0);

    /* --- Restore it, then corrupt its bytes in place: structural
     * mode (existence only) does NOT catch this -- that's exactly
     * what distinguishes it from full mode. --- */
    TEST_CHECK(amisnap_backend_put(&repo, key2, data2, sizeof(data2) - 1) == AMISNAP_OK);
    {
        /* Same length as data2, different bytes -- defeats a
         * length-only check the same way test_restore.c's corruption
         * case does. */
        char corrupt[64];
        size_t len = sizeof(data2) - 1;
        memset(corrupt, 'Z', len);
        TEST_CHECK(amisnap_backend_put(&repo, key2, corrupt, len) == AMISNAP_OK);
    }

    TEST_CHECK(amisnap_verify_manifest(&repo, mf.data, mf.len, 0, &result) == AMISNAP_OK);
    TEST_CHECK(result.objects_missing == 0);
    TEST_CHECK(result.objects_corrupt == 0); /* structural mode is blind to this, by design */

    TEST_CHECK(amisnap_verify_manifest(&repo, mf.data, mf.len, 1, &result) == AMISNAP_OK);
    TEST_CHECK(result.objects_checked == 2);
    TEST_CHECK(result.objects_missing == 0);
    TEST_CHECK(result.objects_corrupt == 1); /* full mode catches it */

    /* --- verify never aborts early: even with b.txt corrupted, a.txt
     * (checked either before or after it) is still reported on. --- */
    TEST_CHECK(result.objects_checked == 2);

    amisnap_buf_free(&mf);
    amisnap_backend_close(&repo);
    TEST_CHECK(system("rm -rf " REPODIR) == 0);
}
