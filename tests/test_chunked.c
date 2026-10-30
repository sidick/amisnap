/* test_chunked.c -- amisnap_repo_writer_file_chunked() (repo.h) end to
 * end: a small chunk size against real content designed to produce a
 * repeated chunk (dedup must still collapse it to one object), then
 * restore.c/verify (repo.c) prove the multi-E_CONTENT-ref entry it
 * produces round-trips correctly through code that was never itself
 * modified for chunking -- restore.c and verify_on_entry already loop
 * over content_count generically, so this is confirmation, not a new
 * code path being tested on their side.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "repo.h"
#include "restore.h"
#include "test.h"
#include "xxhash32.h"

#define REPODIR "build/test-chunked-repo"
#define CHUNK_SIZE 8

typedef struct {
    const uint8_t *data;
    size_t len, pos;
    size_t force_short_at; /* SIZE_MAX = never; otherwise return a
                             * short read once total bytes served
                             * reaches this offset, simulating a file
                             * that shrank mid-scan */
    int force_error;
} mem_reader;

static int mem_read(void *ctx, void *buf, size_t want, size_t *got)
{
    mem_reader *r = (mem_reader *)ctx;
    size_t avail;

    if (r->force_error) return AMISNAP_ERR_IO;

    avail = r->len - r->pos;
    if (want > avail) want = avail;
    if (r->pos + want > r->force_short_at && r->pos < r->force_short_at)
        want = r->force_short_at - r->pos;

    memcpy(buf, r->data + r->pos, want);
    r->pos += want;
    *got = want;
    return AMISNAP_OK;
}

void run_chunked_tests(void)
{
    amisnap_backend repo, dest;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    char snapid[17];
    /* 22 bytes, chunk_size=8 -> chunks of 8,8,6; chunk 0 ("AAAAAAAA")
     * and chunk 2's first 6 bytes ("BBBBBB") are deliberately NOT
     * equal to each other, but chunk 0 is repeated verbatim later in
     * the buffer via a second write (see the dedup entry below) --
     * content-ref dedup is proven across TWO entries sharing a chunk,
     * not within one entry, matching how it'd actually happen (two
     * different large files sharing a common block). */
#define CONTENT_A_LEN 22u
    static const uint8_t content_a[] = "AAAAAAAABBBBBBBBCCCCCC"; /* +1 for the compiler's own NUL */
    /* Second file: same first chunk as content_a ("AAAAAAAA"), 16
     * bytes total -> 2 chunks, the first identical to content_a's
     * first chunk. */
#define CONTENT_B_LEN 16u
    static const uint8_t content_b[] = "AAAAAAAADDDDDDDD"; /* +1 for the compiler's own NUL */
    mem_reader reader;
    int rc;

    TEST_CHECK(system("rm -rf " REPODIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(REPODIR, &repo) == AMISNAP_OK);

    amisnap_repo_writer_init(&rw, &repo, NULL);
    memset(&snap, 0, sizeof(snap));
    snap.created_days = 3000; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);
    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    /* --- file A: 22 bytes, chunk_size=8 -> 3 chunks (8+8+6) --- */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"a.bin"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 3000;

    reader.data = content_a; reader.len = CONTENT_A_LEN; reader.pos = 0;
    reader.force_short_at = (size_t)-1; reader.force_error = 0;

    rc = amisnap_repo_writer_file_chunked(&rw, &e, CONTENT_A_LEN, CHUNK_SIZE, mem_read, &reader);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(e.has_size && e.size == CONTENT_A_LEN);
    TEST_CHECK(e.content_count == 3);
    TEST_CHECK(e.has_xhash && e.xhash == amisnap_xxh32(content_a, CONTENT_A_LEN, 0));

    /* --- file B: 16 bytes, chunk_size=8 -> 2 chunks, first shared
     * with file A's own first chunk -- dedup must collapse it. --- */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"b.bin"; e.path_len = 5;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 3000;

    reader.data = content_b; reader.len = CONTENT_B_LEN; reader.pos = 0;
    reader.force_short_at = (size_t)-1; reader.force_error = 0;

    rc = amisnap_repo_writer_file_chunked(&rw, &e, CONTENT_B_LEN, CHUNK_SIZE, mem_read, &reader);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(e.content_count == 2);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    /* --- B's first chunk ("AAAAAAAA") is byte-identical to A's own
     * first chunk. Two checks: the shared object exists under its own
     * independently-recomputed hash (don't trust the writer's own
     * bookkeeping for what this is checking), AND the repository holds
     * exactly 4 unique objects total, not 5 -- A's 3 (AAAAAAAA,
     * BBBBBBBB, CCCCCC) plus only ONE new one from B (DDDDDDDD; B's
     * own first chunk reuses A's AAAAAAAA instead of writing a
     * duplicate) -- proving dedup genuinely collapsed the shared
     * chunk, not just that a plausible-looking file happens to exist.
     * Counted via a real directory walk (host test only -- backend.h's
     * own list() is one level at a time, no "how many objects total"
     * API, and this doesn't need one just to prove a count here). --- */
    {
        char key[AMISNAP_OBJECT_KEY_LEN];
        uint8_t hash[32];
        amisnap_blake2s256(content_a, 8, hash);
        amisnap_repo_object_key(hash, key);
        TEST_CHECK(amisnap_backend_exists(&repo, key) == 1);

        TEST_CHECK(system("find " REPODIR "/objects -type f | wc -l > "
                           REPODIR ".objcount") == 0);
        {
            FILE *f = fopen(REPODIR ".objcount", "r");
            int count = -1;
            TEST_CHECK(f != NULL);
            if (f) { TEST_CHECK(fscanf(f, "%d", &count) == 1); fclose(f); }
            TEST_CHECK(count == 4);
            remove(REPODIR ".objcount");
        }
    }

    /* --- restore both files and confirm exact byte-for-byte content
     * -- restore.c's own content-ref loop needed zero changes for
     * this to work, confirmed rather than assumed. --- */
    {
        amisnap_buf mf;
        amisnap_restore_result rresult;
        amisnap_verify_result vresult;
        char key[32];
        amisnap_buf got;

        TEST_CHECK(system("rm -rf " REPODIR "-dest") == 0);
        TEST_CHECK(amisnap_backend_dir_open(REPODIR "-dest", &dest) == AMISNAP_OK);

        snprintf(key, sizeof(key), "snapshots/%s.mf", snapid);
        TEST_CHECK(amisnap_backend_get(&repo, key, &mf) == AMISNAP_OK);

        TEST_CHECK(amisnap_restore_manifest(&repo, &dest, NULL, AMISNAP_OBJCOMP_RAW, NULL, mf.data, mf.len, NULL, &rresult) == AMISNAP_OK);
        TEST_CHECK(rresult.files_written == 2);

        TEST_CHECK(amisnap_backend_get(&dest, "a.bin", &got) == AMISNAP_OK);
        TEST_CHECK(got.len == CONTENT_A_LEN && memcmp(got.data, content_a, CONTENT_A_LEN) == 0);
        amisnap_buf_free(&got);

        TEST_CHECK(amisnap_backend_get(&dest, "b.bin", &got) == AMISNAP_OK);
        TEST_CHECK(got.len == CONTENT_B_LEN && memcmp(got.data, content_b, CONTENT_B_LEN) == 0);
        amisnap_buf_free(&got);

        TEST_CHECK(amisnap_verify_manifest(&repo, NULL, AMISNAP_OBJCOMP_RAW, NULL, mf.data, mf.len, 1, &vresult) == AMISNAP_OK);
        TEST_CHECK(vresult.objects_checked == 5); /* 3 refs for a.bin + 2 for b.bin, occurrence-counted */
        TEST_CHECK(vresult.objects_missing == 0 && vresult.objects_corrupt == 0);

        amisnap_buf_free(&mf);
        amisnap_backend_close(&dest);
        TEST_CHECK(system("rm -rf " REPODIR "-dest") == 0);
    }

    amisnap_backend_close(&repo);

    /* --- a file that shrinks mid-scan (short/early-EOF read_fn):
     * entry->size reflects what was actually read, not the caller's
     * possibly-stale total_size estimate -- honest, not a silent
     * truncation-without-reporting. --- */
    {
        amisnap_backend repo2;
        amisnap_repo_writer rw2;
        amisnap_entry_meta e2;
        mem_reader short_reader;

        TEST_CHECK(system("rm -rf " REPODIR "-short") == 0);
        TEST_CHECK(amisnap_backend_dir_open(REPODIR "-short", &repo2) == AMISNAP_OK);
        amisnap_repo_writer_init(&rw2, &repo2, NULL);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 3001; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw2, &snap) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_volume(&rw2, &vol) == AMISNAP_OK);

        memset(&e2, 0, sizeof(e2));
        e2.path = (const uint8_t *)"shrunk.bin"; e2.path_len = 10;
        e2.type = AMISNAP_ETYPE_FILE; e2.date_days = 3001;

        short_reader.data = content_a; short_reader.len = CONTENT_A_LEN; short_reader.pos = 0;
        short_reader.force_short_at = 10; /* claim 22 bytes total, only 10 actually readable */
        short_reader.force_error = 0;

        rc = amisnap_repo_writer_file_chunked(&rw2, &e2, CONTENT_A_LEN, CHUNK_SIZE,
                                               mem_read, &short_reader);
        TEST_CHECK(rc == AMISNAP_OK);
        TEST_CHECK(e2.size == 10); /* not 22 -- the caller's total_size was wrong, this is the truth */

        amisnap_repo_writer_free(&rw2);
        amisnap_backend_close(&repo2);
        TEST_CHECK(system("rm -rf " REPODIR "-short") == 0);
    }

    /* --- read_fn itself failing aborts the whole call with that
     * error, not a partial/silent success. --- */
    {
        amisnap_backend repo3;
        amisnap_repo_writer rw3;
        amisnap_entry_meta e3;
        mem_reader err_reader;

        TEST_CHECK(system("rm -rf " REPODIR "-err") == 0);
        TEST_CHECK(amisnap_backend_dir_open(REPODIR "-err", &repo3) == AMISNAP_OK);
        amisnap_repo_writer_init(&rw3, &repo3, NULL);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 3002; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw3, &snap) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_volume(&rw3, &vol) == AMISNAP_OK);

        memset(&e3, 0, sizeof(e3));
        e3.path = (const uint8_t *)"bad.bin"; e3.path_len = 7;
        e3.type = AMISNAP_ETYPE_FILE; e3.date_days = 3002;

        err_reader.data = content_a; err_reader.len = CONTENT_A_LEN; err_reader.pos = 0;
        err_reader.force_short_at = (size_t)-1; err_reader.force_error = 1;

        rc = amisnap_repo_writer_file_chunked(&rw3, &e3, CONTENT_A_LEN, CHUNK_SIZE,
                                               mem_read, &err_reader);
        TEST_CHECK(rc == AMISNAP_ERR_IO);

        amisnap_repo_writer_free(&rw3);
        amisnap_backend_close(&repo3);
        TEST_CHECK(system("rm -rf " REPODIR "-err") == 0);
    }

    /* --- a file needing more than the old fixed 4096-ref manifest
     * decode scratch (issue #22: the writer has never capped
     * content_count, but the reader used to -- a file between 1 and
     * 2GB at the real 256KiB default chunk size hit exactly this,
     * decoding-failing RESTORE/VERIFY/PRUNE on a snapshot that
     * SNAPSHOT itself had reported as a success). 4097 chunks of this
     * tiny CHUNK_SIZE is a ~32KB file, not a real 1GB+ one, but
     * exercises the identical code path: more E_CONTENT refs for one
     * entry than manifest.c's old AMISNAP_MANIFEST_MAX_CONTENT_REFS
     * (4096) ever allowed it to decode. --- */
    {
        amisnap_backend repo4, dest4;
        amisnap_repo_writer rw4;
        amisnap_entry_meta e4;
        amisnap_buf mf4;
        amisnap_restore_result rresult4;
        amisnap_verify_result vresult4;
        amisnap_buf got4;
        mem_reader many_reader;
        uint8_t *content_many;
        char snapid4[17];
        char key4[32];
#define MANY_CHUNK_COUNT 4097u
#define MANY_LEN (MANY_CHUNK_COUNT * CHUNK_SIZE)
        size_t i;

        content_many = (uint8_t *)malloc(MANY_LEN);
        TEST_CHECK(content_many != NULL);
        for (i = 0; i < MANY_LEN; i++)
            content_many[i] = (uint8_t)(i * 37 + i / CHUNK_SIZE); /* varies per chunk, no real dedup */

        TEST_CHECK(system("rm -rf " REPODIR "-many") == 0);
        TEST_CHECK(amisnap_backend_dir_open(REPODIR "-many", &repo4) == AMISNAP_OK);
        amisnap_repo_writer_init(&rw4, &repo4, NULL);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 3003; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw4, &snap) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_volume(&rw4, &vol) == AMISNAP_OK);

        memset(&e4, 0, sizeof(e4));
        e4.path = (const uint8_t *)"many.bin"; e4.path_len = 8;
        e4.type = AMISNAP_ETYPE_FILE; e4.date_days = 3003;

        many_reader.data = content_many; many_reader.len = MANY_LEN; many_reader.pos = 0;
        many_reader.force_short_at = (size_t)-1; many_reader.force_error = 0;

        rc = amisnap_repo_writer_file_chunked(&rw4, &e4, MANY_LEN, CHUNK_SIZE, mem_read, &many_reader);
        TEST_CHECK(rc == AMISNAP_OK);
        TEST_CHECK(e4.content_count == MANY_CHUNK_COUNT);

        TEST_CHECK(amisnap_repo_writer_finish(&rw4, snapid4) == AMISNAP_OK);
        amisnap_repo_writer_free(&rw4);

        snprintf(key4, sizeof(key4), "snapshots/%s.mf", snapid4);
        TEST_CHECK(amisnap_backend_get(&repo4, key4, &mf4) == AMISNAP_OK);

        TEST_CHECK(amisnap_verify_manifest(&repo4, NULL, AMISNAP_OBJCOMP_RAW, NULL,
                                            mf4.data, mf4.len, 1, &vresult4) == AMISNAP_OK);
        TEST_CHECK(vresult4.objects_checked == MANY_CHUNK_COUNT);
        TEST_CHECK(vresult4.objects_missing == 0 && vresult4.objects_corrupt == 0);

        TEST_CHECK(system("rm -rf " REPODIR "-many-dest") == 0);
        TEST_CHECK(amisnap_backend_dir_open(REPODIR "-many-dest", &dest4) == AMISNAP_OK);
        TEST_CHECK(amisnap_restore_manifest(&repo4, &dest4, NULL, AMISNAP_OBJCOMP_RAW, NULL,
                                             mf4.data, mf4.len, NULL, &rresult4) == AMISNAP_OK);
        TEST_CHECK(rresult4.files_written == 1);

        TEST_CHECK(amisnap_backend_get(&dest4, "many.bin", &got4) == AMISNAP_OK);
        TEST_CHECK(got4.len == MANY_LEN && memcmp(got4.data, content_many, MANY_LEN) == 0);
        amisnap_buf_free(&got4);

        free(content_many);
        amisnap_buf_free(&mf4);
        amisnap_backend_close(&repo4);
        amisnap_backend_close(&dest4);
        TEST_CHECK(system("rm -rf " REPODIR "-many " REPODIR "-many-dest") == 0);
#undef MANY_LEN
#undef MANY_CHUNK_COUNT
    }

    TEST_CHECK(system("rm -rf " REPODIR) == 0);
}
