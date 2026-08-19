/* test_repo_framed.c -- the OBJCOMP=1 write/fetch/verify/restore path
 * (repo.h wired to compress.h) end to end against a real directory
 * backend, plain and encrypted. Checks the bytes actually stored (a
 * frame header, a payload smaller than the content where compression
 * bit, the store-raw fallback where it didn't), not just that the
 * high-level API round-trips. Mirrors test_repo_encrypted.c's
 * structure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "compress.h"
#include "manifest.h"
#include "repo.h"
#include "restore.h"
#include "test.h"

#define TESTDIR "build/test-repo-framed"
#define DESTDIR "build/test-repo-framed-restore"

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

/* Compressible (long runs) and incompressible (xorshift32 noise)
 * fixtures, sized well past the frame header so the size assertions
 * below can't pass by accident. */
static uint8_t runs[8192];
static uint8_t noise[4096];

static void fill_fixtures(void)
{
    uint32_t x = 0x9E3779B9u;
    size_t i;

    for (i = 0; i < sizeof runs; i++)
        runs[i] = (uint8_t)(i >> 8);
    for (i = 0; i < sizeof noise; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        noise[i] = (uint8_t)x;
    }
}

static void plain_framed(void)
{
    amisnap_backend be;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    char snapid[17];
    char mf_key[32];
    amisnap_buf mf, obj, content;
    uint8_t hash[32];
    char objkey[80];

    TEST_CHECK(system("rm -rf " TESTDIR " " DESTDIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(TESTDIR, &be) == AMISNAP_OK);

    amisnap_repo_writer_init(&rw, &be, NULL);
    amisnap_repo_writer_set_compression(&rw, AMISNAP_COMP_LZ4);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 2100; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"runs.bin"; e.path_len = 8;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 2100;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, runs, sizeof runs) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"noise.bin"; e.path_len = 9;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 2100;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, noise, sizeof noise) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    /* --- Stored bytes: the compressible object is an LZ4 frame,
     * genuinely smaller than its content; the noise object fell back
     * to a stored frame (exactly content + header). --- */
    amisnap_blake2s256(runs, sizeof runs, hash);
    object_key_for(hash, objkey);
    TEST_CHECK(amisnap_backend_get(&be, objkey, &obj) == AMISNAP_OK);
    TEST_CHECK(obj.len >= AMISNAP_FRAME_HDR_SIZE && obj.data[0] == AMISNAP_COMP_LZ4);
    TEST_CHECK(obj.len < sizeof runs);
    TEST_CHECK(amisnap_get_be64(obj.data + 1) == sizeof runs);
    amisnap_buf_free(&obj);

    amisnap_blake2s256(noise, sizeof noise, hash);
    object_key_for(hash, objkey);
    TEST_CHECK(amisnap_backend_get(&be, objkey, &obj) == AMISNAP_OK);
    TEST_CHECK(obj.len == AMISNAP_FRAME_HDR_SIZE + sizeof noise);
    TEST_CHECK(obj.data[0] == AMISNAP_COMP_STORED);
    TEST_CHECK(memcmp(obj.data + AMISNAP_FRAME_HDR_SIZE, noise, sizeof noise) == 0);
    amisnap_buf_free(&obj);

    /* --- Fetch decodes and hash-verifies; fetching with the WRONG
     * objcomp (raw) must fail loudly, not hand back frame bytes. --- */
    {
        amisnap_content_ref ref;

        amisnap_blake2s256(runs, sizeof runs, ref.hash);
        ref.size = sizeof runs;
        TEST_CHECK(amisnap_repo_fetch_object(&be, NULL, AMISNAP_OBJCOMP_FRAMED, &ref, &content) == AMISNAP_OK);
        TEST_CHECK(content.len == sizeof runs && memcmp(content.data, runs, sizeof runs) == 0);
        amisnap_buf_free(&content);

        TEST_CHECK(amisnap_repo_fetch_object(&be, NULL, AMISNAP_OBJCOMP_RAW, &ref, &content)
                   == AMISNAP_ERR_MALFORMED);
    }

    /* --- verify FULL and restore, through the public entry points. --- */
    snprintf(mf_key, sizeof(mf_key), "snapshots/%s.mf", snapid);
    TEST_CHECK(amisnap_backend_get(&be, mf_key, &mf) == AMISNAP_OK);
    {
        amisnap_verify_result vresult;

        TEST_CHECK(amisnap_verify_manifest(&be, NULL, AMISNAP_OBJCOMP_FRAMED, NULL,
                                           mf.data, mf.len, 1, &vresult) == AMISNAP_OK);
        TEST_CHECK(vresult.objects_checked == 2);
        TEST_CHECK(vresult.objects_missing == 0);
        TEST_CHECK(vresult.objects_corrupt == 0);

        /* The same verify told the repository is raw calls everything
         * corrupt -- the mismatch is detected, never silent. */
        TEST_CHECK(amisnap_verify_manifest(&be, NULL, AMISNAP_OBJCOMP_RAW, NULL,
                                           mf.data, mf.len, 1, &vresult) == AMISNAP_OK);
        TEST_CHECK(vresult.objects_corrupt == 2);
    }
    {
        amisnap_backend dest;
        amisnap_restore_result rresult;
        FILE *f;
        uint8_t back[sizeof runs];

        TEST_CHECK(amisnap_backend_dir_open(DESTDIR, &dest) == AMISNAP_OK);
        TEST_CHECK(amisnap_restore_manifest(&be, &dest, NULL, AMISNAP_OBJCOMP_FRAMED, NULL,
                                            mf.data, mf.len, NULL, &rresult) == AMISNAP_OK);
        TEST_CHECK(rresult.files_written == 2);
        amisnap_backend_close(&dest);

        f = fopen(DESTDIR "/runs.bin", "rb");
        TEST_CHECK(f != NULL);
        if (f) {
            TEST_CHECK(fread(back, 1, sizeof back, f) == sizeof runs);
            TEST_CHECK(memcmp(back, runs, sizeof runs) == 0);
            fclose(f);
        }
    }
    amisnap_buf_free(&mf);

    /* --- Dedup across writers with a different preference: a second
     * snapshot of the same content writes no new object bytes, and the
     * ref still decodes against the original writer's frame. --- */
    {
        amisnap_repo_writer rw2;
        amisnap_content_ref ref;
        char snapid2[17];
        amisnap_buf before, after;

        amisnap_blake2s256(runs, sizeof runs, hash);
        object_key_for(hash, objkey);
        TEST_CHECK(amisnap_backend_get(&be, objkey, &before) == AMISNAP_OK);

        amisnap_repo_writer_init(&rw2, &be, NULL);
        amisnap_repo_writer_set_compression(&rw2, AMISNAP_COMP_ZLIB);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 2101; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw2, &snap) == AMISNAP_OK);
        memset(&vol, 0, sizeof(vol));
        vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
        TEST_CHECK(amisnap_repo_writer_volume(&rw2, &vol) == AMISNAP_OK);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"runs.bin"; e.path_len = 8;
        e.type = AMISNAP_ETYPE_FILE;
        e.date_days = 2101;
        TEST_CHECK(amisnap_repo_writer_file(&rw2, &e, runs, sizeof runs) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_finish(&rw2, snapid2) == AMISNAP_OK);
        amisnap_repo_writer_free(&rw2);

        TEST_CHECK(amisnap_backend_get(&be, objkey, &after) == AMISNAP_OK);
        TEST_CHECK(after.len == before.len && memcmp(after.data, before.data, after.len) == 0);
        TEST_CHECK(after.data[0] == AMISNAP_COMP_LZ4); /* the original frame, untouched */
        amisnap_buf_free(&before);
        amisnap_buf_free(&after);

        memcpy(ref.hash, hash, 32);
        ref.size = sizeof runs;
        TEST_CHECK(amisnap_repo_fetch_object(&be, NULL, AMISNAP_OBJCOMP_FRAMED, &ref, &content) == AMISNAP_OK);
        TEST_CHECK(content.len == sizeof runs && memcmp(content.data, runs, sizeof runs) == 0);
        amisnap_buf_free(&content);
    }

    amisnap_backend_close(&be);
}

static void encrypted_framed(void)
{
    amisnap_backend be;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    amisnap_repo_subkeys sk;
    uint8_t key[32];
    char snapid[17];
    char mf_key[32];
    amisnap_buf mf, obj, content;
    uint8_t hash[32];
    char objkey[80];
    int i;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0xE0 + i);
    amisnap_repo_derive_subkeys(key, &sk);

    TEST_CHECK(system("rm -rf " TESTDIR " " DESTDIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(TESTDIR, &be) == AMISNAP_OK);

    amisnap_repo_writer_init(&rw, &be, &sk);
    amisnap_repo_writer_set_compression(&rw, AMISNAP_COMP_ZLIB);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 2102; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);
    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"runs.bin"; e.path_len = 8;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 2102;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, runs, sizeof runs) == AMISNAP_OK);
    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    /* --- Stored bytes: encryption envelope around a *compressed*
     * frame -- so the object is smaller than plaintext + envelope
     * would be (compress-then-encrypt actually compressed), and the
     * plaintext is nowhere in it. --- */
    amisnap_blake2s256(runs, sizeof runs, hash);
    object_key_for(hash, objkey);
    TEST_CHECK(amisnap_backend_get(&be, objkey, &obj) == AMISNAP_OK);
    TEST_CHECK(obj.len < AMISNAP_REPO_NONCE_SIZE + sizeof runs + AMISNAP_REPO_MAC_SIZE);
    TEST_CHECK(obj.len >= AMISNAP_REPO_NONCE_SIZE + AMISNAP_FRAME_HDR_SIZE + AMISNAP_REPO_MAC_SIZE);
    {
        size_t j, found = 0;
        for (j = 0; j + 64 <= obj.len; j++) {
            if (memcmp(obj.data + j, runs, 64) == 0) { found = 1; break; }
        }
        TEST_CHECK(!found);
    }
    amisnap_buf_free(&obj);

    /* --- Fetch decrypts, decodes, verifies. --- */
    {
        amisnap_content_ref ref;

        memcpy(ref.hash, hash, 32);
        ref.size = sizeof runs;
        TEST_CHECK(amisnap_repo_fetch_object(&be, &sk, AMISNAP_OBJCOMP_FRAMED, &ref, &content) == AMISNAP_OK);
        TEST_CHECK(content.len == sizeof runs && memcmp(content.data, runs, sizeof runs) == 0);
        amisnap_buf_free(&content);
    }

    /* --- verify FULL through the public entry point. --- */
    snprintf(mf_key, sizeof(mf_key), "snapshots/%s.mf", snapid);
    TEST_CHECK(amisnap_backend_get(&be, mf_key, &mf) == AMISNAP_OK);
    {
        amisnap_verify_result vresult;

        TEST_CHECK(amisnap_verify_manifest(&be, &sk, AMISNAP_OBJCOMP_FRAMED, snapid,
                                           mf.data, mf.len, 1, &vresult) == AMISNAP_OK);
        TEST_CHECK(vresult.objects_checked == 1);
        TEST_CHECK(vresult.objects_missing == 0);
        TEST_CHECK(vresult.objects_corrupt == 0);
    }
    amisnap_buf_free(&mf);

    amisnap_backend_close(&be);
}

void run_repo_framed_tests(void)
{
    fill_fixtures();
    plain_framed();
    encrypted_framed();
}
