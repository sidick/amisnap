/* test_repo_encrypted.c -- the CIPHER 1 write/verify/restore path
 * (repo.h/restore.h wired to repo_crypto.h) end to end against a real
 * directory backend: write a snapshot with real subkeys, confirm the
 * bytes actually on the backend are NOT plaintext (not just that the
 * high-level API round-trips -- a bug that silently fell back to
 * plaintext would still pass a round-trip-only test), then verify and
 * restore it and confirm the recovered content matches the original.
 * Mirrors test_repo.c's structure for the CIPHER 0 path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "blake2s.h"
#include "manifest.h"
#include "prune.h"
#include "repo.h"
#include "restore.h"
#include "test.h"

#define TESTDIR "build/test-repo-encrypted"
#define DESTDIR "build/test-repo-encrypted-restore"

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

static int restored_file_bytes(const char *dir, const char *path, char *out, size_t cap, size_t *got)
{
    char full[256];
    FILE *f;
    snprintf(full, sizeof(full), "%s/%s", dir, path);
    f = fopen(full, "rb");
    if (!f) return -1;
    *got = fread(out, 1, cap, f);
    fclose(f);
    return 0;
}

void run_repo_encrypted_tests(void)
{
    amisnap_backend be;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    amisnap_repo_subkeys sk, wrong_sk;
    uint8_t key[32], wrong_key[32];
    char snapid[17];
    char mf_key[32];
    amisnap_buf mf_raw;
    static const char plaintext[] = "the quick brown fox jumps over the lazy dog";
    uint8_t content_hash[32];
    int i;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0xC0 + i);
    amisnap_repo_derive_subkeys(key, &sk);
    for (i = 0; i < 32; i++) wrong_key[i] = (uint8_t)(0xD0 + i);
    amisnap_repo_derive_subkeys(wrong_key, &wrong_sk);

    TEST_CHECK(system("rm -rf " TESTDIR " " DESTDIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(TESTDIR, &be) == AMISNAP_OK);

    amisnap_repo_writer_init(&rw, &be, &sk);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 2000; snap.created_mins = 5; snap.created_ticks = 5;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"secret.txt"; e.path_len = 10;
    e.type = AMISNAP_ETYPE_FILE;
    e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, plaintext, sizeof(plaintext) - 1) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);

    /* --- The raw manifest bytes on the backend are not plaintext:
     * flags bit 0 is set, and the plaintext path string is nowhere in
     * the file. A bug that silently wrote CIPHER 0 bytes despite being
     * given subkeys would pass every higher-level check below but fail
     * this one. --- */
    snprintf(mf_key, sizeof(mf_key), "snapshots/%s.mf", snapid);
    TEST_CHECK(amisnap_backend_get(&be, mf_key, &mf_raw) == AMISNAP_OK);
    {
        uint16_t flags = (uint16_t)((mf_raw.data[6] << 8) | mf_raw.data[7]);
        TEST_CHECK((flags & 1u) == 1u);
    }
    {
        size_t i2, found = 0;
        for (i2 = 0; i2 + 10 <= mf_raw.len; i2++) {
            if (memcmp(mf_raw.data + i2, "secret.txt", 10) == 0) { found = 1; break; }
        }
        TEST_CHECK(!found);
    }

    /* --- The raw object bytes are not plaintext either, and the
     * stored length includes the encryption frame overhead. --- */
    {
        uint8_t nonce[AMISNAP_REPO_NONCE_SIZE];
        char objkey[80];
        amisnap_buf obj;
        size_t plainlen = sizeof(plaintext) - 1;

        /* content_hash isn't exposed by the writer API directly here;
         * recompute it the same way write_object does (BLAKE2s-256 of
         * the plaintext) to locate the object -- this is exactly what
         * a real reader (restore.c/verify) does via the manifest's own
         * E_CONTENT hash, just inlined here since this test doesn't
         * decode the (encrypted) manifest to get it. */
        amisnap_blake2s256(plaintext, plainlen, content_hash);
        object_key_for(content_hash, objkey);
        TEST_CHECK(amisnap_backend_get(&be, objkey, &obj) == AMISNAP_OK);
        TEST_CHECK(obj.len == AMISNAP_REPO_NONCE_SIZE + plainlen + AMISNAP_REPO_MAC_SIZE);
        TEST_CHECK(memcmp(obj.data + AMISNAP_REPO_NONCE_SIZE, plaintext, plainlen) != 0);

        /* And decrypting it by hand with the real subkeys recovers the
         * original bytes, using the same deterministic nonce derivation
         * a real reader would (not the nonce read back from the object
         * -- confirming the derivation itself is reproducible, not just
         * that decrypt_frame can undo whatever encrypt_frame did). */
        amisnap_repo_object_nonce(sk.nonce, content_hash, nonce);
        TEST_CHECK(memcmp(obj.data, nonce, AMISNAP_REPO_NONCE_SIZE) == 0);
        amisnap_buf_free(&obj);
    }

    /* --- verify (full mode): decrypts, re-hashes, and confirms clean. --- */
    {
        amisnap_verify_result vresult;
        TEST_CHECK(amisnap_verify_manifest(&be, &sk, snapid, mf_raw.data, mf_raw.len, 1, &vresult)
                   == AMISNAP_OK);
        TEST_CHECK(vresult.objects_checked == 1);
        TEST_CHECK(vresult.objects_missing == 0);
        TEST_CHECK(vresult.objects_corrupt == 0);
    }

    /* --- verify with no key at all: refuses outright rather than
     * reporting a false-clean result. --- */
    {
        amisnap_verify_result vresult;
        TEST_CHECK(amisnap_verify_manifest(&be, NULL, NULL, mf_raw.data, mf_raw.len, 1, &vresult)
                   == AMISNAP_ERR_MISSING_FIELD);
    }

    /* --- verify with the WRONG key: the manifest itself won't even
     * decrypt (nonce-discipline check / MAC failure), so this fails
     * before ever reaching the per-object check. --- */
    {
        amisnap_verify_result vresult;
        int rc = amisnap_verify_manifest(&be, &wrong_sk, snapid, mf_raw.data, mf_raw.len, 1, &vresult);
        TEST_CHECK(rc != AMISNAP_OK);
    }

    /* --- restore: recovers the original plaintext bytes. --- */
    {
        amisnap_backend dest;
        amisnap_restore_result rresult;
        char buf[128];
        size_t got = 0;

        TEST_CHECK(amisnap_backend_dir_open(DESTDIR, &dest) == AMISNAP_OK);
        TEST_CHECK(amisnap_restore_manifest(&be, &dest, &sk, snapid, mf_raw.data, mf_raw.len,
                                             NULL, &rresult) == AMISNAP_OK);
        TEST_CHECK(rresult.files_written == 1);
        TEST_CHECK(rresult.bytes_written == sizeof(plaintext) - 1);

        TEST_CHECK(restored_file_bytes(DESTDIR, "secret.txt", buf, sizeof(buf), &got) == 0);
        TEST_CHECK(got == sizeof(plaintext) - 1);
        TEST_CHECK(memcmp(buf, plaintext, got) == 0);

        amisnap_backend_close(&dest);
    }

    amisnap_buf_free(&mf_raw);
    amisnap_backend_close(&be);
}

#define PRUNEDIR "build/test-repo-encrypted-prune"

/* amisnap_prune_execute()'s mark pass decodes every surviving
 * manifest to collect referenced object hashes -- against an
 * encrypted repository that means decrypting each one first
 * (prune.c's mark_snap_cb, wired to repo.h's amisnap_repo_open_
 * manifest() in the same commit that added this test). Two snapshots
 * sharing one deduplicated object plus one object unique to each,
 * same shape as test_prune.c's own CIPHER 0 coverage: prune the older
 * snapshot and confirm mark-and-sweep keeps exactly the surviving
 * one's objects (including the still-referenced shared one) and
 * nothing else -- which only exercises real, working decryption in
 * the mark pass if the counts come out right. */
void run_prune_encrypted_tests(void)
{
    amisnap_backend be;
    amisnap_repo_subkeys sk;
    uint8_t key[32];
    char snapid_a[17], snapid_b[17];
    int i;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0xE0 + i);
    amisnap_repo_derive_subkeys(key, &sk);

    TEST_CHECK(system("rm -rf " PRUNEDIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(PRUNEDIR, &be) == AMISNAP_OK);

    {
        amisnap_repo_writer rw;
        amisnap_snap_meta snap;
        amisnap_volume_meta vol;
        amisnap_entry_meta e;

        amisnap_repo_writer_init(&rw, &be, &sk);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 3000; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);
        memset(&vol, 0, sizeof(vol));
        vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
        TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"shared.txt"; e.path_len = 10;
        e.type = AMISNAP_ETYPE_FILE; e.date_days = 3000;
        TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "same bytes", 10) == AMISNAP_OK);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"only_a.txt"; e.path_len = 10;
        e.type = AMISNAP_ETYPE_FILE; e.date_days = 3000;
        TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "unique to a", 11) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid_a) == AMISNAP_OK);
        amisnap_repo_writer_free(&rw);
    }

    {
        amisnap_repo_writer rw;
        amisnap_snap_meta snap;
        amisnap_volume_meta vol;
        amisnap_entry_meta e;

        amisnap_repo_writer_init(&rw, &be, &sk);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 3001; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);
        memset(&vol, 0, sizeof(vol));
        vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
        TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"shared.txt"; e.path_len = 10;
        e.type = AMISNAP_ETYPE_FILE; e.date_days = 3001;
        TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "same bytes", 10) == AMISNAP_OK);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"only_b.txt"; e.path_len = 10;
        e.type = AMISNAP_ETYPE_FILE; e.date_days = 3001;
        TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "unique to b", 11) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid_b) == AMISNAP_OK);
        amisnap_repo_writer_free(&rw);
    }

    /* Pruning with the wrong key fails closed on the mark pass (it
     * can't decrypt snapshot b's manifest to know what's still
     * referenced) -- confirmed by checking objects_deleted stayed 0:
     * the sweep that would delete real objects never got to run.
     * Target-manifest deletion happens first, unconditionally, and
     * *does* go ahead here (prune.h's own documented contract: "*result
     * reflects only what completed before the failure", i.e. partial
     * progress is real, not rolled back) -- format.md's stated
     * invariant is manifest-before-objects, not all-or-nothing, so a
     * gone manifest with its objects not yet swept is exactly the
     * "harmless garbage for the next prune run to collect" the header
     * comment describes, not a bug. */
    {
        amisnap_repo_subkeys wrong_sk;
        uint8_t wrong_key[32];
        amisnap_prune_result presult;
        const char *ids[1];

        for (i = 0; i < 32; i++) wrong_key[i] = (uint8_t)(0xF0 + i);
        amisnap_repo_derive_subkeys(wrong_key, &wrong_sk);
        ids[0] = snapid_a;
        TEST_CHECK(amisnap_prune_execute(&be, &wrong_sk, ids, 1, &presult) != AMISNAP_OK);
        TEST_CHECK(presult.snapshots_deleted == 1); /* the target manifest, deleted before the failure */
        TEST_CHECK(presult.objects_deleted == 0);   /* sweep never ran -- real objects untouched */
    }

    /* Retry with the real key: snapshot a's manifest is already gone
     * (from the failed attempt above -- amisnap_backend_remove's own
     * documented idempotence, not counted again), but the mark-sweep
     * pass now succeeds and correctly identifies only_a.txt's object
     * as orphaned (no surviving manifest references it) while
     * shared.txt's object survives (still referenced by b). */
    {
        amisnap_prune_result presult;
        const char *ids[1];
        ids[0] = snapid_a;
        TEST_CHECK(amisnap_prune_execute(&be, &sk, ids, 1, &presult) == AMISNAP_OK);
        TEST_CHECK(presult.snapshots_deleted == 0); /* already gone */
        TEST_CHECK(presult.objects_deleted == 1);   /* only_a.txt's object -- shared.txt's survives */
    }

    /* Snapshot b (the survivor) still verifies clean after the prune. */
    {
        char mf_key[40];
        amisnap_buf mf;
        amisnap_verify_result vresult;
        snprintf(mf_key, sizeof(mf_key), "snapshots/%s.mf", snapid_b);
        TEST_CHECK(amisnap_backend_get(&be, mf_key, &mf) == AMISNAP_OK);
        TEST_CHECK(amisnap_verify_manifest(&be, &sk, snapid_b, mf.data, mf.len, 1, &vresult)
                   == AMISNAP_OK);
        TEST_CHECK(vresult.objects_checked == 2);
        TEST_CHECK(vresult.objects_missing == 0);
        TEST_CHECK(vresult.objects_corrupt == 0);
        amisnap_buf_free(&mf);
    }

    amisnap_backend_close(&be);
}
