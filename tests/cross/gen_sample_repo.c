/* gen_sample_repo.c -- test-only fixture generator for the Python
 * reference reader's cross-implementation check (implementation-
 * plan.md Phase 2: "CI asserts they agree"). Writes one deterministic,
 * known-content snapshot to the directory named on argv[1] using the
 * real portable C write path (repo.c/backend_dir.c -- the same code a
 * real SNAPSHOT run uses), then prints the committed snapid to stdout
 * so the driving script can pass it to tools/amisnap_reader.py without
 * having to parse anything itself.
 *
 * With `--compress` as the second argument the repository is framed
 * (OBJCOMP=1, LZ4 preference): an amisnap.repo header is written even
 * in the plain case (a framed repository always needs one), and an
 * extra, genuinely compressible entry (big.txt) is added so at least
 * one object really is LZ4 inside its frame (the small fixtures fall
 * back to stored frames -- itself worth exercising).
 *
 * With a further argument (a passphrase), also writes a CIPHER=1
 * amisnap.repo and encrypts the same snapshot -- implementation-plan.md
 * Phase 4 item 6's "cross-check keeps proving the two agree once
 * CIPHER=1 repositories exist". The repository key itself is a fixed,
 * known-answer value (0x00..0x1f), not real entropy -- this is a test
 * fixture that needs to be reproducible, not a real repository, and
 * repo_crypto.c/repo_header.c don't care where the key came from. The
 * PBKDF2 iteration count is deliberately tiny (real entropy/calibration
 * is src/amiga/random.c's job, exercised on-target, not here) so this
 * fixture generates in CI-test time, not KDF-calibrated real time.
 *
 * Never shipped -- same convention as this repo's own Amiga-side test
 * fixtures under tests/copperline/fixture/, just host-buildable
 * instead of m68k-only, since this one only exercises the portable
 * core.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend_dir.h"
#include "compress.h"
#include "pbkdf2.h"
#include "repo.h"
#include "repo_header.h"

#define TEST_KDF_ITERS 100u

/* Writes a CIPHER=1 amisnap.repo wrapping the fixed test repo key
 * under `passphrase`, and returns the derived object/manifest subkeys
 * via *sk_out for the writer to use. Exits the process on failure --
 * this is a fixture generator, not a library, so a short, loud death
 * is more useful than plumbing an error code back through main(). */
static void init_encrypted_repo(amisnap_backend *be, const char *passphrase, int framed,
                                 uint8_t repo_key[AMISNAP_REPO_KEY_SIZE],
                                 amisnap_repo_subkeys *sk_out)
{
    static const uint8_t salt[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    static const uint8_t wrap_nonce[AMISNAP_REPO_NONCE_SIZE] = {
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb
    };
    uint8_t k_wrap[32];
    uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE];
    amisnap_repo_header hdr;
    amisnap_buf hdr_bytes;
    size_t i;

    for (i = 0; i < AMISNAP_REPO_KEY_SIZE; i++) repo_key[i] = (uint8_t)i;
    amisnap_repo_derive_subkeys(repo_key, sk_out);

    amisnap_pbkdf2_hmac_sha256((const uint8_t *)passphrase, strlen(passphrase),
                                salt, sizeof(salt), TEST_KDF_ITERS, k_wrap, sizeof(k_wrap));
    amisnap_repo_wrap_key(k_wrap, wrap_nonce, repo_key, wrapped);

    memset(&hdr, 0, sizeof(hdr));
    for (i = 0; i < AMISNAP_REPO_ID_SIZE; i++) hdr.repo_id[i] = (uint8_t)(0xc0 + i);
    hdr.cipher = 1;
    if (framed) {
        hdr.objcomp = AMISNAP_OBJCOMP_FRAMED;
        hdr.has_comp_pref = 1;
        hdr.comp_pref = AMISNAP_COMP_LZ4;
    }
    hdr.kdf_id = AMISNAP_KDF_PBKDF2_HMAC_SHA256;
    hdr.kdf_iters = TEST_KDF_ITERS;
    hdr.salt = salt;
    hdr.salt_len = sizeof(salt);
    hdr.wrapped_key = wrapped;
    hdr.has_format_app = 1;
    hdr.format_app = (const uint8_t *)"AmiSnap";
    hdr.format_app_len = 7;

    if (amisnap_repo_header_encode(&hdr, &hdr_bytes) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: repo_header_encode failed\n");
        exit(1);
    }
    if (amisnap_backend_put(be, "amisnap.repo", hdr_bytes.data, hdr_bytes.len) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: writing amisnap.repo failed\n");
        exit(1);
    }
    amisnap_buf_free(&hdr_bytes);
}

/* Writes the CIPHER=0, OBJCOMP=1 amisnap.repo a plain framed
 * repository needs (unlike a raw plain one, which needs no header at
 * all). */
static void init_plain_framed_repo(amisnap_backend *be)
{
    amisnap_repo_header hdr;
    amisnap_buf hdr_bytes;
    size_t i;

    memset(&hdr, 0, sizeof(hdr));
    for (i = 0; i < AMISNAP_REPO_ID_SIZE; i++) hdr.repo_id[i] = (uint8_t)(0xc0 + i);
    hdr.objcomp = AMISNAP_OBJCOMP_FRAMED;
    hdr.has_comp_pref = 1;
    hdr.comp_pref = AMISNAP_COMP_LZ4;
    hdr.has_format_app = 1;
    hdr.format_app = (const uint8_t *)"AmiSnap";
    hdr.format_app_len = 7;

    if (amisnap_repo_header_encode(&hdr, &hdr_bytes) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: repo_header_encode failed\n");
        exit(1);
    }
    if (amisnap_backend_put(be, "amisnap.repo", hdr_bytes.data, hdr_bytes.len) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: writing amisnap.repo failed\n");
        exit(1);
    }
    amisnap_buf_free(&hdr_bytes);
}

int main(int argc, char **argv)
{
    amisnap_backend be;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;
    char snapid[17];
    static const char readme_content[] = "Hello from AmiSnap\n";
    static const char notes_content[] = "notes\n";
    uint8_t repo_key[AMISNAP_REPO_KEY_SIZE];
    amisnap_repo_subkeys sk;
    const amisnap_repo_subkeys *subkeys = NULL;
    const char *passphrase = NULL;
    int framed = 0;
    int argn = 2;

    if (argc >= 3 && strcmp(argv[2], "--compress") == 0) { framed = 1; argn = 3; }
    if (argc == argn + 1) passphrase = argv[argn];
    else if (argc != argn) {
        fprintf(stderr, "usage: %s <repo-dir> [--compress] [passphrase]\n", argv[0]);
        return 1;
    }

    if (amisnap_backend_dir_open(argv[1], &be) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: backend_dir_open failed\n");
        return 1;
    }

    if (passphrase) {
        init_encrypted_repo(&be, passphrase, framed, repo_key, &sk);
        subkeys = &sk;
    } else if (framed) {
        init_plain_framed_repo(&be);
    }

    amisnap_repo_writer_init(&rw, &be, subkeys);
    if (framed)
        amisnap_repo_writer_set_compression(&rw, AMISNAP_COMP_LZ4);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 17000; snap.created_mins = 600; snap.created_ticks = 10;
    snap.has_comment = 1;
    snap.comment = (const uint8_t *)"cross-implementation sample";
    snap.comment_len = strlen((const char *)snap.comment);
    if (amisnap_repo_writer_snap(&rw, &snap) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: writer_snap failed\n");
        return 1;
    }

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:";
    vol.vol_root_len = strlen((const char *)vol.vol_root);
    vol.has_dostype = 1;
    vol.dostype = 0x444F5301u; /* "DOS\1", real FFS dostype */
    vol.has_caps = 1;
    vol.maxnamelen = 30;
    vol.caps_flags = 1; /* bit 0: owner support observed */
    if (amisnap_repo_writer_volume(&rw, &vol) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: writer_volume failed\n");
        return 1;
    }

    /* root dir -- format.md E_PATH: "Empty = the root itself" */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)""; e.path_len = 0;
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0;
    e.date_days = 17000; e.date_mins = 0; e.date_ticks = 0;
    if (amisnap_repo_writer_entry(&rw, &e) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: root entry failed\n");
        return 1;
    }

    /* readme.txt: archive bit, comment, owner -- exercises every
     * optional REC_ENTRY field at once. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"readme.txt"; e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0x10u; /* FIBF_ARCHIVE */
    e.date_days = 17000; e.date_mins = 10; e.date_ticks = 20;
    e.has_comment = 1;
    e.comment = (const uint8_t *)"a readme";
    e.comment_len = strlen((const char *)e.comment);
    e.has_owner = 1; e.uid = 100; e.gid = 200;
    if (amisnap_repo_writer_file(&rw, &e, readme_content, strlen(readme_content)) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: readme.txt write failed\n");
        return 1;
    }

    /* Docs/ subdirectory + a nested file -- exercises E_PATH with a
     * '/' component separator and depth-first ordering. */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Docs"; e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_DIR;
    e.prot = 0;
    e.date_days = 17000; e.date_mins = 0; e.date_ticks = 0;
    if (amisnap_repo_writer_entry(&rw, &e) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: Docs entry failed\n");
        return 1;
    }

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"Docs/notes.txt"; e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0;
    e.date_days = 17000; e.date_mins = 5; e.date_ticks = 5;
    if (amisnap_repo_writer_file(&rw, &e, notes_content, strlen(notes_content)) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: Docs/notes.txt write failed\n");
        return 1;
    }

    /* A zero-byte file: E_SIZE=0, no E_CONTENT at all (format.md:
     * "Required for E_TYPE 1 with E_SIZE > 0"). */
    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"empty.dat"; e.path_len = strlen((const char *)e.path);
    e.type = AMISNAP_ETYPE_FILE;
    e.prot = 0x10u;
    e.date_days = 17000; e.date_mins = 0; e.date_ticks = 0;
    if (amisnap_repo_writer_file(&rw, &e, NULL, 0) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: empty.dat write failed\n");
        return 1;
    }

    /* Framed mode only: a genuinely compressible file, so the fixture
     * holds one real LZ4 frame alongside the small files' stored-
     * fallback frames. Repeating text, generated in place -- keeps the
     * raw fixtures byte-identical to what they were before framing
     * existed. */
    if (framed) {
        static char big[4352];
        size_t off;

        for (off = 0; off < sizeof(big); off += 17)
            memcpy(big + off, "AmigaOS forever! ", 17);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"big.txt"; e.path_len = strlen((const char *)e.path);
        e.type = AMISNAP_ETYPE_FILE;
        e.prot = 0;
        e.date_days = 17000; e.date_mins = 15; e.date_ticks = 0;
        if (amisnap_repo_writer_file(&rw, &e, big, sizeof(big)) != AMISNAP_OK) {
            fprintf(stderr, "gen_sample_repo: big.txt write failed\n");
            return 1;
        }
    }

    if (amisnap_repo_writer_finish(&rw, snapid) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: writer_finish failed\n");
        return 1;
    }
    amisnap_repo_writer_free(&rw);
    amisnap_backend_close(&be);

    printf("%s\n", snapid);
    return 0;
}
