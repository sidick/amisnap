/* gen_sample_repo.c -- test-only fixture generator for the Python
 * reference reader's cross-implementation check (implementation-
 * plan.md Phase 2: "CI asserts they agree"). Writes one deterministic,
 * known-content snapshot to the directory named on argv[1] using the
 * real portable C write path (repo.c/backend_dir.c -- the same code a
 * real SNAPSHOT run uses), then prints the committed snapid to stdout
 * so the driving script can pass it to tools/amisnap_reader.py without
 * having to parse anything itself.
 *
 * Never shipped -- same convention as this repo's own Amiga-side test
 * fixtures under tests/copperline/fixture/, just host-buildable
 * instead of m68k-only, since this one only exercises the portable
 * core.
 */
#include <stdio.h>
#include <string.h>

#include "backend_dir.h"
#include "repo.h"

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

    if (argc != 2) {
        fprintf(stderr, "usage: %s <repo-dir>\n", argv[0]);
        return 1;
    }

    if (amisnap_backend_dir_open(argv[1], &be) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: backend_dir_open failed\n");
        return 1;
    }

    amisnap_repo_writer_init(&rw, &be, NULL);

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

    if (amisnap_repo_writer_finish(&rw, snapid) != AMISNAP_OK) {
        fprintf(stderr, "gen_sample_repo: writer_finish failed\n");
        return 1;
    }
    amisnap_repo_writer_free(&rw);
    amisnap_backend_close(&be);

    printf("%s\n", snapid);
    return 0;
}
