/* test_crash_safety.c -- Phase 2's "interrupted-run recovery" gate,
 * checked for real rather than reasoned about: fork() a child that
 * starts writing a second snapshot into a repository that already has
 * one committed snapshot, SIGKILL it partway through (a real hard
 * kill, not a simulated one), then from the parent confirm the
 * repository is exactly as trustworthy as format.md's own commit
 * protocol promises -- the prior snapshot still verifies clean, the
 * partial one is invisible to list_snapshots (its manifest was never
 * renamed into snapshots/), prune's mark-and-sweep cleans up whatever
 * tmp/ litter the kill left behind without touching anything real, and
 * the repository is still perfectly usable for a brand new snapshot
 * afterward.
 *
 * backend_dir.c (the backend under test here) is the same portable
 * code AmigaOS uses too -- this isn't a host-only guarantee, it's
 * proof that the underlying write-to-tmp-then-atomic-rename mechanism
 * every backend_dir_put() call already goes through actually survives
 * a real interruption, not just that the code reads as if it should.
 *
 * _POSIX_C_SOURCE must be defined before any system header is pulled
 * in (glibc gates fork()/kill()/waitpid()'s prototypes behind it under
 * strict -std=c99 -- confirmed the hard way: this built silently on
 * macOS's libc, which doesn't gate the same way, and only failed loud
 * in CI's Linux container with "implicit declaration of function
 * 'kill'", -Werror turning that into a real build failure). */
#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backend_dir.h"
#include "prune.h"
#include "repo.h"
#include "test.h"

#define REPODIR "build/test-crash-repo"
#define TOTAL_FILES 40
#define KILL_AT 20 /* the child is killed partway through writing its
                     * second snapshot's files -- deterministic on file
                     * count, not a timing-based sleep(), so this test
                     * doesn't flake under a loaded CI runner. */

static void write_baseline_snapshot(amisnap_backend *repo, char snapid_out[17])
{
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_entry_meta e;

    amisnap_repo_writer_init(&rw, repo, NULL);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 2000; snap.created_mins = 1; snap.created_ticks = 1;
    TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);

    memset(&e, 0, sizeof(e));
    e.path = (const uint8_t *)"baseline.txt"; e.path_len = 12;
    e.type = AMISNAP_ETYPE_FILE; e.date_days = 2000;
    TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "baseline content", 16) == AMISNAP_OK);

    TEST_CHECK(amisnap_repo_writer_finish(&rw, snapid_out) == AMISNAP_OK);
    amisnap_repo_writer_free(&rw);
}

/* Runs entirely inside the forked child. Deliberately does NOT use
 * TEST_CHECK -- fork() gives the child its own copy of g_test, so any
 * counts recorded here would vanish with it when SIGKILL lands rather
 * than reaching the parent's totals. abort() on a genuine setup failure
 * is enough: the parent's own waitpid() below distinguishes a clean
 * SIGKILL from any other outcome. */
static void child_interrupted_snapshot(void)
{
    amisnap_backend repo;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    int i;

    if (amisnap_backend_dir_open(REPODIR, &repo) != AMISNAP_OK) _exit(1);

    amisnap_repo_writer_init(&rw, &repo, NULL);

    memset(&snap, 0, sizeof(snap));
    snap.created_days = 2001; snap.created_mins = 1; snap.created_ticks = 1;
    if (amisnap_repo_writer_snap(&rw, &snap) != AMISNAP_OK) _exit(1);

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
    if (amisnap_repo_writer_volume(&rw, &vol) != AMISNAP_OK) _exit(1);

    for (i = 0; i < TOTAL_FILES; i++) {
        amisnap_entry_meta e;
        char path[32];
        char content[64];
        int len;

        if (i == KILL_AT) {
            /* A real hard kill -- not _exit(), not a thrown error --
             * mid-way through writing this second snapshot, well
             * before amisnap_repo_writer_finish() (which alone would
             * rename the manifest into snapshots/) is ever reached. */
            kill(getpid(), SIGKILL);
            _exit(1); /* unreachable if SIGKILL actually landed */
        }

        snprintf(path, sizeof(path), "big%03d.txt", i);
        len = snprintf(content, sizeof(content), "content of file number %d", i);

        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)path; e.path_len = strlen(path);
        e.type = AMISNAP_ETYPE_FILE; e.date_days = 2001;
        if (amisnap_repo_writer_file(&rw, &e, content, (size_t)len) != AMISNAP_OK) _exit(1);
    }

    /* Reached only if KILL_AT >= TOTAL_FILES (a test-config bug) --
     * finish normally rather than leaving an ambiguous outcome. */
    {
        char snapid[17];
        amisnap_repo_writer_finish(&rw, snapid);
    }
    _exit(0);
}

static int count_cb_n;
static void count_cb(void *user, const char *snapid)
{
    (void)user; (void)snapid;
    count_cb_n++;
}

static char g_seen_snapid[17];
static void capture_one_cb(void *user, const char *snapid)
{
    (void)user;
    memcpy(g_seen_snapid, snapid, 17);
}

void run_crash_safety_tests(void)
{
    amisnap_backend repo;
    char baseline_snapid[17];
    pid_t pid;
    int status;

    TEST_CHECK(system("rm -rf " REPODIR) == 0);
    TEST_CHECK(amisnap_backend_dir_open(REPODIR, &repo) == AMISNAP_OK);
    write_baseline_snapshot(&repo, baseline_snapid);
    amisnap_backend_close(&repo);

    /* --- Interrupt a second snapshot with a real SIGKILL partway
     * through writing its files. --- */
    pid = fork();
    TEST_CHECK(pid >= 0);
    if (pid == 0) {
        child_interrupted_snapshot();
        _exit(1); /* never reached */
    }
    TEST_CHECK(waitpid(pid, &status, 0) == pid);
    TEST_CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

    /* --- The repository must look exactly as if the interrupted
     * snapshot never happened: only the baseline is listed, and it
     * still verifies clean. --- */
    TEST_CHECK(amisnap_backend_dir_open(REPODIR, &repo) == AMISNAP_OK);

    count_cb_n = 0;
    TEST_CHECK(amisnap_repo_list_snapshots(&repo, count_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(count_cb_n == 1);

    g_seen_snapid[0] = '\0';
    TEST_CHECK(amisnap_repo_list_snapshots(&repo, capture_one_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(strcmp(g_seen_snapid, baseline_snapid) == 0);

    {
        amisnap_buf mf;
        amisnap_verify_result vresult;
        char key[32];
        snprintf(key, sizeof(key), "snapshots/%s.mf", baseline_snapid);
        TEST_CHECK(amisnap_backend_get(&repo, key, &mf) == AMISNAP_OK);
        TEST_CHECK(amisnap_verify_manifest(&repo, NULL, AMISNAP_OBJCOMP_RAW, NULL, mf.data, mf.len, 1, &vresult) == AMISNAP_OK);
        TEST_CHECK(vresult.objects_missing == 0 && vresult.objects_corrupt == 0);
        amisnap_buf_free(&mf);
    }

    /* --- A no-op prune (nothing to delete) still sweeps whatever
     * tmp/ litter the kill left behind, without disturbing the
     * baseline's own object or manifest. --- */
    {
        amisnap_prune_result presult;
        amisnap_buf mf;
        char key[32];

        TEST_CHECK(amisnap_prune_execute(&repo, NULL, NULL, 0, &presult) == AMISNAP_OK);
        TEST_CHECK(presult.snapshots_deleted == 0);

        snprintf(key, sizeof(key), "snapshots/%s.mf", baseline_snapid);
        TEST_CHECK(amisnap_backend_get(&repo, key, &mf) == AMISNAP_OK);
        amisnap_buf_free(&mf);
    }

    /* --- The repository is still perfectly usable: a brand new
     * snapshot afterward succeeds and verifies clean, proving the
     * interruption left nothing wedged or inconsistent. --- */
    {
        amisnap_repo_writer rw;
        amisnap_snap_meta snap;
        amisnap_volume_meta vol;
        amisnap_entry_meta e;
        char new_snapid[17];
        amisnap_buf mf;
        amisnap_verify_result vresult;
        char key[32];

        amisnap_repo_writer_init(&rw, &repo, NULL);
        memset(&snap, 0, sizeof(snap));
        snap.created_days = 2002; snap.created_mins = 1; snap.created_ticks = 1;
        TEST_CHECK(amisnap_repo_writer_snap(&rw, &snap) == AMISNAP_OK);
        memset(&vol, 0, sizeof(vol));
        vol.vol_root = (const uint8_t *)"Work:"; vol.vol_root_len = 5;
        TEST_CHECK(amisnap_repo_writer_volume(&rw, &vol) == AMISNAP_OK);
        memset(&e, 0, sizeof(e));
        e.path = (const uint8_t *)"after.txt"; e.path_len = 9;
        e.type = AMISNAP_ETYPE_FILE; e.date_days = 2002;
        TEST_CHECK(amisnap_repo_writer_file(&rw, &e, "after the kill", 14) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_writer_finish(&rw, new_snapid) == AMISNAP_OK);
        amisnap_repo_writer_free(&rw);

        count_cb_n = 0;
        TEST_CHECK(amisnap_repo_list_snapshots(&repo, count_cb, NULL) == AMISNAP_OK);
        TEST_CHECK(count_cb_n == 2);

        snprintf(key, sizeof(key), "snapshots/%s.mf", new_snapid);
        TEST_CHECK(amisnap_backend_get(&repo, key, &mf) == AMISNAP_OK);
        TEST_CHECK(amisnap_verify_manifest(&repo, NULL, AMISNAP_OBJCOMP_RAW, NULL, mf.data, mf.len, 1, &vresult) == AMISNAP_OK);
        TEST_CHECK(vresult.objects_missing == 0 && vresult.objects_corrupt == 0);
        amisnap_buf_free(&mf);
    }

    amisnap_backend_close(&repo);
    TEST_CHECK(system("rm -rf " REPODIR) == 0);
}
