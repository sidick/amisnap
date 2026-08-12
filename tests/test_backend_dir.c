/* test_backend_dir.c -- the directory backend (backend_dir.h) against
 * a real temporary directory tree. Host-only (uses system("rm -rf")
 * for test hygiene, not shipped anywhere); the same code under test
 * also cross-builds for m68k -- see Makefile's m68k target -- this
 * test just can't execute there without an emulator.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "backend_dir.h"
#include "test.h"

#define TESTDIR "build/test-backend-dir"

static void count_cb(void *user, const char *name)
{
    (void)name;
    (*(int *)user)++;
}

static char last_listed[64];
static void capture_one_cb(void *user, const char *name)
{
    (void)user;
    strncpy(last_listed, name, sizeof(last_listed) - 1);
    last_listed[sizeof(last_listed) - 1] = '\0';
}

void run_backend_dir_tests(void)
{
    amisnap_backend be;
    amisnap_buf out;
    int n;

    TEST_CHECK(system("rm -rf " TESTDIR) == 0);

    TEST_CHECK(amisnap_backend_dir_open(TESTDIR, &be) == AMISNAP_OK);

    /* put + get round trip, including creating a nested key's parent
     * directories from nothing. */
    TEST_CHECK(amisnap_backend_put(&be, "objects/ab/abcdef", "hello", 5) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/ab/abcdef") == 1);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/ab/nope") == 0);

    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_backend_get(&be, "objects/ab/abcdef", &out) == AMISNAP_OK);
    TEST_CHECK(out.len == 5 && memcmp(out.data, "hello", 5) == 0);
    amisnap_buf_free(&out);

    /* get of a missing key is AMISNAP_ERR_NOT_FOUND, not a generic error. */
    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_backend_get(&be, "objects/ab/nope", &out) == AMISNAP_ERR_NOT_FOUND);
    amisnap_buf_free(&out);

    /* put onto an existing key overwrites atomically (legal per
     * backend.h; repo.c itself avoids this via exists()-gated dedup,
     * but the backend must not refuse it). */
    TEST_CHECK(amisnap_backend_put(&be, "objects/ab/abcdef", "world!", 6) == AMISNAP_OK);
    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_backend_get(&be, "objects/ab/abcdef", &out) == AMISNAP_OK);
    TEST_CHECK(out.len == 6 && memcmp(out.data, "world!", 6) == 0);
    amisnap_buf_free(&out);

    /* zero-byte object round-trips too. */
    TEST_CHECK(amisnap_backend_put(&be, "objects/00/empty", "", 0) == AMISNAP_OK);
    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_backend_get(&be, "objects/00/empty", &out) == AMISNAP_OK);
    TEST_CHECK(out.len == 0);
    amisnap_buf_free(&out);

    /* list is one level, "." and ".." excluded. */
    n = 0;
    last_listed[0] = '\0';
    TEST_CHECK(amisnap_backend_list(&be, "objects/ab", capture_one_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(strcmp(last_listed, "abcdef") == 0);
    TEST_CHECK(amisnap_backend_list(&be, "objects/ab", count_cb, &n) == AMISNAP_OK);
    TEST_CHECK(n == 1);

    /* listing a prefix that doesn't exist yet is empty, not an error --
     * an uninitialized fan-out bucket is normal. */
    n = 0;
    TEST_CHECK(amisnap_backend_list(&be, "snapshots", count_cb, &n) == AMISNAP_OK);
    TEST_CHECK(n == 0);

    /* remove, and remove of an already-gone key. */
    TEST_CHECK(amisnap_backend_remove(&be, "objects/00/empty") == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/00/empty") == 0);
    TEST_CHECK(amisnap_backend_remove(&be, "objects/00/empty") == AMISNAP_ERR_NOT_FOUND);

    amisnap_backend_close(&be);

    /* Re-opening the same root (already initialized) succeeds and
     * still sees earlier data -- mkdir_p tolerating an existing root,
     * and open() not being a destructive operation. */
    TEST_CHECK(amisnap_backend_dir_open(TESTDIR, &be) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/ab/abcdef") == 1);
    amisnap_backend_close(&be);

    TEST_CHECK(system("rm -rf " TESTDIR) == 0);
}
