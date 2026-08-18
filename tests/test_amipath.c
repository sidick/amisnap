/* test_amipath.c -- amisnap_join_amiga_path() (src/amiga/amipath.c).
 * The function is portable C (no Amiga headers), so it is host-tested
 * directly here by including the source -- the same way the join is
 * exercised on-target, but with the separator edge cases (bare
 * volume, trailing '/', empty relpath, overflow) checked explicitly
 * rather than only implicitly through a full restore. */
#include <string.h>

#include "test.h"

/* Include the unit under test directly: it pulls in amipath.h (found
 * beside it under src/amiga/) and tlv.h (found via -Isrc/core), no
 * Makefile change needed. */
#include "../src/amiga/amipath.c"

static int join(const char *root, const char *rel, char *buf, size_t bufsize)
{
    return amisnap_join_amiga_path(root, (const uint8_t *)rel, strlen(rel), buf, bufsize);
}

void run_amipath_tests(void);
void run_amipath_tests(void)
{
    char buf[64];

    /* Directory root: a single '/' separator is inserted. */
    TEST_CHECK(join("Work:Dest", "Sub", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:Dest/Sub") == 0);

    /* Bare volume/assign root (ends ':'): ':' already IS the
     * separator -- no extra '/'. */
    TEST_CHECK(join("Work:", "Sub", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:Sub") == 0);

    /* Trailing '/' root: the regression this test exists for -- a
     * second '/' would make "Work:Dest//Sub", which AmigaDOS resolves
     * as the PARENT ("Work:Sub"), silently targeting the wrong dir.
     * Must stay single-separator. */
    TEST_CHECK(join("Work:Dest/", "Sub", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:Dest/Sub") == 0);

    /* Empty relpath (the root entry itself, format.md E_PATH): the
     * root is returned verbatim, no trailing separator appended in
     * any of the three root forms. */
    TEST_CHECK(join("Work:Dest", "", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:Dest") == 0);
    TEST_CHECK(join("Work:", "", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:") == 0);
    TEST_CHECK(join("Work:Dest/", "", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:Dest/") == 0);

    /* Nested relpath keeps its own internal separators untouched. */
    TEST_CHECK(join("Work:Dest", "a/b/c", buf, sizeof(buf)) == AMISNAP_OK);
    TEST_CHECK(strcmp(buf, "Work:Dest/a/b/c") == 0);

    /* Overflow fails closed (AMISNAP_ERR_TOO_LONG), never truncates
     * into a shorter, wrong path. "Work:Dest" + '/' + "Sub" + NUL =
     * 14 bytes; a 13-byte buffer can't hold it. */
    TEST_CHECK(join("Work:Dest", "Sub", buf, 13) == AMISNAP_ERR_TOO_LONG);
}
