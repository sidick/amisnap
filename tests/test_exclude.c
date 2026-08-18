/* test_exclude.c -- amisnap_exclude_parse/match (src/core/exclude.c),
 * the backup exclude list from implementation-plan.md Phase 2 item 8's
 * deferred design note.
 */
#include <string.h>

#include "exclude.h"
#include "test.h"
#include "tlv.h" /* AMISNAP_OK */

static int matches(amisnap_exclude_list *list, const char *path, int is_dir)
{
    return amisnap_exclude_match(list, path, strlen(path), is_dir);
}

void run_exclude_tests(void);
void run_exclude_tests(void)
{
    amisnap_exclude_list list;

    /* NULL list: never matches anything (SNAPSHOT with no EXCLUDE=
     * given must behave exactly as before this feature existed). */
    TEST_CHECK(amisnap_exclude_match(NULL, "anything", 8, 0) == 0);

    /* Comments and blank lines are ignored; a plain non-anchored
     * pattern matches the exact basename at the root. */
    {
        const char *text = "# a comment\n\n*.info\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(list.count == 1);
        TEST_CHECK(matches(&list, "Foo.info", 0) == 1);
        TEST_CHECK(matches(&list, "Foo.txt", 0) == 0);
        amisnap_exclude_free(&list);
    }

    /* Non-anchored pattern matches a basename at ANY depth, not just
     * the root. */
    {
        const char *text = "*.info\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(matches(&list, "Sub/Deeper/Foo.info", 0) == 1);
        amisnap_exclude_free(&list);
    }

    /* Anchored pattern (interior '/') matches only the exact full
     * relative path -- an entry of the same basename elsewhere is NOT
     * excluded. */
    {
        const char *text = "Work/Projects/scratch\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(list.count == 1 && list.patterns[0].anchored);
        TEST_CHECK(matches(&list, "Work/Projects/scratch", 0) == 1);
        TEST_CHECK(matches(&list, "Other/Projects/scratch", 0) == 0);
        TEST_CHECK(matches(&list, "Work/Projects/scratch/deeper", 0) == 0);
        amisnap_exclude_free(&list);
    }

    /* A leading '/' is an equivalent, explicit way to anchor a
     * single-component pattern to the root only. */
    {
        const char *text = "/T\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(list.patterns[0].anchored);
        TEST_CHECK(matches(&list, "T", 0) == 1);
        TEST_CHECK(matches(&list, "Sub/T", 0) == 0);
        amisnap_exclude_free(&list);
    }

    /* Trailing '/' restricts a pattern to directories -- a same-named
     * file is never excluded by it, and it's still non-anchored. */
    {
        const char *text = "T/\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(list.patterns[0].dir_only && !list.patterns[0].anchored);
        TEST_CHECK(matches(&list, "T", 1) == 1);
        TEST_CHECK(matches(&list, "T", 0) == 0);
        TEST_CHECK(matches(&list, "Sub/T", 1) == 1);
        amisnap_exclude_free(&list);
    }

    /* '*' and '?' stay within one path component -- neither ever
     * crosses a '/', so a wildcard can't accidentally reach into an
     * unrelated subtree. */
    {
        const char *text = "Work/*.bak\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(matches(&list, "Work/Foo.bak", 0) == 1);
        TEST_CHECK(matches(&list, "Work/Sub/Foo.bak", 0) == 0);
        amisnap_exclude_free(&list);
    }
    {
        const char *text = "log?.txt\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(matches(&list, "log1.txt", 0) == 1);
        TEST_CHECK(matches(&list, "log12.txt", 0) == 0);
        amisnap_exclude_free(&list);
    }

    /* Matching is case-insensitive throughout (Amiga filesystems are
     * case-preserving but case-insensitive -- see exclude.h). */
    {
        const char *text = "*.INFO\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(matches(&list, "foo.info", 0) == 1);
        amisnap_exclude_free(&list);
    }

    /* Leading/trailing whitespace on a line is trimmed; CRLF line
     * endings are tolerated (Windows-edited exclude files). */
    {
        const char *text = "  *.tmp  \r\nWork\r\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(list.count == 2);
        TEST_CHECK(matches(&list, "a.tmp", 0) == 1);
        TEST_CHECK(matches(&list, "Work", 0) == 1);
        amisnap_exclude_free(&list);
    }

    /* An empty exclude file parses to zero patterns and excludes
     * nothing. */
    TEST_CHECK(amisnap_exclude_parse(NULL, 0, &list) == AMISNAP_OK);
    TEST_CHECK(list.count == 0);
    TEST_CHECK(matches(&list, "anything", 0) == 0);
    amisnap_exclude_free(&list);

    /* A line that's only "/" or "//" contributes no pattern (nothing
     * left to match once separators are stripped), never a crash or an
     * accidental match-everything pattern. */
    {
        const char *text = "/\n//\n*.keep\n";
        TEST_CHECK(amisnap_exclude_parse(text, strlen(text), &list) == AMISNAP_OK);
        TEST_CHECK(list.count == 1);
        TEST_CHECK(matches(&list, "x", 0) == 0);
        TEST_CHECK(matches(&list, "x.keep", 0) == 1);
        amisnap_exclude_free(&list);
    }
}
