/* test_base64.c -- RFC 4648 section 10's own worked test vectors. */
#include <string.h>

#include "base64.h"
#include "test.h"

static void check(const char *input, const char *expected)
{
    amisnap_buf out;

    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_base64_encode(&out, input, strlen(input)) == AMISNAP_OK);
    TEST_CHECK(out.len == strlen(expected));
    TEST_CHECK(out.len == strlen(expected) && memcmp(out.data, expected, out.len) == 0);
    amisnap_buf_free(&out);
}

void run_base64_tests(void)
{
    check("", "");
    check("f", "Zg==");
    check("fo", "Zm8=");
    check("foo", "Zm9v");
    check("foob", "Zm9vYg==");
    check("fooba", "Zm9vYmE=");
    check("foobar", "Zm9vYmFy");

    /* The exact case this exists for: an HTTP Basic Authorization
     * credential pair. */
    check("user:pass", "dXNlcjpwYXNz");
}
