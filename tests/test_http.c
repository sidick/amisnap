/* test_http.c -- request builder + response parser (http.h), Phase 3's
 * first slice. The response-parser cases are each run twice: once fed
 * the whole response in a single amisnap_http_response_feed() call, and
 * once fed one byte at a time -- proving the split-read case (a real
 * socket read() returning however many bytes happen to be available,
 * possibly mid-header-line or mid-chunk) produces an identical result
 * to the single-shot case, not just that the happy path works.
 */
#include <string.h>

#include "http.h"
#include "test.h"

static void feed_whole(amisnap_http_response *r, const char *resp, size_t len, int *done, int *rc)
{
    amisnap_http_response_init(r);
    *rc = amisnap_http_response_feed(r, resp, len, done);
}

static void feed_byte_at_a_time(amisnap_http_response *r, const char *resp, size_t len, int *done, int *rc)
{
    size_t i;

    amisnap_http_response_init(r);
    *done = 0;
    *rc = AMISNAP_OK;
    for (i = 0; i < len; i++) {
        *rc = amisnap_http_response_feed(r, resp + i, 1, done);
        if (*rc != AMISNAP_OK) return;
        if (*done) {
            TEST_CHECK(i == len - 1); /* must finish exactly on the last byte, not early */
            return;
        }
    }
}

static void run_request_builder_tests(void)
{
    amisnap_buf out;
    amisnap_http_header hdrs[2];
    static const char body[] = "hello";

    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_http_build_request(&out, "GET", "/objects/ab/xyz", "example.com",
                                           NULL, 0, NULL, 0) == AMISNAP_OK);
    TEST_CHECK(out.len > 0);
    TEST_CHECK(memcmp(out.data, "GET /objects/ab/xyz HTTP/1.1\r\n", 30) == 0);
    TEST_CHECK(strstr((char *)out.data, "Host: example.com\r\n") != NULL);
    TEST_CHECK(strstr((char *)out.data, "Connection: keep-alive\r\n") != NULL);
    TEST_CHECK(strstr((char *)out.data, "Content-Length:") == NULL); /* no body -> no Content-Length */
    amisnap_buf_free(&out);

    hdrs[0].name = "Depth";
    hdrs[0].value = "1";
    hdrs[1].name = "Authorization";
    hdrs[1].value = "Basic dXNlcjpwYXNz";
    amisnap_buf_init(&out);
    TEST_CHECK(amisnap_http_build_request(&out, "PUT", "/repo/objects/ab/xyz", "10.0.0.5:8080",
                                           hdrs, 2, body, sizeof(body) - 1) == AMISNAP_OK);
    TEST_CHECK(strstr((char *)out.data, "PUT /repo/objects/ab/xyz HTTP/1.1\r\n") != NULL);
    TEST_CHECK(strstr((char *)out.data, "Host: 10.0.0.5:8080\r\n") != NULL);
    TEST_CHECK(strstr((char *)out.data, "Content-Length: 5\r\n") != NULL);
    TEST_CHECK(strstr((char *)out.data, "Depth: 1\r\n") != NULL);
    TEST_CHECK(strstr((char *)out.data, "Authorization: Basic dXNlcjpwYXNz\r\n") != NULL);
    TEST_CHECK(memcmp(out.data + out.len - 5, "hello", 5) == 0); /* body is the very last bytes */
    amisnap_buf_free(&out);
}

static void run_response_content_length_tests(void)
{
    static const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    amisnap_http_response r;
    int done, rc;
    const amisnap_http_parsed_header *h;

    feed_whole(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.status_code == 200);
    TEST_CHECK(r.body.len == 5);
    TEST_CHECK(memcmp(r.body.data, "hello", 5) == 0);
    h = amisnap_http_response_header(&r, "content-type"); /* case-insensitive lookup */
    TEST_CHECK(h != NULL && h->value_len == 10 && memcmp(h->value, "text/plain", 10) == 0);
    TEST_CHECK(amisnap_http_response_header(&r, "ETag") == NULL);
    amisnap_http_response_free(&r);

    feed_byte_at_a_time(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.status_code == 200);
    TEST_CHECK(r.body.len == 5);
    TEST_CHECK(memcmp(r.body.data, "hello", 5) == 0);
    amisnap_http_response_free(&r);
}

static void run_response_no_body_tests(void)
{
    /* A real WebDAV MKCOL/PUT/DELETE 2xx response commonly has neither
     * Content-Length nor Transfer-Encoding -- must resolve to a clean
     * zero-length body, not hang waiting for more bytes (this client
     * always speaks keep-alive, never "read until close" framing). */
    static const char resp[] = "HTTP/1.1 201 Created\r\nLocation: /repo/objects/ab/xyz\r\n\r\n";
    amisnap_http_response r;
    int done, rc;

    feed_whole(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.status_code == 201);
    TEST_CHECK(r.body.len == 0);
    amisnap_http_response_free(&r);

    feed_byte_at_a_time(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.status_code == 201);
    amisnap_http_response_free(&r);
}

static void run_response_chunked_tests(void)
{
    static const char resp[] =
        "HTTP/1.1 207 Multi-Status\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "hello\r\n"
        "6\r\n"
        " world\r\n"
        "0\r\n"
        "\r\n";
    amisnap_http_response r;
    int done, rc;

    feed_whole(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.status_code == 207);
    TEST_CHECK(r.chunked == 1);
    TEST_CHECK(r.body.len == 11);
    TEST_CHECK(memcmp(r.body.data, "hello world", 11) == 0);
    amisnap_http_response_free(&r);

    feed_byte_at_a_time(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.body.len == 11);
    TEST_CHECK(memcmp(r.body.data, "hello world", 11) == 0);
    amisnap_http_response_free(&r);
}

static void run_response_chunked_with_trailer_tests(void)
{
    static const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "abcd\r\n"
        "0\r\n"
        "X-Trailer: ignored\r\n"
        "\r\n";
    amisnap_http_response r;
    int done, rc;

    feed_whole(&r, resp, sizeof(resp) - 1, &done, &rc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(done == 1);
    TEST_CHECK(r.body.len == 4);
    TEST_CHECK(memcmp(r.body.data, "abcd", 4) == 0);
    amisnap_http_response_free(&r);
}

static void run_response_arbitrary_split_tests(void)
{
    /* Splits deliberately land mid-status-line, mid-header-line, and
     * mid-body -- not just "one byte at a time" (already covered above)
     * or "one clean shot", to catch a parser that only handles the two
     * extremes correctly. */
    static const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 12\r\n"
        "\r\n"
        "hello world!";
    static const size_t splits[] = {1, 5, 9, 17, 18, 37, 38, 39};
    size_t s;

    for (s = 0; s < sizeof(splits) / sizeof(splits[0]); s++) {
        size_t split = splits[s];
        amisnap_http_response r;
        int done1 = 0, done2 = 0;
        int rc;

        if (split >= sizeof(resp) - 1) continue;

        amisnap_http_response_init(&r);
        rc = amisnap_http_response_feed(&r, resp, split, &done1);
        TEST_CHECK(rc == AMISNAP_OK);
        TEST_CHECK(done1 == 0);
        rc = amisnap_http_response_feed(&r, resp + split, sizeof(resp) - 1 - split, &done2);
        TEST_CHECK(rc == AMISNAP_OK);
        TEST_CHECK(done2 == 1);
        TEST_CHECK(r.status_code == 200);
        TEST_CHECK(r.body.len == 12);
        TEST_CHECK(memcmp(r.body.data, "hello world!", 12) == 0);
        amisnap_http_response_free(&r);
    }
}

static void run_response_malformed_tests(void)
{
    amisnap_http_response r;
    int done, rc;

    /* A status line with no recognizable 3-digit status code. */
    {
        static const char resp[] = "HTTP/1.1 OK\r\n\r\n";
        amisnap_http_response_init(&r);
        rc = amisnap_http_response_feed(&r, resp, sizeof(resp) - 1, &done);
        TEST_CHECK(rc == AMISNAP_ERR_MALFORMED);
        amisnap_http_response_free(&r);
    }

    /* Feeding more bytes after the response is already done is a caller
     * error, not silently accepted. */
    {
        static const char resp[] = "HTTP/1.1 200 OK\r\n\r\n";
        amisnap_http_response_init(&r);
        rc = amisnap_http_response_feed(&r, resp, sizeof(resp) - 1, &done);
        TEST_CHECK(rc == AMISNAP_OK && done == 1);
        rc = amisnap_http_response_feed(&r, "x", 1, &done);
        TEST_CHECK(rc == AMISNAP_ERR_MALFORMED);
        amisnap_http_response_free(&r);
    }
}

void run_http_tests(void)
{
    run_request_builder_tests();
    run_response_content_length_tests();
    run_response_no_body_tests();
    run_response_chunked_tests();
    run_response_chunked_with_trailer_tests();
    run_response_arbitrary_split_tests();
    run_response_malformed_tests();
}
