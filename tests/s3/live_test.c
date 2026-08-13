/* live_test.c -- Phase 5's own host-CI check: drives s3.c against a
 * REAL S3-compatible server process (mini_s3_server.py) over a real
 * POSIX TCP connection (tests/webdav/posix_transport.c, reused as-is
 * -- it's a generic POSIX-sockets amisnap_transport_ops implementation
 * with no WebDAV-specific logic, see that file's own header comment)
 * -- an independent implementation from this project's own in-memory
 * mock (tests/test_s3.c), which is what actually catches interop bugs
 * a self-consistent mock never could. Unlike the WebDAV check, this
 * one also proves something the mock explicitly can't: that
 * mini_s3_server.py's own independent SigV4 *verification* accepts a
 * signature s3.c actually produced for a live request.
 *
 * Not part of `make test` (needs a spawned server process) -- driven
 * by tests/s3/run.sh instead, matching tests/webdav/run.sh's own
 * shape. Prints "PASS" and exits 0 on success; prints one FAIL line
 * per failed check (keeps going rather than aborting at the first
 * one) and exits 1 if any failed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "posix_transport.h"
#include "s3.h"

static int g_failed = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed = 1;                                                  \
        }                                                                  \
    } while (0)

struct list_ctx {
    char seen[8][64];
    size_t count;
};

static void list_cb(void *user, const char *name)
{
    struct list_ctx *c = (struct list_ctx *)user;

    if (c->count < 8) {
        strncpy(c->seen[c->count], name, 63);
        c->seen[c->count][63] = '\0';
        c->count++;
    }
}

static int list_has(const struct list_ctx *c, const char *name)
{
    size_t i;

    for (i = 0; i < c->count; i++)
        if (strcmp(c->seen[i], name) == 0) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    amisnap_transport t;
    amisnap_backend be;
    amisnap_s3_config cfg;
    amisnap_buf got;
    void *handle;
    struct list_ctx lc;
    uint16_t port;

    if (argc != 2) {
        fprintf(stderr, "usage: live_test <port>\n");
        return 2;
    }
    port = (uint16_t)atoi(argv[1]);

    t.ops = &amisnap_posix_transport_ops;
    t.ctx = NULL;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.bucket = "amisnap-test-bucket";
    cfg.base_path = "";
    cfg.region = "us-east-1";
    cfg.access_key = "AKIDEXAMPLE";
    cfg.secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    CHECK(amisnap_backend_s3_open(&cfg, &t, &be) == AMISNAP_OK);

    /* whole-object put/get -- and, unlike the mock, a real SigV4
     * signature that a genuinely independent server implementation
     * (mini_s3_server.py, not src/core/sigv4.c) actually verified. */
    CHECK(amisnap_backend_put(&be, "objects/ab/deadbeef", "hello", 5) == AMISNAP_OK);
    CHECK(amisnap_backend_get(&be, "objects/ab/deadbeef", &got) == AMISNAP_OK);
    CHECK(got.len == 5 && memcmp(got.data, "hello", 5) == 0);
    amisnap_buf_free(&got);

    CHECK(amisnap_backend_exists(&be, "objects/ab/deadbeef") == 1);
    CHECK(amisnap_backend_exists(&be, "objects/ab/nope") == 0);
    CHECK(amisnap_backend_get(&be, "objects/ab/nope", &got) == AMISNAP_ERR_NOT_FOUND);

    /* mkcol: a documented no-op even against a real server (S3 has no
     * directory concept for this call to create). */
    CHECK(amisnap_backend_mkcol(&be, "snapshots") == AMISNAP_OK);

    /* streaming upload (buffered whole-chunk PUT at finish -- s3.c has
     * no real chunked-request-body path, see s3.c's own doc comment on
     * why) against a real server. */
    CHECK(amisnap_backend_put_begin(&be, "objects/cd/chunked", &handle) == AMISNAP_OK);
    CHECK(amisnap_backend_put_append(&be, handle, "hello ", 6) == AMISNAP_OK);
    CHECK(amisnap_backend_put_append(&be, handle, "world", 5) == AMISNAP_OK);
    CHECK(amisnap_backend_put_finish(&be, handle) == AMISNAP_OK);
    CHECK(amisnap_backend_get(&be, "objects/cd/chunked", &got) == AMISNAP_OK);
    CHECK(got.len == 11 && memcmp(got.data, "hello world", 11) == 0);
    amisnap_buf_free(&got);

    /* put_abort: a partial upload must never become visible. */
    if (amisnap_backend_put_begin(&be, "objects/cd/aborted", &handle) == AMISNAP_OK) {
        CHECK(amisnap_backend_put_append(&be, handle, "partial", 7) == AMISNAP_OK);
        amisnap_backend_put_abort(&be, handle);
        CHECK(amisnap_backend_exists(&be, "objects/cd/aborted") == 0);
    } else {
        CHECK(0 /* put_begin failed */);
    }

    /* ListObjectsV2-backed list() against a real server's own XML --
     * the whole reason s3_scrape_listing()/xml_extract() exist is to
     * survive a real server's own response shape, not just this
     * project's own hand-built mock XML. */
    memset(&lc, 0, sizeof(lc));
    CHECK(amisnap_backend_list(&be, "objects", list_cb, &lc) == AMISNAP_OK);
    CHECK(lc.count == 2);
    CHECK(list_has(&lc, "ab"));
    CHECK(list_has(&lc, "cd"));

    memset(&lc, 0, sizeof(lc));
    CHECK(amisnap_backend_list(&be, "nonexistent", list_cb, &lc) == AMISNAP_OK);
    CHECK(lc.count == 0);

    /* remove: preserves the AMISNAP_ERR_NOT_FOUND contract despite a
     * real S3 server's own unconditionally-successful DELETE. */
    CHECK(amisnap_backend_remove(&be, "objects/ab/deadbeef") == AMISNAP_OK);
    CHECK(amisnap_backend_exists(&be, "objects/ab/deadbeef") == 0);
    CHECK(amisnap_backend_remove(&be, "objects/ab/deadbeef") == AMISNAP_ERR_NOT_FOUND);

    amisnap_backend_close(&be);

    if (g_failed) {
        fprintf(stderr, "FAIL: one or more checks failed\n");
        return 1;
    }
    printf("PASS\n");
    return 0;
}
