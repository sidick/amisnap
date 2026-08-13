/* live_test.c -- Phase 3 item 5's own host-CI check: drives webdav.c
 * against a REAL WebDAV server process (mini_webdav_server.py) over a
 * real POSIX TCP connection (posix_transport.c) -- an independent
 * implementation from this project's own in-memory mock
 * (tests/test_webdav.c), which is what actually catches interop bugs a
 * self-consistent mock never could.
 *
 * Not part of `make test` (needs a spawned server process, not a pure
 * unit test) -- driven by tests/webdav/run.sh instead, matching the
 * Copperline on-target scripts' own "separate opt-in script"
 * convention. Prints "PASS" and exits 0 on success; prints one FAIL
 * line per failed check (keeps going rather than aborting at the first
 * one, so a run reports everything wrong at once) and exits 1 if any
 * failed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "posix_transport.h"
#include "webdav.h"

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
    amisnap_webdav_config cfg;
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
    cfg.base_path = "/repo";

    CHECK(amisnap_backend_webdav_open(&cfg, &t, &be) == AMISNAP_OK);

    /* whole-object put/get, auto-creating parent collections */
    CHECK(amisnap_backend_put(&be, "objects/ab/deadbeef", "hello", 5) == AMISNAP_OK);
    CHECK(amisnap_backend_get(&be, "objects/ab/deadbeef", &got) == AMISNAP_OK);
    CHECK(got.len == 5 && memcmp(got.data, "hello", 5) == 0);
    amisnap_buf_free(&got);

    CHECK(amisnap_backend_exists(&be, "objects/ab/deadbeef") == 1);
    CHECK(amisnap_backend_exists(&be, "objects/ab/nope") == 0);
    CHECK(amisnap_backend_get(&be, "objects/ab/nope", &got) == AMISNAP_ERR_NOT_FOUND);

    /* streaming chunked-Transfer-Encoding upload against a real server --
     * the exact path that keeps a chunked restore.c restore memory-
     * bounded over WebDAV (Phase 2 item 7 / Phase 3 item 3). */
    CHECK(amisnap_backend_put_begin(&be, "objects/cd/chunked", &handle) == AMISNAP_OK);
    CHECK(amisnap_backend_put_append(&be, handle, "hello ", 6) == AMISNAP_OK);
    CHECK(amisnap_backend_put_append(&be, handle, "world", 5) == AMISNAP_OK);
    CHECK(amisnap_backend_put_finish(&be, handle) == AMISNAP_OK);
    CHECK(amisnap_backend_get(&be, "objects/cd/chunked", &got) == AMISNAP_OK);
    CHECK(got.len == 11 && memcmp(got.data, "hello world", 11) == 0);
    amisnap_buf_free(&got);

    /* put_abort: a partial upload must never become visible. */
    /* A failed put_begin() leaves *handle_out unset -- CHECK() reports
     * and continues rather than aborting, so the append/abort calls
     * below must be skipped rather than run on a garbage handle. */
    if (amisnap_backend_put_begin(&be, "objects/cd/aborted", &handle) == AMISNAP_OK) {
        CHECK(amisnap_backend_put_append(&be, handle, "partial", 7) == AMISNAP_OK);
        amisnap_backend_put_abort(&be, handle);
        CHECK(amisnap_backend_exists(&be, "objects/cd/aborted") == 0);
    } else {
        CHECK(0 /* put_begin failed */);
    }

    /* PROPFIND-backed list() against a real server's own multistatus XML --
     * the whole reason webdav_scrape_hrefs() exists is to survive a real
     * server's own href/namespace conventions, not just this project's own. */
    memset(&lc, 0, sizeof(lc));
    CHECK(amisnap_backend_list(&be, "objects", list_cb, &lc) == AMISNAP_OK);
    CHECK(lc.count == 2);
    CHECK(list_has(&lc, "ab"));
    CHECK(list_has(&lc, "cd"));

    memset(&lc, 0, sizeof(lc));
    CHECK(amisnap_backend_list(&be, "nonexistent", list_cb, &lc) == AMISNAP_OK);
    CHECK(lc.count == 0);

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
