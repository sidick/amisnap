/* test_webdav.c -- exercises webdav.c (an amisnap_backend_ops
 * implementation) against a mock amisnap_transport that implements just
 * enough of an in-memory WebDAV server (PUT/GET/DELETE/MKCOL/PROPFIND,
 * both Content-Length and chunked-Transfer-Encoding request bodies) to
 * prove webdav.c's own request-building, response-interpretation, and
 * auto-MKCOL-parents logic is actually correct -- not just "doesn't
 * crash". No real socket, no real HTTP server: the mock IS the network,
 * same spirit as test_chunked.c's own in-memory mem_reader.
 *
 * The mock deliberately enforces that a PUT/MKCOL's immediate parent
 * must already exist as a known collection (else 409 Conflict) --
 * forcing webdav.c's own mkcol_parents()/webdav_mkcol_abspath() to
 * really issue the right MKCOL requests in the right order for these
 * tests to pass at all, rather than merely not crashing if it didn't.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "backend.h"
#include "test.h"
#include "transport.h"
#include "webdav.h"

/* --- mock WebDAV server state (lives in amisnap_transport.ctx) --- */

typedef struct {
    char *path;
    unsigned char *data;
    size_t len;
} mock_file;

typedef struct {
    char *path;
} mock_col;

typedef struct {
    mock_file *files;
    size_t file_count, file_cap;
    mock_col *cols;
    size_t col_count, col_cap;
    char last_auth[256]; /* last Authorization header value seen, "" if none */
    int require_auth;    /* if set, every request without a valid Authorization is rejected 401 */
} mock_server;

static void mock_server_init(mock_server *s)
{
    memset(s, 0, sizeof(*s));
}

static void mock_server_free(mock_server *s)
{
    size_t i;

    for (i = 0; i < s->file_count; i++) { free(s->files[i].path); free(s->files[i].data); }
    for (i = 0; i < s->col_count; i++) free(s->cols[i].path);
    free(s->files);
    free(s->cols);
}

static int mock_col_exists(mock_server *s, const char *path)
{
    size_t i;
    if (path[0] == '\0') return 1; /* root always exists */
    for (i = 0; i < s->col_count; i++)
        if (strcmp(s->cols[i].path, path) == 0) return 1;
    return 0;
}

static mock_file *mock_file_find(mock_server *s, const char *path)
{
    size_t i;
    for (i = 0; i < s->file_count; i++)
        if (strcmp(s->files[i].path, path) == 0) return &s->files[i];
    return NULL;
}

static void parent_of(const char *path, char *out, size_t outsize)
{
    const char *slash = strrchr(path, '/');
    size_t len = slash ? (size_t)(slash - path) : 0;

    if (len >= outsize) len = outsize - 1;
    memcpy(out, path, len);
    out[len] = '\0';
}

/* --- accumulate send()'d bytes and decode once a full request has
 * arrived (request line + headers + Content-Length or chunked body) --- */

typedef struct {
    amisnap_buf request;
    amisnap_buf response;
    size_t response_pos;
    int have_response;
} mock_conn;

static int try_decode_chunked(const unsigned char *p, size_t len, amisnap_buf *body)
{
    size_t pos = 0;

    amisnap_buf_init(body);
    for (;;) {
        const unsigned char *nl = memchr(p + pos, '\n', len - pos);
        size_t linelen, chunklen = 0;
        size_t i;

        if (!nl) return 0;
        linelen = (size_t)(nl - (p + pos));
        if (linelen > 0 && p[pos + linelen - 1] == '\r') linelen--;
        for (i = 0; i < linelen; i++) {
            char c = (char)p[pos + i];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            chunklen = chunklen * 16 + (size_t)d;
        }
        pos += (size_t)(nl - (p + pos)) + 1;

        if (chunklen == 0) {
            if (pos + 2 > len) return 0;
            return 1; /* trailing "\r\n" after the zero chunk: done */
        }
        if (pos + chunklen + 2 > len) return 0; /* need more data */
        amisnap_buf_bytes(body, p + pos, chunklen);
        pos += chunklen + 2; /* skip data + trailing "\r\n" */
    }
}

static void mock_serve(mock_server *srv, const char *method, const char *path,
                        const char *auth, amisnap_buf *body, amisnap_buf *out_response,
                        const char *depth)
{
    char status_line_buf[64];
    const char *status = "200 OK";
    amisnap_buf resp_body;

    amisnap_buf_init(&resp_body);
    srv->last_auth[0] = '\0';
    if (auth) {
        size_t n = strlen(auth);
        if (n >= sizeof(srv->last_auth)) n = sizeof(srv->last_auth) - 1;
        memcpy(srv->last_auth, auth, n);
        srv->last_auth[n] = '\0';
    }

    if (srv->require_auth && !auth) {
        status = "401 Unauthorized";
    } else if (strcmp(method, "PUT") == 0) {
        char parent[512];
        mock_file *f;

        parent_of(path, parent, sizeof(parent));
        if (!mock_col_exists(srv, parent)) {
            status = "409 Conflict";
        } else {
            f = mock_file_find(srv, path);
            if (!f) {
                srv->files = (mock_file *)realloc(srv->files, (srv->file_count + 1) * sizeof(*srv->files));
                f = &srv->files[srv->file_count++];
                f->path = (char *)malloc(strlen(path) + 1);
                strcpy(f->path, path);
                f->data = NULL;
                f->len = 0;
            }
            free(f->data);
            f->data = (unsigned char *)malloc(body->len ? body->len : 1);
            memcpy(f->data, body->data, body->len);
            f->len = body->len;
            status = "201 Created";
        }
    } else if (strcmp(method, "GET") == 0) {
        mock_file *f = mock_file_find(srv, path);
        if (!f) {
            status = "404 Not Found";
        } else {
            amisnap_buf_bytes(&resp_body, f->data, f->len);
            status = "200 OK";
        }
    } else if (strcmp(method, "DELETE") == 0) {
        mock_file *f = mock_file_find(srv, path);
        if (f) {
            size_t idx = (size_t)(f - srv->files);
            free(f->path);
            free(f->data);
            memmove(&srv->files[idx], &srv->files[idx + 1], (srv->file_count - idx - 1) * sizeof(*srv->files));
            srv->file_count--;
            status = "204 No Content";
        } else {
            status = "404 Not Found";
        }
    } else if (strcmp(method, "MKCOL") == 0) {
        char parent[512];

        if (mock_col_exists(srv, path)) {
            status = "405 Method Not Allowed";
        } else {
            parent_of(path, parent, sizeof(parent));
            if (!mock_col_exists(srv, parent)) {
                status = "409 Conflict";
            } else {
                srv->cols = (mock_col *)realloc(srv->cols, (srv->col_count + 1) * sizeof(*srv->cols));
                srv->cols[srv->col_count].path = (char *)malloc(strlen(path) + 1);
                strcpy(srv->cols[srv->col_count].path, path);
                srv->col_count++;
                status = "201 Created";
            }
        }
    } else if (strcmp(method, "PROPFIND") == 0) {
        int is_col = mock_col_exists(srv, path);
        mock_file *f = is_col ? NULL : mock_file_find(srv, path);

        if (!is_col && !f) {
            status = "404 Not Found";
        } else {
            char buf[4096];
            int n = 0;

            /* Newline-separated elements, on purpose: real servers
             * (Apache mod_dav) pretty-print their PROPFIND XML, and the
             * href scraper must NOT turn the inter-element whitespace
             * into phantom entries (it once matched the "</D:href>"
             * closing tag and scraped the following "\n" as a name). */
            n += snprintf(buf + n, sizeof(buf) - (size_t)n,
                           "<?xml version=\"1.0\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n"
                           "<D:response><D:href>%s%s</D:href></D:response>\n",
                           path[0] ? path : "/", is_col ? "/" : "");
            if (is_col && depth && strcmp(depth, "1") == 0) {
                size_t i;
                size_t plen = strlen(path);

                for (i = 0; i < srv->file_count; i++) {
                    const char *fp = srv->files[i].path;
                    if (strncmp(fp, path, plen) == 0 && fp[plen] == '/' && strchr(fp + plen + 1, '/') == NULL)
                        n += snprintf(buf + n, sizeof(buf) - (size_t)n,
                                      "<D:response><D:href>%s</D:href></D:response>\n", fp);
                }
                for (i = 0; i < srv->col_count; i++) {
                    const char *cp = srv->cols[i].path;
                    if (strncmp(cp, path, plen) == 0 && cp[plen] == '/' && strchr(cp + plen + 1, '/') == NULL)
                        n += snprintf(buf + n, sizeof(buf) - (size_t)n,
                                      "<D:response><D:href>%s/</D:href></D:response>\n", cp);
                }
            }
            n += snprintf(buf + n, sizeof(buf) - (size_t)n, "</D:multistatus>\n");
            amisnap_buf_bytes(&resp_body, buf, (size_t)n);
            status = "207 Multi-Status";
        }
    } else {
        status = "501 Not Implemented";
    }

    snprintf(status_line_buf, sizeof(status_line_buf), "HTTP/1.1 %s\r\n", status);
    amisnap_buf_init(out_response);
    amisnap_buf_bytes(out_response, status_line_buf, strlen(status_line_buf));
    {
        char cl[64];
        int n = snprintf(cl, sizeof(cl), "Content-Length: %lu\r\n\r\n", (unsigned long)resp_body.len);
        amisnap_buf_bytes(out_response, cl, (size_t)n);
    }
    if (resp_body.len) amisnap_buf_bytes(out_response, resp_body.data, resp_body.len);
    amisnap_buf_free(&resp_body);
}

/* memmem() is a GNU/BSD extension (needs _GNU_SOURCE on glibc, absent
 * by default on the CI container's toolchain though present on macOS
 * libc without it -- confirmed the hard way when CI failed here and a
 * local `make test` didn't) -- a plain 4-byte needle search avoids the
 * portability dependency entirely rather than fighting feature-test
 * macros. */
static const unsigned char *find_crlfcrlf(const unsigned char *buf, size_t len)
{
    size_t i;
    if (len < 4) return NULL;
    for (i = 0; i + 4 <= len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i;
    }
    return NULL;
}

static void mock_process_if_ready(amisnap_transport *t, mock_conn *c)
{
    mock_server *srv = (mock_server *)t->ctx;
    const unsigned char *req = c->request.data;
    size_t req_len = c->request.len;
    const unsigned char *hdr_end;
    char method[16], path[512], depth[8], auth[256];
    size_t method_len, path_len;
    const unsigned char *p, *line_end;
    long content_length = -1;
    int chunked = 0;
    amisnap_buf body;

    if (c->have_response) return;

    hdr_end = find_crlfcrlf(req, req_len);
    if (!hdr_end) return; /* headers not fully arrived yet */

    p = req;
    line_end = (const unsigned char *)memchr(p, '\r', req_len);
    if (!line_end) return;

    {
        const unsigned char *sp1 = memchr(p, ' ', (size_t)(line_end - p));
        const unsigned char *sp2 = sp1 ? memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1))) : NULL;
        if (!sp1 || !sp2) return;
        method_len = (size_t)(sp1 - p);
        if (method_len >= sizeof(method)) method_len = sizeof(method) - 1;
        memcpy(method, p, method_len);
        method[method_len] = '\0';
        path_len = (size_t)(sp2 - (sp1 + 1));
        if (path_len >= sizeof(path)) path_len = sizeof(path) - 1;
        memcpy(path, sp1 + 1, path_len);
        path[path_len] = '\0';
    }

    depth[0] = '\0';
    auth[0] = '\0';
    {
        const unsigned char *hp = line_end + 2;
        while (hp < hdr_end) {
            const unsigned char *hl_end = memchr(hp, '\r', (size_t)(hdr_end - hp));
            size_t hl_len = hl_end ? (size_t)(hl_end - hp) : (size_t)(hdr_end - hp);

            if (hl_len > 15 && strncasecmp((const char *)hp, "Content-Length:", 15) == 0)
                content_length = atol((const char *)hp + 15);
            else if (hl_len > 18 && strncasecmp((const char *)hp, "Transfer-Encoding:", 18) == 0 &&
                     strstr((const char *)hp, "chunked"))
                chunked = 1;
            else if (hl_len > 7 && strncasecmp((const char *)hp, "Depth:", 6) == 0) {
                size_t vlen = hl_len - 7;
                if (vlen >= sizeof(depth)) vlen = sizeof(depth) - 1;
                memcpy(depth, hp + 7, vlen);
                depth[vlen] = '\0';
            } else if (hl_len > 15 && strncasecmp((const char *)hp, "Authorization:", 14) == 0) {
                size_t vlen = hl_len - 15;
                if (vlen >= sizeof(auth)) vlen = sizeof(auth) - 1;
                memcpy(auth, hp + 15, vlen);
                auth[vlen] = '\0';
            }
            hp = hl_end ? hl_end + 2 : hdr_end;
        }
    }

    {
        const unsigned char *body_start = hdr_end + 4;
        size_t avail = req_len - (size_t)(body_start - req);

        if (chunked) {
            if (!try_decode_chunked(body_start, avail, &body)) return; /* need more */
        } else if (content_length > 0) {
            if (avail < (size_t)content_length) return; /* need more */
            amisnap_buf_init(&body);
            amisnap_buf_bytes(&body, body_start, (size_t)content_length);
        } else {
            amisnap_buf_init(&body);
        }
    }

    mock_serve(srv, method, path, auth[0] ? auth : NULL, &body, &c->response, depth[0] ? depth : NULL);
    amisnap_buf_free(&body);
    c->have_response = 1;
}

static int mock_connect(amisnap_transport *t, const char *host, uint16_t port, void **handle_out)
{
    mock_conn *c = (mock_conn *)calloc(1, sizeof(*c));
    (void)t; (void)host; (void)port;
    if (!c) return AMISNAP_ERR_NOMEM;
    amisnap_buf_init(&c->request);
    *handle_out = c;
    return AMISNAP_OK;
}

static int mock_send(amisnap_transport *t, void *handle, const void *data, size_t len)
{
    mock_conn *c = (mock_conn *)handle;
    int rc;

    /* A real bsdsocket connection is a persistent byte stream: webdav.c
     * legitimately reuses one connection (keep-alive) for several
     * request/response exchanges in a row. Once we've already answered
     * a previous request on this same handle, this send() call must be
     * the START of the NEXT one (webdav_exchange()'s own discipline
     * guarantees the caller always fully drains a response via recv()
     * before sending anything new) -- reset so the request/response
     * buffers represent only the new exchange, not a mix of two. */
    if (c->have_response) {
        amisnap_buf_free(&c->request);
        amisnap_buf_init(&c->request);
        amisnap_buf_free(&c->response);
        c->response_pos = 0;
        c->have_response = 0;
    }

    rc = amisnap_buf_bytes(&c->request, data, len);
    if (rc != AMISNAP_OK) return rc;
    mock_process_if_ready(t, c);
    return AMISNAP_OK;
}

static int mock_recv(amisnap_transport *t, void *handle, void *buf, size_t len, size_t *got)
{
    mock_conn *c = (mock_conn *)handle;
    size_t avail;
    (void)t;

    if (!c->have_response) { *got = 0; return AMISNAP_OK; }
    avail = c->response.len - c->response_pos;
    if (avail > len) avail = len;
    if (avail > 0) memcpy(buf, c->response.data + c->response_pos, avail);
    c->response_pos += avail;
    *got = avail;
    return AMISNAP_OK;
}

static void mock_close(amisnap_transport *t, void *handle)
{
    mock_conn *c = (mock_conn *)handle;
    (void)t;
    if (c) {
        amisnap_buf_free(&c->request);
        if (c->have_response) amisnap_buf_free(&c->response);
        free(c);
    }
}

static const amisnap_transport_ops mock_ops = { mock_connect, mock_send, mock_recv, mock_close };

/* --- tests --- */

static void run_basic_roundtrip_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_webdav_config cfg;
    amisnap_buf got;
    int rc;

    mock_server_init(&srv);
    t.ops = &mock_ops;
    t.ctx = &srv;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "example.com";
    cfg.port = 80;
    cfg.base_path = "/dav/amisnap";

    rc = amisnap_backend_webdav_open(&cfg, &t, &be);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(mock_col_exists(&srv, "/dav") && mock_col_exists(&srv, "/dav/amisnap"));

    /* put() must auto-MKCOL every missing parent collection first. */
    rc = amisnap_backend_put(&be, "objects/ab/deadbeef", "hello", 5);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(mock_col_exists(&srv, "/dav/amisnap/objects"));
    TEST_CHECK(mock_col_exists(&srv, "/dav/amisnap/objects/ab"));

    rc = amisnap_backend_get(&be, "objects/ab/deadbeef", &got);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(got.len == 5 && memcmp(got.data, "hello", 5) == 0);
    amisnap_buf_free(&got);

    rc = amisnap_backend_get(&be, "objects/ab/doesnotexist", &got);
    TEST_CHECK(rc == AMISNAP_ERR_NOT_FOUND);

    rc = amisnap_backend_exists(&be, "objects/ab/deadbeef");
    TEST_CHECK(rc == 1);
    rc = amisnap_backend_exists(&be, "objects/ab/nope");
    TEST_CHECK(rc == 0);

    rc = amisnap_backend_remove(&be, "objects/ab/deadbeef");
    TEST_CHECK(rc == AMISNAP_OK);
    rc = amisnap_backend_exists(&be, "objects/ab/deadbeef");
    TEST_CHECK(rc == 0);
    rc = amisnap_backend_remove(&be, "objects/ab/deadbeef");
    TEST_CHECK(rc == AMISNAP_ERR_NOT_FOUND);

    amisnap_backend_close(&be);
    mock_server_free(&srv);
}

struct webdav_test_list_ctx {
    char seen[8][64];
    size_t count;
};

static void webdav_test_list_cb(void *user, const char *name)
{
    struct webdav_test_list_ctx *c = (struct webdav_test_list_ctx *)user;

    if (c->count < 8) {
        strncpy(c->seen[c->count], name, 63);
        c->seen[c->count][63] = '\0';
        c->count++;
    }
}

static void run_list_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_webdav_config cfg;
    struct webdav_test_list_ctx lc;
    int rc;

    mock_server_init(&srv);
    t.ops = &mock_ops;
    t.ctx = &srv;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "example.com";
    cfg.port = 80;
    cfg.base_path = "";

    rc = amisnap_backend_webdav_open(&cfg, &t, &be);
    TEST_CHECK(rc == AMISNAP_OK);

    TEST_CHECK(amisnap_backend_put(&be, "objects/ab/one", "x", 1) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put(&be, "objects/cd/two", "y", 1) == AMISNAP_OK);

    memset(&lc, 0, sizeof(lc));
    rc = amisnap_backend_list(&be, "objects", webdav_test_list_cb, &lc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(lc.count == 2);

    /* A prefix that doesn't exist at all lists as empty, not an error. */
    memset(&lc, 0, sizeof(lc));
    rc = amisnap_backend_list(&be, "nonexistent", webdav_test_list_cb, &lc);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(lc.count == 0);

    amisnap_backend_close(&be);
    mock_server_free(&srv);
}

static void run_streaming_upload_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_webdav_config cfg;
    void *handle;
    amisnap_buf got;
    int rc;

    mock_server_init(&srv);
    t.ops = &mock_ops;
    t.ctx = &srv;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "example.com";
    cfg.port = 8080;
    cfg.base_path = "/r";

    rc = amisnap_backend_webdav_open(&cfg, &t, &be);
    TEST_CHECK(rc == AMISNAP_OK);

    rc = amisnap_backend_put_begin(&be, "objects/ff/chunked", &handle);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, "hello ", 6) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, "world", 5) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, NULL, 0) == AMISNAP_OK); /* a no-op, not a terminator */
    TEST_CHECK(amisnap_backend_put_finish(&be, handle) == AMISNAP_OK);

    rc = amisnap_backend_get(&be, "objects/ff/chunked", &got);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(got.len == 11 && memcmp(got.data, "hello world", 11) == 0);
    amisnap_buf_free(&got);

    /* put_abort: the partial upload must never become visible. */
    rc = amisnap_backend_put_begin(&be, "objects/ff/aborted", &handle);
    TEST_CHECK(rc == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, "partial", 7) == AMISNAP_OK);
    amisnap_backend_put_abort(&be, handle);
    rc = amisnap_backend_exists(&be, "objects/ff/aborted");
    TEST_CHECK(rc == 0);

    amisnap_backend_close(&be);
    mock_server_free(&srv);
}

static void run_auth_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_webdav_config cfg;
    int rc;

    mock_server_init(&srv);
    srv.require_auth = 1;
    t.ops = &mock_ops;
    t.ctx = &srv;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "example.com";
    cfg.port = 80;
    cfg.base_path = "/dav"; /* non-empty: open()'s own MKCOL bootstrap must actually
                              * send a request for this test to observe its auth header --
                              * base_path="" sends none at all (root always exists). */
    cfg.username = "user";
    cfg.password = "pass";

    rc = amisnap_backend_webdav_open(&cfg, &t, &be);
    TEST_CHECK(rc == AMISNAP_OK); /* the open()-time MKCOL bootstrap itself needed valid auth to succeed */
    TEST_CHECK(strcmp(srv.last_auth, "Basic dXNlcjpwYXNz") == 0);

    amisnap_backend_close(&be);
    mock_server_free(&srv);

    /* Without credentials, the same server (401 on everything) must
     * make even amisnap_backend_webdav_open() itself fail -- proving
     * the failure isn't silently swallowed. */
    mock_server_init(&srv);
    srv.require_auth = 1;
    t.ctx = &srv;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "example.com";
    cfg.port = 80;
    cfg.base_path = "/dav";
    rc = amisnap_backend_webdav_open(&cfg, &t, &be);
    TEST_CHECK(rc != AMISNAP_OK);
    mock_server_free(&srv);
}

static void run_url_parse_tests(void)
{
    amisnap_webdav_url u;

    TEST_CHECK(amisnap_webdav_parse_url("http://example.com/dav/amisnap", &u) == AMISNAP_OK);
    TEST_CHECK(strcmp(u.host, "example.com") == 0);
    TEST_CHECK(u.port == 80);
    TEST_CHECK(strcmp(u.base_path, "/dav/amisnap") == 0);
    TEST_CHECK(u.username[0] == '\0');
    TEST_CHECK(u.tls == 0);

    TEST_CHECK(amisnap_webdav_parse_url("https://example.com/dav", &u) == AMISNAP_OK);
    TEST_CHECK(u.port == 443);
    TEST_CHECK(u.tls == 1);

    TEST_CHECK(amisnap_webdav_parse_url("http://example.com:8080/x", &u) == AMISNAP_OK);
    TEST_CHECK(u.port == 8080);
    TEST_CHECK(strcmp(u.host, "example.com") == 0);
    TEST_CHECK(strcmp(u.base_path, "/x") == 0);

    TEST_CHECK(amisnap_webdav_parse_url("http://user:pass@example.com/x", &u) == AMISNAP_OK);
    TEST_CHECK(strcmp(u.username, "user") == 0);
    TEST_CHECK(strcmp(u.password, "pass") == 0);
    TEST_CHECK(strcmp(u.host, "example.com") == 0);

    TEST_CHECK(amisnap_webdav_parse_url("http://user@example.com:8080/x", &u) == AMISNAP_OK);
    TEST_CHECK(strcmp(u.username, "user") == 0);
    TEST_CHECK(u.password[0] == '\0');
    TEST_CHECK(u.port == 8080);

    /* no path at all -> base_path defaults to "" (server root) */
    TEST_CHECK(amisnap_webdav_parse_url("http://example.com", &u) == AMISNAP_OK);
    TEST_CHECK(u.base_path[0] == '\0');

    /* percent-encoded userinfo */
    TEST_CHECK(amisnap_webdav_parse_url("http://a%40b:p%3Ass@example.com/x", &u) == AMISNAP_OK);
    TEST_CHECK(strcmp(u.username, "a@b") == 0);
    TEST_CHECK(strcmp(u.password, "p:ss") == 0);

    TEST_CHECK(amisnap_webdav_parse_url("ftp://example.com/x", &u) == AMISNAP_ERR_MALFORMED);
    TEST_CHECK(amisnap_webdav_parse_url("http:///x", &u) == AMISNAP_ERR_MALFORMED); /* empty host */
    TEST_CHECK(amisnap_webdav_parse_url("http://example.com:notaport/x", &u) == AMISNAP_ERR_MALFORMED);
    TEST_CHECK(amisnap_webdav_parse_url("http://example.com:99999/x", &u) == AMISNAP_ERR_MALFORMED);
}

void run_webdav_tests(void)
{
    run_basic_roundtrip_tests();
    run_list_tests();
    run_streaming_upload_tests();
    run_auth_tests();
    run_url_parse_tests();
}
