/* test_s3.c -- exercises s3.c (an amisnap_backend_ops implementation)
 * against a mock amisnap_transport that implements just enough of an
 * in-memory S3-compatible server (PUT/GET/HEAD/DELETE, ListObjectsV2
 * including pagination) to prove s3.c's own request-building and
 * response-interpretation is correct -- not just "doesn't crash". No
 * real socket, no real HTTP server, no real SigV4 verification (that's
 * tests/test_sigv4.c's own job against real AWS vectors; this mock
 * only sanity-checks the Authorization header's shape) -- same spirit
 * as test_webdav.c, simplified where S3 itself is simpler than WebDAV
 * (no MKCOL/collections, no chunked request bodies -- s3_put_finish()
 * always sends one whole-buffer PUT with a real Content-Length).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "backend.h"
#include "s3.h"
#include "test.h"
#include "transport.h"

/* --- mock S3 server state (lives in amisnap_transport.ctx) --- */

typedef struct {
    char *key;   /* full request path, e.g. "/mybucket/objects/ab/hex64" */
    unsigned char *data;
    size_t len;
} mock_object;

typedef struct {
    mock_object *objs;
    size_t count, cap;
    size_t list_page_size; /* objects per ListObjectsV2 page -- small (e.g. 1) to
                             * exercise pagination; 0 = unbounded (one page). */
} mock_server;

static void mock_server_init(mock_server *s)
{
    memset(s, 0, sizeof(*s));
}

static void mock_server_free(mock_server *s)
{
    size_t i;
    for (i = 0; i < s->count; i++) { free(s->objs[i].key); free(s->objs[i].data); }
    free(s->objs);
}

static mock_object *mock_find(mock_server *s, const char *key)
{
    size_t i;
    for (i = 0; i < s->count; i++)
        if (strcmp(s->objs[i].key, key) == 0) return &s->objs[i];
    return NULL;
}

static char *dup_str(const char *s)
{
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    memcpy(out, s, len + 1);
    return out;
}

static void mock_put(mock_server *s, const char *key, const unsigned char *data, size_t len)
{
    mock_object *o = mock_find(s, key);
    unsigned char *copy = (unsigned char *)malloc(len ? len : 1);
    memcpy(copy, data, len);

    if (o) {
        free(o->data);
        o->data = copy;
        o->len = len;
        return;
    }
    if (s->count == s->cap) {
        size_t newcap = s->cap ? s->cap * 2 : 8;
        s->objs = (mock_object *)realloc(s->objs, newcap * sizeof(*s->objs));
        s->cap = newcap;
    }
    s->objs[s->count].key = dup_str(key);
    s->objs[s->count].data = copy;
    s->objs[s->count].len = len;
    s->count++;
}

static int mock_delete(mock_server *s, const char *key)
{
    size_t i;
    for (i = 0; i < s->count; i++) {
        if (strcmp(s->objs[i].key, key) == 0) {
            free(s->objs[i].key);
            free(s->objs[i].data);
            s->objs[i] = s->objs[s->count - 1];
            s->count--;
            return 1;
        }
    }
    return 0;
}

/* --- URL percent-decoding, same shape as s3.c's own (duplicated here
 * deliberately -- this is the test's independent decoder for parsing
 * what s3.c actually sent, not a shortcut that reuses s3.c's own). --- */

static int is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

static void percent_decode(const char *src, size_t len, char *dst, size_t dst_size)
{
    size_t i, j = 0;
    for (i = 0; i < len && j + 1 < dst_size; i++) {
        if (src[i] == '%' && i + 2 < len && is_hex(src[i + 1]) && is_hex(src[i + 2])) {
            dst[j++] = (char)(hexval(src[i + 1]) * 16 + hexval(src[i + 2]));
            i += 2;
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/* --- request accumulation + parsing (Content-Length bodies only --
 * s3.c never sends a chunked request) --- */

typedef struct {
    amisnap_buf request;
    amisnap_buf response;
    size_t response_pos;
    int have_response;
} mock_conn;

static const unsigned char *find_crlfcrlf(const unsigned char *buf, size_t len)
{
    size_t i;
    if (len < 4) return NULL;
    for (i = 0; i + 4 <= len; i++)
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n')
            return buf + i;
    return NULL;
}

static void mock_serve(mock_server *srv, const char *method, const char *raw_path,
                        const char *auth, const amisnap_buf *body, amisnap_buf *resp)
{
    char path[1024], query[1024];
    const char *q = strchr(raw_path, '?');
    int status;
    amisnap_buf out_body;

    amisnap_buf_init(&out_body);

    if (q) {
        size_t plen = (size_t)(q - raw_path);
        if (plen >= sizeof(path)) plen = sizeof(path) - 1;
        memcpy(path, raw_path, plen);
        path[plen] = '\0';
        strncpy(query, q + 1, sizeof(query) - 1);
        query[sizeof(query) - 1] = '\0';
    } else {
        strncpy(path, raw_path, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
        query[0] = '\0';
    }
    /* Every real request must carry a well-formed SigV4 Authorization
     * header -- sanity-checked here (not re-verified cryptographically;
     * test_sigv4.c already proves the signing math against real AWS
     * vectors), so a bug that dropped the header entirely would still
     * be caught. */
    TEST_CHECK(auth != NULL);
    TEST_CHECK(auth && strncmp(auth, "AWS4-HMAC-SHA256 Credential=",
                                strlen("AWS4-HMAC-SHA256 Credential=")) == 0);

    if (strcmp(method, "PUT") == 0) {
        mock_put(srv, path, body->data, body->len);
        status = 200;
    } else if (strcmp(method, "GET") == 0 && query[0] != '\0' && strstr(query, "list-type=2")) {
        /* ListObjectsV2 (bucket-root GET with a query string). */
        char prefix[512] = "", delimiter[8] = "", continuation[512] = "";
        const char *p = query;

        while (p && *p) {
            const char *amp = strchr(p, '&');
            size_t kvlen = amp ? (size_t)(amp - p) : strlen(p);
            const char *eq = (const char *)memchr(p, '=', kvlen);
            if (eq) {
                size_t klen = (size_t)(eq - p);
                size_t vlen = kvlen - klen - 1;
                char decoded[512];
                percent_decode(eq + 1, vlen, decoded, sizeof(decoded));
                if (klen == 6 && strncmp(p, "prefix", 6) == 0) strcpy(prefix, decoded);
                else if (klen == 9 && strncmp(p, "delimiter", 9) == 0) strcpy(delimiter, decoded);
                else if (klen == 18 && strncmp(p, "continuation-token", 18) == 0) strcpy(continuation, decoded);
            }
            p = amp ? amp + 1 : NULL;
        }

        {
            size_t plen = strlen(prefix);
            size_t emitted = 0, skip = 0;
            size_t i;
            int truncated = 0;
            char last_key[512] = "";

            if (continuation[0]) skip = (size_t)atoi(continuation);

            amisnap_buf_bytes(&out_body, "<ListBucketResult>", strlen("<ListBucketResult>"));
            for (i = 0; i < srv->count; i++) {
                /* srv->objs[i].key is the full request path
                 * ("/bucket/objects/ab/hex1"); a real ListObjectsV2
                 * response's <Key> is the S3 object key alone, with no
                 * bucket component -- skip past "/<bucket>/" the same
                 * way s3.c's own queried_prefix never includes it. */
                const char *s3key = strchr(srv->objs[i].key + 1, '/');
                const char *rel;
                if (!s3key) continue;
                s3key++;
                if (strncmp(s3key, prefix, plen) != 0) continue;
                rel = s3key + plen;
                if (delimiter[0] && strchr(rel, delimiter[0])) continue; /* one level only */
                if (skip > 0) { skip--; continue; }
                if (srv->list_page_size && emitted >= srv->list_page_size) { truncated = 1; break; }
                {
                    char entry[600];
                    int n = snprintf(entry, sizeof(entry), "<Contents><Key>%s</Key></Contents>",
                                      s3key);
                    amisnap_buf_bytes(&out_body, entry, (size_t)n);
                }
                strcpy(last_key, s3key);
                emitted++;
            }
            amisnap_buf_bytes(&out_body, "<IsTruncated>", strlen("<IsTruncated>"));
            amisnap_buf_bytes(&out_body, truncated ? "true" : "false", truncated ? 4 : 5);
            amisnap_buf_bytes(&out_body, "</IsTruncated>", strlen("</IsTruncated>"));
            if (truncated) {
                char tok[32];
                int n;
                /* Token encodes how many matching entries to skip on
                 * the next page -- a real server's token is opaque;
                 * this mock's own is deliberately simple since s3.c
                 * only round-trips it verbatim. */
                n = snprintf(tok, sizeof(tok), "%d",
                             (int)((continuation[0] ? atoi(continuation) : 0) + emitted));
                amisnap_buf_bytes(&out_body, "<NextContinuationToken>", strlen("<NextContinuationToken>"));
                amisnap_buf_bytes(&out_body, tok, (size_t)n);
                amisnap_buf_bytes(&out_body, "</NextContinuationToken>", strlen("</NextContinuationToken>"));
            }
            amisnap_buf_bytes(&out_body, "</ListBucketResult>", strlen("</ListBucketResult>"));
        }
        status = 200;
    } else if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
        mock_object *o = mock_find(srv, path);
        if (!o) {
            status = 404;
        } else {
            status = 200;
            if (strcmp(method, "GET") == 0) amisnap_buf_bytes(&out_body, o->data, o->len);
        }
    } else if (strcmp(method, "DELETE") == 0) {
        mock_delete(srv, path);
        status = 204; /* S3's own DELETE is unconditionally "successful" */
    } else {
        status = 400;
    }

    {
        char status_line[64];
        int n = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d X\r\n", status);
        amisnap_buf_bytes(resp, status_line, (size_t)n);
    }
    {
        char cl[64];
        int n = snprintf(cl, sizeof(cl), "Content-Length: %lu\r\n\r\n", (unsigned long)out_body.len);
        amisnap_buf_bytes(resp, cl, (size_t)n);
    }
    if (out_body.len) amisnap_buf_bytes(resp, out_body.data, out_body.len);
    amisnap_buf_free(&out_body);
}

static void mock_process_if_ready(amisnap_transport *t, mock_conn *c)
{
    mock_server *srv = (mock_server *)t->ctx;
    const unsigned char *req = c->request.data;
    size_t req_len = c->request.len;
    const unsigned char *hdr_end;
    char method[16], path[1024], auth[512];
    size_t method_len, path_len;
    const unsigned char *p, *line_end;
    long content_length = 0;
    amisnap_buf body;

    if (c->have_response) return;

    hdr_end = find_crlfcrlf(req, req_len);
    if (!hdr_end) return;

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

    auth[0] = '\0';
    {
        const unsigned char *hp = line_end + 2;
        while (hp < hdr_end) {
            const unsigned char *hl_end = memchr(hp, '\r', (size_t)(hdr_end - hp));
            size_t hl_len = hl_end ? (size_t)(hl_end - hp) : (size_t)(hdr_end - hp);

            if (hl_len > 15 && strncasecmp((const char *)hp, "Content-Length:", 15) == 0)
                content_length = atol((const char *)hp + 15);
            else if (hl_len > 14 && strncasecmp((const char *)hp, "Authorization:", 14) == 0) {
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

        if (content_length > 0) {
            if (avail < (size_t)content_length) return; /* need more */
            amisnap_buf_init(&body);
            amisnap_buf_bytes(&body, body_start, (size_t)content_length);
        } else {
            amisnap_buf_init(&body);
        }
    }

    mock_serve(srv, method, path, auth[0] ? auth : NULL, &body, &c->response);
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

static amisnap_s3_config test_cfg(void)
{
    amisnap_s3_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "s3.example.test";
    cfg.port = 9000;
    cfg.bucket = "mybucket";
    cfg.base_path = "";
    cfg.region = "us-east-1";
    cfg.access_key = "AKIDEXAMPLE";
    cfg.secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    return cfg;
}

static void run_roundtrip_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_s3_config cfg = test_cfg();
    amisnap_buf got;

    mock_server_init(&srv);
    t.ops = &mock_ops;
    t.ctx = &srv;

    TEST_CHECK(amisnap_backend_s3_open(&cfg, &t, &be) == AMISNAP_OK);

    TEST_CHECK(amisnap_backend_exists(&be, "objects/ab/hex64") == 0);
    TEST_CHECK(amisnap_backend_get(&be, "objects/ab/hex64", &got) == AMISNAP_ERR_NOT_FOUND);

    TEST_CHECK(amisnap_backend_put(&be, "objects/ab/hex64", "hello", 5) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/ab/hex64") == 1);
    TEST_CHECK(amisnap_backend_get(&be, "objects/ab/hex64", &got) == AMISNAP_OK);
    TEST_CHECK(got.len == 5 && memcmp(got.data, "hello", 5) == 0);
    amisnap_buf_free(&got);

    /* mkcol is a documented no-op. */
    TEST_CHECK(amisnap_backend_mkcol(&be, "snapshots") == AMISNAP_OK);

    /* remove: preserves the AMISNAP_ERR_NOT_FOUND contract despite S3's
     * own unconditionally-successful DELETE (s3_remove()'s own HEAD
     * first). */
    TEST_CHECK(amisnap_backend_remove(&be, "objects/ab/hex64") == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/ab/hex64") == 0);
    TEST_CHECK(amisnap_backend_remove(&be, "objects/ab/hex64") == AMISNAP_ERR_NOT_FOUND);

    amisnap_backend_close(&be);
    mock_server_free(&srv);
}

static void run_streaming_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_s3_config cfg = test_cfg();
    void *handle;
    amisnap_buf got;

    mock_server_init(&srv);
    t.ops = &mock_ops;
    t.ctx = &srv;
    TEST_CHECK(amisnap_backend_s3_open(&cfg, &t, &be) == AMISNAP_OK);

    TEST_CHECK(amisnap_backend_put_begin(&be, "objects/cd/big", &handle) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, "part1-", 6) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, "part2", 5) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_finish(&be, handle) == AMISNAP_OK);

    TEST_CHECK(amisnap_backend_get(&be, "objects/cd/big", &got) == AMISNAP_OK);
    TEST_CHECK(got.len == 11 && memcmp(got.data, "part1-part2", 11) == 0);
    amisnap_buf_free(&got);

    /* abort: nothing observable at the key. */
    TEST_CHECK(amisnap_backend_put_begin(&be, "objects/cd/aborted", &handle) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put_append(&be, handle, "x", 1) == AMISNAP_OK);
    amisnap_backend_put_abort(&be, handle);
    TEST_CHECK(amisnap_backend_exists(&be, "objects/cd/aborted") == 0);

    amisnap_backend_close(&be);
    mock_server_free(&srv);
}

static int g_list_count;
static char g_list_names[16][80];

static void list_cb(void *user, const char *name)
{
    (void)user;
    if (g_list_count < 16) strncpy(g_list_names[g_list_count++], name, 79);
}

static int has_name(const char *name)
{
    int i;
    for (i = 0; i < g_list_count; i++)
        if (strcmp(g_list_names[i], name) == 0) return 1;
    return 0;
}

static void run_list_tests(void)
{
    mock_server srv;
    amisnap_transport t;
    amisnap_backend be;
    amisnap_s3_config cfg = test_cfg();

    mock_server_init(&srv);
    t.ops = &mock_ops;
    t.ctx = &srv;
    TEST_CHECK(amisnap_backend_s3_open(&cfg, &t, &be) == AMISNAP_OK);

    TEST_CHECK(amisnap_backend_put(&be, "objects/ab/hex1", "a", 1) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put(&be, "objects/ab/hex2", "b", 1) == AMISNAP_OK);
    TEST_CHECK(amisnap_backend_put(&be, "objects/cd/hex3", "c", 1) == AMISNAP_OK);

    g_list_count = 0;
    TEST_CHECK(amisnap_backend_list(&be, "objects/ab", list_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(g_list_count == 2);
    TEST_CHECK(has_name("hex1") && has_name("hex2"));

    /* A prefix with nothing under it lists as empty, not an error. */
    g_list_count = 0;
    TEST_CHECK(amisnap_backend_list(&be, "objects/zz", list_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(g_list_count == 0);

    /* Pagination: force one object per ListObjectsV2 page and confirm
     * every entry is still found across the resulting multiple pages. */
    srv.list_page_size = 1;
    g_list_count = 0;
    TEST_CHECK(amisnap_backend_list(&be, "objects/ab", list_cb, NULL) == AMISNAP_OK);
    TEST_CHECK(g_list_count == 2);
    TEST_CHECK(has_name("hex1") && has_name("hex2"));

    amisnap_backend_close(&be);
    mock_server_free(&srv);
}

static void run_url_parse_tests(void)
{
    amisnap_s3_url u;

    TEST_CHECK(amisnap_s3_parse_url("s3://AKID:SECRET@minio.local:9000/mybucket", &u) == AMISNAP_OK);
    TEST_CHECK(strcmp(u.access_key, "AKID") == 0);
    TEST_CHECK(strcmp(u.secret_key, "SECRET") == 0);
    TEST_CHECK(strcmp(u.host, "minio.local") == 0);
    TEST_CHECK(u.port == 9000);
    TEST_CHECK(strcmp(u.bucket, "mybucket") == 0);
    TEST_CHECK(u.base_path[0] == '\0');
    TEST_CHECK(strcmp(u.region, "us-east-1") == 0); /* default */

    TEST_CHECK(amisnap_s3_parse_url("s3://AKID:SECRET@minio.local/mybucket/some/prefix?region=eu-west-1",
                                     &u) == AMISNAP_OK);
    TEST_CHECK(u.port == 80);
    TEST_CHECK(strcmp(u.base_path, "some/prefix") == 0);
    TEST_CHECK(strcmp(u.region, "eu-west-1") == 0);

    /* Missing credentials, missing bucket, wrong scheme: all refused. */
    TEST_CHECK(amisnap_s3_parse_url("s3://minio.local/mybucket", &u) == AMISNAP_ERR_MALFORMED);
    TEST_CHECK(amisnap_s3_parse_url("s3://AKID:SECRET@minio.local", &u) == AMISNAP_ERR_MALFORMED);
    TEST_CHECK(amisnap_s3_parse_url("http://AKID:SECRET@minio.local/bucket", &u) == AMISNAP_ERR_MALFORMED);
}

void run_s3_tests(void)
{
    run_roundtrip_tests();
    run_streaming_tests();
    run_list_tests();
    run_url_parse_tests();
}
