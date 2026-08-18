/* s3.c -- see s3.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "http.h"
#include "s3.h"
#include "sigv4.h"

typedef struct {
    amisnap_transport *transport;
    char *host;         /* bare hostname/dotted-quad, for transport_connect() */
    uint16_t port;
    char *host_header;  /* "host" or "host:port", for the HTTP Host header */
    char *bucket;
    char *base_path;    /* "" or "some/prefix", no leading/trailing slash */
    char *region;
    char *access_key;
    char *secret_key;
    void *conn;         /* the one kept-alive connection s3_exchange() reuses;
                          * NULL when not currently connected. put_begin/append/
                          * finish never touches this -- it opens and owns its
                          * own separate connection (same reasoning webdav.c's
                          * own webdav_put_handle documents). */
} s3_ctx;

static char *dup_str(const char *s)
{
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);

    if (!out) return NULL;
    memcpy(out, s, len + 1);
    return out;
}

void amisnap_s3_now(char out[17])
{
    time_t t = time(NULL);
    struct tm *g = gmtime(&t);
    char full[96]; /* wider than the real 16-char result -- glibc's fortify
                     * checker sizes its own worst case off each %d's full
                     * theoretical int range (up to 11 chars each, since it
                     * can't statically prove struct tm's fields stay small),
                     * not off any real date, so snprintf'ing straight into
                     * a 17-byte buffer trips -Werror on that platform even
                     * though truncation never actually happens for any real
                     * date; the explicit copy+truncate below sidesteps that
                     * without silencing a genuine class of bug. */

    if (!g) { memcpy(out, "19700101T000000Z", 17); return; }

    snprintf(full, sizeof(full), "%04d%02d%02dT%02d%02d%02dZ",
              g->tm_year + 1900, g->tm_mon + 1, g->tm_mday,
              g->tm_hour, g->tm_min, g->tm_sec);
    memcpy(out, full, 16);
    out[16] = '\0';
}

/* --- request building: encode the full object path (/bucket/base_path/
 * key), sign, and hand back a ready-to-send HTTP request buffer. --- */

static int s3_encoded_path(s3_ctx *ctx, const char *key, amisnap_buf *out)
{
    int rc;

    amisnap_buf_init(out);
    rc = amisnap_buf_bytes(out, "/", 1);
    if (rc == AMISNAP_OK) rc = amisnap_sigv4_uri_encode(ctx->bucket, strlen(ctx->bucket), 0, out);
    if (rc == AMISNAP_OK && key[0] != '\0') {
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "/", 1);
        if (rc == AMISNAP_OK && ctx->base_path[0]) {
            rc = amisnap_sigv4_uri_encode(ctx->base_path, strlen(ctx->base_path), 0, out);
            if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "/", 1);
        }
        if (rc == AMISNAP_OK) rc = amisnap_sigv4_uri_encode(key, strlen(key), 0, out);
    }
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "", 1); /* NUL-terminate for use as a C string */
    if (rc != AMISNAP_OK) { amisnap_buf_free(out); return rc; }
    return AMISNAP_OK;
}

/* Builds a fully-signed HTTP/1.1 request into `out`. `canonical_uri`
 * must already be NUL-terminated (s3_encoded_path()'s own output
 * shape) and `canonical_query_string` may be "" (never NULL). Always
 * signs exactly host + x-amz-content-sha256 + x-amz-date -- the
 * minimum SigV4 needs and all any AmiSnap S3 request ever sends. */
static int s3_build_signed(s3_ctx *ctx, const char *method, const char *canonical_uri,
                            const char *canonical_query_string, const char *payload_hash_hex,
                            const void *body, size_t body_len, amisnap_buf *out)
{
    char date_time[17];
    char date[9];
    char scope[128];
    amisnap_sigv4_header sign_hdrs[3];
    amisnap_buf creq, signed_headers, sts, authz;
    uint8_t signing_key[32];
    char sig_hex[65];
    amisnap_http_header http_hdrs[4];
    int rc;

    amisnap_s3_now(date_time);
    memcpy(date, date_time, 8);
    date[8] = '\0';
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", date, ctx->region);

    sign_hdrs[0].name = "host";
    sign_hdrs[0].value = ctx->host_header;
    sign_hdrs[1].name = "x-amz-content-sha256";
    sign_hdrs[1].value = payload_hash_hex;
    sign_hdrs[2].name = "x-amz-date";
    sign_hdrs[2].value = date_time;

    rc = amisnap_sigv4_canonical_request(method, canonical_uri, canonical_query_string,
                                          sign_hdrs, 3, payload_hash_hex, &creq, &signed_headers);
    if (rc != AMISNAP_OK) return rc;

    rc = amisnap_sigv4_string_to_sign(date_time, scope, creq.data, creq.len, &sts);
    amisnap_buf_free(&creq);
    if (rc != AMISNAP_OK) { amisnap_buf_free(&signed_headers); return rc; }

    amisnap_sigv4_signing_key(ctx->secret_key, date, ctx->region, "s3", signing_key);
    amisnap_sigv4_signature_hex(signing_key, sts.data, sts.len, sig_hex);
    memset(signing_key, 0, sizeof(signing_key));
    amisnap_buf_free(&sts);

    rc = amisnap_sigv4_authorization_header(ctx->access_key, scope,
                                             (const char *)signed_headers.data, sig_hex, &authz);
    amisnap_buf_free(&signed_headers);
    if (rc != AMISNAP_OK) return rc;

    {
        char *path_and_query;
        size_t path_len = strlen(canonical_uri);
        size_t query_len = strlen(canonical_query_string);
        size_t total = path_len + (query_len ? 1 + query_len : 0) + 1;

        path_and_query = (char *)malloc(total);
        if (!path_and_query) { amisnap_buf_free(&authz); return AMISNAP_ERR_NOMEM; }
        memcpy(path_and_query, canonical_uri, path_len);
        if (query_len) {
            path_and_query[path_len] = '?';
            memcpy(path_and_query + path_len + 1, canonical_query_string, query_len);
        }
        path_and_query[path_len + (query_len ? 1 + query_len : 0)] = '\0';

        http_hdrs[0].name = "x-amz-content-sha256";
        http_hdrs[0].value = payload_hash_hex;
        http_hdrs[1].name = "x-amz-date";
        http_hdrs[1].value = date_time;
        http_hdrs[2].name = "Authorization";
        http_hdrs[2].value = (const char *)authz.data;

        amisnap_buf_init(out);
        rc = amisnap_http_build_request(out, method, path_and_query, ctx->host_header,
                                         http_hdrs, 3, body, body_len);
        free(path_and_query);
    }
    amisnap_buf_free(&authz);
    if (rc != AMISNAP_OK) { amisnap_buf_free(out); return rc; }
    return AMISNAP_OK;
}

/* --- request/response exchange, with one-retry-on-stale-keep-alive --
 * identical shape and reasoning to webdav.c's own webdav_exchange(). --- */

/* `idempotent`: 1 for GET/PUT/HEAD/DELETE (safe to replay -- the
 * one-retry-on-stale-keep-alive below applies), 0 for the multipart
 * POSTs (CreateMultipartUpload, CompleteMultipartUpload) which are
 * NOT. For a non-idempotent request the stale-connection retry is
 * dangerous: if the send was delivered and the server acted before the
 * reused connection died mid-response, replaying it would initiate a
 * SECOND upload (orphaning the first, whose UploadId we never learned)
 * or hit an already-completed upload (a false failure for an object
 * that actually committed). So for those we (a) force a FRESH
 * connection -- a just-opened socket is far less likely to be the
 * server's silently-half-closed keep-alive that the retry exists to
 * paper over -- and (b) never retry: one attempt, and an ambiguous
 * failure is reported as a failure rather than blindly replayed. */
static int s3_exchange_ex(s3_ctx *ctx, const amisnap_buf *req, amisnap_http_response *resp,
                          int idempotent)
{
    int attempt;

    if (!idempotent && ctx->conn != NULL) {
        /* Don't send a non-idempotent request down a possibly-stale
         * kept-alive connection -- start clean so the single attempt
         * below is as reliable as it can be. */
        amisnap_transport_close(ctx->transport, ctx->conn);
        ctx->conn = NULL;
    }

    for (attempt = 0; attempt < 2; attempt++) {
        int fresh = (ctx->conn == NULL);
        int rc;

        if (fresh) {
            rc = amisnap_transport_connect(ctx->transport, ctx->host, ctx->port, &ctx->conn);
            if (rc != AMISNAP_OK) {
                ctx->conn = NULL;
                return rc;
            }
        }

        rc = amisnap_transport_send(ctx->transport, ctx->conn, req->data, req->len);
        if (rc == AMISNAP_OK) {
            int done = 0;

            amisnap_http_response_init(resp);
            for (;;) {
                uint8_t buf[4096];
                size_t got;

                rc = amisnap_transport_recv(ctx->transport, ctx->conn, buf, sizeof(buf), &got);
                if (rc != AMISNAP_OK) break;
                if (got == 0) { rc = AMISNAP_ERR_IO; break; }
                rc = amisnap_http_response_feed(resp, buf, got, &done);
                if (rc != AMISNAP_OK || done) break;
            }
            if (rc == AMISNAP_OK && done)
                return AMISNAP_OK;
            amisnap_http_response_free(resp);
        }

        amisnap_transport_close(ctx->transport, ctx->conn);
        ctx->conn = NULL;
        /* Retry only an idempotent request, and only when a REUSED
         * connection failed (fresh false) -- a non-idempotent request
         * never retries (it forced a fresh connection above, so `fresh`
         * is true here anyway, but check idempotent explicitly for
         * clarity). */
        if (!idempotent || rc != AMISNAP_ERR_IO || fresh)
            return rc;
    }
    return AMISNAP_ERR_IO;
}

/* Idempotent requests (GET/PUT/HEAD/DELETE) -- the common case. */
static int s3_exchange(s3_ctx *ctx, const amisnap_buf *req, amisnap_http_response *resp)
{
    return s3_exchange_ex(ctx, req, resp, 1);
}

#define UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"

/* --- amisnap_backend_ops --- */

static int s3_put(amisnap_backend *be, const char *key, const void *data, size_t len)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;
    amisnap_buf path, req;
    amisnap_http_response resp;
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_build_signed(ctx, "PUT", (const char *)path.data, "", UNSIGNED_PAYLOAD, data, len, &req);
    amisnap_buf_free(&path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    rc = (resp.status_code / 100 == 2) ? AMISNAP_OK : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

static int s3_get(amisnap_backend *be, const char *key, amisnap_buf *out)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;
    amisnap_buf path, req;
    amisnap_http_response resp;
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_build_signed(ctx, "GET", (const char *)path.data, "", UNSIGNED_PAYLOAD, NULL, 0, &req);
    amisnap_buf_free(&path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    if (resp.status_code == 404) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_NOT_FOUND;
    }
    if (resp.status_code / 100 != 2) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_IO;
    }
    /* A 2xx GET with a connection-close-delimited body (no
     * Content-Length, not chunked) was truncated to empty by the
     * parser -- reject rather than restore a stored object as zero
     * bytes. See webdav.c's own s3-parallel check / http.h's
     * body_unframed. A real empty object returns "Content-Length: 0". */
    if (resp.body_unframed) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_IO;
    }

    *out = resp.body;
    amisnap_buf_init(&resp.body);
    amisnap_http_response_free(&resp);
    return AMISNAP_OK;
}

static int s3_exists(amisnap_backend *be, const char *key)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;
    amisnap_buf path, req;
    amisnap_http_response resp;
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_build_signed(ctx, "HEAD", (const char *)path.data, "", UNSIGNED_PAYLOAD, NULL, 0, &req);
    amisnap_buf_free(&path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    if (resp.status_code == 404) {
        amisnap_http_response_free(&resp);
        return 0;
    }
    rc = (resp.status_code / 100 == 2) ? 1 : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

static int s3_remove(amisnap_backend *be, const char *key)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;
    amisnap_buf path, req;
    amisnap_http_response resp;
    int rc;

    /* S3's own DELETE is unconditionally idempotent -- a 204 whether or
     * not the key ever existed -- which would silently break backend.h's
     * documented AMISNAP_ERR_NOT_FOUND contract (prune.c and callers
     * rely on it for accurate counts). A HEAD first is the honest way
     * to preserve that contract; a real, deliberate extra request, not
     * an oversight. */
    rc = s3_exists(be, key);
    if (rc < 0) return rc;
    if (rc == 0) return AMISNAP_ERR_NOT_FOUND;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_build_signed(ctx, "DELETE", (const char *)path.data, "", UNSIGNED_PAYLOAD, NULL, 0, &req);
    amisnap_buf_free(&path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    rc = (resp.status_code / 100 == 2) ? AMISNAP_OK : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

static int s3_mkcol(amisnap_backend *be, const char *key)
{
    /* backend.h's own documented contract: "S3 has no directories at
     * all -- a concept that doesn't exist to create" -- a harmless
     * no-op, not an unimplemented stub. */
    (void)be; (void)key;
    return AMISNAP_OK;
}

/* --- ListObjectsV2: a small, hand-rolled XML scan (no general XML
 * library -- the response shape is simple and fixed: <Contents><Key>
 * and <CommonPrefixes><Prefix>, plus <IsTruncated>/<NextContinuation
 * Token> for pagination), same "no general parser" reasoning as
 * webdav.c's own href-scraper. --- */

static const char *xml_find_tag_start(const char *body, size_t len, const char *tag, size_t off)
{
    /* Finds the next "<tag>" (exact, no attributes -- S3's own
     * ListObjectsV2 response never puts attributes on these
     * elements), returning a pointer just past it, or NULL. */
    char open_tag[40];
    size_t tag_len = (size_t)snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    size_t i;

    for (i = off; i + tag_len <= len; i++) {
        if (memcmp(body + i, open_tag, tag_len) == 0)
            return body + i + tag_len;
    }
    return NULL;
}

static int xml_extract(const char *body, size_t len, const char *tag,
                        size_t start_off, char *out, size_t out_cap, size_t *next_off)
{
    const char *val_start = xml_find_tag_start(body, len, tag, start_off);
    const char *val_end;
    char close_tag[40];
    size_t close_len;
    size_t vlen;

    if (!val_start) return 0;
    close_len = (size_t)snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    val_end = NULL;
    {
        size_t i;
        size_t avail = len - (size_t)(val_start - body);
        for (i = 0; i + close_len <= avail; i++) {
            if (memcmp(val_start + i, close_tag, close_len) == 0) {
                val_end = val_start + i;
                break;
            }
        }
    }
    if (!val_end) return 0;

    vlen = (size_t)(val_end - val_start);
    if (vlen >= out_cap) vlen = out_cap - 1;
    memcpy(out, val_start, vlen);
    out[vlen] = '\0';
    if (next_off) *next_off = (size_t)(val_end - body) + close_len;
    return 1;
}

/* Reports every <Contents><Key> and <CommonPrefixes><Prefix> value
 * with `queried_prefix` stripped off the front and any trailing '/'
 * stripped off the back, via cb() -- exactly backend.h's own list()
 * contract ("the final path component, not the full key"). Only ever
 * one path component deep since queried_prefix + delimiter='/' already
 * limits what S3 itself returns to immediate children. */
static void s3_scrape_listing(const char *body, size_t len, const char *queried_prefix,
                               void (*cb)(void *user, const char *name), void *user)
{
    size_t pos = 0;
    size_t prefix_len = strlen(queried_prefix);

    for (;;) {
        char key[AMISNAP_S3_MAX_PATH];
        size_t next;
        const char *rel;
        size_t rel_len;

        if (!xml_extract(body, len, "Key", pos, key, sizeof(key), &next)) break;
        pos = next;

        if (strncmp(key, queried_prefix, prefix_len) != 0) continue;
        rel = key + prefix_len;
        rel_len = strlen(rel);
        if (rel_len == 0) continue;
        cb(user, rel);
    }

    pos = 0;
    for (;;) {
        char prefix[AMISNAP_S3_MAX_PATH];
        size_t next;
        char rel[AMISNAP_S3_MAX_PATH];
        size_t rel_len;

        if (!xml_extract(body, len, "Prefix", pos, prefix, sizeof(prefix), &next)) break;
        pos = next;

        if (strncmp(prefix, queried_prefix, prefix_len) != 0) continue;
        rel_len = strlen(prefix + prefix_len);
        if (rel_len == 0) continue;
        memcpy(rel, prefix + prefix_len, rel_len + 1);
        if (rel_len > 0 && rel[rel_len - 1] == '/') rel[--rel_len] = '\0';
        if (rel_len == 0) continue;
        cb(user, rel);
    }
}

static int s3_list(amisnap_backend *be, const char *prefix,
                    void (*cb)(void *user, const char *name), void *user)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;
    char queried_prefix[AMISNAP_S3_MAX_PATH];
    char continuation[512];
    int have_continuation = 0;
    int n;
    /* Bounded so a server that claims IsTruncated=true forever (a real
     * bug, or a hostile/broken S3-compatible endpoint) can't hang this
     * call indefinitely -- same defensive-bound reasoning prune.c's own
     * snapid-collision loop documents. A real repository's objects/<hh>
     * fan-out bucket or snapshots/ directory is nowhere near this many
     * pages even at extreme scale. */
    unsigned page;
    static const unsigned MAX_PAGES = 100000u;

    n = ctx->base_path[0]
        ? snprintf(queried_prefix, sizeof(queried_prefix), "%s/%s/", ctx->base_path, prefix)
        : snprintf(queried_prefix, sizeof(queried_prefix), "%s/", prefix);
    if (n < 0 || (size_t)n >= sizeof(queried_prefix)) return AMISNAP_ERR_MALFORMED;

    for (page = 0; page < MAX_PAGES; page++) {
        amisnap_buf bucket_path, query, req;
        amisnap_http_response resp;
        int rc;
        char is_truncated[8];
        int truncated;

        rc = s3_encoded_path(ctx, "", &bucket_path);
        if (rc != AMISNAP_OK) return rc;

        amisnap_buf_init(&query);
        rc = amisnap_buf_bytes(&query, "delimiter=%2F&list-type=2&prefix=",
                                strlen("delimiter=%2F&list-type=2&prefix="));
        if (rc == AMISNAP_OK)
            rc = amisnap_sigv4_uri_encode(queried_prefix, strlen(queried_prefix), 1, &query);
        if (rc == AMISNAP_OK && have_continuation) {
            const char *cont_kv = "&continuation-token=";
            /* Alphabetically "continuation-token" < "delimiter", but
             * SigV4's canonical query string must be sorted by the
             * FULL key set -- rebuilding with the right order here
             * would need a real sort for 4 fixed keys; simpler and
             * just as correct: build continuation-token first when
             * present, since it always sorts before the other three. */
            amisnap_buf reordered;
            amisnap_buf_init(&reordered);
            rc = amisnap_buf_bytes(&reordered, "continuation-token=", 19);
            if (rc == AMISNAP_OK)
                rc = amisnap_sigv4_uri_encode(continuation, strlen(continuation), 1, &reordered);
            if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&reordered, "&", 1);
            if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&reordered, query.data, query.len);
            amisnap_buf_free(&query);
            query = reordered;
            (void)cont_kv;
        }
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&query, "", 1);
        if (rc != AMISNAP_OK) { amisnap_buf_free(&bucket_path); amisnap_buf_free(&query); return rc; }

        rc = s3_build_signed(ctx, "GET", (const char *)bucket_path.data, (const char *)query.data,
                              UNSIGNED_PAYLOAD, NULL, 0, &req);
        amisnap_buf_free(&bucket_path);
        amisnap_buf_free(&query);
        if (rc != AMISNAP_OK) return rc;

        rc = s3_exchange(ctx, &req, &resp);
        amisnap_buf_free(&req);
        if (rc != AMISNAP_OK) return rc;

        /* "A prefix that doesn't exist at all lists as empty ... not
         * an error" -- backend.h's own list() contract. ListObjectsV2
         * itself never 404s for a nonexistent prefix (only for a
         * nonexistent bucket), but this keeps the same shape as
         * webdav_list() for the case that does apply here. */
        if (resp.status_code == 404) {
            amisnap_http_response_free(&resp);
            return AMISNAP_OK;
        }
        if (resp.status_code / 100 != 2) {
            amisnap_http_response_free(&resp);
            return AMISNAP_ERR_IO;
        }

        s3_scrape_listing((const char *)resp.body.data, resp.body.len, queried_prefix, cb, user);

        truncated = xml_extract((const char *)resp.body.data, resp.body.len, "IsTruncated",
                                 0, is_truncated, sizeof(is_truncated), NULL)
                    && strcmp(is_truncated, "true") == 0;
        if (truncated) {
            size_t got_len;
            truncated = xml_extract((const char *)resp.body.data, resp.body.len,
                                     "NextContinuationToken", 0, continuation, sizeof(continuation),
                                     &got_len);
            (void)got_len;
        }
        amisnap_http_response_free(&resp);

        if (!truncated) return AMISNAP_OK;
        have_continuation = 1;
    }
    return AMISNAP_ERR_IO; /* MAX_PAGES exceeded -- a server that never stops
                             * claiming IsTruncated is indistinguishable from
                             * a real I/O fault as far as this call is concerned. */
}

/* --- streaming upload (put_begin/put_append/put_finish/put_abort):
 * buffers into `body` and, once it reaches AMISNAP_S3_MIN_PART_SIZE,
 * escalates to a REAL S3 multipart upload (CreateMultipartUpload ->
 * UploadPart* -> CompleteMultipartUpload) rather than continuing to
 * grow one unbounded in-memory buffer -- exactly the memory-bounded
 * treatment restore.c's own put_begin/append/finish call already
 * relies on: it spans an ENTIRE reconstructed destination file
 * (restore.c's own restore_file(), looping put_append() once per
 * E_CONTENT chunk read from the repository), which can be arbitrarily
 * large regardless of how small AmiSnap's own AMISNAP_DEFAULT_CHUNK_SIZE
 * chunks are -- a single unbounded buffer here would silently defeat
 * the entire point of chunked restore for any S3 destination. An
 * upload that never reaches the threshold falls back to the original
 * one-PUT path unchanged (implementation-plan.md Phase 5's own note
 * that SigV4's UNSIGNED-PAYLOAD still needs a definite Content-Length,
 * so this is never a real chunked-Transfer-Encoding stream on the
 * request side, unlike webdav.c's). Real S3 requires every part
 * except the last to be >= 5 MiB -- AMISNAP_S3_MIN_PART_SIZE matches
 * that exactly, so every part this uploads (other than the final one
 * at put_finish()) is already large enough. */
#define AMISNAP_S3_MIN_PART_SIZE (5u * 1024u * 1024u)

typedef struct {
    char etag[128]; /* including the quotes S3 itself returns them with --
                      * CompleteMultipartUpload must echo them back verbatim */
} s3_part;

static int s3_multipart_initiate(s3_ctx *ctx, const char *key, char upload_id_out[512])
{
    amisnap_buf path, req;
    amisnap_http_response resp;
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_build_signed(ctx, "POST", (const char *)path.data, "uploads=", UNSIGNED_PAYLOAD,
                          NULL, 0, &req);
    amisnap_buf_free(&path);
    if (rc != AMISNAP_OK) return rc;
    rc = s3_exchange_ex(ctx, &req, &resp, 0); /* CreateMultipartUpload: NOT idempotent */
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    if (resp.status_code / 100 != 2) { amisnap_http_response_free(&resp); return AMISNAP_ERR_IO; }

    if (!xml_extract((const char *)resp.body.data, resp.body.len, "UploadId", 0,
                      upload_id_out, 512, NULL)) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_MALFORMED;
    }
    amisnap_http_response_free(&resp);
    return AMISNAP_OK;
}

static int s3_multipart_upload_part(s3_ctx *ctx, const char *key, const char *upload_id,
                                     unsigned part_number, const void *data, size_t len,
                                     char etag_out[128])
{
    amisnap_buf path, query, req;
    amisnap_http_response resp;
    const amisnap_http_parsed_header *etag_hdr;
    char partbuf[16];
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;

    snprintf(partbuf, sizeof(partbuf), "%u", part_number);
    amisnap_buf_init(&query);
    rc = amisnap_buf_bytes(&query, "partNumber=", strlen("partNumber="));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&query, partbuf, strlen(partbuf));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&query, "&uploadId=", strlen("&uploadId="));
    if (rc == AMISNAP_OK) rc = amisnap_sigv4_uri_encode(upload_id, strlen(upload_id), 1, &query);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&query, "", 1);
    if (rc != AMISNAP_OK) { amisnap_buf_free(&path); amisnap_buf_free(&query); return rc; }

    rc = s3_build_signed(ctx, "PUT", (const char *)path.data, (const char *)query.data,
                          UNSIGNED_PAYLOAD, data, len, &req);
    amisnap_buf_free(&path);
    amisnap_buf_free(&query);
    if (rc != AMISNAP_OK) return rc;

    rc = s3_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    if (resp.status_code / 100 != 2) { amisnap_http_response_free(&resp); return AMISNAP_ERR_IO; }

    etag_hdr = amisnap_http_response_header(&resp, "etag");
    if (!etag_hdr || etag_hdr->value_len == 0 || etag_hdr->value_len >= 128) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_MALFORMED;
    }
    memcpy(etag_out, etag_hdr->value, etag_hdr->value_len);
    etag_out[etag_hdr->value_len] = '\0';
    amisnap_http_response_free(&resp);
    return AMISNAP_OK;
}

static int s3_multipart_complete(s3_ctx *ctx, const char *key, const char *upload_id,
                                  const s3_part *parts, size_t part_count)
{
    amisnap_buf path, query, body, req;
    amisnap_http_response resp;
    size_t i;
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return rc;

    amisnap_buf_init(&query);
    rc = amisnap_buf_bytes(&query, "uploadId=", strlen("uploadId="));
    if (rc == AMISNAP_OK) rc = amisnap_sigv4_uri_encode(upload_id, strlen(upload_id), 1, &query);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&query, "", 1);
    if (rc != AMISNAP_OK) { amisnap_buf_free(&path); amisnap_buf_free(&query); return rc; }

    amisnap_buf_init(&body);
    rc = amisnap_buf_bytes(&body, "<CompleteMultipartUpload>", strlen("<CompleteMultipartUpload>"));
    for (i = 0; rc == AMISNAP_OK && i < part_count; i++) {
        char entry[256];
        int n = snprintf(entry, sizeof(entry),
                          "<Part><PartNumber>%u</PartNumber><ETag>%s</ETag></Part>",
                          (unsigned)(i + 1), parts[i].etag);
        rc = amisnap_buf_bytes(&body, entry, (size_t)n);
    }
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_bytes(&body, "</CompleteMultipartUpload>",
                                strlen("</CompleteMultipartUpload>"));
    if (rc != AMISNAP_OK) {
        amisnap_buf_free(&path); amisnap_buf_free(&query); amisnap_buf_free(&body);
        return rc;
    }

    rc = s3_build_signed(ctx, "POST", (const char *)path.data, (const char *)query.data,
                          UNSIGNED_PAYLOAD, body.data, body.len, &req);
    amisnap_buf_free(&path);
    amisnap_buf_free(&query);
    amisnap_buf_free(&body);
    if (rc != AMISNAP_OK) return rc;

    rc = s3_exchange_ex(ctx, &req, &resp, 0); /* CompleteMultipartUpload: NOT idempotent */
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    /* CompleteMultipartUpload can, in rare real-S3 cases, answer 200
     * with an error embedded in the XML body instead of a non-2xx
     * status -- not handled specially here (same "2xx == success"
     * convention every other operation in this file uses); a real,
     * documented limitation, not an oversight. */
    rc = (resp.status_code / 100 == 2) ? AMISNAP_OK : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

/* Best-effort cleanup on a failed/aborted multipart upload -- nothing
 * more useful to do with an error here (the handle is already being
 * torn down); a real S3 also auto-expires abandoned multipart uploads
 * via bucket lifecycle rules some operators configure, so this isn't
 * the only backstop against orphaned parts accumulating storage cost. */
static void s3_multipart_abort(s3_ctx *ctx, const char *key, const char *upload_id)
{
    amisnap_buf path, query, req;
    amisnap_http_response resp;
    int rc;

    rc = s3_encoded_path(ctx, key, &path);
    if (rc != AMISNAP_OK) return;

    amisnap_buf_init(&query);
    rc = amisnap_buf_bytes(&query, "uploadId=", strlen("uploadId="));
    if (rc == AMISNAP_OK) rc = amisnap_sigv4_uri_encode(upload_id, strlen(upload_id), 1, &query);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&query, "", 1);
    if (rc != AMISNAP_OK) { amisnap_buf_free(&path); amisnap_buf_free(&query); return; }

    rc = s3_build_signed(ctx, "DELETE", (const char *)path.data, (const char *)query.data,
                          UNSIGNED_PAYLOAD, NULL, 0, &req);
    amisnap_buf_free(&path);
    amisnap_buf_free(&query);
    if (rc != AMISNAP_OK) return;

    rc = s3_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc == AMISNAP_OK) amisnap_http_response_free(&resp);
}

typedef struct {
    s3_ctx *ctx;
    char *key;
    amisnap_buf body;      /* bytes accumulated for the part not yet uploaded */
    char *upload_id;       /* NULL until MIN_PART_SIZE forces real multipart */
    s3_part *parts;
    size_t part_count, part_cap;
    int failed;             /* first error hit mid-stream, if any -- once set,
                              * every further call just reports it back rather
                              * than trying to keep talking to a connection/
                              * upload already known to be broken. */
} s3_put_handle;

/* Uploads whatever is currently buffered in h->body as the next part
 * (initiating the multipart upload first if this is the first
 * escalation), then resets the buffer. Called both when MIN_PART_SIZE
 * is reached mid-stream and, from put_finish(), for the final
 * (possibly short) part. */
static int s3_upload_next_part(s3_put_handle *h)
{
    char etag[128];
    int rc;

    if (!h->upload_id) {
        char upload_id[512];
        rc = s3_multipart_initiate(h->ctx, h->key, upload_id);
        if (rc != AMISNAP_OK) return rc;
        h->upload_id = dup_str(upload_id);
        if (!h->upload_id) return AMISNAP_ERR_NOMEM;
    }

    rc = s3_multipart_upload_part(h->ctx, h->key, h->upload_id, (unsigned)(h->part_count + 1),
                                   h->body.data, h->body.len, etag);
    if (rc != AMISNAP_OK) return rc;

    if (h->part_count == h->part_cap) {
        size_t newcap = h->part_cap ? h->part_cap * 2 : 8;
        s3_part *newarr = (s3_part *)realloc(h->parts, newcap * sizeof(*newarr));
        if (!newarr) return AMISNAP_ERR_NOMEM;
        h->parts = newarr;
        h->part_cap = newcap;
    }
    memcpy(h->parts[h->part_count].etag, etag, sizeof(etag));
    h->part_count++;

    amisnap_buf_free(&h->body);
    amisnap_buf_init(&h->body);
    return AMISNAP_OK;
}

static int s3_put_begin(amisnap_backend *be, const char *key, void **handle_out)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;
    s3_put_handle *h = (s3_put_handle *)malloc(sizeof(*h));

    if (!h) return AMISNAP_ERR_NOMEM;
    memset(h, 0, sizeof(*h));
    h->ctx = ctx;
    h->key = dup_str(key);
    if (!h->key) { free(h); return AMISNAP_ERR_NOMEM; }
    amisnap_buf_init(&h->body);
    *handle_out = h;
    return AMISNAP_OK;
}

static int s3_put_append(amisnap_backend *be, void *handle, const void *data, size_t len)
{
    s3_put_handle *h = (s3_put_handle *)handle;
    int rc;

    (void)be;
    if (h->failed != AMISNAP_OK) return h->failed;
    if (len == 0) return AMISNAP_OK;

    rc = amisnap_buf_bytes(&h->body, data, len);
    if (rc != AMISNAP_OK) { h->failed = rc; return rc; }

    if (h->body.len >= AMISNAP_S3_MIN_PART_SIZE) {
        rc = s3_upload_next_part(h);
        if (rc != AMISNAP_OK) h->failed = rc;
    }
    return rc;
}

static int s3_put_finish(amisnap_backend *be, void *handle)
{
    s3_put_handle *h = (s3_put_handle *)handle;
    int rc = h->failed;

    if (rc == AMISNAP_OK && !h->upload_id) {
        /* Never escalated -- small enough for one ordinary PUT, same
         * path amisnap_repo_writer_file()'s own whole-object put() takes. */
        rc = s3_put(be, h->key, h->body.data, h->body.len);
    } else if (rc == AMISNAP_OK) {
        /* Final part -- may be shorter than MIN_PART_SIZE, which S3
         * explicitly permits only for the last part of a multipart
         * upload. A zero-byte final part (the stream ended exactly on
         * a part boundary) is skipped; S3 doesn't want one and every
         * byte is already durably uploaded in the prior parts. */
        if (h->body.len > 0) rc = s3_upload_next_part(h);
        if (rc == AMISNAP_OK)
            rc = s3_multipart_complete(h->ctx, h->key, h->upload_id, h->parts, h->part_count);
    }

    if (rc != AMISNAP_OK && h->upload_id)
        s3_multipart_abort(h->ctx, h->key, h->upload_id);

    amisnap_buf_free(&h->body);
    free(h->key);
    free(h->upload_id);
    free(h->parts);
    free(h);
    return rc;
}

static void s3_put_abort(amisnap_backend *be, void *handle)
{
    s3_put_handle *h = (s3_put_handle *)handle;
    (void)be;
    if (h) {
        if (h->upload_id) s3_multipart_abort(h->ctx, h->key, h->upload_id);
        amisnap_buf_free(&h->body);
        free(h->key);
        free(h->upload_id);
        free(h->parts);
        free(h);
    }
}

static void s3_close(amisnap_backend *be)
{
    s3_ctx *ctx = (s3_ctx *)be->ctx;

    if (ctx) {
        if (ctx->conn) amisnap_transport_close(ctx->transport, ctx->conn);
        free(ctx->host);
        free(ctx->host_header);
        free(ctx->bucket);
        free(ctx->base_path);
        free(ctx->region);
        free(ctx->access_key);
        if (ctx->secret_key) {
            memset(ctx->secret_key, 0, strlen(ctx->secret_key));
            free(ctx->secret_key);
        }
        free(ctx);
    }
    be->ctx = NULL;
}

static const amisnap_backend_ops s3_ops = {
    s3_put, s3_get, s3_exists, s3_list, s3_remove, s3_mkcol,
    s3_put_begin, s3_put_append, s3_put_finish, s3_put_abort,
    s3_close
};

int amisnap_backend_s3_open(const amisnap_s3_config *cfg, amisnap_transport *transport,
                             amisnap_backend *out)
{
    s3_ctx *ctx;
    int rc = AMISNAP_OK;

    ctx = (s3_ctx *)malloc(sizeof(*ctx));
    if (!ctx) return AMISNAP_ERR_NOMEM;
    memset(ctx, 0, sizeof(*ctx));
    ctx->transport = transport;
    ctx->port = cfg->port;

    ctx->host = dup_str(cfg->host);
    if (!ctx->host) { rc = AMISNAP_ERR_NOMEM; goto fail; }

    if (cfg->port == 80) {
        ctx->host_header = dup_str(cfg->host);
    } else {
        char buf[300];
        int n = snprintf(buf, sizeof(buf), "%s:%u", cfg->host, (unsigned)cfg->port);

        if (n < 0 || (size_t)n >= sizeof(buf)) { rc = AMISNAP_ERR_MALFORMED; goto fail; }
        ctx->host_header = dup_str(buf);
    }
    if (!ctx->host_header) { rc = AMISNAP_ERR_NOMEM; goto fail; }

    ctx->bucket = dup_str(cfg->bucket);
    ctx->base_path = dup_str(cfg->base_path ? cfg->base_path : "");
    ctx->region = dup_str(cfg->region);
    ctx->access_key = dup_str(cfg->access_key);
    ctx->secret_key = dup_str(cfg->secret_key);
    if (!ctx->bucket || !ctx->base_path || !ctx->region || !ctx->access_key || !ctx->secret_key) {
        rc = AMISNAP_ERR_NOMEM;
        goto fail;
    }

    out->ops = &s3_ops;
    out->ctx = ctx;
    return AMISNAP_OK;

fail:
    /* free(NULL) on whichever fields never got set is always safe --
     * ctx was memset(0) up front, same pattern webdav.c's own open()
     * failure path documents. */
    free(ctx->host);
    free(ctx->host_header);
    free(ctx->bucket);
    free(ctx->base_path);
    free(ctx->region);
    free(ctx->access_key);
    free(ctx->secret_key);
    free(ctx);
    return rc;
}

/* --- URL parsing (the CLI's own REPO=/DEST= form). --- */

static int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return c - 'A' + 10;
}

static void percent_decode(const char *src, size_t len, char *dst, size_t dst_size)
{
    size_t i, j = 0;

    for (i = 0; i < len && j + 1 < dst_size; i++) {
        if (src[i] == '%' && i + 2 < len && is_hex_digit(src[i + 1]) && is_hex_digit(src[i + 2])) {
            dst[j++] = (char)(hex_val(src[i + 1]) * 16 + hex_val(src[i + 2]));
            i += 2;
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

int amisnap_s3_parse_url(const char *url, amisnap_s3_url *out)
{
    const char *p = url;
    const char *at, *colon, *host_start, *host_end, *path_start, *scan_end;
    const char *bucket_start, *bucket_end, *rest;
    const char *query;
    size_t host_len;

    memset(out, 0, sizeof(*out));
    strcpy(out->region, "us-east-1"); /* default -- most S3-compatible servers (MinIO included)
                                        * don't validate region at all; real AWS/B2 need the
                                        * caller to override it via ?region= */

    if (strncmp(p, "s3://", 5) != 0) return AMISNAP_ERR_MALFORMED;
    p += 5;

    /* userinfo (optional: access_key:secret_key@ -- absent means the
     * CLI's AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env-var fallback
     * supplies them instead, see s3.h's own doc comment). Same parsing
     * shape as amisnap_webdav_parse_url()'s own optional userinfo.
     * Scanned unbounded by any '/' in the remaining string (unlike the
     * host/bucket searches below, which bound themselves by the next
     * '/' on purpose): a real S3 secret key is base64-alphabet and
     * routinely contains a literal '/' (about a 1-in-32 chance per
     * character, no escaping required by this scheme's own documented
     * syntax) -- bounding this search by the first '/' anywhere in the
     * URL, including one inside the secret key itself, misidentifies
     * the userinfo/host boundary and was confirmed live to reject
     * exactly this shape of real-world credential ("bad arguments"/
     * "malformed S3 URL" against AWS's own published example secret
     * key, which contains a '/'). '@' cannot legitimately appear in
     * the host or bucket/prefix components that follow, so the first
     * '@' in the whole remaining string, if any, is always the real
     * boundary. */
    at = NULL;
    {
        const char *q;
        for (q = p; *q; q++) if (*q == '@') { at = q; break; }
    }
    out->has_credentials = (at != NULL);
    if (at) {
        colon = NULL;
        {
            const char *q;
            for (q = p; q < at; q++) if (*q == ':') { colon = q; break; }
        }
        if (!colon) return AMISNAP_ERR_MALFORMED; /* both access_key AND secret_key required together */
        {
            size_t klen = (size_t)(colon - p);
            size_t slen = (size_t)(at - (colon + 1));
            if (klen == 0 || klen >= sizeof(out->access_key)) return AMISNAP_ERR_MALFORMED;
            if (slen == 0 || slen >= sizeof(out->secret_key)) return AMISNAP_ERR_MALFORMED;
            percent_decode(p, klen, out->access_key, sizeof(out->access_key));
            percent_decode(colon + 1, slen, out->secret_key, sizeof(out->secret_key));
        }
        p = at + 1;
    }
    path_start = strchr(p, '/');

    host_start = p;
    scan_end = path_start ? path_start : p + strlen(p);
    colon = NULL;
    {
        const char *q;
        for (q = host_start; q < scan_end; q++) if (*q == ':') { colon = q; break; }
    }
    host_end = colon ? colon : scan_end;
    host_len = (size_t)(host_end - host_start);
    if (host_len == 0 || host_len >= sizeof(out->host)) return AMISNAP_ERR_MALFORMED;
    memcpy(out->host, host_start, host_len);
    out->host[host_len] = '\0';

    if (colon) {
        char portbuf[8];
        size_t plen = (size_t)(scan_end - (colon + 1));
        long portval;

        if (plen == 0 || plen >= sizeof(portbuf)) return AMISNAP_ERR_MALFORMED;
        memcpy(portbuf, colon + 1, plen);
        portbuf[plen] = '\0';
        portval = strtol(portbuf, NULL, 10);
        if (portval <= 0 || portval > 65535) return AMISNAP_ERR_MALFORMED;
        out->port = (uint16_t)portval;
    } else {
        out->port = 80;
    }

    if (!path_start || path_start[1] == '\0') return AMISNAP_ERR_MALFORMED; /* bucket required */

    query = strchr(path_start, '?');
    rest = query ? query : path_start + strlen(path_start);

    bucket_start = path_start + 1;
    bucket_end = (const char *)memchr(bucket_start, '/', (size_t)(rest - bucket_start));
    if (!bucket_end) bucket_end = rest;
    {
        size_t blen = (size_t)(bucket_end - bucket_start);
        if (blen == 0 || blen >= sizeof(out->bucket)) return AMISNAP_ERR_MALFORMED;
        memcpy(out->bucket, bucket_start, blen);
        out->bucket[blen] = '\0';
    }

    if (bucket_end < rest) {
        size_t plen = (size_t)(rest - (bucket_end + 1));
        if (plen >= sizeof(out->base_path)) return AMISNAP_ERR_MALFORMED;
        memcpy(out->base_path, bucket_end + 1, plen);
        out->base_path[plen] = '\0';
        /* Strip a trailing slash -- s3_ctx's own base_path convention
         * (like webdav's) never carries one. */
        if (plen > 0 && out->base_path[plen - 1] == '/') out->base_path[plen - 1] = '\0';
    }

    if (query) {
        static const char REGION_KEY[] = "region=";
        const char *q = query + 1;
        size_t klen = sizeof(REGION_KEY) - 1;

        if (strncmp(q, REGION_KEY, klen) == 0) {
            size_t vlen = strlen(q) - klen;
            if (vlen >= sizeof(out->region)) return AMISNAP_ERR_MALFORMED;
            percent_decode(q + klen, vlen, out->region, sizeof(out->region));
            out->has_region = 1;
        }
    }

    return AMISNAP_OK;
}
