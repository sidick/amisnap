/* webdav.c -- see webdav.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "base64.h"
#include "webdav.h"

typedef struct {
    amisnap_transport *transport;
    char *host;         /* bare hostname/dotted-quad, for transport_connect() */
    uint16_t port;
    char *host_header;  /* "host" or "host:port", for the HTTP Host header */
    char *base_path;    /* "" (root) or "/dav/amisnap" form, no trailing slash */
    char *auth_header;  /* "Basic <b64>" or NULL */
    void *conn;         /* the one kept-alive connection webdav_exchange() reuses;
                          * NULL when not currently connected. A dedicated streaming
                          * upload (put_begin/append/finish) never touches this --
                          * it opens and owns its own separate connection, so the
                          * two never alias each other. */
} webdav_ctx;

static char *dup_str(const char *s)
{
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);

    if (!out) return NULL;
    memcpy(out, s, len + 1);
    return out;
}

/* --- request building --- */

static int webdav_build_abs(webdav_ctx *ctx, const char *method, const char *abspath,
                             const amisnap_http_header *extra, size_t extra_count,
                             const void *body, size_t body_len, amisnap_buf *out)
{
    amisnap_http_header hdrs[8];
    size_t hdr_count = 0;
    size_t i;

    if (ctx->auth_header) {
        hdrs[hdr_count].name = "Authorization";
        hdrs[hdr_count].value = ctx->auth_header;
        hdr_count++;
    }
    /* extra_count is always small and caller-controlled (internal call
     * sites below, never derived from repository content), so this is a
     * real bound check against a coding mistake, not an expected runtime
     * condition. */
    if (extra_count > (sizeof(hdrs) / sizeof(hdrs[0])) - hdr_count)
        return AMISNAP_ERR_MALFORMED;
    for (i = 0; i < extra_count; i++)
        hdrs[hdr_count++] = extra[i];

    amisnap_buf_init(out);
    {
        /* Free `out` on ANY failure from here: amisnap_http_build_request
         * can fail (AMISNAP_ERR_MALFORMED) AFTER already appending the
         * request line/headers -- e.g. a header line over 255 bytes, which
         * a long Basic-auth credential hits on every request -- leaving a
         * partially-filled buffer. Every caller does
         * `if (rc != AMISNAP_OK) return rc;` without its own free, so
         * releasing it here is the single point that keeps them all
         * leak-free. (The earlier extra_count return is before
         * amisnap_buf_init, so `out` is untouched there -- nothing to
         * free.) */
        int rc = amisnap_http_build_request(out, method, abspath, ctx->host_header,
                                             hdrs, hdr_count, body, body_len);
        if (rc != AMISNAP_OK)
            amisnap_buf_free(out);
        return rc;
    }
}

static int webdav_build(webdav_ctx *ctx, const char *method, const char *key,
                         const amisnap_http_header *extra, size_t extra_count,
                         const void *body, size_t body_len, amisnap_buf *out)
{
    char abspath[AMISNAP_WEBDAV_MAX_PATH];
    int n = snprintf(abspath, sizeof(abspath), "%s/%s", ctx->base_path, key);

    if (n < 0 || (size_t)n >= sizeof(abspath)) return AMISNAP_ERR_MALFORMED;
    return webdav_build_abs(ctx, method, abspath, extra, extra_count, body, body_len, out);
}

/* --- request/response exchange, with one-retry-on-stale-keep-alive --- */

/* Sends `req` and parses the full response into `resp` (caller frees on
 * success via amisnap_http_response_free() -- on any error return,
 * `resp` has already been freed/never allocated, matching
 * amisnap_backend_get()'s own "*out untouched on error" convention).
 *
 * Reuses ctx->conn across calls (proposal.md's "HTTP/1.1 client with
 * keep-alive"). A real send/recv failure on an ALREADY-open (reused)
 * connection is retried exactly once on a fresh connection -- the
 * common real-world case of a server closing an idle keep-alive
 * connection between two of this client's requests, not a genuine
 * network failure. A failure on a freshly-opened connection is never
 * retried (the network/server is actually down; retrying would just
 * repeat the same failure). A malformed-response parse error is never
 * retried either way -- garbage framing isn't a staleness symptom. */
static int webdav_exchange(webdav_ctx *ctx, const amisnap_buf *req, amisnap_http_response *resp)
{
    int attempt;

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
                if (got == 0) { rc = AMISNAP_ERR_IO; break; } /* peer closed mid-response */
                rc = amisnap_http_response_feed(resp, buf, got, &done);
                if (rc != AMISNAP_OK || done) break;
            }
            if (rc == AMISNAP_OK && done)
                return AMISNAP_OK; /* success -- ctx->conn stays open for reuse */
            amisnap_http_response_free(resp);
        }

        amisnap_transport_close(ctx->transport, ctx->conn);
        ctx->conn = NULL;
        if (rc != AMISNAP_ERR_IO || fresh)
            return rc;
        /* else: a reused connection failed -- retry once on a fresh one. */
    }
    return AMISNAP_ERR_IO;
}

/* --- MKCOL, walked one path component at a time like backend_dir.c's
 * own mkdir_p, operating on an absolute URL path (not base_path-
 * relative -- used both by the public mkcol() op, via webdav_mkcol()
 * below, and by amisnap_backend_webdav_open()'s own base_path
 * bootstrap, which has no key to prepend it to yet). --- */

static int webdav_mkcol_one(webdav_ctx *ctx, const char *abspath)
{
    amisnap_buf req;
    amisnap_http_response resp;
    int rc;

    rc = webdav_build_abs(ctx, "MKCOL", abspath, NULL, 0, NULL, 0, &req);
    if (rc != AMISNAP_OK) return rc;
    rc = webdav_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    /* 2xx = created; 405 (RFC 4918 9.3.1: MKCOL on an existing resource)
     * and 409 (some servers' own choice) both mean "already exists" --
     * tolerated exactly like backend_dir.c's own EEXIST-tolerant
     * mkdir_one(). */
    rc = (resp.status_code / 100 == 2 || resp.status_code == 405 || resp.status_code == 409)
             ? AMISNAP_OK : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

static int webdav_mkcol_abspath(webdav_ctx *ctx, const char *abspath)
{
    char buf[AMISNAP_WEBDAV_MAX_PATH];
    size_t i, len = strlen(abspath);
    int rc;

    if (len == 0) return AMISNAP_OK; /* server root: always exists */
    if (len >= sizeof(buf)) return AMISNAP_ERR_MALFORMED;
    memcpy(buf, abspath, len + 1);

    for (i = 1; i < len; i++) { /* start at 1: buf[0] is abspath's own leading '/' */
        if (buf[i] == '/') {
            buf[i] = '\0';
            rc = webdav_mkcol_one(ctx, buf);
            buf[i] = '/';
            if (rc != AMISNAP_OK) return rc;
        }
    }
    return webdav_mkcol_one(ctx, buf);
}

static int mkcol_parents(webdav_ctx *ctx, const char *key)
{
    const char *slash = strrchr(key, '/');
    char abspath[AMISNAP_WEBDAV_MAX_PATH];
    int n;

    if (!slash) return AMISNAP_OK; /* no parent beyond base_path, already ensured at open() */

    n = snprintf(abspath, sizeof(abspath), "%s/%.*s", ctx->base_path,
                 (int)(slash - key), key);
    if (n < 0 || (size_t)n >= sizeof(abspath)) return AMISNAP_ERR_MALFORMED;
    return webdav_mkcol_abspath(ctx, abspath);
}

/* --- PROPFIND response scraping: extracts every <...href>...</...>
 * value (any/no XML namespace prefix -- Apache mod_dav uses "D:",
 * Nextcloud "d:", others none at all) from a Depth: 1 multistatus body,
 * percent-decodes it, strips the request's own "self" entry (always
 * present in a Depth: 1 response, per RFC 4918 9.1), and reports just
 * the final path component of everything else via `cb` -- matching
 * backend.h's own list() contract ("`name` being just the final path
 * component, not the full key"). Deliberately a scraper, not a real
 * namespace-aware XML parser -- scoped to the one shape every real
 * WebDAV server's PROPFIND response actually takes, not a general SGML/
 * XML document (documented limitation, not an oversight). --- */

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

static const char *find_ci(const char *hay, size_t haylen, const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    if (needle_len == 0 || haylen < needle_len) return NULL;
    for (i = 0; i + needle_len <= haylen; i++) {
        size_t j;

        for (j = 0; j < needle_len; j++) {
            char a = hay[i + j], b = needle[j];

            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == needle_len) return hay + i;
    }
    return NULL;
}

static void webdav_scrape_hrefs(const char *body, size_t body_len, const char *self_path,
                                 void (*cb)(void *user, const char *name), void *user)
{
    size_t pos = 0;

    while (pos < body_len) {
        const char *h = find_ci(body + pos, body_len - pos, "href");
        const char *tag_start;
        const char *gt, *lt;
        char decoded[AMISNAP_WEBDAV_MAX_PATH];
        size_t hreflen, dl;
        const char *name;

        if (!h) break;

        /* Confirm this "href" match is an OPENING tag name, not
         * incidental text or a closing tag -- walk back to the nearest
         * '<' or '>' and require '<' (tolerates a namespace prefix like
         * "D:" or "lp1:" in between). tag_start now points just after
         * that '<'; if it points at '/', this is a CLOSING tag
         * ("</D:href>") -- reject it. Without this reject, a closing
         * tag was accepted as if it were opening, and the "content"
         * scraped between its '>' and the next '<' was the inter-
         * element whitespace a pretty-printing server (Apache mod_dav)
         * emits -- yielding a phantom "\n" entry per real one, which
         * snapshot enumeration and prune would then act on. */
        tag_start = h;
        while (tag_start > body && tag_start[-1] != '<' && tag_start[-1] != '>')
            tag_start--;
        if (tag_start == body || tag_start[-1] != '<' || tag_start[0] == '/') {
            pos = (size_t)(h - body) + 4;
            continue;
        }

        gt = (const char *)memchr(h, '>', body_len - (size_t)(h - body));
        if (!gt) break;
        if (gt[-1] == '/') { /* self-closing <.../> -- an empty href, nothing to extract */
            pos = (size_t)(gt - body) + 1;
            continue;
        }

        lt = (const char *)memchr(gt + 1, '<', body_len - (size_t)(gt + 1 - body));
        if (!lt) break;

        hreflen = (size_t)(lt - (gt + 1));
        if (hreflen >= sizeof(decoded)) hreflen = sizeof(decoded) - 1;
        percent_decode(gt + 1, hreflen, decoded, sizeof(decoded));

        dl = strlen(decoded);
        if (dl > 0 && decoded[dl - 1] == '/') decoded[--dl] = '\0'; /* a collection's own trailing slash */

        if (strcmp(decoded, self_path) != 0) {
            name = strrchr(decoded, '/');
            name = name ? name + 1 : decoded;
            /* Defence in depth beyond the closing-tag reject above: an
             * empty or all-whitespace name is never a real entry (it's
             * inter-element formatting), so never surface it as one. */
            {
                const char *s = name;
                while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
                if (*s != '\0') cb(user, name);
            }
        }

        pos = (size_t)(lt - body);
    }
}

static const char PROPFIND_BODY[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
    "<D:propfind xmlns:D=\"DAV:\"><D:prop><D:resourcetype/></D:prop></D:propfind>";

/* --- URL parsing (the CLI's own REPO=/DEST= form): reuses
 * percent_decode() above for userinfo, same as any other percent-
 * encoded text this file handles. --- */

int amisnap_webdav_parse_url(const char *url, amisnap_webdav_url *out)
{
    const char *p = url;
    const char *at = NULL;
    const char *host_start, *host_end, *path_start;
    const char *scan_end;
    const char *colon;
    size_t host_len;

    memset(out, 0, sizeof(*out));

    if (strncmp(p, "https://", 8) == 0) { out->tls = 1; p += 8; }
    else if (strncmp(p, "http://", 7) == 0) { out->tls = 0; p += 7; }
    else return AMISNAP_ERR_MALFORMED;

    /* userinfo ("user[:pass]@"), only searched before the first '/' --
     * a bare '@' inside the path (rare, but legal in a URL path
     * component) must not be mistaken for one. */
    path_start = strchr(p, '/');
    scan_end = path_start ? path_start : p + strlen(p);
    {
        const char *q;
        for (q = p; q < scan_end; q++) {
            if (*q == '@') { at = q; break; }
        }
    }
    if (at) {
        colon = NULL;
        {
            const char *q;
            for (q = p; q < at; q++) {
                if (*q == ':') { colon = q; break; }
            }
        }
        if (colon) {
            size_t ulen = (size_t)(colon - p);
            size_t plen = (size_t)(at - (colon + 1));

            if (ulen >= sizeof(out->username) || plen >= sizeof(out->password))
                return AMISNAP_ERR_MALFORMED;
            percent_decode(p, ulen, out->username, sizeof(out->username));
            percent_decode(colon + 1, plen, out->password, sizeof(out->password));
        } else {
            size_t ulen = (size_t)(at - p);

            if (ulen >= sizeof(out->username)) return AMISNAP_ERR_MALFORMED;
            percent_decode(p, ulen, out->username, sizeof(out->username));
        }
        p = at + 1;
        path_start = strchr(p, '/'); /* re-derive: userinfo may have shifted where the path starts */
    }

    host_start = p;
    scan_end = path_start ? path_start : p + strlen(p);
    colon = NULL;
    {
        const char *q;
        for (q = host_start; q < scan_end; q++) {
            if (*q == ':') { colon = q; break; }
        }
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
        out->port = out->tls ? 443 : 80;
    }

    if (path_start) {
        size_t plen = strlen(path_start);

        if (plen >= sizeof(out->base_path)) return AMISNAP_ERR_MALFORMED;
        memcpy(out->base_path, path_start, plen + 1);
    }
    return AMISNAP_OK;
}

/* --- amisnap_backend_ops --- */

static int webdav_put(amisnap_backend *be, const char *key, const void *data, size_t len)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    amisnap_buf req;
    amisnap_http_response resp;
    int rc;

    rc = mkcol_parents(ctx, key);
    if (rc != AMISNAP_OK) return rc;

    rc = webdav_build(ctx, "PUT", key, NULL, 0, data, len, &req);
    if (rc != AMISNAP_OK) return rc;
    rc = webdav_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    rc = (resp.status_code / 100 == 2) ? AMISNAP_OK : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

static int webdav_get(amisnap_backend *be, const char *key, amisnap_buf *out)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    amisnap_buf req;
    amisnap_http_response resp;
    int rc;

    rc = webdav_build(ctx, "GET", key, NULL, 0, NULL, 0, &req);
    if (rc != AMISNAP_OK) return rc;
    rc = webdav_exchange(ctx, &req, &resp);
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
    /* A 2xx GET whose body was connection-close delimited (no
     * Content-Length, not chunked) was truncated to empty by the
     * parser -- never accept that as a valid object, or a stored file
     * would silently restore as zero bytes. A real empty object comes
     * back framed as "Content-Length: 0" (body_unframed clear). */
    if (resp.body_unframed) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_IO;
    }

    *out = resp.body;
    amisnap_buf_init(&resp.body); /* ownership moved to *out -- don't let response_free() touch it */
    amisnap_http_response_free(&resp);
    return AMISNAP_OK;
}

static int webdav_exists(amisnap_backend *be, const char *key)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    amisnap_http_header hdr;
    amisnap_buf req;
    amisnap_http_response resp;
    int rc;

    hdr.name = "Depth";
    hdr.value = "0";
    rc = webdav_build(ctx, "PROPFIND", key, &hdr, 1, PROPFIND_BODY, sizeof(PROPFIND_BODY) - 1, &req);
    if (rc != AMISNAP_OK) return rc;
    rc = webdav_exchange(ctx, &req, &resp);
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

static int webdav_list(amisnap_backend *be, const char *prefix,
                        void (*cb)(void *user, const char *name), void *user)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    char self_path[AMISNAP_WEBDAV_MAX_PATH];
    amisnap_http_header hdr;
    amisnap_buf req;
    amisnap_http_response resp;
    int rc, n;

    n = snprintf(self_path, sizeof(self_path), "%s/%s", ctx->base_path, prefix);
    if (n < 0 || (size_t)n >= sizeof(self_path)) return AMISNAP_ERR_MALFORMED;
    if (n > 0 && self_path[n - 1] == '/') self_path[--n] = '\0';

    hdr.name = "Depth";
    hdr.value = "1";
    rc = webdav_build(ctx, "PROPFIND", prefix, &hdr, 1, PROPFIND_BODY, sizeof(PROPFIND_BODY) - 1, &req);
    if (rc != AMISNAP_OK) return rc;
    rc = webdav_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    /* "A prefix that doesn't exist at all lists as empty ... not an
     * error" -- backend.h's own list() contract. */
    if (resp.status_code == 404) {
        amisnap_http_response_free(&resp);
        return AMISNAP_OK;
    }
    if (resp.status_code / 100 != 2) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_IO;
    }

    webdav_scrape_hrefs((const char *)resp.body.data, resp.body.len, self_path, cb, user);
    amisnap_http_response_free(&resp);
    return AMISNAP_OK;
}

static int webdav_remove(amisnap_backend *be, const char *key)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    amisnap_buf req;
    amisnap_http_response resp;
    int rc;

    rc = webdav_build(ctx, "DELETE", key, NULL, 0, NULL, 0, &req);
    if (rc != AMISNAP_OK) return rc;
    rc = webdav_exchange(ctx, &req, &resp);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) return rc;

    if (resp.status_code == 404) {
        amisnap_http_response_free(&resp);
        return AMISNAP_ERR_NOT_FOUND;
    }
    rc = (resp.status_code / 100 == 2) ? AMISNAP_OK : AMISNAP_ERR_IO;
    amisnap_http_response_free(&resp);
    return rc;
}

static int webdav_mkcol(amisnap_backend *be, const char *key)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    char abspath[AMISNAP_WEBDAV_MAX_PATH];
    int n;

    if (key[0] == '\0') return AMISNAP_OK; /* root: already ensured at open() */

    n = snprintf(abspath, sizeof(abspath), "%s/%s", ctx->base_path, key);
    if (n < 0 || (size_t)n >= sizeof(abspath)) return AMISNAP_ERR_MALFORMED;
    return webdav_mkcol_abspath(ctx, abspath);
}

/* --- streaming upload (put_begin/put_append/put_finish/put_abort):
 * chunked Transfer-Encoding on the REQUEST side, so a large chunked
 * restore.c restore stays memory-bounded over WebDAV too, not just on
 * the directory backend -- restore.c never knows the total size up
 * front (repo.h/restore.c's own doc comments: each chunk arrives one at
 * a time), so Content-Length can't be used here the way webdav_put()
 * above uses it. Owns a dedicated connection for the whole upload,
 * separate from ctx->conn's keep-alive slot (never aliases it). --- */

typedef struct {
    webdav_ctx *ctx;
    void *conn;
    int failed; /* AMISNAP_OK, or the first error an append() hit -- once set,
                 * every further append()/finish() call just reports it back
                 * rather than trying to keep writing to a socket already
                 * known to be broken. */
} webdav_put_handle;

static int webdav_put_begin(amisnap_backend *be, const char *key, void **handle_out)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;
    webdav_put_handle *h;
    amisnap_http_header hdr;
    amisnap_buf req;
    int rc;

    rc = mkcol_parents(ctx, key);
    if (rc != AMISNAP_OK) return rc;

    h = (webdav_put_handle *)malloc(sizeof(*h));
    if (!h) return AMISNAP_ERR_NOMEM;
    h->ctx = ctx;
    h->conn = NULL;
    h->failed = AMISNAP_OK;

    hdr.name = "Transfer-Encoding";
    hdr.value = "chunked";
    /* body=NULL/len=0: amisnap_http_build_request() then sends neither
     * Content-Length nor a body itself -- exactly right, since the body
     * is streamed separately below, one chunk at a time. */
    rc = webdav_build(ctx, "PUT", key, &hdr, 1, NULL, 0, &req);
    if (rc != AMISNAP_OK) {
        free(h);
        return rc;
    }

    rc = amisnap_transport_connect(ctx->transport, ctx->host, ctx->port, &h->conn);
    if (rc == AMISNAP_OK)
        rc = amisnap_transport_send(ctx->transport, h->conn, req.data, req.len);
    amisnap_buf_free(&req);
    if (rc != AMISNAP_OK) {
        if (h->conn) amisnap_transport_close(ctx->transport, h->conn);
        free(h);
        return rc;
    }

    *handle_out = h;
    return AMISNAP_OK;
}

static int webdav_put_append(amisnap_backend *be, void *handle, const void *data, size_t len)
{
    webdav_put_handle *h = (webdav_put_handle *)handle;
    char sizeline[2 + sizeof(unsigned long) * 2 + 1]; /* "<hex len>\r\n", generous */
    int n;
    int rc;

    (void)be;
    if (h->failed != AMISNAP_OK) return h->failed;
    /* A zero-length chunk is the TERMINATOR in HTTP chunked encoding
     * (RFC 7230 4.1) -- must never be emitted mid-stream just because a
     * caller happened to pass len=0 (repo.h's own read_fn contract
     * allows a final short/empty read; the equivalent here is simply
     * "nothing to send this call", not "end the body early"). */
    if (len == 0) return AMISNAP_OK;

    n = snprintf(sizeline, sizeof(sizeline), "%lx\r\n", (unsigned long)len);
    rc = amisnap_transport_send(h->ctx->transport, h->conn, sizeline, (size_t)n);
    if (rc == AMISNAP_OK)
        rc = amisnap_transport_send(h->ctx->transport, h->conn, data, len);
    if (rc == AMISNAP_OK)
        rc = amisnap_transport_send(h->ctx->transport, h->conn, "\r\n", 2);
    if (rc != AMISNAP_OK) h->failed = rc;
    return rc;
}

static int webdav_put_finish(amisnap_backend *be, void *handle)
{
    webdav_put_handle *h = (webdav_put_handle *)handle;
    amisnap_http_response resp;
    int rc = h->failed;
    int have_resp = 0;

    (void)be;
    if (rc == AMISNAP_OK)
        rc = amisnap_transport_send(h->ctx->transport, h->conn, "0\r\n\r\n", 5);

    if (rc == AMISNAP_OK) {
        int done = 0;

        amisnap_http_response_init(&resp);
        have_resp = 1;
        for (;;) {
            uint8_t buf[4096];
            size_t got;

            rc = amisnap_transport_recv(h->ctx->transport, h->conn, buf, sizeof(buf), &got);
            if (rc != AMISNAP_OK) break;
            if (got == 0) { rc = AMISNAP_ERR_IO; break; }
            rc = amisnap_http_response_feed(&resp, buf, got, &done);
            if (rc != AMISNAP_OK || done) break;
        }
        if (rc == AMISNAP_OK && !done) rc = AMISNAP_ERR_IO;
    }

    amisnap_transport_close(h->ctx->transport, h->conn);

    if (have_resp) {
        if (rc == AMISNAP_OK && resp.status_code / 100 != 2)
            rc = AMISNAP_ERR_IO;
        amisnap_http_response_free(&resp);
    }

    free(h);
    return rc;
}

static void webdav_put_abort(amisnap_backend *be, void *handle)
{
    webdav_put_handle *h = (webdav_put_handle *)handle;

    (void)be;
    if (h) {
        /* No explicit WebDAV "abort a PUT" primitive exists -- closing
         * the connection without ever sending the "0\r\n\r\n" chunked
         * terminator leaves the request body permanently incomplete, so
         * a compliant server must not commit it (matches this backend's
         * own atomic-on-success contract: nothing observable at `key`
         * until put_finish() succeeds). */
        if (h->conn) amisnap_transport_close(h->ctx->transport, h->conn);
        free(h);
    }
}

static void webdav_close(amisnap_backend *be)
{
    webdav_ctx *ctx = (webdav_ctx *)be->ctx;

    if (ctx) {
        if (ctx->conn) amisnap_transport_close(ctx->transport, ctx->conn);
        free(ctx->host);
        free(ctx->host_header);
        free(ctx->base_path);
        free(ctx->auth_header);
        free(ctx);
    }
    be->ctx = NULL;
}

static const amisnap_backend_ops webdav_ops = {
    webdav_put, webdav_get, webdav_exists, webdav_list, webdav_remove, webdav_mkcol,
    webdav_put_begin, webdav_put_append, webdav_put_finish, webdav_put_abort,
    webdav_close
};

/* Every failure path below jumps to `fail`, which relies on `ctx` having
 * been zeroed by memset() up front -- free(NULL) on whichever fields
 * never got set is always safe, same pattern amisnap_repo_writer_file_
 * chunked() uses for its own `out:` cleanup label. */
int amisnap_backend_webdav_open(const amisnap_webdav_config *cfg, amisnap_transport *transport,
                                 amisnap_backend *out)
{
    webdav_ctx *ctx;
    size_t base_len;
    int rc = AMISNAP_OK;

    ctx = (webdav_ctx *)malloc(sizeof(*ctx));
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

    base_len = cfg->base_path ? strlen(cfg->base_path) : 0;
    while (base_len > 0 && cfg->base_path[base_len - 1] == '/') base_len--;
    if (base_len == 0) {
        ctx->base_path = dup_str("");
    } else {
        ctx->base_path = (char *)malloc(base_len + 1);
        if (ctx->base_path) {
            memcpy(ctx->base_path, cfg->base_path, base_len);
            ctx->base_path[base_len] = '\0';
        }
    }
    if (!ctx->base_path) { rc = AMISNAP_ERR_NOMEM; goto fail; }

    if (cfg->username && cfg->password) {
        amisnap_buf cred, b64;
        char *hdr;

        amisnap_buf_init(&cred);
        rc = amisnap_buf_bytes(&cred, cfg->username, strlen(cfg->username));
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&cred, ":", 1);
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(&cred, cfg->password, strlen(cfg->password));

        amisnap_buf_init(&b64);
        if (rc == AMISNAP_OK) rc = amisnap_base64_encode(&b64, cred.data, cred.len);
        amisnap_buf_free(&cred);
        if (rc != AMISNAP_OK) { amisnap_buf_free(&b64); goto fail; }

        hdr = (char *)malloc(b64.len + 7); /* "Basic " (6) + b64 + NUL */
        if (!hdr) { amisnap_buf_free(&b64); rc = AMISNAP_ERR_NOMEM; goto fail; }
        memcpy(hdr, "Basic ", 6);
        memcpy(hdr + 6, b64.data, b64.len);
        hdr[6 + b64.len] = '\0';
        amisnap_buf_free(&b64);
        ctx->auth_header = hdr;
    }

    out->ops = &webdav_ops;
    out->ctx = ctx;

    rc = webdav_mkcol_abspath(ctx, ctx->base_path);
    if (rc != AMISNAP_OK) {
        webdav_close(out); /* out->ctx == ctx already, so this frees everything above too */
        return rc;
    }
    return AMISNAP_OK;

fail:
    free(ctx->host);
    free(ctx->host_header);
    free(ctx->base_path);
    free(ctx->auth_header);
    free(ctx);
    return rc;
}
