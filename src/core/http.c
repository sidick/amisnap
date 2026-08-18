/* http.c -- see http.h. */
#include <stdio.h>
#include <string.h>

#include "http.h"

int amisnap_http_build_request(amisnap_buf *out, const char *method, const char *path,
                                const char *host, const amisnap_http_header *headers,
                                size_t header_count, const void *body, size_t body_len)
{
    char line[256];
    size_t i;
    int rc;
    int n;

    n = snprintf(line, sizeof(line), "%s %s HTTP/1.1\r\n", method, path);
    if (n < 0 || (size_t)n >= sizeof(line)) return AMISNAP_ERR_MALFORMED;
    rc = amisnap_buf_bytes(out, line, (size_t)n);
    if (rc != AMISNAP_OK) return rc;

    n = snprintf(line, sizeof(line), "Host: %s\r\n", host);
    if (n < 0 || (size_t)n >= sizeof(line)) return AMISNAP_ERR_MALFORMED;
    rc = amisnap_buf_bytes(out, line, (size_t)n);
    if (rc != AMISNAP_OK) return rc;

    if (body_len > 0) {
        n = snprintf(line, sizeof(line), "Content-Length: %lu\r\n", (unsigned long)body_len);
        if (n < 0 || (size_t)n >= sizeof(line)) return AMISNAP_ERR_MALFORMED;
        rc = amisnap_buf_bytes(out, line, (size_t)n);
        if (rc != AMISNAP_OK) return rc;
    }

    for (i = 0; i < header_count; i++) {
        n = snprintf(line, sizeof(line), "%s: %s\r\n", headers[i].name, headers[i].value);
        if (n < 0 || (size_t)n >= sizeof(line)) return AMISNAP_ERR_MALFORMED;
        rc = amisnap_buf_bytes(out, line, (size_t)n);
        if (rc != AMISNAP_OK) return rc;
    }

    {
        static const char tail[] = "Connection: keep-alive\r\n\r\n";

        /* sizeof(tail) - 1, not a hand-counted literal -- a hardcoded
         * length here previously miscounted by one (27 instead of the
         * real 26), appending this string literal's own NUL terminator
         * as a stray extra byte before every single request body. Never
         * caught by test_http.c (which only exercises the response
         * parser), only found once webdav.c's own tests checked a
         * request's exact bytes against a real body. */
        rc = amisnap_buf_bytes(out, tail, sizeof(tail) - 1);
    }
    if (rc != AMISNAP_OK) return rc;

    if (body_len > 0) {
        rc = amisnap_buf_bytes(out, body, body_len);
        if (rc != AMISNAP_OK) return rc;
    }
    return AMISNAP_OK;
}

void amisnap_http_response_init(amisnap_http_response *r)
{
    memset(r, 0, sizeof(*r));
    r->state = AMISNAP_HTTP_PARSE_STATUS_LINE;
    amisnap_buf_init(&r->headers_raw);
    amisnap_buf_init(&r->body);
    amisnap_buf_init(&r->line_scratch);
}

void amisnap_http_response_free(amisnap_http_response *r)
{
    amisnap_buf_free(&r->headers_raw);
    amisnap_buf_free(&r->body);
    amisnap_buf_free(&r->line_scratch);
}

static int header_name_eq(const char *name, size_t name_len, const char *literal)
{
    size_t lit_len = strlen(literal);
    size_t i;

    if (name_len != lit_len) return 0;
    for (i = 0; i < name_len; i++) {
        char a = name[i];
        char b = literal[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

static int value_contains_ci(const char *value, size_t value_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    if (needle_len == 0 || value_len < needle_len) return 0;
    for (i = 0; i + needle_len <= value_len; i++) {
        if (header_name_eq(value + i, needle_len, needle)) return 1;
    }
    return 0;
}

/* Both parsers set *ok = 0 on overflow (the accumulated value would
 * exceed UINT64_MAX) so a hostile/broken server can't wrap a body
 * length mod 2^64 and desync the parser into framing the body off an
 * attacker-chosen value. *ok stays 1 otherwise; passing ok = NULL
 * skips the signal (used for the 3-digit status code, which cannot
 * overflow). Parsing still stops at the first non-digit, so a chunk
 * extension (";ext") or trailing space ends the number as before --
 * trailing-garbage rejection, where it matters (Content-Length), is
 * the caller's job. */
static uint64_t parse_u64(const char *p, size_t len, int *ok)
{
    uint64_t v = 0;
    size_t i;

    if (ok) *ok = 1;
    for (i = 0; i < len; i++) {
        uint64_t d;
        if (p[i] < '0' || p[i] > '9') break;
        d = (uint64_t)(p[i] - '0');
        if (v > (UINT64_MAX - d) / 10u) { if (ok) *ok = 0; return 0; }
        v = v * 10u + d;
    }
    return v;
}

static uint64_t parse_hex64(const char *p, size_t len, int *ok)
{
    uint64_t v = 0;
    size_t i;

    if (ok) *ok = 1;
    for (i = 0; i < len; i++) {
        char c = p[i];
        uint64_t digit;

        if (c >= '0' && c <= '9') digit = (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uint64_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uint64_t)(c - 'A' + 10);
        else break; /* chunk extensions (";ext") stop hex parsing here, same as trailing space */
        if (v > (UINT64_MAX - digit) / 16u) { if (ok) *ok = 0; return 0; }
        v = v * 16u + digit;
    }
    return v;
}

/* Rescans the fully-accumulated, NUL-line-separated headers_raw block
 * (built one line at a time by AMISNAP_HTTP_PARSE_HEADERS below) into
 * r->headers[]/header_count and the Content-Length/Transfer-Encoding
 * framing fields. Done as a single pass over the FINAL buffer, once
 * headers_raw is done growing, rather than pointing into it while still
 * appending -- amisnap_buf_bytes() may realloc() and move the whole
 * buffer, which would invalidate any pointer captured mid-scan. */
static int populate_headers(amisnap_http_response *r)
{
    const char *p = (const char *)r->headers_raw.data;
    const char *end = p + r->headers_raw.len;

    r->header_count = 0;
    r->has_content_length = 0;
    r->chunked = 0;

    while (p < end) {
        size_t linelen = strlen(p);
        const char *colon = (const char *)memchr(p, ':', linelen);

        if (colon) {
            const char *name = p;
            size_t name_len = (size_t)(colon - p);
            const char *value = colon + 1;
            size_t value_len = linelen - name_len - 1;

            while (value_len > 0 && *value == ' ') { value++; value_len--; }

            if (r->header_count < AMISNAP_HTTP_MAX_HEADERS) {
                r->headers[r->header_count].name = name;
                r->headers[r->header_count].name_len = name_len;
                r->headers[r->header_count].value = value;
                r->headers[r->header_count].value_len = value_len;
                r->header_count++;
            }

            if (header_name_eq(name, name_len, "Content-Length")) {
                /* Must be a run of digits, optionally trailing spaces,
                 * and must not overflow -- a hostile "Content-Length:
                 * 12garbage" (parsed as 12 before) or a value wrapping
                 * mod 2^64 would let the server frame the body off a
                 * bogus length and truncate the download. Fail closed. */
                int ok;
                size_t d = 0, t;
                while (d < value_len && value[d] >= '0' && value[d] <= '9') d++;
                if (d == 0) return AMISNAP_ERR_MALFORMED; /* no digits at all */
                for (t = d; t < value_len; t++)
                    if (value[t] != ' ') return AMISNAP_ERR_MALFORMED; /* trailing garbage */
                r->content_length = parse_u64(value, value_len, &ok);
                if (!ok) return AMISNAP_ERR_MALFORMED; /* overflow */
                r->has_content_length = 1;
            } else if (header_name_eq(name, name_len, "Transfer-Encoding")) {
                if (value_contains_ci(value, value_len, "chunked"))
                    r->chunked = 1;
            }
        }
        p += linelen + 1; /* skip the NUL populate_headers' own caller placed there */
    }
    return AMISNAP_OK;
}

/* Consumes bytes from data[*pos..len) into r->line_scratch until a '\n'
 * is found (trailing '\r', if present, stripped) or the input runs out.
 * Returns 1 with *pos advanced past the '\n' and r->line_scratch holding
 * the complete line when one was found; 0 (with *pos == len) if more
 * input is needed -- the partial line stays buffered in line_scratch for
 * the next feed() call, exactly the split-read case this parser exists
 * to handle; a negative AMISNAP_ERR_* if line_scratch couldn't grow. */
static int take_line(amisnap_http_response *r, const uint8_t *data, size_t len, size_t *pos)
{
    const uint8_t *start = data + *pos;
    const uint8_t *nl = (const uint8_t *)memchr(start, '\n', len - *pos);
    size_t chunk_len;
    int rc;

    if (!nl) {
        rc = amisnap_buf_bytes(&r->line_scratch, start, len - *pos);
        if (rc != AMISNAP_OK) return rc;
        *pos = len;
        return 0;
    }

    chunk_len = (size_t)(nl - start);
    rc = amisnap_buf_bytes(&r->line_scratch, start, chunk_len);
    if (rc != AMISNAP_OK) return rc;
    *pos += chunk_len + 1;

    if (r->line_scratch.len > 0 && r->line_scratch.data[r->line_scratch.len - 1] == '\r')
        r->line_scratch.len--;
    return 1;
}

static void reset_line(amisnap_http_response *r)
{
    r->line_scratch.len = 0;
}

int amisnap_http_response_feed(amisnap_http_response *r, const void *data_v, size_t len, int *done)
{
    const uint8_t *data = (const uint8_t *)data_v;
    size_t pos = 0;
    int rc;

    *done = 0;
    if (r->state == AMISNAP_HTTP_PARSE_DONE)
        return AMISNAP_ERR_MALFORMED;

    while (pos < len) {
        switch (r->state) {
        case AMISNAP_HTTP_PARSE_STATUS_LINE: {
            size_t i;

            {
                int tl = take_line(r, data, len, &pos);
                if (tl < 0) return tl;
                if (!tl) break;
            }

            i = 0;
            while (i < r->line_scratch.len && r->line_scratch.data[i] != ' ') i++;
            if (i >= r->line_scratch.len) return AMISNAP_ERR_MALFORMED;
            i++;
            if (r->line_scratch.len - i < 3) return AMISNAP_ERR_MALFORMED;
            r->status_code = (int)parse_u64((const char *)r->line_scratch.data + i, 3, NULL);
            reset_line(r);
            r->state = AMISNAP_HTTP_PARSE_HEADERS;
            break;
        }

        case AMISNAP_HTTP_PARSE_HEADERS: {
            {
                int tl = take_line(r, data, len, &pos);
                if (tl < 0) return tl;
                if (!tl) break;
            }

            if (r->line_scratch.len == 0) {
                rc = populate_headers(r);
                if (rc != AMISNAP_OK) return rc;
                reset_line(r);
                if (r->chunked) {
                    r->state = AMISNAP_HTTP_PARSE_CHUNK_SIZE;
                } else if (r->has_content_length && r->content_length > 0) {
                    r->state = AMISNAP_HTTP_PARSE_BODY;
                } else {
                    /* No chunked, no positive Content-Length. If there
                     * was no Content-Length header AT ALL (not even
                     * "Content-Length: 0"), the body is connection-close
                     * delimited (RFC 7230 3.3.3) and this parser can't
                     * read it -- flag it so a GET caller rejects the
                     * response rather than accepting a truncated-to-
                     * empty object. A framed "Content-Length: 0" (a
                     * genuinely empty body) leaves the flag clear. */
                    if (!r->has_content_length)
                        r->body_unframed = 1;
                    r->state = AMISNAP_HTTP_PARSE_DONE;
                    *done = 1;
                    return AMISNAP_OK;
                }
                break;
            }

            rc = amisnap_buf_bytes(&r->headers_raw, r->line_scratch.data, r->line_scratch.len);
            if (rc != AMISNAP_OK) return rc;
            rc = amisnap_buf_bytes(&r->headers_raw, "", 1); /* line separator: one NUL byte */
            if (rc != AMISNAP_OK) return rc;
            reset_line(r);
            break;
        }

        case AMISNAP_HTTP_PARSE_BODY: {
            size_t want = (size_t)(r->content_length - r->body.len);
            size_t avail = len - pos;
            size_t take = want < avail ? want : avail;

            rc = amisnap_buf_bytes(&r->body, data + pos, take);
            if (rc != AMISNAP_OK) return rc;
            pos += take;
            if (r->body.len == r->content_length) {
                r->state = AMISNAP_HTTP_PARSE_DONE;
                *done = 1;
                return AMISNAP_OK;
            }
            break;
        }

        case AMISNAP_HTTP_PARSE_CHUNK_SIZE: {
            {
                int tl = take_line(r, data, len, &pos);
                if (tl < 0) return tl;
                if (!tl) break;
            }
            {
                int ok;
                r->chunk_remaining = parse_hex64((const char *)r->line_scratch.data,
                                                  r->line_scratch.len, &ok);
                if (!ok) return AMISNAP_ERR_MALFORMED; /* chunk size overflowed uint64 */
            }
            reset_line(r);
            r->state = (r->chunk_remaining == 0) ? AMISNAP_HTTP_PARSE_CHUNK_TRAILER
                                                  : AMISNAP_HTTP_PARSE_CHUNK_DATA;
            break;
        }

        case AMISNAP_HTTP_PARSE_CHUNK_DATA: {
            size_t avail = len - pos;
            size_t take = (size_t)(r->chunk_remaining < avail ? r->chunk_remaining : avail);

            rc = amisnap_buf_bytes(&r->body, data + pos, take);
            if (rc != AMISNAP_OK) return rc;
            pos += take;
            r->chunk_remaining -= take;
            if (r->chunk_remaining == 0)
                r->state = AMISNAP_HTTP_PARSE_CHUNK_CRLF;
            break;
        }

        case AMISNAP_HTTP_PARSE_CHUNK_CRLF: {
            {
                int tl = take_line(r, data, len, &pos);
                if (tl < 0) return tl;
                if (!tl) break;
            }
            /* A non-empty line here means the server's chunk framing
             * doesn't match its own declared chunk size -- treated as
             * malformed rather than silently resyncing (house rule 1:
             * a data-losing/data-corrupting ambiguity must never pass
             * quietly). */
            if (r->line_scratch.len != 0) return AMISNAP_ERR_MALFORMED;
            reset_line(r);
            r->state = AMISNAP_HTTP_PARSE_CHUNK_SIZE;
            break;
        }

        case AMISNAP_HTTP_PARSE_CHUNK_TRAILER: {
            {
                int tl = take_line(r, data, len, &pos);
                if (tl < 0) return tl;
                if (!tl) break;
            }
            if (r->line_scratch.len == 0) {
                reset_line(r);
                r->state = AMISNAP_HTTP_PARSE_DONE;
                *done = 1;
                return AMISNAP_OK;
            }
            /* Trailer headers (RFC 7230 4.1.2) are rare in practice for
             * WebDAV responses and not needed by this client -- consumed
             * and discarded so body/framing stays in sync, not indexed
             * into r->headers[]. */
            reset_line(r);
            break;
        }

        case AMISNAP_HTTP_PARSE_DONE:
            return AMISNAP_ERR_MALFORMED;
        }
    }

    return AMISNAP_OK;
}

const amisnap_http_parsed_header *amisnap_http_response_header(const amisnap_http_response *r,
                                                                 const char *name)
{
    size_t i;

    if (r->state == AMISNAP_HTTP_PARSE_STATUS_LINE || r->state == AMISNAP_HTTP_PARSE_HEADERS)
        return NULL;

    for (i = 0; i < r->header_count; i++) {
        if (header_name_eq(r->headers[i].name, r->headers[i].name_len, name))
            return &r->headers[i];
    }
    return NULL;
}
