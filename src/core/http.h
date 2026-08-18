/* http.h -- portable HTTP/1.1 client protocol layer (docs/proposal.md
 * "Tier 2 -- WebDAV over HTTP(S)", implementation-plan.md Phase 3): request
 * building and incremental response parsing, with no socket or TLS
 * dependency at all -- src/amiga/socket.c (bsdsocket) and tls.c
 * (soft-loaded AmiSSL) are the only pieces that ever touch the network.
 * This module is deliberately host-testable like every other portable
 * core piece (module map's "portable core, thin Amiga rind" -- webdav.c
 * builds on this the same way repo.c builds on manifest.c).
 *
 * The response parser is a streaming state machine, not a whole-buffer
 * decoder: a real socket read() returns whatever bytes happen to be
 * available, which may be less than one header line or split a chunk
 * boundary in half -- amisnap_http_response_feed() is designed to be
 * called repeatedly with however many bytes actually arrived, in any
 * split, and still produce the same result (proven by test_http.c
 * feeding identical response bytes both in one shot and one byte at a
 * time).
 */
#ifndef AMISNAP_HTTP_H
#define AMISNAP_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

/* One request header, name/value as plain C strings (no embedded NUL --
 * these are always short, caller-supplied ASCII like "Content-Type" /
 * "application/octet-stream", never untrusted/binary data). */
typedef struct {
    const char *name;
    const char *value;
} amisnap_http_header;

/* Builds a full HTTP/1.1 request (request line + headers + optional
 * body) into `out` (appended, not reset -- caller owns an
 * amisnap_buf_init()'d buffer). Always sends Host (from `host`, which
 * must already include ":<port>" if non-default -- this layer has no
 * URL/port concept of its own) and, when `body_len` > 0, Content-Length
 * -- WebDAV PUT/PROPFIND bodies are always fully buffered by the caller
 * first (repo.c-style whole-object or chunked-object writes), never
 * chunked-encoded on the request side; chunked *response* bodies (a
 * server behavior this client doesn't control) are handled by the
 * response parser below. `headers`/`header_count` are appended verbatim
 * after Host/Content-Length, letting the caller add
 * Authorization/Depth/Overwrite/Destination/If etc. per WebDAV method.
 * Connection: keep-alive is always sent -- proposal.md's "HTTP/1.1
 * client with keep-alive". Returns AMISNAP_OK or AMISNAP_ERR_NOMEM. */
int amisnap_http_build_request(amisnap_buf *out, const char *method, const char *path,
                                const char *host, const amisnap_http_header *headers,
                                size_t header_count, const void *body, size_t body_len);

typedef enum {
    AMISNAP_HTTP_PARSE_STATUS_LINE,
    AMISNAP_HTTP_PARSE_HEADERS,
    AMISNAP_HTTP_PARSE_BODY,
    AMISNAP_HTTP_PARSE_CHUNK_SIZE,
    AMISNAP_HTTP_PARSE_CHUNK_DATA,
    AMISNAP_HTTP_PARSE_CHUNK_CRLF,
    AMISNAP_HTTP_PARSE_CHUNK_TRAILER,
    AMISNAP_HTTP_PARSE_DONE
} amisnap_http_parse_state;

/* One parsed response header (points into `headers_raw` below --
 * borrowed, same convention as tlv.h's own read side: valid only as
 * long as the amisnap_http_response itself is, never past
 * amisnap_http_response_free()). */
typedef struct {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
} amisnap_http_parsed_header;

/* AMISNAP_HTTP_MAX_HEADERS: generous over any real WebDAV server
 * response (Apache mod_dav/Nextcloud/rclone's own webdav server all
 * send under 15) -- an actual response with more is truncated (the
 * excess still consumed and skipped so body parsing stays in sync,
 * just not indexed), not a hard failure; nothing this client needs
 * lives past a typical header set. */
#define AMISNAP_HTTP_MAX_HEADERS 32

typedef struct {
    amisnap_http_parse_state state;
    int status_code;

    int has_content_length;
    uint64_t content_length;
    int chunked;
    uint64_t chunk_remaining; /* CHUNK_DATA: bytes left in the current chunk */
    int body_unframed;        /* set when headers ended with NEITHER Content-Length
                                * NOR chunked Transfer-Encoding: the body (if any) is
                                * delimited only by connection close (RFC 7230 3.3.3),
                                * which this parser does not read. Correct to treat as
                                * empty for a genuinely bodyless response (204/304, a
                                * PUT/MKCOL/DELETE reply), but a GET whose object body
                                * is framed this way would be silently truncated to
                                * empty -- so GET callers must reject a 2xx with this
                                * set rather than accept a zero-byte object. */

    amisnap_buf headers_raw;  /* raw header-block bytes, CRLF-terminated lines,
                                * NUL-separated in place of each line's CRLF once
                                * parsed -- amisnap_http_parsed_header points into this */
    amisnap_http_parsed_header headers[AMISNAP_HTTP_MAX_HEADERS];
    size_t header_count;

    amisnap_buf body;         /* fully decoded (dechunked) body accumulated so far */

    /* Parser-internal scratch: a partial status/header line or chunk-size
     * line carried across feed() calls when a read boundary split it. */
    amisnap_buf line_scratch;
} amisnap_http_response;

void amisnap_http_response_init(amisnap_http_response *r);
void amisnap_http_response_free(amisnap_http_response *r);

/* Feeds `len` more bytes of a response as they arrive off a socket.
 * May be called any number of times with any split of the underlying
 * bytes (including one byte at a time). Sets *done = 1 once the full
 * response (status line + headers + complete body, per Content-Length
 * or chunked framing) has been parsed -- after that, further calls are
 * a caller error and return AMISNAP_ERR_MALFORMED without consuming
 * anything. A response with neither Content-Length nor
 * Transfer-Encoding: chunked is treated as a zero-length body (correct
 * for WebDAV's own PUT/MKCOL/DELETE/PROPPATCH 2xx responses, which
 * commonly have no body) rather than "read until connection close" --
 * this client always speaks keep-alive, so that HTTP/1.0-era framing
 * mode doesn't apply. Returns AMISNAP_OK (check *done) or a negative
 * AMISNAP_ERR_* on a malformed response / AMISNAP_ERR_NOMEM. */
int amisnap_http_response_feed(amisnap_http_response *r, const void *data, size_t len, int *done);

/* Case-insensitive lookup (HTTP header names are case-insensitive,
 * RFC 7230 3.2) into the already-parsed headers. Returns NULL if not
 * present. Only valid once amisnap_http_response_feed() has reported
 * headers fully parsed (state past AMISNAP_HTTP_PARSE_HEADERS) --
 * calling earlier returns NULL, not partial/wrong data. */
const amisnap_http_parsed_header *amisnap_http_response_header(const amisnap_http_response *r,
                                                                 const char *name);

#endif /* AMISNAP_HTTP_H */
