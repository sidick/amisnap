/* sigv4.h -- AWS Signature Version 4 request signing (docs/proposal.md
 * "Tier 3 -- S3-compatible object storage"), the auth scheme every S3
 * request needs. Portable, host-testable, no HTTP/socket knowledge of
 * its own -- src/core/s3.c (Phase 5 item 2) builds requests on top of
 * this exactly the way webdav.c builds requests on top of http.c.
 *
 * Built entirely on the already-vendored HMAC-SHA256/SHA-256
 * (hmac_sha256.h/sha256.h) -- SigV4's signing chain is HMAC-SHA256
 * throughout, no new primitive needed. Vectors in tests/test_sigv4.c
 * are AWS's own published `aws-sig-v4-test-suite` (fetched live from
 * its GitHub mirror, not transcribed from memory) -- canonical
 * request, string-to-sign, AND final signature for each case, so this
 * checks the whole chain end to end, not just intermediate steps.
 */
#ifndef AMISNAP_SIGV4_H
#define AMISNAP_SIGV4_H

#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

#define AMISNAP_SIGV4_ALGORITHM "AWS4-HMAC-SHA256"

/* One request header, name/value as plain C strings -- same shape as
 * http.h's amisnap_http_header. Case/whitespace need not be
 * pre-normalized (amisnap_sigv4_canonical_request lowercases names and
 * canonicalizes values itself), and headers need not be pre-sorted. */
typedef struct {
    const char *name;
    const char *value;
} amisnap_sigv4_header;

/* At most this many headers get signed in one request -- generous for
 * what any AmiSnap S3 request actually sends (host, x-amz-date,
 * x-amz-content-sha256, occasionally content-type); a real, documented
 * limit rather than an unbounded allocation. */
#define AMISNAP_SIGV4_MAX_HEADERS 16

/* Builds the 6-line (LF-joined, no trailing newline) canonical request
 * text into `out`: method, canonical_uri, canonical_query_string,
 * canonical_headers (one "name:value\n" per header, name lowercased,
 * value trimmed with internal whitespace runs collapsed to a single
 * space -- AWS's own documented CanonicalHeaders rule, confirmed
 * against the get-header-value-trim test vector), a blank line,
 * signed_headers (lowercased names, sorted, ';'-joined), and
 * payload_hash_hex verbatim.
 *
 * `canonical_uri`/`canonical_query_string` are used exactly as given
 * -- building and percent-encoding a path or query string is the
 * caller's job (amisnap_sigv4_uri_encode() below is the primitive for
 * that), since a caller building an S3 path already knows which parts
 * are literal separators ('/') and which are values to encode.
 * `payload_hash_hex` is likewise used verbatim, letting the caller
 * pass either a real lowercase-hex SHA-256 or S3's own
 * "UNSIGNED-PAYLOAD" literal -- this function has no opinion on which.
 *
 * `signed_headers_out` receives just the signed-headers line (borrowed
 * from a small internal buffer copied into it, caller
 * amisnap_buf_free()s it) since amisnap_sigv4_authorization_header()
 * below needs that same string again to build the Authorization value
 * without re-deriving it. Returns AMISNAP_OK, AMISNAP_ERR_TOO_LONG if
 * header_count exceeds AMISNAP_SIGV4_MAX_HEADERS, or
 * AMISNAP_ERR_NOMEM. */
int amisnap_sigv4_canonical_request(const char *method, const char *canonical_uri,
                                     const char *canonical_query_string,
                                     const amisnap_sigv4_header *headers, size_t header_count,
                                     const char *payload_hash_hex,
                                     amisnap_buf *out, amisnap_buf *signed_headers_out);

/* The 4-line string to sign: AMISNAP_SIGV4_ALGORITHM, `date_time`
 * (the x-amz-date value, YYYYMMDD'T'HHMMSS'Z'), `scope`
 * ("YYYYMMDD/region/service/aws4_request"), and the lowercase-hex
 * SHA-256 of `canonical_request`/`canonical_request_len` (hashed
 * internally -- the caller passes the canonical request text from
 * amisnap_sigv4_canonical_request() above, not a pre-hashed value).
 * Returns AMISNAP_OK or AMISNAP_ERR_NOMEM. */
int amisnap_sigv4_string_to_sign(const char *date_time, const char *scope,
                                  const uint8_t *canonical_request, size_t canonical_request_len,
                                  amisnap_buf *out);

/* Derives the signing key (AWS's own documented 4-step HMAC-SHA256
 * chain): DateKey = HMAC("AWS4"+secret_key, date) -> DateRegionKey =
 * HMAC(DateKey, region) -> DateRegionServiceKey = HMAC(DateRegionKey,
 * service) -> SigningKey = HMAC(DateRegionServiceKey, "aws4_request").
 * `date` is YYYYMMDD (not the full date_time -- just the day, per
 * AWS's own credential-scope granularity). `out` must hold 32 bytes. */
void amisnap_sigv4_signing_key(const char *secret_key, const char *date,
                                const char *region, const char *service,
                                uint8_t out[32]);

/* The final signature: HMAC-SHA256(signing_key, string_to_sign),
 * lowercase hex. `out` must hold 65 bytes (64 hex chars + NUL). */
void amisnap_sigv4_signature_hex(const uint8_t signing_key[32],
                                  const uint8_t *string_to_sign, size_t string_to_sign_len,
                                  char out[65]);

/* Builds the full `Authorization` header value:
 * "AWS4-HMAC-SHA256 Credential=<access_key>/<scope>, "
 * "SignedHeaders=<signed_headers>, Signature=<signature_hex>".
 * `signed_headers` is the string amisnap_sigv4_canonical_request()
 * returned via its own signed_headers_out. Returns AMISNAP_OK or
 * AMISNAP_ERR_NOMEM. */
int amisnap_sigv4_authorization_header(const char *access_key, const char *scope,
                                        const char *signed_headers, const char *signature_hex,
                                        amisnap_buf *out);

/* URI-encodes `s`/`len` per AWS's own documented UriEncode(): every
 * byte except the unreserved set (A-Z a-z 0-9 - . _ ~) becomes
 * "%XX" with uppercase hex digits; space becomes "%20", never "+".
 * `encode_slash` controls '/': left unencoded (0) for a canonical URI
 * path's own literal separators, always encoded (nonzero) for query
 * string keys/values, per AWS's own "encode the forward slash
 * character everywhere except in the object key name" rule -- the
 * caller decides which case applies to what it's encoding; this
 * function has no path/query awareness of its own. Returns AMISNAP_OK
 * or AMISNAP_ERR_NOMEM. */
int amisnap_sigv4_uri_encode(const char *s, size_t len, int encode_slash, amisnap_buf *out);

#endif /* AMISNAP_SIGV4_H */
