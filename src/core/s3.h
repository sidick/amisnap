/* s3.h -- the S3-compatible backend (docs/proposal.md "Tier 3 -- S3-
 * compatible object storage", implementation-plan.md Phase 5): an
 * amisnap_backend_ops implementation over http.h (request/response
 * protocol), transport.h (the abstract byte-stream connection), and
 * sigv4.h (request signing) -- PUT/GET/HEAD/DELETE mapped onto
 * backend.h's put/get/exists/remove, `ListObjectsV2` (a small,
 * hand-rolled XML scan -- no general XML library, same reasoning
 * webdav.c's own href-scraper uses for PROPFIND multistatus bodies)
 * onto `list`, and `mkcol` as a documented no-op (backend.h's own
 * comment: "S3 has no directories at all -- a concept that doesn't
 * exist to create").
 *
 * Deliberately built against transport.h's abstract interface only,
 * mirroring webdav.c exactly (this file's module-map slot: "webdav.c,
 * s3.c protocol clients over a socket abstraction") -- host-testable
 * via a mock transport, with the real network connection supplied by
 * whatever links this in.
 *
 * S3 request signing (SigV4, UNSIGNED-PAYLOAD -- proposal.md's own
 * "keeps this affordable by signing with UNSIGNED-PAYLOAD") needs a
 * fresh, real wall-clock UTC timestamp per request; unlike every other
 * portable core module here, that makes this file NOT purely
 * deterministic -- amisnap_s3_now() (implemented with plain ISO C
 * time()/gmtime(), which libnix provides even under -noixemul) is the
 * one non-deterministic seam, isolated so tests can still drive the
 * rest of this file with a fixed date_time.
 */
#ifndef AMISNAP_S3_H
#define AMISNAP_S3_H

#include <stdint.h>

#include "backend.h"
#include "transport.h"

/* Generous fixed bound on the full request path (bucket + base_path +
 * key, URI-encoded) this implementation builds within -- same
 * convention as webdav.h's AMISNAP_WEBDAV_MAX_PATH. */
#define AMISNAP_S3_MAX_PATH 1024

typedef struct {
    const char *host;      /* hostname or dotted-quad, never NULL */
    uint16_t port;
    const char *bucket;    /* required, no leading/trailing slash */
    /* Key prefix within the bucket: "" (bucket root) or "some/prefix"
     * form (no leading or trailing slash) -- mirrors webdav_config's
     * own base_path, just as an S3 key prefix instead of a URL path. */
    const char *base_path;
    const char *region;     /* e.g. "us-east-1" -- required by SigV4's
                              * credential scope even against a region-
                              * agnostic server like MinIO */
    const char *access_key;
    const char *secret_key;
} amisnap_s3_config;

/* `transport` is borrowed (must outlive `out`), same convention as
 * amisnap_backend_webdav_open()'s own `transport` parameter. Unlike
 * the WebDAV backend, there is no bucket-creation bootstrap at open
 * time -- S3 buckets are provisioned out of band (the AWS/MinIO/B2
 * console or CLI), not implicitly by a backup tool, so a missing
 * bucket surfaces as a real error on first use rather than being
 * silently created. Returns AMISNAP_OK with *out populated, or a
 * negative AMISNAP_ERR_* code. */
int amisnap_backend_s3_open(const amisnap_s3_config *cfg, amisnap_transport *transport,
                             amisnap_backend *out);

/* Generous fixed bounds for amisnap_s3_url's fields -- same "fails
 * cleanly rather than overflows" convention as AMISNAP_S3_MAX_PATH. */
#define AMISNAP_S3_URL_HOST_MAX   256
#define AMISNAP_S3_URL_CRED_MAX   128
#define AMISNAP_S3_URL_BUCKET_MAX 128
#define AMISNAP_S3_URL_REGION_MAX 64

typedef struct {
    char host[AMISNAP_S3_URL_HOST_MAX];
    uint16_t port;
    char bucket[AMISNAP_S3_URL_BUCKET_MAX];
    char base_path[AMISNAP_S3_MAX_PATH]; /* "" or "some/prefix", no leading/trailing slash */
    char region[AMISNAP_S3_URL_REGION_MAX]; /* defaults to "us-east-1" if the URL omits ?region= */
    char access_key[AMISNAP_S3_URL_CRED_MAX];
    char secret_key[AMISNAP_S3_URL_CRED_MAX];
} amisnap_s3_url;

/* Parses "s3://<access_key>:<secret_key>@host[:port]/<bucket>[/prefix]
 * [?region=<region>]" (the CLI's own REPO=/DEST= form for an S3
 * destination, docs/proposal.md Tier 3) into `out`. Path-style
 * addressing only (bucket as the first path component, not a virtual-
 * hosted subdomain) -- the form every S3-compatible server (MinIO, B2,
 * Wasabi, R2) supports, unlike virtual-hosted-style's DNS wildcard
 * requirement. TLS is not yet supported here (`s3://` is always
 * plaintext) -- the same known, documented AmiSSL blocking-handshake
 * issue that disabled `https://` for WebDAV (implementation-plan.md
 * Phase 3 item 4) applies equally here; there is no separate `s3s://`
 * scheme to fail into until that's fixed. Purely syntactic -- does not
 * open a connection. Returns AMISNAP_OK, or AMISNAP_ERR_MALFORMED for
 * anything that isn't a recognizable `s3://` URL with both credentials
 * and a bucket. */
int amisnap_s3_parse_url(const char *url, amisnap_s3_url *out);

/* Current UTC time as "YYYYMMDD'T'HHMMSS'Z'" (SigV4's own x-amz-date
 * format, 16 characters + NUL) via plain ISO C time()/gmtime() -- see
 * this header's own top comment on why this is the one place in this
 * file that isn't purely a function of its inputs. Writes 17 bytes
 * (16 chars + NUL) to `out`. */
void amisnap_s3_now(char out[17]);

#endif /* AMISNAP_S3_H */
