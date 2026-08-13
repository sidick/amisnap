/* sigv4.c -- see sigv4.h. */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "sigv4.h"
#include "hmac_sha256.h"
#include "sha256.h"

static const char HEXD[] = "0123456789abcdef";
static const char HEXD_UPPER[] = "0123456789ABCDEF";

static void hex_encode(const uint8_t *data, size_t len, char *out /* 2*len+1 */)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2]     = HEXD[data[i] >> 4];
        out[i * 2 + 1] = HEXD[data[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
}

static int is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '_' || c == '~';
}

int amisnap_sigv4_uri_encode(const char *s, size_t len, int encode_slash, amisnap_buf *out)
{
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        int rc;

        if (is_unreserved(c) || (c == '/' && !encode_slash)) {
            rc = amisnap_buf_bytes(out, &s[i], 1);
        } else {
            uint8_t enc[3];
            enc[0] = '%';
            enc[1] = (uint8_t)HEXD_UPPER[c >> 4];
            enc[2] = (uint8_t)HEXD_UPPER[c & 0x0Fu];
            rc = amisnap_buf_bytes(out, enc, 3);
        }
        if (rc != AMISNAP_OK) return rc;
    }
    return AMISNAP_OK;
}

/* AWS's own documented header-value canonicalization: trim leading/
 * trailing whitespace, collapse any internal run of whitespace to a
 * single space -- confirmed exactly (including inside a quoted value)
 * against the get-header-value-trim test vector: "a   b   c" (inside
 * quotes) becomes "a b c". */
static int canon_header_value(const char *v, amisnap_buf *out)
{
    const char *p = v;
    int in_run = 0;

    while (*p && isspace((unsigned char)*p)) p++; /* skip leading whitespace */

    for (; *p; p++) {
        if (isspace((unsigned char)*p)) {
            in_run = 1;
            continue;
        }
        if (in_run) {
            int rc = amisnap_buf_bytes(out, " ", 1);
            if (rc != AMISNAP_OK) return rc;
            in_run = 0;
        }
        {
            int rc = amisnap_buf_bytes(out, p, 1);
            if (rc != AMISNAP_OK) return rc;
        }
    }
    return AMISNAP_OK;
}

static void lowercase_copy(char *dst, const char *src, size_t cap)
{
    size_t i;
    for (i = 0; src[i] != '\0' && i + 1 < cap; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

typedef struct {
    char name[64];
    amisnap_buf value;
} canon_header;

static int header_cmp(const void *a, const void *b)
{
    return strcmp(((const canon_header *)a)->name, ((const canon_header *)b)->name);
}

int amisnap_sigv4_canonical_request(const char *method, const char *canonical_uri,
                                     const char *canonical_query_string,
                                     const amisnap_sigv4_header *headers, size_t header_count,
                                     const char *payload_hash_hex,
                                     amisnap_buf *out, amisnap_buf *signed_headers_out)
{
    canon_header ch[AMISNAP_SIGV4_MAX_HEADERS];
    size_t i;
    int rc;

    if (header_count > AMISNAP_SIGV4_MAX_HEADERS) return AMISNAP_ERR_TOO_LONG;

    for (i = 0; i < header_count; i++) {
        lowercase_copy(ch[i].name, headers[i].name, sizeof(ch[i].name));
        amisnap_buf_init(&ch[i].value);
        rc = canon_header_value(headers[i].value, &ch[i].value);
        if (rc != AMISNAP_OK) {
            size_t j;
            for (j = 0; j <= i; j++) amisnap_buf_free(&ch[j].value);
            return rc;
        }
    }

    /* Simple insertion sort -- header_count is always tiny (a handful
     * of headers per request), no need for qsort's indirection. */
    for (i = 1; i < header_count; i++) {
        canon_header key = ch[i];
        size_t j = i;
        while (j > 0 && header_cmp(&ch[j - 1], &key) > 0) {
            ch[j] = ch[j - 1];
            j--;
        }
        ch[j] = key;
    }

    amisnap_buf_init(out);
    amisnap_buf_init(signed_headers_out);

    rc = amisnap_buf_bytes(out, method, strlen(method));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, canonical_uri, strlen(canonical_uri));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);
    if (rc == AMISNAP_OK)
        rc = amisnap_buf_bytes(out, canonical_query_string, strlen(canonical_query_string));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);

    for (i = 0; rc == AMISNAP_OK && i < header_count; i++) {
        rc = amisnap_buf_bytes(out, ch[i].name, strlen(ch[i].name));
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, ":", 1);
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, ch[i].value.data, ch[i].value.len);
        if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);

        if (rc == AMISNAP_OK && i > 0)
            rc = amisnap_buf_bytes(signed_headers_out, ";", 1);
        if (rc == AMISNAP_OK)
            rc = amisnap_buf_bytes(signed_headers_out, ch[i].name, strlen(ch[i].name));
    }
    for (i = 0; i < header_count; i++) amisnap_buf_free(&ch[i].value);
    if (rc != AMISNAP_OK) { amisnap_buf_free(out); amisnap_buf_free(signed_headers_out); return rc; }

    rc = amisnap_buf_bytes(out, "\n", 1); /* blank line after headers */
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, signed_headers_out->data, signed_headers_out->len);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, payload_hash_hex, strlen(payload_hash_hex));

    if (rc != AMISNAP_OK) { amisnap_buf_free(out); amisnap_buf_free(signed_headers_out); return rc; }

    /* NUL-terminate signed_headers_out -- callers (amisnap_sigv4_
     * authorization_header(), and any caller building the SignedHeaders=
     * part of an Authorization header directly) use it as a C string,
     * not via its own .len. */
    rc = amisnap_buf_bytes(signed_headers_out, "", 1);
    if (rc != AMISNAP_OK) { amisnap_buf_free(out); amisnap_buf_free(signed_headers_out); return rc; }
    signed_headers_out->len--; /* the NUL is real storage, but not part of the string's own length */

    return AMISNAP_OK;
}

int amisnap_sigv4_string_to_sign(const char *date_time, const char *scope,
                                  const uint8_t *canonical_request, size_t canonical_request_len,
                                  amisnap_buf *out)
{
    uint8_t hash[AMISNAP_SHA256_DIGEST_SIZE];
    char hash_hex[AMISNAP_SHA256_DIGEST_SIZE * 2 + 1];
    int rc;

    amisnap_sha256(canonical_request, canonical_request_len, hash);
    hex_encode(hash, sizeof(hash), hash_hex);

    amisnap_buf_init(out);
    rc = amisnap_buf_bytes(out, AMISNAP_SIGV4_ALGORITHM, strlen(AMISNAP_SIGV4_ALGORITHM));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, date_time, strlen(date_time));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, scope, strlen(scope));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "\n", 1);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, hash_hex, strlen(hash_hex));

    if (rc != AMISNAP_OK) { amisnap_buf_free(out); return rc; }
    return AMISNAP_OK;
}

void amisnap_sigv4_signing_key(const char *secret_key, const char *date,
                                const char *region, const char *service,
                                uint8_t out[32])
{
    char prefixed_key[4 + 256]; /* "AWS4" + secret key, generous */
    size_t prefixed_len;
    uint8_t date_key[32], date_region_key[32], date_region_service_key[32];

    prefixed_len = (size_t)snprintf(prefixed_key, sizeof(prefixed_key), "AWS4%s", secret_key);
    if (prefixed_len >= sizeof(prefixed_key)) prefixed_len = sizeof(prefixed_key) - 1;

    amisnap_hmac_sha256((const uint8_t *)prefixed_key, prefixed_len,
                         (const uint8_t *)date, strlen(date), date_key);
    amisnap_hmac_sha256(date_key, sizeof(date_key), (const uint8_t *)region, strlen(region),
                         date_region_key);
    amisnap_hmac_sha256(date_region_key, sizeof(date_region_key),
                         (const uint8_t *)service, strlen(service), date_region_service_key);
    amisnap_hmac_sha256(date_region_service_key, sizeof(date_region_service_key),
                         (const uint8_t *)"aws4_request", 12, out);

    memset(prefixed_key, 0, sizeof(prefixed_key));
    memset(date_key, 0, sizeof(date_key));
    memset(date_region_key, 0, sizeof(date_region_key));
    memset(date_region_service_key, 0, sizeof(date_region_service_key));
}

void amisnap_sigv4_signature_hex(const uint8_t signing_key[32],
                                  const uint8_t *string_to_sign, size_t string_to_sign_len,
                                  char out[65])
{
    uint8_t sig[AMISNAP_SHA256_DIGEST_SIZE];
    amisnap_hmac_sha256(signing_key, 32, string_to_sign, string_to_sign_len, sig);
    hex_encode(sig, sizeof(sig), out);
}

int amisnap_sigv4_authorization_header(const char *access_key, const char *scope,
                                        const char *signed_headers, const char *signature_hex,
                                        amisnap_buf *out)
{
    int rc;

    amisnap_buf_init(out);
    rc = amisnap_buf_bytes(out, AMISNAP_SIGV4_ALGORITHM, strlen(AMISNAP_SIGV4_ALGORITHM));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, " Credential=", 12);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, access_key, strlen(access_key));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, "/", 1);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, scope, strlen(scope));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, ", SignedHeaders=", 16);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, signed_headers, strlen(signed_headers));
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, ", Signature=", 12);
    if (rc == AMISNAP_OK) rc = amisnap_buf_bytes(out, signature_hex, strlen(signature_hex));

    if (rc != AMISNAP_OK) { amisnap_buf_free(out); return rc; }

    /* NUL-terminate -- this is used as a C string (an HTTP header
     * value passed straight to amisnap_http_build_request()'s own
     * "%s" formatting), not via its own .len. */
    rc = amisnap_buf_bytes(out, "", 1);
    if (rc != AMISNAP_OK) { amisnap_buf_free(out); return rc; }
    out->len--;

    return AMISNAP_OK;
}
