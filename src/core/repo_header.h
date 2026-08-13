/* repo_header.h -- the repository header (`amisnap.repo` / REC_REPO,
 * docs/format.md "Repository header"). Read/write for the tags that
 * exist today: REPO_ID, CIPHER, CHUNK_SIZE, and (CIPHER != 0) KDF +
 * WRAPPED_KEY, plus the informational FORMAT_APP string. This is pure
 * TLV framing -- no crypto -- built on tlv.h exactly like manifest.c;
 * repo_crypto.h is the module that actually wraps/unwraps the key this
 * header carries.
 */
#ifndef AMISNAP_REPO_HEADER_H
#define AMISNAP_REPO_HEADER_H

#include <stddef.h>
#include <stdint.h>

#include "tlv.h"
#include "repo_crypto.h"

#define AMISNAP_REPO_ID_SIZE 16
#define AMISNAP_KDF_PBKDF2_HMAC_SHA256 1u

typedef struct {
    uint8_t repo_id[AMISNAP_REPO_ID_SIZE];

    uint8_t cipher;                 /* 0 = none, 1 = ChaCha20 + keyed-BLAKE2s-256 */

    int has_chunk_size;
    uint32_t chunk_size;            /* informational only -- format.md "Repository header" */

    /* Present iff cipher != 0. salt/wrapped_key borrow into the buffer
     * amisnap_repo_header_decode() was called with -- see that
     * function's own note on lifetime. */
    uint8_t kdf_id;
    uint32_t kdf_iters;
    const uint8_t *salt;
    size_t salt_len;
    const uint8_t *wrapped_key;     /* exactly AMISNAP_WRAPPED_KEY_SIZE bytes when present */

    int has_format_app;
    const uint8_t *format_app;
    size_t format_app_len;
} amisnap_repo_header;

/* Encodes a full amisnap.repo file (common header + REC_REPO) into
 * `out` (caller amisnap_buf_free()s it). Returns AMISNAP_OK,
 * AMISNAP_ERR_TOO_LONG if salt/format_app exceed 65535 bytes, or
 * AMISNAP_ERR_MALFORMED if `cipher != 0` but salt/wrapped_key are
 * unset (or the reverse: cipher == 0 with either set -- a plaintext
 * repository MUST NOT carry key material). */
int amisnap_repo_header_encode(const amisnap_repo_header *hdr, amisnap_buf *out);

/* Decodes `data`/`len` (the raw contents of amisnap.repo) into `out`.
 * `out`'s salt/wrapped_key/format_app pointers borrow directly into
 * `data` -- same convention as tlv.h's cursor API -- so the caller
 * must keep `data` alive for as long as it uses those fields, and copy
 * out whatever it needs (e.g. before the backend buffer holding `data`
 * is freed). Returns AMISNAP_OK, or AMISNAP_ERR_CRITICAL_TAG if
 * `cipher` names a value this reader doesn't implement (today: only 0
 * and 1) or an unrecognised critical tag is present (format.md "A
 * reader that does not implement the stated CIPHER MUST refuse the
 * repository"), or another AMISNAP_ERR_* on malformed/truncated input. */
int amisnap_repo_header_decode(const uint8_t *data, size_t len, amisnap_repo_header *out);

#endif /* AMISNAP_REPO_HEADER_H */
