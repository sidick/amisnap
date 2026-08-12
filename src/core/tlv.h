/* tlv.h -- the big-endian TLV primitives docs/format.md's "Conventions"
 * and "TLV encoding" sections define: a growable write buffer, a
 * read cursor over a borrowed byte range, and the scalar/string
 * codecs every record type (meta.c's REC_ENTRY today; manifest.c's
 * REC_SNAP/REC_VOLUME/REC_END later) builds on. Shared here so the
 * framing is implemented exactly once.
 *
 * The read side never copies: amisnap_cursor_field() and
 * amisnap_decode_string() hand back pointers into the caller's own
 * buffer. Callers that need to keep a decoded value past the buffer's
 * lifetime must copy it themselves.
 */
#ifndef AMISNAP_TLV_H
#define AMISNAP_TLV_H

#include <stddef.h>
#include <stdint.h>

/* Shared error codes -- returned (negated as needed) by every codec
 * built on this file, not just the ones defined here. */
#define AMISNAP_OK                   0
#define AMISNAP_ERR_TRUNCATED       -1  /* buffer ends mid-field */
#define AMISNAP_ERR_CRITICAL_TAG    -2  /* unknown tag with 0x8000 set (format.md "TLV encoding") */
#define AMISNAP_ERR_MALFORMED       -3  /* a field's own length/content contract is broken */
#define AMISNAP_ERR_TOO_LONG        -4  /* a string exceeds 65535 bytes (format.md "Limits") */
#define AMISNAP_ERR_MISSING_FIELD   -5  /* a critical field required by the record was absent */
#define AMISNAP_ERR_NOMEM           -6

/* A tag's high bit (0x8000) marks it critical -- format.md "TLV encoding". */
#define AMISNAP_TAG_CRITICAL 0x8000u

/* --- Big-endian scalar packing, used directly by composite fields
 * (E_DATE, E_OWNER, E_CONTENT) whose value is several packed scalars,
 * not one TLV-wrapped field each. --- */
void amisnap_put_be16(uint8_t *p, uint16_t v);
void amisnap_put_be32(uint8_t *p, uint32_t v);
void amisnap_put_be64(uint8_t *p, uint64_t v);
uint16_t amisnap_get_be16(const uint8_t *p);
uint32_t amisnap_get_be32(const uint8_t *p);
uint64_t amisnap_get_be64(const uint8_t *p);

/* --- Growable write buffer --- */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} amisnap_buf;

void amisnap_buf_init(amisnap_buf *b);
void amisnap_buf_free(amisnap_buf *b);

/* Appends raw bytes, growing as needed. Returns 0 on success,
 * AMISNAP_ERR_NOMEM if realloc() failed (the buffer is left in its
 * last valid state, unchanged by the failed append). */
int amisnap_buf_bytes(amisnap_buf *b, const void *p, size_t n);

/* Appends one TLV field: tag (u16) + length (u32) + value (valuelen
 * bytes) -- the raw framing, for values the caller has already
 * assembled (composite fixed-layout fields). */
int amisnap_buf_field(amisnap_buf *b, uint16_t tag, const void *value, size_t valuelen);

/* Convenience wrappers for the common single-scalar field shapes. */
int amisnap_buf_field_u8(amisnap_buf *b, uint16_t tag, uint8_t v);
int amisnap_buf_field_u16(amisnap_buf *b, uint16_t tag, uint16_t v);
int amisnap_buf_field_u32(amisnap_buf *b, uint16_t tag, uint32_t v);
int amisnap_buf_field_u64(amisnap_buf *b, uint16_t tag, uint64_t v);

/* Appends a field whose value is the string primitive (u16 length +
 * bytes -- format.md "Conventions"). Returns AMISNAP_ERR_TOO_LONG
 * without modifying b if len > 65535. */
int amisnap_buf_field_string(amisnap_buf *b, uint16_t tag, const void *p, size_t len);

/* --- Read cursor over a borrowed byte range --- */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} amisnap_cursor;

void amisnap_cursor_init(amisnap_cursor *c, const uint8_t *data, size_t len);

/* Reads the next field. *value and *valuelen borrow into c's own
 * buffer. Returns 1 with a field populated, 0 at a clean end (pos ==
 * len exactly, nothing left to read), or AMISNAP_ERR_TRUNCATED if the
 * buffer ends mid-header or mid-value. */
int amisnap_cursor_field(amisnap_cursor *c, uint16_t *tag, const uint8_t **value, size_t *valuelen);

/* Decodes a string primitive out of a field's value. Returns 0 and
 * borrows *str and *strlen into value on success; AMISNAP_ERR_MALFORMED if
 * value is shorter than its own declared length prefix, or if bytes
 * remain after the string (a string field's value must be exactly the
 * u16 prefix plus that many bytes, nothing more). */
int amisnap_decode_string(const uint8_t *value, size_t valuelen,
                           const uint8_t **str, size_t *strlen);

/* Fixed-width scalar decode: AMISNAP_ERR_MALFORMED if valuelen doesn't
 * exactly match the expected width. */
int amisnap_decode_u8(const uint8_t *value, size_t valuelen, uint8_t *out);
int amisnap_decode_u16(const uint8_t *value, size_t valuelen, uint16_t *out);
int amisnap_decode_u32(const uint8_t *value, size_t valuelen, uint32_t *out);
int amisnap_decode_u64(const uint8_t *value, size_t valuelen, uint64_t *out);

#endif /* AMISNAP_TLV_H */
