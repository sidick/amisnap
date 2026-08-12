/* meta.h -- the per-path metadata record: docs/format.md's REC_ENTRY
 * (tag 0x8004), the format's core unit and the whole reason it exists
 * (docs/implementation-plan.md principle 3, "metadata is the product").
 * One amisnap_entry_meta models one manifest entry; encode/decode are
 * exact inverses of each other, and of the wire layout format.md
 * specifies -- this header's field list IS that spec's REC_ENTRY table.
 *
 * Decoded string/byte fields (path, comment, link, content refs) are
 * borrowed pointers into the caller's own decode buffer, never copied
 * -- see tlv.h's cursor contract. A caller that needs an entry to
 * outlive its source buffer must copy the fields itself.
 */
#ifndef AMISNAP_META_H
#define AMISNAP_META_H

#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

#define AMISNAP_ETYPE_FILE     1
#define AMISNAP_ETYPE_DIR      2
#define AMISNAP_ETYPE_SOFTLINK 3
#define AMISNAP_ETYPE_HARDLINK 4

#define AMISNAP_REC_ENTRY_TAG  0x8004u

/* One content reference (format.md E_CONTENT): a whole file, or one
 * fixed-size chunk of one, addressed by its plaintext BLAKE2s-256. */
typedef struct {
    uint8_t hash[32];
    uint64_t size;
} amisnap_content_ref;

typedef struct {
    const uint8_t *path;
    size_t path_len;

    uint8_t type; /* AMISNAP_ETYPE_* */

    uint32_t prot;                 /* full 32-bit mask, verbatim */
    uint32_t date_days, date_mins, date_ticks;

    int has_comment;
    const uint8_t *comment;
    size_t comment_len;

    int has_owner;
    uint16_t uid, gid;

    int has_size;
    uint64_t size;

    /* Borrowed pointer to a caller-owned array; not copied or freed by
     * this module. NULL/0 for directories and links. */
    const amisnap_content_ref *content;
    size_t content_count;

    int has_link;
    const uint8_t *link;
    size_t link_len;

    int has_xhash;
    uint32_t xhash;
} amisnap_entry_meta;

/* Appends one REC_ENTRY field (tag + length + the fields below) to
 * `out`. Returns AMISNAP_OK, AMISNAP_ERR_TOO_LONG if path/comment/link
 * exceeds 65535 bytes (format.md "Limits" -- the caller must fail that
 * entry loudly, per policy, not retry or truncate), or
 * AMISNAP_ERR_NOMEM. Does not validate cross-field consistency (e.g.
 * E_SIZE matching the sum of content ref sizes) -- that is the
 * manifest writer's job, once real content exists to check against. */
int amisnap_meta_encode_entry(amisnap_buf *out, const amisnap_entry_meta *e);

/* Decodes one REC_ENTRY's already-unwrapped value bytes (as returned
 * by amisnap_cursor_field for tag AMISNAP_REC_ENTRY_TAG) into *out.
 * `content_storage`/`content_cap` is caller-provided scratch for the
 * repeated E_CONTENT fields (out->content is set to point into it);
 * decode fails with AMISNAP_ERR_MALFORMED if more refs are present
 * than content_cap allows, rather than silently dropping any.
 *
 * Returns AMISNAP_OK, AMISNAP_ERR_TRUNCATED/AMISNAP_ERR_MALFORMED on a
 * corrupt record, AMISNAP_ERR_CRITICAL_TAG on an unrecognised critical
 * field (format.md "TLV encoding" -- refuse rather than guess), or
 * AMISNAP_ERR_MISSING_FIELD if a field required for out->type is
 * absent (E_PATH/E_TYPE/E_PROT/E_DATE always; E_SIZE+E_CONTENT for a
 * non-empty file; E_LINK for a soft/hard link). */
int amisnap_meta_decode_entry(const uint8_t *value, size_t valuelen,
                               amisnap_entry_meta *out,
                               amisnap_content_ref *content_storage, size_t content_cap);

#endif /* AMISNAP_META_H */
