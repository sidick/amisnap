/* manifest.h -- docs/format.md's manifest file (`snapshots/<snapid>.mf`):
 * REC_SNAP, REC_VOLUME, the REC_ENTRY sequence meta.c already encodes/
 * decodes, and REC_END with its truncation tripwire and self-hash.
 *
 * The writer is a simple streaming builder (snap, then volume+entries
 * per volume, then finish) matching the manifest's own required record
 * order (format.md "Manifest": REC_SNAP first, REC_END last). The
 * reader is a visitor: manifests can hold an unbounded number of
 * volumes and entries, so decode calls back into caller-supplied
 * functions rather than returning an array.
 */
#ifndef AMISNAP_MANIFEST_H
#define AMISNAP_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "meta.h"
#include "tlv.h"

typedef struct {
    uint32_t created_days, created_mins, created_ticks;

    int has_hostname;
    const uint8_t *hostname;
    size_t hostname_len;

    int has_toolver;
    const uint8_t *toolver;
    size_t toolver_len;

    int has_comment;
    const uint8_t *comment;
    size_t comment_len;
} amisnap_snap_meta;

/* VOL_CAPS flags (format.md REC_VOLUME table). */
#define AMISNAP_VOLCAP_OWNER    0x0001u
#define AMISNAP_VOLCAP_COMMENT  0x0002u

typedef struct {
    const uint8_t *vol_root;
    size_t vol_root_len;

    int has_name;
    const uint8_t *name;
    size_t name_len;

    int has_dostype;
    uint32_t dostype;

    int has_created;
    uint32_t created_days, created_mins, created_ticks;

    int has_caps;
    uint16_t maxnamelen;
    uint16_t caps_flags;
} amisnap_volume_meta;

/* --- Writer --- */

typedef struct {
    amisnap_buf body;   /* accumulates records after the common header */
    size_t entry_count;
    int have_snap;
    int error;          /* sticky: once non-zero, further calls are no-ops
                          * that return it unchanged; amisnap_manifest_
                          * writer_finish() reports it too. */
} amisnap_manifest_writer;

void amisnap_manifest_writer_init(amisnap_manifest_writer *w);
void amisnap_manifest_writer_free(amisnap_manifest_writer *w);

/* Call exactly once, before any volume/entry (format.md "Manifest":
 * REC_SNAP is always the first record) -- calling volume/entry first
 * is rejected with AMISNAP_ERR_MISSING_FIELD, and calling snap twice
 * with AMISNAP_ERR_MALFORMED, so a writer used correctly cannot
 * produce a manifest decode would reject for record ordering. */
int amisnap_manifest_writer_snap(amisnap_manifest_writer *w, const amisnap_snap_meta *snap);

int amisnap_manifest_writer_volume(amisnap_manifest_writer *w, const amisnap_volume_meta *vol);

/* Wraps meta.h's REC_ENTRY codec; same error contract as
 * amisnap_meta_encode_entry (AMISNAP_ERR_TOO_LONG on an oversized
 * path/comment/link -- the caller must fail that entry, per format.md
 * "Limits", not retry into the same writer). */
int amisnap_manifest_writer_entry(amisnap_manifest_writer *w, const amisnap_entry_meta *entry);

/* Writes the common header, the accumulated body, and REC_END (entry
 * count + a BLAKE2s-256 self-hash over everything before it) into a
 * fresh buffer at *out (caller owns it: amisnap_buf_free() when done).
 * Returns AMISNAP_ERR_MISSING_FIELD if amisnap_manifest_writer_snap()
 * was never called, or propagates any earlier latched failure. */
int amisnap_manifest_writer_finish(amisnap_manifest_writer *w, amisnap_buf *out);

/* --- Reader (visitor) --- */

/* Scratch capacity for one entry's E_CONTENT refs during decode --
 * reused across entries within a single amisnap_manifest_decode() call
 * (each on_entry callback must copy anything it wants to keep past its
 * own invocation, same borrowing contract as meta.h). 4096 refs at the
 * default 8MB chunk size is 32GB, comfortably past anything OS 3.x can
 * produce; decode fails loudly (AMISNAP_ERR_MALFORMED, from meta.c) on
 * an entry needing more, rather than silently truncating it. */
#define AMISNAP_MANIFEST_MAX_CONTENT_REFS 4096

/* Each callback returns 0 to keep decoding, or a nonzero value
 * (conventionally a negative AMISNAP_ERR_* code, though decode never
 * interprets it -- just propagates it) to abort immediately: decode
 * stops calling back and amisnap_manifest_decode() returns exactly
 * that value. Needed for consumers like restore.c, where continuing
 * to process entries after a fatal error (a corrupt object, an I/O
 * failure) would just be pointless extra work on data already known
 * bad -- a callback that never needs to abort (e.g. verify, which
 * deliberately wants a full report even after finding corruption)
 * simply always returns 0. */
typedef struct {
    void *user;
    int (*on_snap)(void *user, const amisnap_snap_meta *snap);
    int (*on_volume)(void *user, const amisnap_volume_meta *vol);
    int (*on_entry)(void *user, const amisnap_entry_meta *entry);
} amisnap_manifest_visitor;

/* Parses and validates a complete manifest buffer: common header
 * (magic/ftype/version), REC_SNAP first, then any mix of REC_VOLUME/
 * REC_ENTRY, then REC_END last with END_COUNT matching the number of
 * REC_ENTRY records actually seen and END_HASH matching a fresh
 * BLAKE2s-256 over every byte before it.
 *
 * All borrowed pointers handed to the visitor point into `data` and
 * are valid only during that callback (E_CONTENT refs point into a
 * reused scratch array -- see AMISNAP_MANIFEST_MAX_CONTENT_REFS).
 *
 * Returns AMISNAP_OK, a callback's own nonzero abort value (see
 * amisnap_manifest_visitor above), or: AMISNAP_ERR_TRUNCATED/MALFORMED
 * on a corrupt header or record framing; AMISNAP_ERR_CRITICAL_TAG on an
 * unrecognised critical record or field tag; AMISNAP_ERR_MISSING_FIELD
 * if REC_SNAP is absent/not first, or REC_END is absent (a manifest
 * without a valid REC_END is not a snapshot -- format.md); AMISNAP_
 * ERR_HASH_MISMATCH if END_HASH doesn't match. A manifest failing any
 * of these MUST be treated as absent/corrupt, never partially trusted. */
int amisnap_manifest_decode(const uint8_t *data, size_t len, const amisnap_manifest_visitor *visitor);

#endif /* AMISNAP_MANIFEST_H */
