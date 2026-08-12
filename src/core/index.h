/* index.h -- the local per-repository index: a fast in-memory lookup
 * over the latest snapshot's manifest, and the change-detection policy
 * decided in implementation-plan.md's "Decisions since the proposal"
 * section ("The archive bit is corroboration, never sole evidence").
 *
 * This is explicitly NOT part of the wire format -- format.md's "Local
 * index cache" section: "a cache derived from the latest manifest,
 * self-healing... its format may change freely; the manifest format
 * may not." Nothing here is read or written by any other repository
 * implementation; it exists purely to make an incremental scan fast.
 */
#ifndef AMISNAP_INDEX_H
#define AMISNAP_INDEX_H

#include <stddef.h>
#include <stdint.h>

#include "meta.h"

/* fib_Protection bit 4 (dos/dos.h FIBF_ARCHIVE) -- the archive bit
 * this module's change-detection policy reads out of E_PROT's already-
 * verbatim mask. Defined here rather than pulled from a real Amiga
 * header because this file is portable core (host-buildable); when
 * src/amiga/scan.c lands (implementation-plan.md Phase 1 item 6) it
 * must #include <dos/dos.h> and statically assert this matches the
 * real FIBF_ARCHIVE, not silently drift from it. */
#define AMISNAP_FIBF_ARCHIVE 0x10u

typedef struct {
    amisnap_buf raw;             /* owned copy of the manifest bytes entries' path/comment/link borrow into */
    amisnap_entry_meta *entries; /* owned array; each entry's .content is also an owned copy (manifest.h's decode scratch is reused across entries and cannot be borrowed past one callback) */
    size_t count, cap;
} amisnap_index;

/* Decodes `manifest_data`/`manifest_len` (format.md manifest bytes,
 * e.g. read via amisnap_backend_get on "snapshots/<snapid>.mf") into
 * an index. The input buffer is copied, not borrowed -- the caller may
 * free it immediately after this returns. Returns AMISNAP_OK or
 * whatever amisnap_manifest_decode() returned (a corrupt/truncated/
 * hash-mismatched manifest fails index_build the same way it fails
 * decode -- an index is never built from a manifest that didn't fully
 * validate) or AMISNAP_ERR_NOMEM. */
int amisnap_index_build(const uint8_t *manifest_data, size_t manifest_len, amisnap_index *out);

void amisnap_index_free(amisnap_index *idx);

/* O(n) linear scan over idx->count entries. Fine for the ~50k-file
 * target at Phase 1's correctness-first stage; implementation-plan.md
 * flags this as a candidate for a sorted/hashed lookup if a real
 * incremental-run benchmark (Phase 1's own gate) shows it's the
 * bottleneck -- not assumed in advance. Returns NULL if no entry with
 * this exact path exists. */
const amisnap_entry_meta *amisnap_index_lookup(const amisnap_index *idx,
                                                 const uint8_t *path, size_t path_len);

/* The change-detection policy: is `current` (freshly scanned) the
 * same as `last` (the index's record for that same path -- callers
 * look it up via amisnap_index_lookup(); this function does not
 * itself compare paths)?
 *
 * Returns 1 ("skip -- unchanged") only when:
 *   - `last` is non-NULL (a NULL `last`, e.g. no lookup hit, always
 *     means "examine": first run or a genuinely new path), AND
 *   - type, protection (excluding the archive bit), datestamp,
 *     comment (present-vs-absent and content), and owner all match
 *     exactly, AND for files, size also matches; for links, the link
 *     target also matches, AND
 *   - `current`'s archive bit (AMISNAP_FIBF_ARCHIVE within E_PROT) is
 *     currently SET.
 *
 * The archive bit is deliberately NOT compared against what `last`
 * had -- it is required to be set on `current` as an independent
 * corroborating signal, per the policy decided in implementation-
 * plan.md: a set bit with no other change means "provably unchanged
 * since some archiver's run"; a clear bit means "examine", regardless
 * of what any other metadata says, since the filesystem clears it on
 * every write (dos/dos.h FIBF_ARCHIVE semantics) and AmiSnap does not
 * set it by default. Every other field mismatch also forces
 * "examine" -- content hashes are never compared here, by design:
 * this is the metadata-first fast path, not a fallback content check
 * (that is paranoid verify mode, phase 2). */
int amisnap_index_unchanged(const amisnap_entry_meta *last, const amisnap_entry_meta *current);

#endif /* AMISNAP_INDEX_H */
