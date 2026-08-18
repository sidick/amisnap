/* scan.h -- ExAll()-based directory-tree walk producing meta.h's
 * amisnap_entry_meta records, plus the per-volume capability probe
 * feeding docs/format.md's REC_VOLUME/VOL_CAPS.
 *
 * Amiga-only (dos.library); cannot be host-built or host-tested the
 * way src/core/ is. Verified so far: cross-build against the real NDK
 * (ghcr.io/sidick/amiga-dev) confirms every struct field, constant,
 * and version floor cited in scan.c's own comments -- house rule 6,
 * checked against dos.doc/dos.h/dosextens.h/exall.h before writing
 * any code, not assumed from memory. Real execution against a live
 * filesystem is still unverified pending item 7's on-target harness.
 *
 * Two honest, explicit, tracked gaps, not silently dropped:
 *
 * - Soft/hard links (ST_SOFTLINK/ST_LINKDIR/ST_LINKFILE) are detected
 *   but not captured as entries -- format.md requires E_LINK (the
 *   real link target) for those types, and reading it needs
 *   ReadLink()'s msgport-level packet contract (softlinks) or
 *   filesystem-specific hard-link source resolution (hardlinks),
 *   neither implemented yet. Counted in result->links_skipped,
 *   symmetric with restore.c's own links_skipped.
 * - Owner capture (ED_OWNER) is V39; on V37 (our floor) it is
 *   unavailable. This degrades via exall.h's own documented contract
 *   (request ED_OWNER, retry with ED_COMMENT on ERROR_BAD_NUMBER) --
 *   not a version check, since ExAll() itself exists at V37 and is
 *   simply rejecting an unsupported parameter value, a different
 *   (and simpler) case than implementation-plan.md's "OS floor is
 *   V37" policy for functions that don't exist in the jump table at
 *   all (e.g. restore-side SetOwner()).
 */
#ifndef AMISNAP_SCAN_H
#define AMISNAP_SCAN_H

#include <stddef.h>
#include <stdint.h>

#include "exclude.h"
#include "meta.h"

/* Generous fixed bound on a scanned path's length, matching
 * restore.c's own RESTORE_PATH_BUF_LEN convention. format.md's Limits
 * section caps a path at 65535 bytes; a real Amiga path this module
 * can't fit is reported via AMISNAP_ERR_TOO_LONG (that entry fails
 * loudly, per format.md's own policy), never silently truncated. */
#define AMISNAP_SCAN_PATH_BUF_LEN 2048

typedef struct {
    uint32_t dostype;      /* Info()'s id_DiskType, e.g. "DOS\7" */
    uint16_t maxnamelen;   /* the longest name actually seen during this
                             * scan -- a LOWER BOUND on the filesystem's
                             * real capacity, not its theoretical ceiling
                             * (deliberately not probed by writing a test
                             * file: a backup tool must never mutate the
                             * source it's reading). Stays 0 on an empty
                             * volume. */
    int owner_supported;   /* ED_OWNER succeeded (V39+ dos.library and
                             * filesystem) -- format.md VOL_CAPS bit 0 */
} amisnap_scan_caps;

typedef struct {
    size_t dirs_seen;
    size_t files_seen;
    size_t links_skipped;  /* see this header's own note above */
    size_t dirs_excluded;  /* matched an exclude.h pattern -- not walked, not emitted */
    size_t files_excluded; /* matched an exclude.h pattern -- not emitted */
} amisnap_scan_result;

/* Each callback returns 0 to continue or a nonzero value (propagated
 * verbatim as amisnap_scan_volume()'s own return) to abort -- same
 * contract as manifest.h's visitor. `entry`'s path/comment/link
 * pointers are valid only during the call. scan.c deliberately does
 * NOT read file content here (only metadata) -- reading bytes to hash
 * is the caller's job, keeping this module's memory footprint
 * independent of file size. */
typedef struct {
    void *user;
    int (*on_entry)(void *user, const amisnap_entry_meta *entry);
} amisnap_scan_visitor;

/* Scans the tree rooted at `root_path` (a real AmigaDOS path, e.g.
 * "Work:" or "Work:Projects"), calling visitor->on_entry once for the
 * root itself (E_PATH = "", format.md's own convention) and then
 * depth-first, directories-before-their-contents, for everything
 * under it -- matching the order a manifest needs (implementation-
 * plan.md: this is why restore relies on manifest order rather than
 * re-deriving it, and scan.c produces entries in that same order from
 * the source side too).
 *
 * `exclude` may be NULL (scan everything, the original behavior). A
 * matching entry is filtered before visitor->on_entry is ever called
 * for it; a matching directory is never recursed into either -- an
 * excluded subtree costs nothing beyond the one ExAll() batch call
 * that revealed the directory's own name, never a walk of its
 * contents. The root itself (E_PATH = "") is never excludable.
 *
 * Returns AMISNAP_OK, a visitor abort value, or AMISNAP_ERR_IO if
 * `root_path` cannot be locked or a directory operation fails
 * abnormally partway through, or AMISNAP_ERR_NOMEM/AMISNAP_ERR_TOO_LONG. */
int amisnap_scan_volume(const char *root_path, const amisnap_scan_visitor *visitor,
                         const amisnap_exclude_list *exclude,
                         amisnap_scan_caps *caps, amisnap_scan_result *result);

#endif /* AMISNAP_SCAN_H */
