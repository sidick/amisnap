/* restore_meta.h -- Amiga-side metadata application: SetProtection/
 * SetComment/SetFileDate/SetOwner, applied to a path restore.c (the
 * portable content layer) has already created. Every function/version
 * floor verified against the real NDK before writing any code (house
 * rule 6):
 *
 *   SetComment    dos.doc, no version label -- pre-2.0, always safe
 *   SetFileDate   dos.doc "(V36)" -- at our V37 floor. Documented,
 *                 expected failure: "for OFS/FFS, the date of the
 *                 root directory cannot be set" -- not a bug when it
 *                 happens on the restore root.
 *   SetOwner      dos.doc "(V39)", but its own FUNCTION text adds a
 *                 real nuance: "This entrypoint did not exist in V36
 *                 ... V37 dos.library will return FALSE to this
 *                 call." The call slot exists from V37 -- calling it
 *                 unconditionally is safe (not a jump into an absent
 *                 jump-table entry the way implementation-plan.md's
 *                 general V39+ policy warns about); it just always
 *                 fails pre-V39, which the ordinary success/failure
 *                 result handling already covers correctly with no
 *                 separate version check needed. A genuinely useful
 *                 exception to record alongside ED_OWNER's different
 *                 (return-code-negotiated) case in scan.c.
 *   SetProtection dos.doc, no version label -- pre-2.0, always safe
 *
 * This module is inherently coupled to a real AmigaDOS destination
 * path, not to amisnap_backend's abstraction -- SetProtection() etc.
 * have no meaning against a WebDAV/S3 key. restore.c stays backend-
 * agnostic on purpose (implementation-plan.md principle 4); this
 * module's adapter takes the destination's real root path explicitly,
 * known by whoever opened that backend_dir in the first place, rather
 * than restore.c growing a "real filesystem path" concept it doesn't
 * otherwise need.
 */
#ifndef AMISNAP_RESTORE_META_H
#define AMISNAP_RESTORE_META_H

#include <stddef.h>

#include "meta.h"

typedef struct {
    size_t prot_ok, prot_failed;
    size_t comment_ok, comment_failed;   /* only counted when entry->has_comment */
    size_t date_ok, date_failed;
    size_t owner_ok, owner_failed;       /* only counted when entry->has_owner */
} amisnap_restore_meta_result;

/* Applies protection/comment/date/owner from `entry` onto the real,
 * already-existing AmigaDOS path `path` (a NUL-terminated string --
 * this must run AFTER restore.c has created the file or directory,
 * matching format.md's "apply metadata as far as the target system
 * allows" applied last).
 *
 * Each field is independently best-effort: incremented into *result
 * (caller zero-initializes once and may reuse across many calls to
 * accumulate a running total, matching restore.h's own
 * amisnap_restore_result style) rather than treated as fatal --
 * implementation-plan.md: restore degrades explicitly, never
 * silently, and losing a comment or a protection bit is not the kind
 * of data loss principle 1 is about.
 *
 * Protection is applied LAST among the four calls, since a
 * restrictive mask could otherwise block a later SetComment/
 * SetFileDate/SetOwner on the very same object -- the same reasoning
 * docs/proposal.md gives for applying metadata after content
 * ("protection bits like `d` don't block the restore itself"),
 * applied within this module's own four calls too, not just against
 * the earlier content write. */
void amisnap_restore_meta_apply(const char *path, const amisnap_entry_meta *entry,
                                 amisnap_restore_meta_result *result);

/* Adapter for restore.h's amisnap_restore_options: set
 * opts.on_entry_restored = amisnap_restore_meta_on_entry and
 * opts.user = &ctx, where ctx.dest_root is the exact root string
 * passed to amisnap_backend_dir_open() for the restore destination.
 * Reconstructs the real path as dest_root + "/" + entry->path (empty
 * entry->path -- format.md's "root itself" -- resolves to dest_root
 * unchanged) and calls amisnap_restore_meta_apply(), accumulating
 * into ctx.totals. Soft/hard link entries never reach here at all
 * (restore.c's own on_entry_restored contract only fires for entries
 * it actually created content/a container for -- see restore.h). */
typedef struct {
    const char *dest_root;
    amisnap_restore_meta_result totals;
} amisnap_restore_meta_ctx;

void amisnap_restore_meta_on_entry(void *user, const amisnap_entry_meta *entry);

#endif /* AMISNAP_RESTORE_META_H */
