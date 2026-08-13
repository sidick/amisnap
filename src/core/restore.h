/* restore.h -- the portable content-restore layer: reconstructs file
 * content and directory structure from a decoded manifest into a
 * destination backend, per docs/format.md's own disaster-recovery
 * reading procedure ("for each entry concatenate its E_CONTENT objects
 * (verifying each against its name) and apply metadata as far as the
 * target system allows").
 *
 * This module handles the "concatenate and verify content" half only.
 * Metadata application (SetProtection/SetComment/SetFileDate/SetOwner)
 * is inherently Amiga-only and does NOT happen here -- it lands in
 * src/amiga/restore_meta.c (implementation-plan.md Phase 1 item 6),
 * which consumes the same amisnap_entry_meta this module already hands
 * to its optional per-entry callback for exactly that purpose. This
 * split is "portable core, thin Amiga rind" (implementation-plan.md
 * principle 4) applied to restore specifically.
 *
 * Destination is any amisnap_backend, in practice backend_dir pointed
 * at wherever the user chose (docs/proposal.md "restore... to original
 * or alternate path" -- that choice is entirely which root the caller
 * opens as `dest`; this module has no opinion on it).
 *
 * Full-tree relative paths are always preserved under `dest`, even for
 * a subtree restore -- restoring "Work/Projects" into "T:Recovered"
 * produces "T:Recovered/Work/Projects/...", not a flattened
 * "T:Recovered/...". This matches how restic/borg-style tools behave
 * and avoids a family of edge cases a path-stripping design would
 * otherwise need to handle (a single-file subtree, the subtree root's
 * own metadata) -- a deliberate design choice, not an oversight.
 *
 * Soft/hard link restoration is an explicit, honest gap right now:
 * backend.h has no link concept, and creating a real Amiga link needs
 * MakeLink(), which is inherently Amiga-only -- link entries are
 * counted in `links_skipped`, never silently dropped or attempted as
 * plain files. Follow-up work (naturally alongside restore_meta.c)
 * needs to add a distinct mechanism for these, not shoehorn them
 * through amisnap_backend_put().
 */
#ifndef AMISNAP_RESTORE_H
#define AMISNAP_RESTORE_H

#include <stddef.h>
#include <stdint.h>

#include "backend.h"
#include "meta.h"
#include "repo_crypto.h"

typedef struct {
    /* NULL/0 = full restore (every entry). Otherwise selects the
     * entry at this exact path plus everything under it (a real path-
     * component boundary, not a naive string prefix -- "Work" does
     * not match "Workbench/foo"). */
    const uint8_t *subtree_prefix;
    size_t subtree_prefix_len;

    /* Optional: called for each non-link entry once, after every
     * entry's content/container has been created at `dest` (a distinct
     * second pass over the manifest, run only if this is non-NULL --
     * see restore.c's own on_entry_meta comment for why metadata can't
     * be applied to a directory right after its own mkcol()). Still
     * holds the entry's full metadata -- the hook point for applying
     * protection/comment/datestamp/owner on Amiga. NULL is fine for a
     * portable-core-only restore (e.g. these host tests). */
    void (*on_entry_restored)(void *user, const amisnap_entry_meta *entry);
    void *user;
} amisnap_restore_options;

typedef struct {
    size_t dirs_created;
    size_t files_written;
    size_t bytes_written;
    size_t entries_skipped;   /* outside the subtree filter */
    size_t links_skipped;     /* soft/hard links -- see this header's own note above */
} amisnap_restore_result;

/* Restores `manifest_data`/`manifest_len` (already-fetched manifest
 * bytes, e.g. via amisnap_backend_get on a repository backend) from
 * `repo` (where content objects are read) into `dest`. Every object
 * read is verified against its declared BLAKE2s-256 hash before being
 * written out (format.md's own "verifying each against its name") --
 * AMISNAP_ERR_HASH_MISMATCH or AMISNAP_ERR_NOT_FOUND on a corrupt or
 * missing object aborts the whole restore immediately (implementation-
 * plan.md principle 1: a data-losing bug is fatal, and silently
 * writing out unverified or partial content would be exactly that).
 * Entries are processed in the manifest's own depth-first, directories
 * -before-contents order, so a directory's amisnap_backend_mkcol
 * always happens before anything is written under it. When
 * opts->on_entry_restored is set, the manifest is walked a second time
 * afterward, purely to invoke that callback once every entry's content/
 * container already exists -- see restore.c's on_entry_meta.
 *
 * Returns AMISNAP_OK (check *result for what actually happened),
 * or the first error encountered (a manifest-decode error if
 * `manifest_data` itself never validated, or a backend/hash error from
 * partway through -- *result reflects only what completed before the
 * failure).
 *
 * `manifest_data`/`manifest_len` are the raw manifest FILE bytes (as
 * fetched from the backend, still carrying the common header) --
 * decrypted internally (repo.h's amisnap_repo_open_manifest()) using
 * `subkeys`/`snapid` when the manifest turns out to be encrypted, and
 * every content object is likewise decrypted via
 * amisnap_repo_fetch_object() before being written to `dest`. Pass
 * subkeys=NULL, snapid=NULL for a CIPHER 0 repository. */
int amisnap_restore_manifest(amisnap_backend *repo, amisnap_backend *dest,
                              const amisnap_repo_subkeys *subkeys, const char *snapid,
                              const uint8_t *manifest_data, size_t manifest_len,
                              const amisnap_restore_options *opts,
                              amisnap_restore_result *result);

#endif /* AMISNAP_RESTORE_H */
