/* prune.h -- docs/format.md's "Prune" section, implemented exactly:
 * delete target manifests first, then a mark-and-sweep pass over every
 * surviving snapshot's referenced objects. This module is the low-level
 * mechanism only -- it deletes whatever snapshot ids it's handed, with
 * no opinion on *which* ids that should be. Retention policy (keep
 * last N, keep daily/weekly/monthly) is a separate decision layered on
 * top by the CLI, matching implementation-plan.md principle 4
 * ("portable core, thin Amiga rind"): the mark-and-sweep engine is
 * pure repository mechanics and belongs here; picking which snapshots
 * a user's retention flags mean to keep is policy, not mechanism.
 */
#ifndef AMISNAP_PRUNE_H
#define AMISNAP_PRUNE_H

#include <stddef.h>

#include "backend.h"
#include "repo_crypto.h"

typedef struct {
    size_t snapshots_deleted;
    size_t objects_deleted;
    size_t tmp_deleted;
} amisnap_prune_result;

/* Deletes each of `delete_snapids` (an array of `delete_count` 16-hex-
 * character, NUL-terminated snapshot ids) from `repo`, then performs a
 * full mark-and-sweep pass over the REMAINING snapshots: mark (decode
 * every surviving manifest, collect every referenced object hash),
 * sweep (delete every objects/<hh>/<hex64> not in that set, then
 * everything under tmp/ -- nothing legitimately persists there between
 * operations that completed normally, per format.md's own commit
 * protocol).
 *
 * Deletion order is always manifest-first, objects-second (format.md's
 * stated invariant): every target manifest is gone before the sweep
 * ever starts, so interrupting this call at any point leaves only
 * harmless garbage for the next prune run to collect, never a manifest
 * referencing a deleted object.
 *
 * A delete_snapids entry that doesn't exist (already pruned, a typo)
 * is not an error -- idempotent, matching amisnap_backend_remove's own
 * AMISNAP_ERR_NOT_FOUND being expected/ignorable here. Any other
 * backend or decode error aborts immediately -- this call does not
 * attempt partial credit; *result reflects only what completed before
 * the failure. Returns AMISNAP_OK or a negative AMISNAP_ERR_* code.
 *
 * `subkeys` (NULL for a CIPHER 0 repository) is used only to decrypt
 * each surviving manifest during the mark pass -- object *names* are
 * always the plaintext content hash regardless of CIPHER (format.md
 * "Objects"), so the sweep pass (matching those names against the mark
 * set) needs no key at all. */
int amisnap_prune_execute(amisnap_backend *repo, const amisnap_repo_subkeys *subkeys,
                           const char *const *delete_snapids,
                           size_t delete_count, amisnap_prune_result *result);

#endif /* AMISNAP_PRUNE_H */
