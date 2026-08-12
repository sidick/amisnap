/* repo.h -- the snapshot write path: turns metadata + raw file bytes
 * into a committed repository snapshot over an amisnap_backend,
 * implementing docs/format.md's "Snapshot commit protocol" (content
 * objects first, manifest rename last) and content-addressed dedup
 * ("Objects already present are never rewritten").
 *
 * A thin layer over manifest.h's writer: this module's only added
 * value is (1) hashing file content and turning it into E_CONTENT refs
 * + backend objects, and (2) the snapshot id / commit-to-`snapshots/`
 * step. Directory/link entries, which have no content to hash, forward
 * straight to the manifest writer.
 *
 * Repository-level state (amisnap.repo / REC_REPO: REPO_ID, CIPHER,
 * CHUNK_SIZE, FORMAT_APP) is explicitly out of scope here -- this
 * writer assumes CIPHER=0 (format.md's default) and doesn't touch
 * amisnap.repo at all; that lands with encryption wiring (phase 4) or
 * whichever future item first needs to read it back (see
 * implementation-plan.md).
 */
#ifndef AMISNAP_REPO_H
#define AMISNAP_REPO_H

#include <stddef.h>
#include <stdint.h>

#include "backend.h"
#include "manifest.h"

/* "objects/" + 2 fan-out chars + "/" + 64 hex + NUL, generous. */
#define AMISNAP_OBJECT_KEY_LEN 80

/* format.md "Content objects": objects/<hh>/<hex64>, the fan-out
 * bucket being the first two hex characters. Shared by the writer,
 * restore.c, and verify -- implemented exactly once. */
void amisnap_repo_object_key(const uint8_t hash[32], char out[AMISNAP_OBJECT_KEY_LEN]);

typedef struct {
    amisnap_backend *be;
    amisnap_manifest_writer mw;
    uint32_t snap_days, snap_mins, snap_ticks;
    int have_snap;
} amisnap_repo_writer;

/* `be` is borrowed -- the writer never opens or closes it. */
void amisnap_repo_writer_init(amisnap_repo_writer *rw, amisnap_backend *be);
void amisnap_repo_writer_free(amisnap_repo_writer *rw);

/* Forwards to the manifest writer (see manifest.h for the ordering
 * rules this enforces) and additionally remembers the creation
 * DateStamp for amisnap_repo_writer_finish()'s snapshot id. */
int amisnap_repo_writer_snap(amisnap_repo_writer *rw, const amisnap_snap_meta *snap);

int amisnap_repo_writer_volume(amisnap_repo_writer *rw, const amisnap_volume_meta *vol);

/* Writes `data`/`len` as a content object (its BLAKE2s-256 becomes the
 * object key under objects/<hh>/<hex64>), skipping the backend write
 * entirely if that object already exists (dedup), then adds a
 * REC_ENTRY for it. `entry->type` must be AMISNAP_ETYPE_FILE;
 * entry->has_size/size/content/content_count are overwritten by this
 * call (the caller sets every other field: path, prot, date, comment,
 * owner, xhash). For a zero-length file pass data=NULL, len=0 -- no
 * object is written, matching format.md's E_SIZE=0/no-refs case.
 * Returns AMISNAP_OK or a negative AMISNAP_ERR_* code (from the
 * backend, or AMISNAP_ERR_TOO_LONG from an oversized path/comment --
 * see meta.h). */
int amisnap_repo_writer_file(amisnap_repo_writer *rw, amisnap_entry_meta *entry,
                              const void *data, size_t len);

/* For directories and links, which carry no content -- forwards
 * directly to the manifest writer. */
int amisnap_repo_writer_entry(amisnap_repo_writer *rw, const amisnap_entry_meta *entry);

/* Commits: finishes the manifest (REC_END + self-hash, per manifest.h),
 * derives the snapshot id from the creation DateStamp passed to
 * amisnap_repo_writer_snap() (format.md "<snapid>": days:u32.mins:u16.
 * ticks:u16 as 16 lower-case hex characters), and writes it to
 * snapshots/<snapid>.mf. On an id collision (an existing snapshot at
 * that exact id -- two snapshots in the same tick) increments ticks
 * until a free id is found, matching format.md's stated collision
 * policy. Copies the committed id into snapid_out (a 17-byte buffer:
 * 16 hex characters + NUL). Returns AMISNAP_ERR_MISSING_FIELD if
 * amisnap_repo_writer_snap() was never called, or propagates any
 * writer/backend error. */
int amisnap_repo_writer_finish(amisnap_repo_writer *rw, char snapid_out[17]);

/* Enumerates every successfully-committed snapshot in the repository
 * (format.md "Snapshot commit protocol": nothing partially written is
 * ever visible under snapshots/, so this never sees a half-written
 * manifest), calling cb(user, snapid) once per snapshot with a 16-hex-
 * character, NUL-terminated id (valid only during that call). Order
 * matches whatever the backend's list() returns (a directory backend
 * is not necessarily sorted) -- format.md's snapid design makes a
 * caller-side lexicographic sort equivalent to chronological order if
 * that's wanted. A listed name not shaped like "<16 hex>.mf" (a stray
 * tmp/ leftover, a foreign file) is silently skipped -- this is a
 * best-effort listing, not a repository integrity check. Returns
 * AMISNAP_OK (including when there are zero snapshots) or a negative
 * AMISNAP_ERR_* code from the backend. */
int amisnap_repo_list_snapshots(amisnap_backend *be,
                                 void (*cb)(void *user, const char *snapid), void *user);

typedef struct {
    size_t objects_checked;   /* one count per E_CONTENT ref occurrence, not
                                * per unique object -- see amisnap_verify_manifest's
                                * own doc comment on why that's not a bug */
    size_t objects_missing;
    size_t objects_corrupt;   /* FULL mode only: content read but hash mismatched */
} amisnap_verify_result;

/* format.md "Operations (v1)" verify: structural always (every
 * E_CONTENT ref's object exists in `repo`, size matches, checked via
 * amisnap_backend_exists() -- no content read), `full` additionally
 * re-reads and re-hashes every object's actual bytes against its
 * declared BLAKE2s-256 (catching bit-rot/corruption that mere
 * presence can't). The manifest itself is decoded via
 * amisnap_manifest_decode(), whose own END_HASH self-check already
 * covers the manifest file's own structural integrity -- a manifest
 * that doesn't decode fails this call outright (its own AMISNAP_ERR_*
 * code is returned) rather than reporting a partial result.
 *
 * Every content-ref *occurrence* is checked, not every unique object
 * once -- a file referenced by dedup from ten entries is checked ten
 * times. This is correct (never gives a false pass) but not maximally
 * efficient; a unique-object-set optimisation is deferred to land
 * alongside prune's own object enumeration (phase 2), not promised
 * here. Returns AMISNAP_OK once verification has run to completion
 * (check *result for the actual findings) or a manifest-decode error
 * if the manifest itself never validated. */
int amisnap_verify_manifest(amisnap_backend *repo, const uint8_t *manifest_data, size_t manifest_len,
                             int full, amisnap_verify_result *result);

#endif /* AMISNAP_REPO_H */
