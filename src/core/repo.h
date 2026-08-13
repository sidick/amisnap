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
 * Encryption (docs/format.md "Encryption (CIPHER 1)"): every entry
 * point here takes an `amisnap_repo_subkeys *` -- NULL for a CIPHER 0
 * repository (unchanged behavior), or a real one (from
 * amisnap_repo_derive_subkeys(), repo_crypto.h) to encrypt objects/
 * manifests on write and decrypt+verify them on read. This module
 * still has no opinion on where that repository key comes from --
 * generating it (real entropy) and wrapping it under a passphrase are
 * repo_header.h/entropy.h's job, not this one's; repo.c only ever
 * consumes already-derived subkeys.
 *
 * Repository-level state (amisnap.repo / REC_REPO: REPO_ID, CIPHER,
 * CHUNK_SIZE, KDF, WRAPPED_KEY, FORMAT_APP) is still out of scope
 * here -- reading/writing amisnap.repo itself is repo_header.h; this
 * module doesn't touch it. Whatever opens a repository is responsible
 * for reading amisnap.repo, unwrapping the key if CIPHER != 0, and
 * handing the resulting subkeys to the functions below.
 */
#ifndef AMISNAP_REPO_H
#define AMISNAP_REPO_H

#include <stddef.h>
#include <stdint.h>

#include "backend.h"
#include "manifest.h"
#include "repo_crypto.h"

/* "objects/" + 2 fan-out chars + "/" + 64 hex + NUL, generous. */
#define AMISNAP_OBJECT_KEY_LEN 80

/* format.md "Content objects": objects/<hh>/<hex64>, the fan-out
 * bucket being the first two hex characters. Shared by the writer,
 * restore.c, and verify -- implemented exactly once. */
void amisnap_repo_object_key(const uint8_t hash[32], char out[AMISNAP_OBJECT_KEY_LEN]);

/* Fetches content object `ref` from `repo`, decrypts it if `subkeys`
 * is non-NULL, and verifies the resulting plaintext against
 * `ref->hash` -- every caller needs fetch+decrypt+verify together
 * (format.md's disaster-recovery procedure: "verifying each against
 * its name"), so this does all three in one call rather than making
 * restore.c and verify's own full-mode duplicate the sequence. `out`
 * receives the plaintext (caller amisnap_buf_free()s it). Returns
 * AMISNAP_OK, AMISNAP_ERR_NOT_FOUND, AMISNAP_ERR_MALFORMED (stored
 * size doesn't match `ref->size` once the encryption frame overhead,
 * when `subkeys` is set, is accounted for), AMISNAP_ERR_HASH_MISMATCH
 * (MAC or content hash mismatch), or another backend error. */
int amisnap_repo_fetch_object(amisnap_backend *repo, const amisnap_repo_subkeys *subkeys,
                               const amisnap_content_ref *ref, amisnap_buf *out);

/* Given the raw bytes of a manifest file as fetched from the backend
 * (snapshots/<snapid>.mf), returns its plaintext body via
 * `plaintext_out` (caller amisnap_buf_free()s it) -- decrypting first
 * if the common header's flags bit 0 is set (format.md "Encryption
 * ... Manifests"). `subkeys` may be NULL only if the manifest turns
 * out not to be encrypted; a NULL `subkeys` against an encrypted
 * manifest returns AMISNAP_ERR_MISSING_FIELD. `snapid` (the
 * manifest's own 16-hex-character identifier, no NUL required beyond
 * that -- see docs/format.md "Nonce discipline" for why the decrypt
 * nonce is derived from it rather than stored) is only read when
 * decryption is actually needed. The returned buffer always has
 * flags=0 in its own 8-byte header regardless of whether decryption
 * happened, so amisnap_manifest_decode() and everything built on it
 * never need to know CIPHER was involved. */
int amisnap_repo_open_manifest(const amisnap_repo_subkeys *subkeys, const char *snapid,
                                const uint8_t *raw, size_t rawlen, amisnap_buf *plaintext_out);

typedef struct {
    amisnap_backend *be;
    amisnap_manifest_writer mw;
    uint32_t snap_days, snap_mins, snap_ticks;
    int have_snap;
    const amisnap_repo_subkeys *subkeys;   /* NULL = CIPHER 0 (plaintext) */
} amisnap_repo_writer;

/* `be` is borrowed -- the writer never opens or closes it. `subkeys`
 * is also borrowed (must outlive the writer) and may be NULL for a
 * CIPHER 0 repository; when non-NULL, every object
 * amisnap_repo_writer_file[_chunked]() writes and the manifest
 * amisnap_repo_writer_finish() commits are encrypted per
 * docs/format.md's Encryption section. */
void amisnap_repo_writer_init(amisnap_repo_writer *rw, amisnap_backend *be,
                               const amisnap_repo_subkeys *subkeys);
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

/* Files at or under this size go through amisnap_repo_writer_file()
 * (one object, read whole into memory); files over it use
 * amisnap_repo_writer_file_chunked() below instead, which never needs
 * more than one chunk's worth of memory at a time regardless of the
 * file's total size.
 *
 * 256 KiB, not format.md's own originally-documented 8 MiB default --
 * corrected after real testing, not by inspection: an 8 MiB chunk
 * buffer failed to allocate even at 8 MiB of fast RAM (Zorro II's own
 * ceiling) under Copperline, confirmed via AMISNAP_ERR_NOMEM, not
 * merely suspected. Whatever else is resident (AmiSnap itself, the
 * OS, ExAll buffers, the growable content-ref array) needs headroom
 * too, and the whole point of chunking is bounding memory for the
 * *common*, resource-constrained case -- a well-equipped 68020+
 * system with real 32-bit fast RAM can supply far more than this if
 * it ever needs to, but the default has to work on a modest one
 * first. format.md's own CHUNK_SIZE field stays "informational; refs
 * are self-describing" either way -- this is a real, not merely
 * documented, corrected default. */
#define AMISNAP_DEFAULT_CHUNK_SIZE (256u * 1024u)

/* Streaming counterpart to amisnap_repo_writer_file(), for files too
 * large to read into memory whole -- a real constraint on a real
 * Amiga's RAM budget, not just a future optimisation. The caller
 * supplies `total_size` up front and a `read_fn` callback this
 * function calls repeatedly, each time asking for up to `chunk_size`
 * bytes at once (into a `chunk_size`-byte buffer this function
 * allocates and frees itself, never the whole file): `read_fn(ctx,
 * buf, want, *got)` must fill `buf` with exactly `want` bytes unless
 * it's the final read, when returning fewer bytes (via *got) signals
 * EOF; a negative AMISNAP_ERR_* return from `read_fn` aborts the whole
 * call with that error. Each chunk becomes its own independently
 * content-addressed, independently deduped object (format.md
 * E_CONTENT: "several = fixed-size chunks") -- concatenating them in
 * order reconstructs the file, exactly like restore.c already expects
 * for any entry with more than one content ref.
 *
 * E_XHASH is computed via xxhash32.h's streaming API across every
 * chunk read as it's read, covering the whole logical file with one
 * value, not per chunk, per format.md's own definition of that field.
 *
 * entry->has_size/size/content/content_count/has_xhash/xhash are all
 * overwritten by this call, same contract as amisnap_repo_writer_
 * file(). Returns AMISNAP_OK or a negative AMISNAP_ERR_* code (from
 * the backend, `read_fn`, or AMISNAP_ERR_NOMEM if the chunk buffer or
 * the growable ref array can't be allocated). */
int amisnap_repo_writer_file_chunked(amisnap_repo_writer *rw, amisnap_entry_meta *entry,
                                      uint64_t total_size, size_t chunk_size,
                                      int (*read_fn)(void *ctx, void *buf, size_t want, size_t *got),
                                      void *ctx);

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
 * if the manifest itself never validated.
 *
 * `manifest_data`/`manifest_len` are the raw manifest FILE bytes (as
 * fetched from the backend, still carrying the common header) --
 * decrypted internally via amisnap_repo_open_manifest() using
 * `subkeys`/`snapid` when the manifest turns out to be encrypted;
 * pass subkeys=NULL, snapid=NULL for a CIPHER 0 repository. */
int amisnap_verify_manifest(amisnap_backend *repo, const amisnap_repo_subkeys *subkeys,
                             const char *snapid, const uint8_t *manifest_data, size_t manifest_len,
                             int full, amisnap_verify_result *result);

#endif /* AMISNAP_REPO_H */
