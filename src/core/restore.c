/* restore.c -- see restore.h. */
#include <stdlib.h>
#include <string.h>

#include "blake2s.h"
#include "manifest.h"
#include "repo.h"
#include "restore.h"

typedef struct {
    amisnap_backend *repo;
    amisnap_backend *dest;
    const amisnap_restore_options *opts;
    amisnap_restore_result *result;
} restore_ctx;

static int path_in_subtree(const uint8_t *path, size_t path_len,
                            const uint8_t *prefix, size_t prefix_len)
{
    if (prefix_len == 0)
        return 1; /* no filter: full restore */
    if (path_len < prefix_len)
        return 0;
    if (memcmp(path, prefix, prefix_len) != 0)
        return 0;
    if (path_len == prefix_len)
        return 1; /* the subtree root itself */
    return path[prefix_len] == '/'; /* a real path-component boundary, not a string prefix */
}

/* NUL-terminates a borrowed, non-NUL-terminated path into a fixed
 * stack buffer for use as a backend key (amisnap_backend's key
 * parameter is a C string; E_PATH is length-prefixed, not NUL-
 * terminated). format.md's own path Limits section caps a single
 * path at 65535 bytes, but AMISNAP_BACKEND_DIR_MAX_PATH-driven
 * repository keys are far shorter in every real case (see that
 * section's own reasoning) -- a path this module can't fit is
 * reported via AMISNAP_ERR_TOO_LONG rather than silently truncated. */
#define RESTORE_PATH_BUF_LEN 2048

static int path_to_key(const uint8_t *path, size_t path_len, char out[RESTORE_PATH_BUF_LEN])
{
    if (path_len + 1 > RESTORE_PATH_BUF_LEN)
        return AMISNAP_ERR_TOO_LONG;
    memcpy(out, path, path_len);
    out[path_len] = '\0';
    return AMISNAP_OK;
}

/* Streams each content object straight to the destination via
 * backend.h's put_begin/put_append/put_finish rather than accumulating
 * the whole reconstructed file into one buffer first -- for a file
 * chunked by amisnap_repo_writer_file_chunked() (repo.h), that
 * accumulation would defeat the entire point of chunking on the write
 * side: the destination-side buffer would still need to hold the full
 * file at once. Each amisnap_backend_get() below only ever needs to
 * hold one content object (at most AMISNAP_DEFAULT_CHUNK_SIZE bytes for
 * a chunked entry) in memory at a time. */
static int restore_file(restore_ctx *rc, const amisnap_entry_meta *entry, const char *key)
{
    void *handle;
    uint64_t total = 0;
    size_t i;
    int status;

    if (entry->content_count == 0) {
        status = amisnap_backend_put(rc->dest, key, NULL, 0);
        if (status == AMISNAP_OK)
            rc->result->files_written++;
        return status;
    }

    status = amisnap_backend_put_begin(rc->dest, key, &handle);
    if (status != AMISNAP_OK) return status;

    for (i = 0; i < entry->content_count; i++) {
        char objkey[AMISNAP_OBJECT_KEY_LEN];
        amisnap_buf obj;
        uint8_t actual_hash[32];

        amisnap_repo_object_key(entry->content[i].hash, objkey);

        status = amisnap_backend_get(rc->repo, objkey, &obj);
        if (status != AMISNAP_OK) { amisnap_backend_put_abort(rc->dest, handle); return status; }

        if (obj.len != entry->content[i].size) {
            amisnap_buf_free(&obj);
            amisnap_backend_put_abort(rc->dest, handle);
            return AMISNAP_ERR_MALFORMED;
        }

        /* format.md's own disaster-recovery procedure: "verifying
         * each against its name" -- never write out content whose
         * bytes don't match the hash the manifest declared for them. */
        amisnap_blake2s256(obj.data, obj.len, actual_hash);
        if (memcmp(actual_hash, entry->content[i].hash, 32) != 0) {
            amisnap_buf_free(&obj);
            amisnap_backend_put_abort(rc->dest, handle);
            return AMISNAP_ERR_HASH_MISMATCH;
        }

        status = amisnap_backend_put_append(rc->dest, handle, obj.data, obj.len);
        total += obj.len;
        amisnap_buf_free(&obj);
        if (status != AMISNAP_OK) { amisnap_backend_put_abort(rc->dest, handle); return status; }
    }

    status = amisnap_backend_put_finish(rc->dest, handle);
    if (status == AMISNAP_OK) {
        rc->result->files_written++;
        rc->result->bytes_written += total;
    }
    return status;
}

static int on_entry(void *user, const amisnap_entry_meta *entry)
{
    restore_ctx *rc = (restore_ctx *)user;
    char key[RESTORE_PATH_BUF_LEN];
    int status;

    if (rc->opts && !path_in_subtree(entry->path, entry->path_len,
                                      rc->opts->subtree_prefix, rc->opts->subtree_prefix_len)) {
        rc->result->entries_skipped++;
        return 0;
    }

    if (entry->type == AMISNAP_ETYPE_SOFTLINK || entry->type == AMISNAP_ETYPE_HARDLINK) {
        /* Honest gap -- see restore.h's own header comment. */
        rc->result->links_skipped++;
        return 0;
    }

    status = path_to_key(entry->path, entry->path_len, key);
    if (status != AMISNAP_OK) return status;

    if (entry->type == AMISNAP_ETYPE_DIR) {
        status = amisnap_backend_mkcol(rc->dest, key);
        if (status != AMISNAP_OK) return status;
        rc->result->dirs_created++;
    } else {
        status = restore_file(rc, entry, key);
        if (status != AMISNAP_OK) return status;
    }

    /* Metadata is applied in a separate pass after every entry's content
     * exists -- see on_entry_meta below for why. */
    return 0;
}

/* Collects every entry from a second manifest decode so the metadata pass
 * (see amisnap_restore_manifest below) can apply them in REVERSE order --
 * deepest entries first, directories last. A shallow `*entry` copy is not
 * enough: `.content` borrows manifest.h's per-entry decode scratch, reused
 * on the next callback, so it needs a real copy to survive past this one
 * call, exactly like index.c's own on_entry_cb faces the same issue for
 * the same reason. `.path`/`.comment`/`.link` keep borrowing straight into
 * `manifest_data`, which the caller guarantees outlives this whole call. */
typedef struct {
    amisnap_entry_meta *entries;
    size_t count;
    size_t cap;
} meta_collect_ctx;

static int collect_entry(void *user, const amisnap_entry_meta *entry)
{
    meta_collect_ctx *cc = (meta_collect_ctx *)user;
    amisnap_entry_meta copy = *entry;
    amisnap_content_ref *refs = NULL;

    if (entry->content_count > 0) {
        refs = (amisnap_content_ref *)malloc(entry->content_count * sizeof(*refs));
        if (!refs) return AMISNAP_ERR_NOMEM;
        memcpy(refs, entry->content, entry->content_count * sizeof(*refs));
    }
    copy.content = refs;

    if (cc->count == cc->cap) {
        size_t newcap = cc->cap ? cc->cap * 2 : 64;
        amisnap_entry_meta *newarr =
            (amisnap_entry_meta *)realloc(cc->entries, newcap * sizeof(*newarr));
        if (!newarr) { free(refs); return AMISNAP_ERR_NOMEM; }
        cc->entries = newarr;
        cc->cap = newcap;
    }
    cc->entries[cc->count++] = copy;
    return 0;
}

/* Applies on_entry_restored (Amiga metadata -- SetProtection/SetComment/
 * SetFileDate/SetOwner) only after every entry's content/container from
 * the first pass already exists, and in REVERSE manifest order -- a
 * directory's own metadata goes last among everything under it, not just
 * after its own mkcol(). Both orderings were tried empirically against
 * the real-FFS Copperline harness (implementation-plan.md item 8's real-
 * FFS follow-up) before landing here, not assumed correct from reasoning
 * alone (house rule 6):
 *
 *   1. Metadata applied immediately after each entry's own mkcol()/write
 *      (the original design): failed -- a directory's protection/
 *      datestamp came back wrong on real FFS, because creating its
 *      children afterward updates its own datestamp.
 *   2. A separate pass, but still in manifest (parent-before-children)
 *      order: ALSO failed, confirmed live -- real AmigaDOS FFS updates a
 *      directory's own datestamp not just when a child is *created*, but
 *      also when a child's own metadata is later changed (SetProtection/
 *      SetFileDate/SetComment on the child rewrites its FileHeader block,
 *      which apparently touches the parent directory block too). Manifest
 *      order still processes the parent's metadata before its children's,
 *      so the children's later metadata calls clobbered it right back.
 *   3. Reverse manifest order (this one): passes on OFS/FFS/FFS+Intl.
 *      Manifest entries are the scanner's own pre-order DFS (parent
 *      immediately followed by its descendants before any later
 *      sibling), so reversing the list turns that into a post-order walk
 *      -- every entry's metadata is applied before its parent's, with no
 *      need to reconstruct the tree structure to get that ordering.
 *
 * Repeats the identical subtree/link filtering `on_entry` already applied
 * so this only calls back for the same entries the content pass counted,
 * but must not touch `result` -- the first pass already counted each one. */
static int apply_metadata_reverse(restore_ctx *rc, const meta_collect_ctx *cc)
{
    size_t i;

    for (i = cc->count; i > 0; i--) {
        const amisnap_entry_meta *entry = &cc->entries[i - 1];

        if (rc->opts && !path_in_subtree(entry->path, entry->path_len,
                                          rc->opts->subtree_prefix, rc->opts->subtree_prefix_len))
            continue;
        if (entry->type == AMISNAP_ETYPE_SOFTLINK || entry->type == AMISNAP_ETYPE_HARDLINK)
            continue;

        rc->opts->on_entry_restored(rc->opts->user, entry);
    }
    return AMISNAP_OK;
}

int amisnap_restore_manifest(amisnap_backend *repo, amisnap_backend *dest,
                              const uint8_t *manifest_data, size_t manifest_len,
                              const amisnap_restore_options *opts,
                              amisnap_restore_result *result)
{
    restore_ctx rc;
    amisnap_manifest_visitor v;
    int status;

    memset(result, 0, sizeof(*result));
    rc.repo = repo;
    rc.dest = dest;
    rc.opts = opts;
    rc.result = result;

    memset(&v, 0, sizeof(v));
    v.user = &rc;
    v.on_entry = on_entry;

    status = amisnap_manifest_decode(manifest_data, manifest_len, &v);
    if (status != AMISNAP_OK) return status;

    if (opts && opts->on_entry_restored) {
        meta_collect_ctx cc;
        size_t i;

        memset(&cc, 0, sizeof(cc));
        memset(&v, 0, sizeof(v));
        v.user = &cc;
        v.on_entry = collect_entry;

        status = amisnap_manifest_decode(manifest_data, manifest_len, &v);
        if (status == AMISNAP_OK)
            status = apply_metadata_reverse(&rc, &cc);

        for (i = 0; i < cc.count; i++)
            free((void *)cc.entries[i].content); /* cast away const -- collect_entry's own malloc */
        free(cc.entries);
    }
    return status;
}
