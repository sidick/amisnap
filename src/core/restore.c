/* restore.c -- see restore.h. */
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

static int restore_file(restore_ctx *rc, const amisnap_entry_meta *entry, const char *key)
{
    amisnap_buf content;
    size_t i;
    int status;

    amisnap_buf_init(&content);

    for (i = 0; i < entry->content_count; i++) {
        char objkey[AMISNAP_OBJECT_KEY_LEN];
        amisnap_buf obj;
        uint8_t actual_hash[32];

        amisnap_repo_object_key(entry->content[i].hash, objkey);

        status = amisnap_backend_get(rc->repo, objkey, &obj);
        if (status != AMISNAP_OK) { amisnap_buf_free(&content); return status; }

        if (obj.len != entry->content[i].size) {
            amisnap_buf_free(&obj);
            amisnap_buf_free(&content);
            return AMISNAP_ERR_MALFORMED;
        }

        /* format.md's own disaster-recovery procedure: "verifying
         * each against its name" -- never write out content whose
         * bytes don't match the hash the manifest declared for them. */
        amisnap_blake2s256(obj.data, obj.len, actual_hash);
        if (memcmp(actual_hash, entry->content[i].hash, 32) != 0) {
            amisnap_buf_free(&obj);
            amisnap_buf_free(&content);
            return AMISNAP_ERR_HASH_MISMATCH;
        }

        status = amisnap_buf_bytes(&content, obj.data, obj.len);
        amisnap_buf_free(&obj);
        if (status != AMISNAP_OK) { amisnap_buf_free(&content); return status; }
    }

    status = amisnap_backend_put(rc->dest, key, content.data, content.len);
    if (status == AMISNAP_OK) {
        rc->result->files_written++;
        rc->result->bytes_written += content.len;
    }
    amisnap_buf_free(&content);
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

    if (rc->opts && rc->opts->on_entry_restored)
        rc->opts->on_entry_restored(rc->opts->user, entry);

    return 0;
}

int amisnap_restore_manifest(amisnap_backend *repo, amisnap_backend *dest,
                              const uint8_t *manifest_data, size_t manifest_len,
                              const amisnap_restore_options *opts,
                              amisnap_restore_result *result)
{
    restore_ctx rc;
    amisnap_manifest_visitor v;

    memset(result, 0, sizeof(*result));
    rc.repo = repo;
    rc.dest = dest;
    rc.opts = opts;
    rc.result = result;

    memset(&v, 0, sizeof(v));
    v.user = &rc;
    v.on_entry = on_entry;

    return amisnap_manifest_decode(manifest_data, manifest_len, &v);
}
