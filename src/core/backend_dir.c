/* backend_dir.c -- see backend_dir.h. Built entirely on standard/
 * widely-portable C (stdio's fopen/fread/fwrite/fclose/rename/remove,
 * plus mkdir/opendir/readdir/stat) -- no platform #ifdefs, on the
 * expectation that libnix provides working equivalents on the m68k
 * target (this file lives in src/core/, not src/amiga/, precisely
 * because implementation-plan.md's module map treats it as portable).
 * If Phase 1's on-target harness finds that assumption wrong for some
 * call here, that is exactly the kind of gap it exists to catch --
 * fix it here first before reaching for a src/amiga/dosio.c split.
 *
 * '/' is used as the path separator throughout, matching both this
 * repository format's own key convention (format.md "Repository
 * layout") and native AmigaDOS multi-component path syntax
 * (Volume:dir1/dir2/file) -- no translation needed on either platform.
 */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "backend_dir.h"
#include "xxhash32.h"

typedef struct {
    char *root; /* no trailing '/' */
} dir_ctx;

/* Builds the tmp/ staging filename for `key`: "<basename>.<8 hex
 * digits>", the hex digits being xxHash32 of the FULL key (not just
 * the basename). format.md's own commit protocol only documents
 * "tmp/<hex64>" and "tmp/<snapid>.mf" for the repository backend's own
 * writes (repo.c), where the basename alone is already unique --
 * content hashes and snapshot IDs never collide in practice -- so
 * this suffix is a no-op collision risk there. It matters for the
 * OTHER real caller of this same backend: RESTORE's destination
 * (main.c's open_backend() opens amisnap_backend_dir_open() for any
 * non-http(s)/s3 DEST=, i.e. every local-path restore), where the key
 * is a real user file path and two different subdirectories commonly
 * share a filename (two "readme.txt", two "index.html", ...) -- an
 * earlier version of this function used the bare basename alone,
 * which meant two such entries collided on the identical tmp path.
 * Not exploitable today given restore.c's strictly-sequential one-
 * entry-at-a-time processing (each entry's own rename() completes
 * before the next tmp file is opened), but a crash mid-restore
 * leaving a stale tmp file, or any future concurrent/prefetching
 * restore path, would have silently corrupted or lost data -- fixed
 * at the root instead of documented as a constraint to remember.
 * xxHash32 (not a cryptographic hash -- this project's own "CPU
 * budget" default per proposal.md) is more than sufficient for a
 * scratch/staging filename: a collision only matters if it also
 * matches the OTHER colliding key's basename AND both are in flight
 * at the same time, an astronomically unlikely conjunction for a
 * 32-bit hash at backup-repository scale. */
static int tmp_name_for_key(const char *key, const char *base, char *out, size_t outsize)
{
    uint32_t h = amisnap_xxh32(key, strlen(key), 0);

    if (snprintf(out, outsize, "%s.%08lx", base, (unsigned long)h) >= (int)outsize)
        return AMISNAP_ERR_MALFORMED;
    return AMISNAP_OK;
}

static int join_path(const dir_ctx *ctx, const char *key, char *buf, size_t bufsize)
{
    size_t rootlen = strlen(ctx->root);
    size_t keylen = strlen(key);
    /* A root ending in ':' is an AmigaDOS bare volume/assign
     * ("Repo:") -- ':' already IS the separator there, same role '/'
     * plays after a directory name; joining "Repo:" + "/" + "tmp/x"
     * produces "Repo:/tmp/x", which real AmigaDOS/Copperline rejects
     * (confirmed live, item 8's on-target harness, 2026-08-12: Lock()
     * fails with IoErr 209) -- only "Repo:tmp/x" (no extra slash)
     * resolves. Harmless on host: no host root ever ends in ':', so
     * this never changes host behavior (backend_dir.c stays portable,
     * host CI exercises the same code path either way). ctx->root
     * never ends in '/' either (stripped in amisnap_backend_dir_open),
     * so the two cases are mutually exclusive in practice, but both
     * are checked for robustness. */
    int has_sep = rootlen > 0 && (ctx->root[rootlen - 1] == ':' || ctx->root[rootlen - 1] == '/');
    size_t seplen = has_sep ? 0 : 1;

    if (rootlen + seplen + keylen + 1 > bufsize)
        return AMISNAP_ERR_MALFORMED;

    memcpy(buf, ctx->root, rootlen);
    if (!has_sep)
        buf[rootlen] = '/';
    memcpy(buf + rootlen + seplen, key, keylen + 1); /* + trailing NUL */
    return AMISNAP_OK;
}

static int mkdir_one(const char *path)
{
    if (mkdir(path, 0755) == 0)
        return AMISNAP_OK;
    if (errno == EEXIST)
        return AMISNAP_OK;
    return AMISNAP_ERR_IO;
}

/* Creates every directory component of `path` (mutated in place,
 * temporarily, and restored), tolerating ones that already exist.
 * `path` must be absolute-ish (start with a separator or a volume
 * prefix) -- the loop starts at index 1 so a POSIX leading '/' is
 * never mkdir'd as "" past pos 0. */
static int mkdir_p(char *path)
{
    char *p;
    int rc;

    for (p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            rc = mkdir_one(path);
            *p = '/';
            if (rc != AMISNAP_OK)
                return rc;
        }
    }
    return mkdir_one(path);
}

static int ensure_parent_dir(char *full_path)
{
    char *slash = strrchr(full_path, '/');
    int rc;

    if (!slash)
        return AMISNAP_OK; /* no parent component to create */

    *slash = '\0';
    rc = mkdir_p(full_path);
    *slash = '/';
    return rc;
}

static int dir_put(amisnap_backend *be, const char *key, const void *data, size_t len)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    char final_path[AMISNAP_BACKEND_DIR_MAX_PATH];
    char tmp_dir[AMISNAP_BACKEND_DIR_MAX_PATH];
    char tmp_name[AMISNAP_BACKEND_DIR_MAX_PATH];
    char tmp_path[AMISNAP_BACKEND_DIR_MAX_PATH];
    const char *base;
    FILE *f;
    int rc;

    rc = join_path(ctx, key, final_path, sizeof(final_path));
    if (rc != AMISNAP_OK) return rc;

    /* format.md's commit protocol names the temp file after the
     * target's own basename (tmp/<hex64> for objects, tmp/<snapid>.mf
     * for manifests) -- matched here for a human poking around a
     * live repository mid-write, though only the atomicity (not the
     * exact temp name) is load-bearing. tmp_name_for_key()'s own
     * comment has the "why a hash suffix" reasoning -- collision-free
     * across differently-pathed same-basename keys (the actual
     * destination-restore case; the repo's own hex64/snapid.mf keys
     * are already unique on the basename alone). */
    base = strrchr(key, '/');
    base = base ? base + 1 : key;
    rc = tmp_name_for_key(key, base, tmp_name, sizeof(tmp_name));
    if (rc != AMISNAP_OK) return rc;

    rc = join_path(ctx, "tmp", tmp_dir, sizeof(tmp_dir));
    if (rc != AMISNAP_OK) return rc;
    if (snprintf(tmp_path, sizeof(tmp_path), "%s/%s", tmp_dir, tmp_name) >= (int)sizeof(tmp_path))
        return AMISNAP_ERR_MALFORMED;

    rc = mkdir_p(tmp_dir);
    if (rc != AMISNAP_OK) return rc;

    f = fopen(tmp_path, "wb");
    if (!f) return AMISNAP_ERR_IO;
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        remove(tmp_path);
        return AMISNAP_ERR_IO;
    }
    if (fclose(f) != 0) {
        remove(tmp_path);
        return AMISNAP_ERR_IO;
    }

    rc = ensure_parent_dir(final_path);
    if (rc != AMISNAP_OK) { remove(tmp_path); return rc; }

    if (rename(tmp_path, final_path) != 0) {
        remove(tmp_path);
        return AMISNAP_ERR_IO;
    }
    return AMISNAP_OK;
}

typedef struct {
    FILE *f;
    char tmp_path[AMISNAP_BACKEND_DIR_MAX_PATH];
    char final_path[AMISNAP_BACKEND_DIR_MAX_PATH];
} dir_put_handle;

static int dir_put_begin(amisnap_backend *be, const char *key, void **handle_out)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    dir_put_handle *h;
    char tmp_dir[AMISNAP_BACKEND_DIR_MAX_PATH];
    char tmp_name[AMISNAP_BACKEND_DIR_MAX_PATH];
    const char *base;
    int rc;

    h = (dir_put_handle *)malloc(sizeof(*h));
    if (!h) return AMISNAP_ERR_NOMEM;

    rc = join_path(ctx, key, h->final_path, sizeof(h->final_path));
    if (rc != AMISNAP_OK) { free(h); return rc; }

    /* See dir_put()'s own identical comment / tmp_name_for_key(). */
    base = strrchr(key, '/');
    base = base ? base + 1 : key;
    rc = tmp_name_for_key(key, base, tmp_name, sizeof(tmp_name));
    if (rc != AMISNAP_OK) { free(h); return rc; }

    rc = join_path(ctx, "tmp", tmp_dir, sizeof(tmp_dir));
    if (rc != AMISNAP_OK) { free(h); return rc; }
    if (snprintf(h->tmp_path, sizeof(h->tmp_path), "%s/%s", tmp_dir, tmp_name) >= (int)sizeof(h->tmp_path)) {
        free(h);
        return AMISNAP_ERR_MALFORMED;
    }

    rc = mkdir_p(tmp_dir);
    if (rc != AMISNAP_OK) { free(h); return rc; }

    h->f = fopen(h->tmp_path, "wb");
    if (!h->f) { free(h); return AMISNAP_ERR_IO; }

    *handle_out = h;
    return AMISNAP_OK;
}

static int dir_put_append(amisnap_backend *be, void *handle, const void *data, size_t len)
{
    dir_put_handle *h = (dir_put_handle *)handle;
    (void)be;

    if (len > 0 && fwrite(data, 1, len, h->f) != len)
        return AMISNAP_ERR_IO;
    return AMISNAP_OK;
}

static int dir_put_finish(amisnap_backend *be, void *handle)
{
    dir_put_handle *h = (dir_put_handle *)handle;
    int rc;
    (void)be;

    if (fclose(h->f) != 0) {
        remove(h->tmp_path);
        free(h);
        return AMISNAP_ERR_IO;
    }

    rc = ensure_parent_dir(h->final_path);
    if (rc != AMISNAP_OK) { remove(h->tmp_path); free(h); return rc; }

    if (rename(h->tmp_path, h->final_path) != 0) {
        remove(h->tmp_path);
        free(h);
        return AMISNAP_ERR_IO;
    }
    free(h);
    return AMISNAP_OK;
}

static void dir_put_abort(amisnap_backend *be, void *handle)
{
    dir_put_handle *h = (dir_put_handle *)handle;
    (void)be;

    if (h) {
        fclose(h->f);
        remove(h->tmp_path);
        free(h);
    }
}

static int dir_get(amisnap_backend *be, const char *key, amisnap_buf *out)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    char path[AMISNAP_BACKEND_DIR_MAX_PATH];
    FILE *f;
    long size;
    int rc;

    rc = join_path(ctx, key, path, sizeof(path));
    if (rc != AMISNAP_OK) return rc;

    f = fopen(path, "rb");
    if (!f) return (errno == ENOENT) ? AMISNAP_ERR_NOT_FOUND : AMISNAP_ERR_IO;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return AMISNAP_ERR_IO; }
    size = ftell(f);
    if (size < 0) { fclose(f); return AMISNAP_ERR_IO; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return AMISNAP_ERR_IO; }

    amisnap_buf_init(out);
    if (size > 0) {
        void *tmp = malloc((size_t)size);
        if (!tmp) { fclose(f); return AMISNAP_ERR_NOMEM; }
        if (fread(tmp, 1, (size_t)size, f) != (size_t)size) {
            free(tmp);
            fclose(f);
            amisnap_buf_free(out);
            return AMISNAP_ERR_IO;
        }
        rc = amisnap_buf_bytes(out, tmp, (size_t)size);
        free(tmp);
        if (rc != AMISNAP_OK) { fclose(f); amisnap_buf_free(out); return rc; }
    }
    fclose(f);
    return AMISNAP_OK;
}

static int dir_exists(amisnap_backend *be, const char *key)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    char path[AMISNAP_BACKEND_DIR_MAX_PATH];
    struct stat st;
    int rc = join_path(ctx, key, path, sizeof(path));

    if (rc != AMISNAP_OK) return rc;
    return (stat(path, &st) == 0) ? 1 : 0;
}

static int dir_list(amisnap_backend *be, const char *prefix,
                     void (*cb)(void *user, const char *name), void *user)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    char path[AMISNAP_BACKEND_DIR_MAX_PATH];
    DIR *d;
    struct dirent *ent;
    int rc = join_path(ctx, prefix, path, sizeof(path));

    if (rc != AMISNAP_OK) return rc;

    d = opendir(path);
    if (!d)
        return (errno == ENOENT) ? AMISNAP_OK : AMISNAP_ERR_IO;

    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        cb(user, ent->d_name);
    }
    closedir(d);
    return AMISNAP_OK;
}

static int dir_remove(amisnap_backend *be, const char *key)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    char path[AMISNAP_BACKEND_DIR_MAX_PATH];
    int rc = join_path(ctx, key, path, sizeof(path));

    if (rc != AMISNAP_OK) return rc;
    if (remove(path) != 0)
        return (errno == ENOENT) ? AMISNAP_ERR_NOT_FOUND : AMISNAP_ERR_IO;
    return AMISNAP_OK;
}

static int dir_mkcol(amisnap_backend *be, const char *key)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;
    char path[AMISNAP_BACKEND_DIR_MAX_PATH];
    size_t plen;
    int rc = join_path(ctx, key, path, sizeof(path));

    if (rc != AMISNAP_OK) return rc;

    /* An empty key (mkcol("") -- the repository/destination root
     * itself, format.md E_PATH's "empty = the root") joins to
     * "<root>/" with a trailing separator; strip it so mkdir_p sees a
     * clean path rather than relying on platform-specific trailing-
     * slash mkdir() behavior. */
    plen = strlen(path);
    if (plen > 0 && path[plen - 1] == '/')
        path[plen - 1] = '\0';

    return mkdir_p(path);
}

static void dir_close(amisnap_backend *be)
{
    dir_ctx *ctx = (dir_ctx *)be->ctx;

    if (ctx) {
        free(ctx->root);
        free(ctx);
    }
    be->ctx = NULL;
}

static const amisnap_backend_ops dir_ops = {
    dir_put, dir_get, dir_exists, dir_list, dir_remove, dir_mkcol,
    dir_put_begin, dir_put_append, dir_put_finish, dir_put_abort,
    dir_close
};

int amisnap_backend_dir_open(const char *root, amisnap_backend *out)
{
    dir_ctx *ctx;
    size_t len = strlen(root);
    char rootbuf[AMISNAP_BACKEND_DIR_MAX_PATH];
    int rc;

    while (len > 1 && root[len - 1] == '/')
        len--;

    if (len + 1 > sizeof(rootbuf))
        return AMISNAP_ERR_MALFORMED;

    ctx = (dir_ctx *)malloc(sizeof(*ctx));
    if (!ctx) return AMISNAP_ERR_NOMEM;
    ctx->root = (char *)malloc(len + 1);
    if (!ctx->root) { free(ctx); return AMISNAP_ERR_NOMEM; }
    memcpy(ctx->root, root, len);
    ctx->root[len] = '\0';

    memcpy(rootbuf, ctx->root, len + 1);
    rc = mkdir_p(rootbuf);
    if (rc != AMISNAP_OK) { free(ctx->root); free(ctx); return rc; }

    out->ops = &dir_ops;
    out->ctx = ctx;
    return AMISNAP_OK;
}
