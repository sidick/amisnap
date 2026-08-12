/* backend.h -- the storage abstraction docs/format.md's repository
 * layout sits on top of ("the backend API maps them to a directory
 * tree, WebDAV collection, or S3 key prefix identically"). One vtable
 * (amisnap_backend_ops) plus an opaque context; repo.c is written
 * entirely against this interface and never knows which concrete
 * backend it's talking to.
 *
 * Keys are backend-relative paths using '/' as the component
 * separator, exactly as format.md's "Repository layout" writes them
 * (e.g. "objects/ab/<hex64>", "snapshots/<snapid>.mf") -- never an
 * absolute filesystem path, and never containing the backend's own
 * root.
 */
#ifndef AMISNAP_BACKEND_H
#define AMISNAP_BACKEND_H

#include <stddef.h>

#include "tlv.h"

typedef struct amisnap_backend amisnap_backend;

typedef struct {
    /* Atomic-on-success write of `len` bytes to `key`, creating any
     * missing parent "directories" as needed. A reader must never
     * observe a partial write -- format.md "Backends MUST provide
     * atomic-on-success finalize". Overwriting an existing key is
     * legal (repo.c relies on this being harmless when the bytes are
     * identical, e.g. re-committing after a retry) but callers that
     * want the "never rewritten" dedup guarantee check `exists` first
     * (format.md "Content objects"). Returns AMISNAP_OK or a negative
     * AMISNAP_ERR_* code. */
    int (*put)(amisnap_backend *be, const char *key, const void *data, size_t len);

    /* Reads the whole object at `key` into a fresh buffer at *out
     * (caller owns it: amisnap_buf_free() when done). Returns
     * AMISNAP_OK, AMISNAP_ERR_NOT_FOUND, or another error; *out is
     * untouched on error. */
    int (*get)(amisnap_backend *be, const char *key, amisnap_buf *out);

    /* Returns 1 if `key` exists, 0 if it does not, or a negative
     * AMISNAP_ERR_* code on an I/O failure (distinct from "does not
     * exist" -- callers must not conflate the two). */
    int (*exists)(amisnap_backend *be, const char *key);

    /* Lists the immediate children of `prefix` -- one level, not
     * recursive (matches how snapshots/ and each objects/<hh>/ fan-out
     * bucket are enumerated) -- via `cb(user, name)` once per entry,
     * `name` being just the final path component, not the full key.
     * A prefix that doesn't exist at all lists as empty (AMISNAP_OK,
     * zero callbacks), not an error -- an uninitialized objects/
     * fan-out bucket is a normal, expected state. */
    int (*list)(amisnap_backend *be, const char *prefix,
                void (*cb)(void *user, const char *name), void *user);

    /* Returns AMISNAP_OK or AMISNAP_ERR_NOT_FOUND/other error. */
    int (*remove)(amisnap_backend *be, const char *key);

    void (*close)(amisnap_backend *be);
} amisnap_backend_ops;

struct amisnap_backend {
    const amisnap_backend_ops *ops;
    void *ctx;
};

static inline int amisnap_backend_put(amisnap_backend *be, const char *key,
                                       const void *data, size_t len)
{
    return be->ops->put(be, key, data, len);
}

static inline int amisnap_backend_get(amisnap_backend *be, const char *key, amisnap_buf *out)
{
    return be->ops->get(be, key, out);
}

static inline int amisnap_backend_exists(amisnap_backend *be, const char *key)
{
    return be->ops->exists(be, key);
}

static inline int amisnap_backend_list(amisnap_backend *be, const char *prefix,
                                        void (*cb)(void *user, const char *name), void *user)
{
    return be->ops->list(be, prefix, cb, user);
}

static inline int amisnap_backend_remove(amisnap_backend *be, const char *key)
{
    return be->ops->remove(be, key);
}

static inline void amisnap_backend_close(amisnap_backend *be)
{
    if (be->ops->close)
        be->ops->close(be);
}

#endif /* AMISNAP_BACKEND_H */
