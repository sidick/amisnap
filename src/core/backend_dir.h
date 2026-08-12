/* backend_dir.h -- the directory backend: docs/format.md's Tier 1
 * ("mounted filesystem... AmiSnap just does DOS I/O to a path"). On
 * Amiga this targets any mounted volume directly; on the host it is
 * also the CI test backend (implementation-plan.md's module map) --
 * same code, same file layout, no platform-specific behavior beyond
 * what the standard C library already abstracts (fopen/mkdir/opendir/
 * rename/remove).
 */
#ifndef AMISNAP_BACKEND_DIR_H
#define AMISNAP_BACKEND_DIR_H

#include "backend.h"

/* Generous fixed bound on root + key length this implementation
 * builds real paths within; a key exceeding it fails with
 * AMISNAP_ERR_MALFORMED rather than overflowing a buffer. Repository
 * keys are short and structured (format.md "Repository layout"), so
 * this is far beyond anything the format itself produces. */
#define AMISNAP_BACKEND_DIR_MAX_PATH 1024

/* Opens (creating if absent) a directory-backed repository rooted at
 * `root`. Returns AMISNAP_OK with *out populated (ops + an owned
 * context later released by amisnap_backend_close()), or a negative
 * AMISNAP_ERR_* code. */
int amisnap_backend_dir_open(const char *root, amisnap_backend *out);

#endif /* AMISNAP_BACKEND_DIR_H */
