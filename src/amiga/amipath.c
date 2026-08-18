/* amipath.c -- see amipath.h. */
#include <string.h>

#include "amipath.h"
#include "tlv.h" /* AMISNAP_OK / AMISNAP_ERR_TOO_LONG */

int amisnap_join_amiga_path(const char *root, const uint8_t *relpath, size_t rellen,
                             char *buf, size_t bufsize)
{
    size_t root_len = strlen(root);
    /* A root already ending in a separator gets no extra one: ':' is the
     * volume/assign separator ("Work:" + "Sub" = "Work:Sub"), and '/'
     * is the directory separator. Critically, a trailing '/' must NOT
     * get another appended -- "Work:Dest/" + "Sub" would become
     * "Work:Dest//Sub", and in AmigaDOS an empty path component ("//")
     * means "up one level" (the parent), so the join would silently
     * resolve to "Work:Sub" and operate on the wrong directory. This
     * matches backend_dir.c's own join_path, which strips a trailing
     * separator at open; here the two joiners must agree, since a
     * restore uses backend_dir for the object write but this joiner for
     * the metadata pass (restore_meta.c) -- a disagreement applied
     * SetProtection/SetFileDate to same-named entries in the parent. */
    int root_ends_sep = root_len > 0 &&
                        (root[root_len - 1] == ':' || root[root_len - 1] == '/');
    int need_sep = rellen > 0 && !root_ends_sep;
    size_t needed = root_len + (need_sep ? 1 : 0) + rellen + 1;

    if (needed > bufsize)
        return AMISNAP_ERR_TOO_LONG;

    memcpy(buf, root, root_len);
    if (need_sep)
        buf[root_len] = '/';
    if (rellen > 0)
        memcpy(buf + root_len + (need_sep ? 1 : 0), relpath, rellen);
    buf[root_len + (need_sep ? 1 : 0) + rellen] = '\0';
    return AMISNAP_OK;
}
