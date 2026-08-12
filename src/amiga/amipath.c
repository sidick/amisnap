/* amipath.c -- see amipath.h. */
#include <string.h>

#include "amipath.h"
#include "tlv.h" /* AMISNAP_OK / AMISNAP_ERR_TOO_LONG */

int amisnap_join_amiga_path(const char *root, const uint8_t *relpath, size_t rellen,
                             char *buf, size_t bufsize)
{
    size_t root_len = strlen(root);
    int root_ends_colon = root_len > 0 && root[root_len - 1] == ':';
    int need_sep = rellen > 0 && !root_ends_colon;
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
