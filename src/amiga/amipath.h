/* amipath.h -- joining an AmigaDOS root path with a manifest-relative
 * path (format.md's '/'-separated E_PATH). Shared by scan.c,
 * restore_meta.c, and src/cli/main.c, which all need exactly this.
 *
 * Confirmed live under Copperline (implementation-plan.md Phase 1
 * item 8, 2026-08-12), not assumed: a root ending in ':' (a bare
 * volume or assign, e.g. "Source:") must NOT get a '/' inserted
 * before the relative part -- "Source:/Sub" fails to Lock() (IoErr
 * 209), only "Source:Sub" works. A root NOT ending in ':' (e.g.
 * "Source:SomeDir") DOES need the '/' separator, exactly like a
 * normal multi-component path. This was an unverified assumption in
 * three places before this file existed (all three said "unconditional
 * separator is harmless" -- it is not); fixed once, here, rather than
 * patched independently and inconsistently in each.
 */
#ifndef AMISNAP_AMIPATH_H
#define AMISNAP_AMIPATH_H

#include <stddef.h>
#include <stdint.h>

/* Joins `root` with `relpath`/`rellen` (empty rellen = root itself,
 * per format.md E_PATH's own "empty = the root" convention) into a
 * real AmigaDOS path in `buf`. Returns AMISNAP_ERR_TOO_LONG (buf left
 * unmodified) rather than overflowing if it doesn't fit. */
int amisnap_join_amiga_path(const char *root, const uint8_t *relpath, size_t rellen,
                             char *buf, size_t bufsize);

#endif /* AMISNAP_AMIPATH_H */
