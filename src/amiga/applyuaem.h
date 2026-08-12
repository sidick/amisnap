/* applyuaem.h -- ACTION=APPLYUAEM: walks a directory tree applying
 * .uaem sidecar files (protection/datestamp/comment) to their sibling
 * entry, then leaves the sidecar in place (idempotent -- safe to
 * re-run, matching restore/verify's own "never destructive" posture).
 *
 * The companion to tools/amisnap_reader.py's own `restore --uaem`:
 * that tool can restore file *content* faithfully on a bare PC (it
 * has BLAKE2s-256 verification and no Amiga dependency) but can't
 * apply AmigaDOS-specific metadata at all (no fib_Protection concept,
 * no FileNote, no shared uid/gid namespace) -- so it writes .uaem
 * sidecars instead, the same FS-UAE/Amiberry/Copperline host-
 * directory-metadata convention already used and documented
 * elsewhere in this project (implementation-plan.md item 8). This
 * tool is what turns those sidecars into a real, bit-perfect restore
 * once the tree reaches a real Amiga (or an emulator's own host-
 * directory filesystem, which reads them natively already -- this
 * tool is for when it doesn't, e.g. after copying the tree onto a
 * real AmigaDOS volume via Zmodem/network/floppy).
 */
#ifndef AMISNAP_APPLYUAEM_H
#define AMISNAP_APPLYUAEM_H

#include <stddef.h>

typedef struct {
    size_t applied;   /* .uaem files successfully parsed and applied */
    size_t failed;    /* found but couldn't be parsed, or the target
                        * entry didn't exist / couldn't be modified */
} amisnap_applyuaem_result;

/* Recursively walks `root_path`. Returns AMISNAP_OK once the walk
 * completes (check *result for what actually happened -- a single
 * bad .uaem file is reported via result->failed, not a fatal error
 * for the whole run) or a negative AMISNAP_ERR_* code if `root_path`
 * itself can't even be locked. */
int amisnap_applyuaem_run(const char *root_path, amisnap_applyuaem_result *result);

#endif /* AMISNAP_APPLYUAEM_H */
