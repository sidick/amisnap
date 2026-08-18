/* exclude.h -- the backup exclude list (implementation-plan.md Phase 2
 * item 8's deferred design note): a plain-text file naming files/
 * directories a SNAPSHOT should never walk into or capture, read by
 * scan.c *before* recursing so an excluded subtree never even gets
 * Examine()'d/ExAll()'d, matching docs/proposal.md's already-planned
 * "include/exclude patterns for snapshot".
 *
 * Portable core (host-buildable/-testable), matching the module map's
 * "portable core, thin Amiga rind" split -- pattern matching is pure
 * string logic, nothing here needs dos.library. Local-only, like
 * index.h's cache: not part of the wire format, never read by another
 * repository implementation, free to change shape without a format
 * version bump.
 *
 * File format, one pattern per line (gitignore's well-known subset,
 * deliberately not AmigaDOS's own '#?'/'~' pattern syntax -- this is a
 * plain list a user hand-edits, and gitignore's rules are the more
 * widely understood convention for "one path pattern per line"):
 *
 *   - Blank lines and lines whose first non-blank character is '#' are
 *     ignored (comments).
 *   - '*' matches any run of characters (including none) within one
 *     path component; '?' matches exactly one. Neither crosses a '/'.
 *   - A pattern containing no '/' (other than an optional trailing
 *     one) matches against every path component at any depth -- e.g.
 *     "*.info" excludes ANY entry named "*.info", not just one at the
 *     source root.
 *   - A pattern containing an interior '/' (a leading '/' is an
 *     explicit, equivalent way to say the same thing) is anchored: it
 *     matches the full path relative to the scanned root only.
 *   - A trailing '/' restricts the pattern to directories -- matching
 *     it excludes the whole subtree under that directory (scan.c never
 *     recurses into an excluded directory), but never a plain file of
 *     the same name.
 *
 * Matching is case-insensitive throughout: every native Amiga
 * filesystem this tool targets (OFS/FFS, "international" or not, PFS3)
 * is case-preserving but case-insensitive, and a case-sensitive
 * exclude list would silently fail to match a file whose case differs
 * from what the user typed -- the fail-open direction principle 1
 * treats as the dangerous one for an exclude list specifically (a
 * pattern that should have matched but didn't means the file gets
 * backed up anyway, which is safe; the reverse -- silently skipping
 * something the user meant to keep -- is what case-sensitivity risks
 * here, so case-insensitive is the conservative choice).
 */
#ifndef AMISNAP_EXCLUDE_H
#define AMISNAP_EXCLUDE_H

#include <stddef.h>

typedef struct {
    const char *text; /* borrowed into amisnap_exclude_list.raw; NUL-terminated, no trailing '/' */
    size_t len;
    int dir_only;  /* line ended in '/' */
    int anchored;  /* line had an interior (or leading) '/' -- match the full path, not any component */
} amisnap_exclude_pattern;

typedef struct {
    char *raw; /* owned copy of the source text; patterns[].text points into it */
    amisnap_exclude_pattern *patterns;
    size_t count, cap;
} amisnap_exclude_list;

/* Parses `text`/`len` (the exclude file's raw bytes, not necessarily
 * NUL-terminated) into `out`. The input is copied, not borrowed -- the
 * caller may free it immediately after this returns. Always succeeds
 * except on allocation failure (AMISNAP_ERR_NOMEM); a malformed line
 * can't occur (every byte is either a comment, blank, or a valid glob
 * pattern by construction). `text` may be NULL if `len` is 0 (an empty
 * list). */
int amisnap_exclude_parse(const char *text, size_t len, amisnap_exclude_list *out);

void amisnap_exclude_free(amisnap_exclude_list *list);

/* Does any pattern in `list` match `path` (scan.c's format.md-style
 * relative path -- no leading '/', "" only for the root, which callers
 * should never pass here since the root itself can't be excluded)?
 * `is_dir` selects whether dir_only patterns are even considered.
 * `list` may be NULL (no exclusions at all -- always returns 0). */
int amisnap_exclude_match(const amisnap_exclude_list *list, const char *path, size_t path_len,
                           int is_dir);

#endif /* AMISNAP_EXCLUDE_H */
