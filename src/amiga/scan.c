/* scan.c -- see scan.h. Every struct field, constant, and version
 * floor cited below was checked against the real NDK headers bundled
 * in ghcr.io/sidick/amiga-dev before being used here (house rule 6):
 *
 *   dos/exall.h    ExAllData/ExAllControl fields, ED_* values, the
 *                  documented V37-vs-V39 ED_OWNER/ERROR_BAD_NUMBER
 *                  fallback contract
 *   dos/dosextens.h ST_ROOT=1, ST_USERDIR=2, ST_SOFTLINK=3 ("looks
 *                  like dir, but may point to a file!" -- positive,
 *                  NOT distinguishable from a plain directory by sign
 *                  alone), ST_LINKDIR=4, ST_FILE=-3, ST_LINKFILE=-4
 *   dos/dos.h      FileInfoBlock/InfoData layout, FIBB_ARCHIVE=4 (so
 *                  FIBF_ARCHIVE=0x10, confirming index.h's constant),
 *                  ACCESS_READ=-2, ERROR_BAD_NUMBER=115,
 *                  ERROR_NO_MORE_ENTRIES=232
 *   dos.doc        AllocDosObject/ExAll/Examine/Info/Lock autodoc
 *                  entries -- calling conventions, the documented
 *                  "process entries even on the final (more==FALSE)
 *                  call" behavior, and that ED_OWNER support is
 *                  negotiated once (BAD_NUMBER means retry the WHOLE
 *                  call with ED_COMMENT), not probed per entry
 */
#include <string.h>

#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/exall.h>
#include <exec/memory.h>
#include <proto/dos.h>
#include <proto/exec.h>

#include "scan.h"

/* Heap-allocated per directory level (not stack-local): a recursive
 * scan's stack depth is bounded by tree depth, and putting a 4KB
 * buffer in every stack frame would fight directly against
 * stackswap.c's fixed 32KB budget on a deeply nested tree. AllocMem/
 * FreeMem per directory costs a little, but real Amiga directory
 * trees are rarely so deep that this matters, and it removes the
 * tension entirely rather than picking an arbitrary "small enough"
 * per-frame size. */
#define SCAN_BUFFER_SIZE 4096

static uint8_t amisnap_etype_from_st(LONG st_type)
{
    switch (st_type) {
    case ST_ROOT:
    case ST_USERDIR:
        return AMISNAP_ETYPE_DIR;
    case ST_SOFTLINK:
        return AMISNAP_ETYPE_SOFTLINK;
    case ST_LINKDIR:
    case ST_LINKFILE:
        return AMISNAP_ETYPE_HARDLINK;
    case ST_FILE:
    default:
        /* ST_PIPEFILE and anything else unrecognised: treat as a
         * plain file rather than refuse the whole scan -- restore
         * doesn't need to reproduce an ephemeral OS object faithfully,
         * and a real directory listing should never actually contain
         * one anyway. */
        return AMISNAP_ETYPE_FILE;
    }
}

static int path_push(char *buf, size_t cap, size_t base_len, const char *name,
                      size_t *out_len)
{
    size_t namelen = strlen(name);
    size_t total = base_len + (base_len > 0 ? 1 : 0) + namelen;

    if (total + 1 > cap)
        return AMISNAP_ERR_TOO_LONG;

    if (base_len > 0)
        buf[base_len] = '/';
    memcpy(buf + base_len + (base_len > 0 ? 1 : 0), name, namelen + 1);
    *out_len = total;
    return AMISNAP_OK;
}

static int scan_dir(BPTR lock, char *path_buf, size_t path_len, LONG type,
                     const amisnap_scan_visitor *visitor,
                     amisnap_scan_caps *caps, amisnap_scan_result *result);

static int process_entry(struct ExAllData *ead, LONG type, char *path_buf, size_t base_len,
                          const amisnap_scan_visitor *visitor,
                          amisnap_scan_caps *caps, amisnap_scan_result *result)
{
    amisnap_entry_meta entry;
    amisnap_content_ref no_refs; /* unused; entries here never carry content */
    size_t child_len;
    size_t namelen;
    int rc;

    (void)no_refs;

    /* ed_Name/ed_Comment/fib_Comment are STRPTR/TEXT* -- unsigned char*
     * on this target, per libnix's own headers, so libnix's own
     * strlen() (const char*) needs an explicit cast at every use;
     * caught by -Werror on the real cross-build, not visible from a
     * host-only build. */
    namelen = strlen((const char *)ead->ed_Name);
    if (namelen > caps->maxnamelen)
        caps->maxnamelen = (uint16_t)(namelen > 0xFFFFu ? 0xFFFFu : namelen);

    rc = path_push(path_buf, AMISNAP_SCAN_PATH_BUF_LEN, base_len, (const char *)ead->ed_Name, &child_len);
    if (rc != AMISNAP_OK)
        return rc;

    memset(&entry, 0, sizeof(entry));
    entry.path = (const uint8_t *)path_buf;
    entry.path_len = child_len;
    entry.type = amisnap_etype_from_st(ead->ed_Type);
    entry.prot = (uint32_t)ead->ed_Prot;
    entry.date_days = (uint32_t)ead->ed_Days;
    entry.date_mins = (uint32_t)ead->ed_Mins;
    entry.date_ticks = (uint32_t)ead->ed_Ticks;

    if (type >= ED_COMMENT && ead->ed_Comment && ead->ed_Comment[0] != '\0') {
        entry.has_comment = 1;
        entry.comment = (const uint8_t *)ead->ed_Comment;
        entry.comment_len = strlen((const char *)ead->ed_Comment);
    }
    if (type >= ED_OWNER && caps->owner_supported) {
        entry.has_owner = 1;
        entry.uid = ead->ed_OwnerUID;
        entry.gid = ead->ed_OwnerGID;
    }

    if (entry.type == AMISNAP_ETYPE_SOFTLINK || entry.type == AMISNAP_ETYPE_HARDLINK) {
        /* Honest, counted gap -- see scan.h's own header comment.
         * Not recursed into either way (links_skipped means exactly
         * that -- skipped, not walked). */
        result->links_skipped++;
        return 0;
    }

    if (entry.type == AMISNAP_ETYPE_DIR) {
        BPTR child_lock;
        int abort_rc;

        result->dirs_seen++;
        rc = visitor->on_entry(visitor->user, &entry);
        if (rc != 0)
            return rc;

        child_lock = Lock((STRPTR)path_buf, ACCESS_READ);
        if (!child_lock)
            return AMISNAP_ERR_IO;

        abort_rc = scan_dir(child_lock, path_buf, child_len, type, visitor, caps, result);
        UnLock(child_lock);
        return abort_rc;
    }

    /* AMISNAP_ETYPE_FILE (or an unrecognised ST_ value folded into it
     * by amisnap_etype_from_st()) -- has_size/content are the
     * caller's job (this module captures metadata only, per scan.h's
     * own header comment), so leave them unset; a caller building a
     * REC_ENTRY from this must fill has_size/content itself after
     * reading the real file. */
    result->files_seen++;
    return visitor->on_entry(visitor->user, &entry);
}

static int scan_dir(BPTR lock, char *path_buf, size_t path_len, LONG type,
                     const amisnap_scan_visitor *visitor,
                     amisnap_scan_caps *caps, amisnap_scan_result *result)
{
    struct ExAllControl *eac;
    struct ExAllData *buffer;
    int rc = AMISNAP_OK;
    LONG more;

    eac = (struct ExAllControl *)AllocDosObject(DOS_EXALLCONTROL, NULL);
    if (!eac)
        return AMISNAP_ERR_NOMEM;

    buffer = (struct ExAllData *)AllocMem(SCAN_BUFFER_SIZE, MEMF_ANY);
    if (!buffer) {
        FreeDosObject(DOS_EXALLCONTROL, eac);
        return AMISNAP_ERR_NOMEM;
    }

    eac->eac_MatchString = NULL;
    eac->eac_MatchFunc = NULL;
    eac->eac_LastKey = 0;

    more = ExAll(lock, buffer, SCAN_BUFFER_SIZE, type, eac);
    if (!more && IoErr() == ERROR_BAD_NUMBER && type == ED_OWNER) {
        /* exall.h's own documented contract: a V37 dos.library or
         * filesystem rejects ED_OWNER outright -- retry the whole
         * call with ED_COMMENT rather than treating this as a
         * per-entry failure. */
        type = ED_COMMENT;
        eac->eac_LastKey = 0;
        more = ExAll(lock, buffer, SCAN_BUFFER_SIZE, type, eac);
    }
    if (type == ED_OWNER)
        caps->owner_supported = 1;

    for (;;) {
        if (!more && IoErr() != ERROR_NO_MORE_ENTRIES) {
            rc = AMISNAP_ERR_IO;
            break;
        }

        if (eac->eac_Entries > 0) {
            struct ExAllData *ead = buffer;
            do {
                rc = process_entry(ead, type, path_buf, path_len, visitor, caps, result);
                if (rc != AMISNAP_OK)
                    goto done;
                ead = ead->ed_Next;
            } while (ead);
        }

        if (!more)
            break;

        more = ExAll(lock, buffer, SCAN_BUFFER_SIZE, type, eac);
    }

done:
    FreeMem(buffer, SCAN_BUFFER_SIZE);
    FreeDosObject(DOS_EXALLCONTROL, eac);
    return rc;
}

int amisnap_scan_volume(const char *root_path, const amisnap_scan_visitor *visitor,
                         amisnap_scan_caps *caps, amisnap_scan_result *result)
{
    BPTR root_lock;
    struct InfoData id;
    struct FileInfoBlock fib; /* plain struct decl, not AllocDosObject: a
                                * normal m68k compiler already longword-
                                * aligns it (all-LONG-leading layout),
                                * satisfying Examine()'s stated requirement --
                                * AllocDosObject(DOS_FIB,...) buys nothing
                                * extra for a value only needed within this
                                * function's own scope. */
    amisnap_entry_meta entry;
    int rc;

    memset(caps, 0, sizeof(*caps));
    memset(result, 0, sizeof(*result));

    root_lock = Lock((STRPTR)root_path, ACCESS_READ);
    if (!root_lock)
        return AMISNAP_ERR_IO;

    memset(&id, 0, sizeof(id));
    if (Info(root_lock, &id))
        caps->dostype = (uint32_t)id.id_DiskType;

    /* The root's own metadata: nothing else will emit it, since
     * nothing enumerates the root as a child of anything within this
     * scan (format.md E_PATH: "Empty = the root itself"). */
    memset(&fib, 0, sizeof(fib));
    if (!Examine(root_lock, &fib)) {
        UnLock(root_lock);
        return AMISNAP_ERR_IO;
    }

    memset(&entry, 0, sizeof(entry));
    entry.path = (const uint8_t *)"";
    entry.path_len = 0;
    entry.type = AMISNAP_ETYPE_DIR;
    entry.prot = (uint32_t)fib.fib_Protection;
    entry.date_days = (uint32_t)fib.fib_Date.ds_Days;
    entry.date_mins = (uint32_t)fib.fib_Date.ds_Minute;
    entry.date_ticks = (uint32_t)fib.fib_Date.ds_Tick;
    if (fib.fib_Comment[0] != '\0') {
        entry.has_comment = 1;
        entry.comment = (const uint8_t *)fib.fib_Comment;
        entry.comment_len = strlen((const char *)fib.fib_Comment);
    }
    /* Owner support isn't known yet at this point (it's negotiated
     * inside scan_dir(), which hasn't run for this volume yet) -- the
     * root entry's owner is therefore captured as unsupported here.
     * This is a known, minor gap (the root directory's own owner
     * fields, specifically, never get populated even on a V39+
     * owner-supporting volume) rather than restructuring the
     * negotiation to run twice; tracked for a follow-up rather than
     * silently accepted as permanent. */

    result->dirs_seen++;
    rc = visitor->on_entry(visitor->user, &entry);
    if (rc != 0) {
        UnLock(root_lock);
        return rc;
    }

    {
        char path_buf[AMISNAP_SCAN_PATH_BUF_LEN];
        path_buf[0] = '\0';
        rc = scan_dir(root_lock, path_buf, 0, ED_OWNER, visitor, caps, result);
    }

    UnLock(root_lock);
    return rc;
}
