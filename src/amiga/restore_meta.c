/* restore_meta.c -- see restore_meta.h. */
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>

#include "restore_meta.h"

/* SetComment()'s own autodoc: "a pointer to a null-terminated string
 * of up to 80 characters" -- matches FileInfoBlock's fib_Comment
 * TEXT[80]. A comment this module can't fit is a reported degradation
 * (comment_failed++), never a silent truncation. */
#define COMMENT_BUF_LEN 81

static void apply_comment(const char *path, const amisnap_entry_meta *entry,
                           amisnap_restore_meta_result *result)
{
    char buf[COMMENT_BUF_LEN];

    if (!entry->has_comment)
        return;

    if (entry->comment_len + 1 > COMMENT_BUF_LEN) {
        result->comment_failed++;
        return;
    }

    memcpy(buf, entry->comment, entry->comment_len);
    buf[entry->comment_len] = '\0';

    if (SetComment((STRPTR)path, (STRPTR)buf))
        result->comment_ok++;
    else
        result->comment_failed++;
}

static void apply_date(const char *path, const amisnap_entry_meta *entry,
                        amisnap_restore_meta_result *result)
{
    struct DateStamp ds;

    ds.ds_Days = (LONG)entry->date_days;
    ds.ds_Minute = (LONG)entry->date_mins;
    ds.ds_Tick = (LONG)entry->date_ticks;

    /* A documented, EXPECTED failure on OFS/FFS's root directory
     * (SetFileDate()'s own autodoc) counts as date_failed like any
     * other -- restore_meta.h's caller-facing contract already treats
     * every field as best-effort, so this needs no special case here. */
    if (SetFileDate((STRPTR)path, &ds))
        result->date_ok++;
    else
        result->date_failed++;
}

static void apply_owner(const char *path, const amisnap_entry_meta *entry,
                         amisnap_restore_meta_result *result)
{
    LONG owner_info;

    if (!entry->has_owner)
        return;

    /* SetOwner()'s own autodoc: uid in bits 31-16, gid in bits 15-0.
     * Safe to call unconditionally even pre-V39 -- see restore_meta.h's
     * own header comment on why this specific V39 function is an
     * exception to the general "must version-gate" policy. */
    owner_info = (LONG)(((ULONG)entry->uid << 16) | (ULONG)entry->gid);

    if (SetOwner((STRPTR)path, owner_info))
        result->owner_ok++;
    else
        result->owner_failed++;
}

static void apply_protection(const char *path, const amisnap_entry_meta *entry,
                              amisnap_restore_meta_result *result)
{
    if (SetProtection((STRPTR)path, (LONG)entry->prot))
        result->prot_ok++;
    else
        result->prot_failed++;
}

void amisnap_restore_meta_apply(const char *path, const amisnap_entry_meta *entry,
                                 amisnap_restore_meta_result *result)
{
    apply_comment(path, entry, result);
    apply_date(path, entry, result);
    apply_owner(path, entry, result);
    apply_protection(path, entry, result); /* last -- see restore_meta.h */
}

/* dest_root + '/' + entry path -- generous, matching scan.c/restore.c's
 * own fixed-path-buffer convention; not shared with either (this
 * module has no reason to depend on scan.h just for one constant). */
#define RESTORE_META_PATH_BUF_LEN 2304

void amisnap_restore_meta_on_entry(void *user, const amisnap_entry_meta *entry)
{
    amisnap_restore_meta_ctx *ctx = (amisnap_restore_meta_ctx *)user;
    char path[RESTORE_META_PATH_BUF_LEN];
    size_t root_len = strlen(ctx->dest_root);
    size_t needed = root_len + (entry->path_len > 0 ? 1 + entry->path_len : 0) + 1;

    if (needed > sizeof(path)) {
        /* Astronomically unlikely (format.md's own Limits section:
         * paths anywhere near this size are unreachable from a real
         * filesystem) but must degrade explicitly, not overflow the
         * buffer -- there is no single "path too long" counter in
         * amisnap_restore_meta_result, so this is recorded as a
         * failure on every field that would otherwise have been
         * attempted, an honest if blunt signal that something here
         * was skipped rather than silence. */
        ctx->totals.prot_failed++;
        if (entry->has_comment) ctx->totals.comment_failed++;
        ctx->totals.date_failed++;
        if (entry->has_owner) ctx->totals.owner_failed++;
        return;
    }

    if (entry->path_len == 0) {
        /* format.md: empty E_PATH is the root itself. */
        memcpy(path, ctx->dest_root, root_len + 1);
    } else {
        memcpy(path, ctx->dest_root, root_len);
        path[root_len] = '/';
        memcpy(path + root_len + 1, entry->path, entry->path_len);
        path[root_len + 1 + entry->path_len] = '\0';
    }

    amisnap_restore_meta_apply(path, entry, &ctx->totals);
}
