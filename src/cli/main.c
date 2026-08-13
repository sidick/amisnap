/* main.c -- AmiSnap CLI entry point: ReadArgs-based front end wiring
 * every module built so far (backend_dir, repo, scan, restore,
 * restore_meta, index) into the four working verbs (docs/proposal.md
 * "Operations (v1)": snapshot, restore, list, verify -- prune is
 * phase 2, not wired here).
 *
 * Verb dispatch: a single combined ReadArgs template with ACTION as
 * the one positional (/A, required) field and everything else /K
 * (keyword-only: REPO=..., SOURCE=..., ...). Deliberately not
 * per-verb positional templates (which would need a second ReadArgs
 * pass over a CSource-wrapped remainder string) -- with one shared
 * template, a field's position in the template isn't verb-aware, so
 * positional (unlabeled) values would land in the wrong slot for
 * different verbs; keyword syntax sidesteps that ambiguity entirely.
 * Each verb validates its own required fields manually after parsing,
 * since ReadArgs' own /A can't be conditional on ACTION's value.
 *
 * m68k-amigaos-gcc only: real_main() runs behind amisnap_stackswap_run()
 * (docs/implementation-plan.md "Stack management"), which every
 * AmiSnap entry point must do before any real work.
 *
 * RC convention (dos/dos.h RETURN_*, verified against the real NDK):
 * RETURN_OK (0) full success; RETURN_WARN (5) completed with some
 * entries degraded/skipped (reported, not fatal -- implementation-
 * plan.md: restore/verify degrade explicitly, never silently);
 * RETURN_ERROR (10) a usage/argument problem; RETURN_FAIL (20) the
 * operation could not run at all (repository unreachable, out of
 * memory, a corrupt/missing manifest).
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dos/dos.h>
#include <dos/rdargs.h>
#include <proto/dos.h>

#include "amipath.h"
#include "backend_dir.h"
#include "index.h"
#include "applyuaem.h"
#include "prune.h"
#include "repo.h"
#include "restore.h"
#include "restore_meta.h"
#include "scan.h"
#include "socket.h"
#include "stackswap.h"
#include "webdav.h"
#include "xxhash32.h"

#ifndef VERSION
#define VERSION 0
#endif
#ifndef REVISION
#define REVISION 0
#endif

/* Standard AmigaDOS "$VER:" version cookie (RKRM: DOS, "The Version
 * Command") -- date is DD.MM.YYYY digits per the convention; bump it with
 * version.mk on release. `make dist` greps the binary for exactly this
 * string, so keep the format "AmiSnap <VERSION>.<REVISION> (date)". */
#define XSTR(s) STR(s)
#define STR(s) #s
static const char verstring[] =
    "$VER: AmiSnap " XSTR(VERSION) "." XSTR(REVISION) " (12.08.2026)";

/* --- logging ------------------------------------------------------------
 * LOG=<path> (implementation-plan.md's item 8 scope, decided over
 * relying on untested Startup-Sequence '>' file redirection in a
 * minimal, no-Workbench boot): when given, AmiSnap opens the file
 * itself via fopen() and both normal output (amilog) and error output
 * (amilog_err) go there instead of stdout/stderr -- one combined log
 * a host-mounted directory can read back after the run, no Shell
 * redirection semantics depended on. Without LOG=, behaves exactly as
 * before (stdout/stderr). */
static FILE *g_log = NULL;

static void amilog(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log ? g_log : stdout, fmt, ap);
    va_end(ap);
}

static void amilog_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log ? g_log : stderr, fmt, ap);
    va_end(ap);
}

/* --- backend dispatch: REPO=/DEST= is either a native AmigaDOS path
 * (mounted volume / assign, docs/proposal.md Tier 1) or a
 * "http://"/"https://" URL (Tier 2, WebDAV) -- decided purely by the
 * scheme prefix, same convention curl/git use for the same ambiguity.
 * bsdsocket.library is opened lazily, only the first time a WebDAV
 * destination is actually used: a pure mounted-volume backup (the
 * common case, e.g. a local NAS over SMB) must not require any TCP/IP
 * stack to be installed at all. --------------------------------------- */

static int g_socket_lib_open = 0;
static amisnap_transport g_bsdsocket_transport;

static int open_backend(const char *path, amisnap_backend *out)
{
    if (strncmp(path, "http://", 7) == 0 || strncmp(path, "https://", 8) == 0) {
        amisnap_webdav_url url;
        amisnap_webdav_config cfg;
        int rc;

        rc = amisnap_webdav_parse_url(path, &url);
        if (rc != AMISNAP_OK) {
            amilog_err("AmiSnap: malformed WebDAV URL \"%s\"\n", path);
            return rc;
        }

        if (url.tls) {
            /* Deliberately disabled, not merely unfinished:
             * implementation-plan.md Phase 3 item 4's own retest found
             * a real, CPU-speed-independent hang in AmiSSL's blocking
             * SSL_set_fd()+SSL_connect() path on this platform (also
             * independently hit and documented by a second AmiSSL
             * client, micropython's own Amiga port) -- confirmed with
             * a 14x clock increase plus JIT making no difference at
             * all, not merely suspected. tls.c's own soft-load/cert-
             * verification/connection-setup logic is confirmed correct
             * up to that point and stays in the tree, ready to wire
             * back in once rebuilt around a non-blocking BIO-pair pump
             * (the fix micropython's own modssl.c already proves works
             * here) -- but actually reaching a hung connection from the
             * CLI is a worse failure mode for a backup tool than a
             * clear refusal, so this path is refused unconditionally
             * for now rather than left reachable. */
            amilog_err("AmiSnap: \"%s\" needs TLS (https://) -- currently disabled, "
                       "not merely unimplemented: AmiSSL has a known, confirmed "
                       "handshake hang on this platform (see implementation-plan.md "
                       "Phase 3 item 4) -- use an http:// destination instead\n", path);
            return AMISNAP_ERR_IO;
        }

        if (!g_socket_lib_open) {
            rc = amisnap_socket_lib_open();
            if (rc != AMISNAP_OK) {
                amilog_err("AmiSnap: bsdsocket.library not available -- \"%s\" needs "
                           "a running TCP/IP stack\n", path);
                return rc;
            }
            g_bsdsocket_transport.ops = &amisnap_bsdsocket_transport_ops;
            g_bsdsocket_transport.ctx = NULL;
            g_socket_lib_open = 1;
        }

        memset(&cfg, 0, sizeof(cfg));
        cfg.host = url.host;
        cfg.port = url.port;
        cfg.base_path = url.base_path;
        if (url.username[0]) {
            cfg.username = url.username;
            cfg.password = url.password;
        }
        /* amisnap_backend_webdav_open() copies every string out of cfg/
         * url synchronously before returning (webdav.c's own dup_str()
         * calls) -- url/cfg going out of scope right after this call is
         * safe, same as backend_dir_open()'s own `root` parameter. */
        return amisnap_backend_webdav_open(&cfg, &g_bsdsocket_transport, out);
    }

    return amisnap_backend_dir_open(path, out);
}

/* --- shared helpers --------------------------------------------------- */

#define MAX_SNAPSHOTS 1024

typedef struct {
    char ids[MAX_SNAPSHOTS][17];
    int count;
} snapshot_list;

static void collect_snapshot_cb(void *user, const char *snapid)
{
    snapshot_list *list = (snapshot_list *)user;
    if (list->count < MAX_SNAPSHOTS) {
        memcpy(list->ids[list->count], snapid, 17);
        list->count++;
    }
}

static int strcmp_qsort(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Lists every snapshot in `be` (via amisnap_repo_list_snapshots,
 * capped at MAX_SNAPSHOTS -- a real, documented limit, not silently
 * truncated: callers needing more must wait for phase 2's prune/
 * proper index work) sorted lexicographically, which format.md's
 * snapid design makes equivalent to chronological order. Returns
 * AMISNAP_OK or a backend error. */
static int list_all_snapshots(amisnap_backend *be, snapshot_list *out)
{
    int rc;
    out->count = 0;
    rc = amisnap_repo_list_snapshots(be, collect_snapshot_cb, out);
    if (rc != AMISNAP_OK)
        return rc;
    qsort(out->ids, (size_t)out->count, sizeof(out->ids[0]), strcmp_qsort);
    return AMISNAP_OK;
}

/* Resolves SNAPID: if the user supplied one, use it verbatim
 * (validated only by the later backend_get -- a bad id just reports
 * AMISNAP_ERR_NOT_FOUND, an honest failure). Otherwise the latest
 * (lexicographically greatest, per format.md's snapid design)
 * snapshot in the repository. Returns AMISNAP_OK, AMISNAP_ERR_NOT_FOUND
 * if the repository has no snapshots at all and none was requested,
 * or a backend error from listing. */
static int resolve_snapid(amisnap_backend *be, const char *requested, char out[17])
{
    if (requested && requested[0] != '\0') {
        strncpy(out, requested, 16);
        out[16] = '\0';
        return AMISNAP_OK;
    }

    {
        snapshot_list list;
        int rc = list_all_snapshots(be, &list);
        if (rc != AMISNAP_OK)
            return rc;
        if (list.count == 0)
            return AMISNAP_ERR_NOT_FOUND;
        memcpy(out, list.ids[list.count - 1], 17);
        return AMISNAP_OK;
    }
}

/* Fetches and decodes the manifest for `snapid` from `be`. Caller
 * frees *mf_out via amisnap_buf_free() when done. */
static int fetch_manifest(amisnap_backend *be, const char *snapid, amisnap_buf *mf_out)
{
    char key[32];
    snprintf(key, sizeof(key), "snapshots/%s.mf", snapid);
    return amisnap_backend_get(be, key, mf_out);
}

/* --- snapshot ----------------------------------------------------------- */

static int caps_only_on_entry(void *user, const amisnap_entry_meta *entry)
{
    (void)user; (void)entry;
    return 0;
}

typedef struct {
    amisnap_repo_writer *rw;
    const char *source_root;
    const amisnap_index *prev_index; /* NULL on a first-ever backup (no previous snapshot) */
    int paranoid;
    size_t files_ok, files_failed, files_unchanged, files_paranoid_mismatch;
} snapshot_ctx;

/* Sets the archive bit on the just-backed-up source file (best-effort,
 * failure silently ignored -- see below) so a later snapshot can
 * recognize it as provably unchanged via amisnap_index_unchanged().
 * implementation-plan.md's "Decisions since the proposal": "the
 * filesystem clears the bit when a file is written; backup software
 * sets it" -- AmiSnap is that backup software, and nothing else in
 * this codebase ever sets this bit, so without this call the fast path
 * below could never fire on a second run.
 *
 * Best-effort because a failure here (write-protected media, a
 * filesystem that doesn't support protection bits) doesn't lose or
 * corrupt anything already safely written to the repository -- it
 * only means the NEXT run won't get the fast-path speed-up for this
 * one file and will fall back to a full read+hash, which is always
 * correct, just slower. Not worth failing an otherwise-successful
 * backup over. */
static void mark_backed_up(const char *path, uint32_t prot)
{
    SetProtection((STRPTR)path, (LONG)(prot | AMISNAP_FIBF_ARCHIVE));
}

typedef struct {
    BPTR fh;
} amiga_chunk_read_ctx;

/* repo.h's amisnap_repo_writer_file_chunked()'s own read_fn contract:
 * fill buf with up to `want` bytes, fewer only at real EOF. Read()'s
 * own autodoc: negative return is a real I/O error, 0 is a clean EOF
 * (which repo.c's own loop already treats as "got=0, stop" via this
 * function's normal *got=0 return -- no special case needed here). */
static int amiga_chunk_read(void *ctx_v, void *buf, size_t want, size_t *got)
{
    amiga_chunk_read_ctx *ctx = (amiga_chunk_read_ctx *)ctx_v;
    LONG n = Read(ctx->fh, buf, (LONG)want);
    if (n < 0) return AMISNAP_ERR_IO;
    *got = (size_t)n;
    return AMISNAP_OK;
}

static int snapshot_on_entry(void *user, const amisnap_entry_meta *entry)
{
    snapshot_ctx *ctx = (snapshot_ctx *)user;
    amisnap_entry_meta e = *entry; /* local mutable copy -- writer_file overwrites size/content */
    int rc;

    if (entry->type == AMISNAP_ETYPE_DIR)
        return amisnap_repo_writer_entry(ctx->rw, &e);

    /* AMISNAP_ETYPE_FILE: read the real content from the source
     * volume (scan.c deliberately captures metadata only -- see
     * scan.h). Links never reach here (scan.c doesn't emit them at
     * all yet -- see its own header comment on that gap). */
    {
        char path[AMISNAP_SCAN_PATH_BUF_LEN + 256];
        BPTR lock, fh;
        struct FileInfoBlock fib;
        LONG size;
        uint8_t *data = NULL;
        const amisnap_entry_meta *prev;
        int unchanged;

        rc = amisnap_join_amiga_path(ctx->source_root, entry->path, entry->path_len, path, sizeof(path));
        if (rc != AMISNAP_OK) { ctx->files_failed++; return 0; }

        lock = Lock((STRPTR)path, ACCESS_READ);
        if (!lock || !Examine(lock, &fib)) {
            if (lock) UnLock(lock);
            ctx->files_failed++;
            return 0;
        }
        size = fib.fib_Size;
        UnLock(lock);

        /* scan.c deliberately never sets has_size/size (it's a
         * metadata-only walk) -- this is the one place that does, and
         * it must happen before the amisnap_index_unchanged() check
         * below, which compares it. */
        e.has_size = 1;
        e.size = (uint64_t)size;

        prev = ctx->prev_index ? amisnap_index_lookup(ctx->prev_index, entry->path, entry->path_len) : NULL;
        unchanged = prev && amisnap_index_unchanged(prev, &e);

        /* Pure fast path (metadata-first, no paranoid re-check): every
         * field index_unchanged() checks already proves this file's
         * bytes are identical to what the previous snapshot already
         * has safely stored, so reuse its content refs verbatim
         * without ever reading the file at all. */
        if (unchanged && !ctx->paranoid) {
            e.content = prev->content;
            e.content_count = prev->content_count;
            rc = amisnap_repo_writer_entry(ctx->rw, &e);
            if (rc != AMISNAP_OK) { ctx->files_failed++; return 0; }
            ctx->files_ok++;
            ctx->files_unchanged++;
            mark_backed_up(path, e.prot);
            return 0;
        }

        /* Files over the chunk threshold never get malloc'd whole --
         * a real Amiga's RAM budget can't always afford it -- so they
         * split into repo.c's own streaming chunked writer instead.
         * PARANOID mode's byte-for-byte re-check (below, for small
         * files) is deliberately skipped here even when `unchanged`:
         * reading the whole file just to verify a metadata match
         * would defeat the entire point of chunking in the first
         * place. A known, honest scope limit -- large files still get
         * the ordinary metadata-trust fast path even under PARANOID;
         * only small files get the full re-check. */
        if ((uint64_t)size > AMISNAP_DEFAULT_CHUNK_SIZE) {
            if (unchanged) {
                e.content = prev->content;
                e.content_count = prev->content_count;
                rc = amisnap_repo_writer_entry(ctx->rw, &e);
                if (rc != AMISNAP_OK) { ctx->files_failed++; return 0; }
                ctx->files_ok++;
                ctx->files_unchanged++;
                mark_backed_up(path, e.prot);
                return 0;
            }

            {
                amiga_chunk_read_ctx cctx;
                cctx.fh = Open((STRPTR)path, MODE_OLDFILE);
                if (!cctx.fh) { ctx->files_failed++; return 0; }
                rc = amisnap_repo_writer_file_chunked(ctx->rw, &e, (uint64_t)size,
                                                       AMISNAP_DEFAULT_CHUNK_SIZE,
                                                       amiga_chunk_read, &cctx);
                Close(cctx.fh);
            }
            if (rc != AMISNAP_OK) { ctx->files_failed++; return 0; }
            ctx->files_ok++;
            mark_backed_up(path, e.prot);
            return 0;
        }

        /* Everything else (a file at or under the chunk threshold)
         * needs the actual bytes, read whole into memory: a genuine
         * change, OR paranoid mode re-checking a metadata match before
         * trusting it (docs/proposal.md: "Optional paranoid mode adds
         * xxHash32 verification of allegedly-unchanged files"). */
        if (size > 0) {
            LONG got = 0;
            data = (uint8_t *)malloc((size_t)size);
            if (!data) { ctx->files_failed++; return 0; }

            fh = Open((STRPTR)path, MODE_OLDFILE);
            if (!fh) { free(data); ctx->files_failed++; return 0; }
            while (got < size) {
                LONG n = Read(fh, data + got, size - got);
                if (n <= 0) break;
                got += n;
            }
            Close(fh);
            if (got != size) { free(data); ctx->files_failed++; return 0; }
        }

        if (unchanged) {
            /* Paranoid re-check: cross-check the CHEAP xxHash32 (near-
             * memory-speed, docs/proposal.md's own CPU-budget case for
             * using it freely) against what was stored alongside the
             * previous entry's content, rather than trusting the
             * metadata match blindly. A previous entry with no xhash
             * at all (predates repo.c always recording one) can't be
             * cross-checked -- degrades to "can't confirm, so don't
             * claim it", i.e. falls through to a full re-hash+write
             * below, the same as a genuine mismatch. */
            if (prev->has_xhash &&
                amisnap_xxh32(data, (size_t)(size > 0 ? size : 0), 0) == prev->xhash) {
                free(data);
                e.content = prev->content;
                e.content_count = prev->content_count;
                e.has_xhash = 1;
                e.xhash = prev->xhash;
                rc = amisnap_repo_writer_entry(ctx->rw, &e);
                if (rc != AMISNAP_OK) { ctx->files_failed++; return 0; }
                ctx->files_ok++;
                ctx->files_unchanged++;
                mark_backed_up(path, e.prot);
                return 0;
            }
            /* Metadata said "unchanged" but the paranoid re-check
             * couldn't confirm it -- an honest, worth-reporting
             * degradation (implementation-plan.md principle 1: never
             * silently trust a fast path that might be wrong), not a
             * silent fall-through. */
            ctx->files_paranoid_mismatch++;
        }

        rc = amisnap_repo_writer_file(ctx->rw, &e, data, (size_t)(size > 0 ? size : 0));
        free(data);
        if (rc != AMISNAP_OK) { ctx->files_failed++; return 0; }
        ctx->files_ok++;
        mark_backed_up(path, e.prot);
        return 0;
    }
}

/* Returns 1 if `descendant` is the same object as `ancestor`, or is
 * nested anywhere underneath it (walking ParentDir() up from
 * `descendant` until either a SameLock() match or the top of the
 * logical volume tree, which ParentDir()'s own autodoc says returns a
 * NULL lock rather than looping). Returns 0 if it reaches the top
 * without a match. `descendant` is borrowed (never UnLock()'d here);
 * every intermediate lock this function itself creates via ParentDir()
 * is UnLock()'d before returning.
 *
 * SameLock()'s own autodoc warns LOCK_SAME_VOLUME ("same volume,
 * different object") shouldn't be treated as an alias -- e.g. sibling
 * directories DH0:Work and DH0:Backups are on the same volume but
 * don't overlap -- so only an exact LOCK_SAME counts as a match here,
 * checked at every level on the way up, not just at the two starting
 * points. */
static int lock_is_ancestor_or_self(BPTR ancestor, BPTR descendant)
{
    BPTR cur = descendant;
    BPTR next;
    int owns_cur = 0;

    for (;;) {
        if (SameLock(ancestor, cur) == LOCK_SAME) {
            if (owns_cur) UnLock(cur);
            return 1;
        }
        next = ParentDir(cur);
        if (owns_cur) UnLock(cur);
        if (!next) return 0;
        cur = next;
        owns_cur = 1;
    }
}

/* Refuses a SNAPSHOT whose REPO= is the same object as, nested inside,
 * or an ancestor of SOURCE= -- backing up a volume onto itself. Without
 * this, writing new repository objects into a directory that's also
 * being scanned would feed the scan its own just-written output on any
 * later run (or even mid-run, depending on scan/write interleaving),
 * silently corrupting or endlessly growing the backup -- exactly the
 * "data-losing bug" implementation-plan.md's principle 1 says must
 * never happen quietly. Checked both directions: REPO under SOURCE is
 * the dangerous, likely-accidental case ("SOURCE=DH0: REPO=DH0:
 * Backups"), but SOURCE under REPO is also a real misconfiguration
 * worth refusing rather than silently backing up the repository's own
 * previous output as if it were user data.
 *
 * Lock() failures here are deliberately non-fatal to this check alone
 * -- if either path can't be locked, the normal scan/backend-open path
 * a few lines below reports that failure with its own clear message;
 * this guard only needs to fire when both locks are real and it can
 * prove an overlap.
 *
 * A WebDAV `repo` (a "http://"/"https://" URL, open_backend()'s own
 * scheme dispatch) is skipped outright, not just left to fail Lock()
 * "normally": a URL can never alias a local AmigaDOS path (categorically
 * different address space, no shared Lock()/SameLock() identity
 * possible), so the check is meaningless there -- and, confirmed live
 * under Copperline, calling `Lock()` on a URL string doesn't fail
 * cleanly the way a merely-unmounted device name would; it hangs
 * indefinitely instead. Not investigated further (a real AmigaDOS
 * bug/quirk parsing a string shaped nothing like a device:path, not
 * this codebase's own to fix) -- avoided entirely instead, same
 * "degrade explicitly rather than chase an unrelated hang" instinct as
 * every other honest gap in this codebase. */
static int snapshot_source_repo_overlap(const char *source, const char *repo)
{
    BPTR source_lock, repo_lock;

    if (strncmp(repo, "http://", 7) == 0 || strncmp(repo, "https://", 8) == 0)
        return 0;
    int overlap = 0;

    source_lock = Lock((STRPTR)source, ACCESS_READ);
    if (!source_lock)
        return 0;

    repo_lock = Lock((STRPTR)repo, ACCESS_READ);
    if (!repo_lock) {
        UnLock(source_lock);
        return 0;
    }

    if (lock_is_ancestor_or_self(source_lock, repo_lock) ||
        lock_is_ancestor_or_self(repo_lock, source_lock))
        overlap = 1;

    UnLock(repo_lock);
    UnLock(source_lock);
    return overlap;
}

static LONG cmd_snapshot(const char *source, const char *repo, const char *comment, int paranoid)
{
    amisnap_backend be;
    amisnap_repo_writer rw;
    amisnap_snap_meta snap;
    amisnap_volume_meta vol;
    amisnap_scan_caps caps;
    amisnap_scan_result caps_pass_result, real_result;
    amisnap_scan_visitor caps_visitor, real_visitor;
    snapshot_ctx ctx;
    struct DateStamp now;
    char snapid[17];
    amisnap_index prev_index;
    int have_prev_index = 0;
    int rc;

    if (!source || !repo) {
        amilog_err("AmiSnap: SNAPSHOT needs SOURCE=<path> and REPO=<path>\n");
        return RETURN_ERROR;
    }

    rc = open_backend(repo, &be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot open repository \"%s\" (error %d)\n", repo, rc);
        return RETURN_FAIL;
    }

    if (snapshot_source_repo_overlap(source, repo)) {
        amilog_err("AmiSnap: REPO=\"%s\" is the same as, inside, or an ancestor of "
                        "SOURCE=\"%s\" -- refusing to back a volume up onto itself\n",
                repo, source);
        amisnap_backend_close(&be);
        return RETURN_ERROR;
    }

    /* Pass 1: caps-only walk (dostype/maxnamelen/owner_supported) so
     * REC_VOLUME can be written with real, complete data before any
     * REC_ENTRY -- format.md's required record order means VOL_CAPS
     * can't be patched in after the fact once entries have started
     * streaming into the manifest writer. This costs a second
     * directory-only walk (no file content read), not a second
     * content read -- see this function's own note in
     * implementation-plan.md's CLI wiring entry for the trade-off. */
    caps_visitor.user = NULL;
    caps_visitor.on_entry = caps_only_on_entry;
    rc = amisnap_scan_volume(source, &caps_visitor, &caps, &caps_pass_result);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot scan \"%s\" (error %d)\n", source, rc);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    amisnap_repo_writer_init(&rw, &be, NULL);

    DateStamp(&now);
    memset(&snap, 0, sizeof(snap));
    snap.created_days = (uint32_t)now.ds_Days;
    snap.created_mins = (uint32_t)now.ds_Minute;
    snap.created_ticks = (uint32_t)now.ds_Tick;
    if (comment) {
        snap.has_comment = 1;
        snap.comment = (const uint8_t *)comment;
        snap.comment_len = strlen(comment);
    }
    rc = amisnap_repo_writer_snap(&rw, &snap);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot start snapshot (error %d)\n", rc);
        amisnap_repo_writer_free(&rw);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    memset(&vol, 0, sizeof(vol));
    vol.vol_root = (const uint8_t *)source;
    vol.vol_root_len = strlen(source);
    vol.has_dostype = 1;
    vol.dostype = caps.dostype;
    vol.has_caps = 1;
    vol.maxnamelen = caps.maxnamelen;
    vol.caps_flags = caps.owner_supported ? AMISNAP_VOLCAP_OWNER : 0;
    rc = amisnap_repo_writer_volume(&rw, &vol);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot record volume info (error %d)\n", rc);
        amisnap_repo_writer_free(&rw);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    /* Incremental fast path (implementation-plan.md's archive-bit
     * policy, wired in here for the first time): if a previous
     * snapshot exists, load its manifest into a lookup index so
     * snapshot_on_entry() can recognize provably-unchanged files and
     * skip re-reading/re-hashing their content. AMISNAP_ERR_NOT_FOUND
     * (no previous snapshot at all) is the normal first-ever-backup
     * case, not an error -- silently falls through to a full scan, as
     * always. A previous manifest that fails to read or decode also
     * degrades to a full scan rather than aborting this snapshot over
     * it -- losing the speed-up is not the same class of problem as
     * losing data (principle 1 is about the latter). */
    {
        char prev_snapid[17];
        int prc = resolve_snapid(&be, NULL, prev_snapid);
        if (prc == AMISNAP_OK) {
            amisnap_buf prev_mf;
            prc = fetch_manifest(&be, prev_snapid, &prev_mf);
            if (prc == AMISNAP_OK) {
                prc = amisnap_index_build(prev_mf.data, prev_mf.len, &prev_index);
                amisnap_buf_free(&prev_mf);
                if (prc == AMISNAP_OK) {
                    have_prev_index = 1;
                } else {
                    amilog_err("AmiSnap: previous snapshot's manifest didn't decode (error %d) "
                                    "-- doing a full scan instead of an incremental one\n", prc);
                }
            } else {
                amilog_err("AmiSnap: could not read previous manifest (error %d) "
                                "-- doing a full scan instead of an incremental one\n", prc);
            }
        }
    }

    ctx.rw = &rw;
    ctx.source_root = source;
    ctx.prev_index = have_prev_index ? &prev_index : NULL;
    ctx.paranoid = paranoid;
    ctx.files_ok = 0;
    ctx.files_failed = 0;
    ctx.files_unchanged = 0;
    ctx.files_paranoid_mismatch = 0;
    real_visitor.user = &ctx;
    real_visitor.on_entry = snapshot_on_entry;
    rc = amisnap_scan_volume(source, &real_visitor, &caps, &real_result);
    if (have_prev_index) amisnap_index_free(&prev_index);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: scan failed partway through (error %d)\n", rc);
        amisnap_repo_writer_free(&rw);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    rc = amisnap_repo_writer_finish(&rw, snapid);
    amisnap_repo_writer_free(&rw);
    amisnap_backend_close(&be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: could not commit snapshot (error %d)\n", rc);
        return RETURN_FAIL;
    }

    amilog("Snapshot %s: %lu dirs, %lu files (%lu unchanged, %lu failed), %lu links skipped\n",
           snapid, (unsigned long)real_result.dirs_seen, (unsigned long)ctx.files_ok,
           (unsigned long)ctx.files_unchanged, (unsigned long)ctx.files_failed,
           (unsigned long)real_result.links_skipped);
    if (paranoid)
        amilog("Paranoid verify: %lu file(s) claimed unchanged by metadata but failed the "
                   "xxHash32 re-check and were re-read in full\n",
               (unsigned long)ctx.files_paranoid_mismatch);

    if (ctx.files_failed > 0 || real_result.links_skipped > 0)
        return RETURN_WARN;
    return RETURN_OK;
}

/* --- list ----------------------------------------------------------------- */

typedef struct {
    int seen;
    amisnap_snap_meta snap;
    size_t entry_count;
} list_summary_ctx;

static int list_on_snap(void *user, const amisnap_snap_meta *snap)
{
    list_summary_ctx *ctx = (list_summary_ctx *)user;
    ctx->seen = 1;
    ctx->snap = *snap;
    return 0;
}

static int list_on_entry(void *user, const amisnap_entry_meta *entry)
{
    list_summary_ctx *ctx = (list_summary_ctx *)user;
    (void)entry;
    ctx->entry_count++;
    return 0;
}

static LONG cmd_list(const char *repo)
{
    amisnap_backend be;
    snapshot_list list;
    int rc, i;

    if (!repo) {
        amilog_err("AmiSnap: LIST needs REPO=<path>\n");
        return RETURN_ERROR;
    }

    rc = open_backend(repo, &be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot open repository \"%s\" (error %d)\n", repo, rc);
        return RETURN_FAIL;
    }

    rc = list_all_snapshots(&be, &list);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot list snapshots (error %d)\n", rc);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    if (list.count == 0)
        amilog("No snapshots in \"%s\"\n", repo);

    for (i = 0; i < list.count; i++) {
        amisnap_buf mf;
        list_summary_ctx ctx;
        amisnap_manifest_visitor v;

        rc = fetch_manifest(&be, list.ids[i], &mf);
        if (rc != AMISNAP_OK) {
            amilog("%s  (manifest unreadable, error %d)\n", list.ids[i], rc);
            continue;
        }

        memset(&ctx, 0, sizeof(ctx));
        memset(&v, 0, sizeof(v));
        v.user = &ctx;
        v.on_snap = list_on_snap;
        v.on_entry = list_on_entry;
        rc = amisnap_manifest_decode(mf.data, mf.len, &v);
        amisnap_buf_free(&mf);

        if (rc != AMISNAP_OK || !ctx.seen) {
            amilog("%s  (manifest invalid, error %d)\n", list.ids[i], rc);
            continue;
        }

        amilog("%s  %lu entries", list.ids[i], (unsigned long)ctx.entry_count);
        if (ctx.snap.has_comment)
            amilog("  \"%.*s\"", (int)ctx.snap.comment_len, (const char *)ctx.snap.comment);
        amilog("\n");
    }

    amisnap_backend_close(&be);
    return RETURN_OK;
}

/* --- verify ----------------------------------------------------------------- */

static LONG cmd_verify(const char *repo, const char *snapid_arg, int full)
{
    amisnap_backend be;
    char snapid[17];
    amisnap_buf mf;
    amisnap_verify_result result;
    int rc;

    if (!repo) {
        amilog_err("AmiSnap: VERIFY needs REPO=<path>\n");
        return RETURN_ERROR;
    }

    rc = open_backend(repo, &be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot open repository \"%s\" (error %d)\n", repo, rc);
        return RETURN_FAIL;
    }

    rc = resolve_snapid(&be, snapid_arg, snapid);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: no snapshot to verify (error %d)\n", rc);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    rc = fetch_manifest(&be, snapid, &mf);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot read manifest %s (error %d)\n", snapid, rc);
        amisnap_backend_close(&be);
        return RETURN_FAIL;
    }

    rc = amisnap_verify_manifest(&be, NULL, NULL, mf.data, mf.len, full, &result);
    amisnap_buf_free(&mf);
    amisnap_backend_close(&be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: manifest %s failed to decode (error %d)\n", snapid, rc);
        return RETURN_FAIL;
    }

    amilog("Verify %s (%s): %lu objects checked, %lu missing, %lu corrupt\n",
           snapid, full ? "FULL" : "structural",
           (unsigned long)result.objects_checked, (unsigned long)result.objects_missing,
           (unsigned long)result.objects_corrupt);

    if (result.objects_missing > 0 || result.objects_corrupt > 0)
        return RETURN_WARN;
    return RETURN_OK;
}

/* --- prune ---------------------------------------------------------------- */

/* PRUNE SNAPID=<id> deletes exactly that one snapshot (format.md's own
 * raw "delete the target snapshot" primitive, verbatim). PRUNE
 * KEEP_LAST=<n> is the retention-policy layer this CLI adds on top:
 * keep the N most recent snapshots (list_all_snapshots' own ascending
 * lexicographic order, format.md's own note that this is equivalent to
 * chronological order), delete every older one. Exactly one of the two
 * must be given -- combining them, or giving neither, is a usage error,
 * not a guess at what the user meant. Daily/weekly/monthly retention
 * (docs/proposal.md's fuller policy) needs real calendar arithmetic
 * over AmigaDOS's day-since-1978 DateStamp and is deliberately not
 * attempted here -- a separate follow-up, not silently approximated by
 * KEEP_LAST alone. */
static LONG cmd_prune(const char *repo, const char *snapid_arg, const LONG *keep_last)
{
    amisnap_backend be;
    amisnap_prune_result result;
    int rc;

    if (!repo) {
        amilog_err("AmiSnap: PRUNE needs REPO=<path>\n");
        return RETURN_ERROR;
    }
    if (!snapid_arg && !keep_last) {
        amilog_err("AmiSnap: PRUNE needs SNAPID=<id> or KEEP_LAST=<n>\n");
        return RETURN_ERROR;
    }
    if (snapid_arg && keep_last) {
        amilog_err("AmiSnap: PRUNE takes SNAPID= or KEEP_LAST=, not both\n");
        return RETURN_ERROR;
    }
    if (keep_last && *keep_last < 0) {
        amilog_err("AmiSnap: KEEP_LAST must be >= 0\n");
        return RETURN_ERROR;
    }

    rc = open_backend(repo, &be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot open repository \"%s\" (error %d)\n", repo, rc);
        return RETURN_FAIL;
    }

    if (snapid_arg) {
        const char *ids[1];
        ids[0] = snapid_arg;
        rc = amisnap_prune_execute(&be, ids, 1, &result);
    } else {
        snapshot_list list;
        const char *delete_ids[MAX_SNAPSHOTS];
        int delete_count, keep_n, i;

        rc = list_all_snapshots(&be, &list);
        if (rc != AMISNAP_OK) {
            amilog_err("AmiSnap: cannot list snapshots (error %d)\n", rc);
            amisnap_backend_close(&be);
            return RETURN_FAIL;
        }

        keep_n = (*keep_last > list.count) ? list.count : (int)*keep_last;
        delete_count = list.count - keep_n;
        for (i = 0; i < delete_count; i++)
            delete_ids[i] = list.ids[i]; /* ascending order: the oldest come first */

        rc = amisnap_prune_execute(&be, delete_ids, (size_t)delete_count, &result);
    }

    amisnap_backend_close(&be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: prune of \"%s\" aborted (error %d) -- %lu snapshots, %lu objects, "
                        "%lu tmp entries removed before the failure\n",
                repo, rc, (unsigned long)result.snapshots_deleted,
                (unsigned long)result.objects_deleted, (unsigned long)result.tmp_deleted);
        return RETURN_FAIL;
    }

    amilog("Prune %s: %lu snapshots, %lu objects, %lu tmp entries removed\n",
           repo, (unsigned long)result.snapshots_deleted, (unsigned long)result.objects_deleted,
           (unsigned long)result.tmp_deleted);
    return RETURN_OK;
}

/* --- applyuaem -------------------------------------------------------------- */

/* Companion to `tools/amisnap_reader.py restore --uaem`: applies
 * .uaem sidecars a host reader wrote (real AmigaDOS metadata that host
 * couldn't apply itself) onto a tree that's now on real AmigaDOS --
 * see src/amiga/applyuaem.h for the full rationale. */
static LONG cmd_applyuaem(const char *source)
{
    amisnap_applyuaem_result result;
    int rc;

    if (!source) {
        amilog_err("AmiSnap: APPLYUAEM needs SOURCE=<path>\n");
        return RETURN_ERROR;
    }

    rc = amisnap_applyuaem_run(source, &result);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: APPLYUAEM of \"%s\" aborted (error %d) -- %lu applied, %lu failed "
                        "before the failure\n",
                source, rc, (unsigned long)result.applied, (unsigned long)result.failed);
        return RETURN_FAIL;
    }

    amilog("ApplyUAEM %s: %lu applied, %lu failed\n",
           source, (unsigned long)result.applied, (unsigned long)result.failed);
    return result.failed > 0 ? RETURN_WARN : RETURN_OK;
}

/* --- restore ----------------------------------------------------------------- */

static LONG cmd_restore(const char *repo, const char *dest, const char *snapid_arg,
                         const char *subtree)
{
    amisnap_backend repo_be, dest_be;
    char snapid[17];
    amisnap_buf mf;
    amisnap_restore_options opts;
    amisnap_restore_result result;
    amisnap_restore_meta_ctx meta_ctx;
    int rc;

    if (!repo || !dest) {
        amilog_err("AmiSnap: RESTORE needs REPO=<path> and DEST=<path>\n");
        return RETURN_ERROR;
    }

    rc = open_backend(repo, &repo_be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot open repository \"%s\" (error %d)\n", repo, rc);
        return RETURN_FAIL;
    }
    rc = open_backend(dest, &dest_be);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot open destination \"%s\" (error %d)\n", dest, rc);
        amisnap_backend_close(&repo_be);
        return RETURN_FAIL;
    }

    rc = resolve_snapid(&repo_be, snapid_arg, snapid);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: no snapshot to restore (error %d)\n", rc);
        amisnap_backend_close(&repo_be);
        amisnap_backend_close(&dest_be);
        return RETURN_FAIL;
    }

    rc = fetch_manifest(&repo_be, snapid, &mf);
    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: cannot read manifest %s (error %d)\n", snapid, rc);
        amisnap_backend_close(&repo_be);
        amisnap_backend_close(&dest_be);
        return RETURN_FAIL;
    }

    memset(&meta_ctx, 0, sizeof(meta_ctx));
    meta_ctx.dest_root = dest;

    memset(&opts, 0, sizeof(opts));
    if (subtree) {
        opts.subtree_prefix = (const uint8_t *)subtree;
        opts.subtree_prefix_len = strlen(subtree);
    }
    opts.on_entry_restored = amisnap_restore_meta_on_entry;
    opts.user = &meta_ctx;

    rc = amisnap_restore_manifest(&repo_be, &dest_be, NULL, NULL, mf.data, mf.len, &opts, &result);
    amisnap_buf_free(&mf);
    amisnap_backend_close(&repo_be);
    amisnap_backend_close(&dest_be);

    if (rc != AMISNAP_OK) {
        amilog_err("AmiSnap: restore of %s aborted (error %d) -- %lu dirs, %lu files "
                        "written before the failure\n",
                snapid, rc, (unsigned long)result.dirs_created, (unsigned long)result.files_written);
        return RETURN_FAIL;
    }

    amilog("Restored %s: %lu dirs, %lu files (%lu bytes), %lu links skipped, %lu entries "
           "outside the subtree filter\n",
           snapid, (unsigned long)result.dirs_created, (unsigned long)result.files_written,
           (unsigned long)result.bytes_written, (unsigned long)result.links_skipped,
           (unsigned long)result.entries_skipped);
    amilog("Metadata: protection %lu/%lu, comment %lu/%lu, date %lu/%lu, owner %lu/%lu ok\n",
           (unsigned long)meta_ctx.totals.prot_ok,
           (unsigned long)(meta_ctx.totals.prot_ok + meta_ctx.totals.prot_failed),
           (unsigned long)meta_ctx.totals.comment_ok,
           (unsigned long)(meta_ctx.totals.comment_ok + meta_ctx.totals.comment_failed),
           (unsigned long)meta_ctx.totals.date_ok,
           (unsigned long)(meta_ctx.totals.date_ok + meta_ctx.totals.date_failed),
           (unsigned long)meta_ctx.totals.owner_ok,
           (unsigned long)(meta_ctx.totals.owner_ok + meta_ctx.totals.owner_failed));

    if (result.links_skipped > 0 || meta_ctx.totals.prot_failed > 0 ||
        meta_ctx.totals.comment_failed > 0 || meta_ctx.totals.date_failed > 0 ||
        meta_ctx.totals.owner_failed > 0)
        return RETURN_WARN;
    return RETURN_OK;
}

/* --- dispatch --------------------------------------------------------- */

static int str_ieq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char cb = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

#define TEMPLATE "ACTION/A,SOURCE/K,REPO/K,DEST/K,SNAPID/K,SUBTREE/K,COMMENT/K,FULL/S,LOG/K,KEEP_LAST/K/N,PARANOID/S"
enum { ARG_ACTION, ARG_SOURCE, ARG_REPO, ARG_DEST, ARG_SNAPID, ARG_SUBTREE, ARG_COMMENT, ARG_FULL, ARG_LOG,
       ARG_KEEP_LAST, ARG_PARANOID, ARG_COUNT };

static int real_main(void *arg)
{
    struct RDArgs *rdargs;
    LONG args[ARG_COUNT];
    LONG rc;
    const char *action;
    const char *logpath;

    (void)arg;

    /* Reference verstring so the compiler never discards it -- the
     * $VER cookie must survive into the binary for `version` and
     * `make dist`'s own grep. Always on plain stderr: LOG= isn't known
     * until after ReadArgs succeeds, so this banner can't respect it. */
    fprintf(stderr, "%s\n", verstring + 6);

    memset(args, 0, sizeof(args));
    rdargs = ReadArgs((STRPTR)TEMPLATE, args, NULL);
    if (!rdargs) {
        fprintf(stderr, "AmiSnap: bad arguments. Template: %s\n", TEMPLATE);
        return RETURN_ERROR;
    }

    logpath = (const char *)args[ARG_LOG];
    if (logpath) {
        g_log = fopen(logpath, "w");
        if (!g_log) {
            fprintf(stderr, "AmiSnap: cannot open LOG=\"%s\" for writing\n", logpath);
            FreeArgs(rdargs);
            return RETURN_FAIL;
        }
        /* Unbuffered, not stdio's default full-buffering-on-a-non-tty:
         * a run that hangs or crashes before its own fclose() must
         * never leave behind a log that's silently empty just because
         * everything written so far was still sitting in a libc buffer
         * -- exactly the kind of quiet failure principle 1 rules out,
         * and a real one hit live while debugging the WebDAV on-target
         * harness (tests/copperline/run-webdav.sh): a hang left a
         * completely empty snapshot.log with zero diagnostic value. */
        setvbuf(g_log, NULL, _IONBF, 0);
    }

    action = (const char *)args[ARG_ACTION];

    if (str_ieq(action, "SNAPSHOT")) {
        rc = cmd_snapshot((const char *)args[ARG_SOURCE], (const char *)args[ARG_REPO],
                           (const char *)args[ARG_COMMENT], args[ARG_PARANOID] != 0);
    } else if (str_ieq(action, "RESTORE")) {
        rc = cmd_restore((const char *)args[ARG_REPO], (const char *)args[ARG_DEST],
                          (const char *)args[ARG_SNAPID], (const char *)args[ARG_SUBTREE]);
    } else if (str_ieq(action, "LIST")) {
        rc = cmd_list((const char *)args[ARG_REPO]);
    } else if (str_ieq(action, "VERIFY")) {
        rc = cmd_verify((const char *)args[ARG_REPO], (const char *)args[ARG_SNAPID],
                         args[ARG_FULL] != 0);
    } else if (str_ieq(action, "PRUNE")) {
        rc = cmd_prune((const char *)args[ARG_REPO], (const char *)args[ARG_SNAPID],
                        (const LONG *)args[ARG_KEEP_LAST]);
    } else if (str_ieq(action, "APPLYUAEM")) {
        rc = cmd_applyuaem((const char *)args[ARG_SOURCE]);
    } else {
        amilog_err("AmiSnap: unknown ACTION \"%s\" -- expected SNAPSHOT, RESTORE, LIST, VERIFY, "
                       "PRUNE, or APPLYUAEM\n",
                   action ? action : "");
        rc = RETURN_ERROR;
    }

    if (g_socket_lib_open) {
        amisnap_socket_lib_close();
        g_socket_lib_open = 0;
    }
    if (g_log) {
        fclose(g_log);
        g_log = NULL;
    }
    FreeArgs(rdargs);
    return (int)rc;
}

int main(void)
{
    int degraded = 0;
    int rc = amisnap_stackswap_run(real_main, NULL, &degraded);

    if (degraded)
        fprintf(stderr, "AmiSnap: warning: could not allocate a larger stack; "
                         "running on the default stack (low memory?)\n");
    return rc;
}
