/* applyuaem.c -- see applyuaem.h.
 *
 * .uaem line format (one line, fixed-width prefix, implementation-
 * plan.md item 8's own documentation of the FS-UAE/Amiberry/Copperline
 * convention, confirmed against real captured Copperline output):
 *
 *   HSPARWED 2024-07-19 02:03:00.14 optional comment to end of line
 *   ^8 chars ^4-2-2      ^2:2:2.2   ^rest of line, absent = no comment
 *
 * Directory walk uses classic Examine()/ExNext() (not ExAll() --
 * scan.c's own justification for ExAll doesn't apply here: this tool
 * only needs filenames, not bulk metadata, and Examine()/ExNext() is
 * the simpler, longer-established API for exactly that -- NDK
 * dos.doc's own ExNext() autodoc, checked before using it: reuse the
 * SAME lock/FileInfoBlock pair across calls at one directory level,
 * but a FRESH FileInfoBlock (never the parent's) when recursing into
 * a subdirectory, or the parent scan's own state is lost).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>

#include "amipath.h"
#include "applyuaem.h"
#include "tlv.h" /* AMISNAP_OK / AMISNAP_ERR_* */

#define UAEM_PATH_BUF_LEN 2304 /* matches restore_meta.c's own convention */
#define UAEM_LINE_BUF_LEN 512  /* 8+1+22 fixed prefix, generous room for a comment */
#define UAEM_SUFFIX ".uaem"
#define UAEM_SUFFIX_LEN 5

/* Howard Hinnant's days_from_civil (public domain,
 * http://howardhinnant.github.io/date_algorithms.html): days since
 * 1970-01-01 for a proleptic-Gregorian y/m/d, no floating point. The
 * Python writer (tools/amisnap_reader.py) uses the standard library's
 * own equivalent; this is the from-scratch C side, since neither
 * AmigaOS nor libnix ships a calendar library. */
static long days_from_civil(long y, int m, int d)
{
    long era;
    unsigned yoe, doy, doe;

    y -= (m <= 2) ? 1 : 0;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153u * (unsigned)(m + (m > 2 ? -3 : 9)) + 2u) / 5u + (unsigned)d - 1u;
    doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097L + (long)doe - 719468L; /* days since 1970-01-01 */
}

/* AmigaOS DateStamp epoch is 1978-01-01, not 1970-01-01 -- format.md
 * "Conventions": "days since 1978-01-01". */
static long amiga_days_from_civil(long y, int m, int d)
{
    return days_from_civil(y, m, d) - days_from_civil(1978, 1, 1);
}

/* Inverse of tools/amisnap_reader.py's prot_to_uaem_flags(): HSPA
 * (bits 7-4) show their letter when SET; rwed (bits 3-0) show their
 * letter when CLEAR (the classic active-low permission bits) -- same
 * table, same order, checked against the same three real captured
 * Copperline samples that table's own Python-side comment cites. */
static LONG uaem_flags_to_prot(const char *flags)
{
    static const struct { char letter; LONG mask; int active_high; } table[8] = {
        {'h', 0x80, 1}, {'s', 0x40, 1}, {'p', 0x20, 1}, {'a', 0x10, 1},
        {'r', 0x08, 0}, {'w', 0x04, 0}, {'e', 0x02, 0}, {'d', 0x01, 0},
    };
    LONG prot = 0;
    int i;

    for (i = 0; i < 8; i++) {
        int present = (flags[i] == table[i].letter);
        int bit_set = table[i].active_high ? present : !present;
        if (bit_set) prot |= table[i].mask;
    }
    return prot;
}

/* Parses one fixed-layout .uaem line (already NUL-terminated, no
 * trailing newline). Returns AMISNAP_OK, or AMISNAP_ERR_MALFORMED if
 * it doesn't match the expected shape at all. */
static int parse_uaem_line(const char *line, size_t len, LONG *prot_out,
                            struct DateStamp *ds_out, const char **comment_out)
{
    long year, mon, day, hh, mm, ss, cc;
    int i;

    if (len < 31) return AMISNAP_ERR_MALFORMED;
    for (i = 0; i < 8; i++) {
        char c = line[i];
        if (c != '-' && (c < 'a' || c > 'z')) return AMISNAP_ERR_MALFORMED;
    }
    if (line[8] != ' ' || line[13] != '-' || line[16] != '-' || line[19] != ' ' ||
        line[22] != ':' || line[25] != ':' || line[28] != '.')
        return AMISNAP_ERR_MALFORMED;

    for (i = 9; i < 31; i++) {
        if (i == 13 || i == 16 || i == 19 || i == 22 || i == 25 || i == 28) continue;
        if (line[i] < '0' || line[i] > '9') return AMISNAP_ERR_MALFORMED;
    }

    year = (line[9] - '0') * 1000L + (line[10] - '0') * 100L + (line[11] - '0') * 10L + (line[12] - '0');
    mon  = (line[14] - '0') * 10L + (line[15] - '0');
    day  = (line[17] - '0') * 10L + (line[18] - '0');
    hh   = (line[20] - '0') * 10L + (line[21] - '0');
    mm   = (line[23] - '0') * 10L + (line[24] - '0');
    ss   = (line[26] - '0') * 10L + (line[27] - '0');
    cc   = (line[29] - '0') * 10L + (line[30] - '0');

    *prot_out = uaem_flags_to_prot(line);

    ds_out->ds_Days = amiga_days_from_civil(year, (int)mon, (int)day);
    ds_out->ds_Minute = hh * 60L + mm;
    /* cc is centiseconds (0-99); TICKS_PER_SECOND=50, so each tick is
     * 2 centiseconds -- an odd cc (never written by our own Python
     * writer, but a real Amiberry/FS-UAE file could have one) loses
     * at most 1/100s of precision to integer division, an inherent
     * limit of centisecond<->tick granularity, not a bug. */
    ds_out->ds_Tick = ss * 50L + cc / 2L;

    if (len > 31 && line[31] == ' ')
        *comment_out = line + 32;
    else
        *comment_out = NULL;

    return AMISNAP_OK;
}

static void apply_one_uaem(const char *dir_path, const char *uaem_name,
                            amisnap_applyuaem_result *result)
{
    char sidecar_path[UAEM_PATH_BUF_LEN];
    char target_path[UAEM_PATH_BUF_LEN];
    char line[UAEM_LINE_BUF_LEN];
    FILE *f;
    size_t name_len = strlen(uaem_name);
    size_t target_len = name_len - UAEM_SUFFIX_LEN;
    LONG prot;
    struct DateStamp ds;
    const char *comment;
    size_t linelen;

    if (amisnap_join_amiga_path(dir_path, (const uint8_t *)uaem_name, name_len,
                                 sidecar_path, sizeof(sidecar_path)) != AMISNAP_OK) {
        result->failed++;
        return;
    }
    if (amisnap_join_amiga_path(dir_path, (const uint8_t *)uaem_name, target_len,
                                 target_path, sizeof(target_path)) != AMISNAP_OK) {
        result->failed++;
        return;
    }

    f = fopen(sidecar_path, "r");
    if (!f) { result->failed++; return; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); result->failed++; return; }
    fclose(f);

    linelen = strlen(line);
    while (linelen > 0 && (line[linelen - 1] == '\n' || line[linelen - 1] == '\r'))
        line[--linelen] = '\0';

    if (parse_uaem_line(line, linelen, &prot, &ds, &comment) != AMISNAP_OK) {
        result->failed++;
        return;
    }

    /* Same order restore_meta.c already established (comment, date,
     * owner N/A here -- .uaem has no owner field at all, per
     * implementation-plan.md's own documented format --, protection
     * LAST since it can deny access to the entry itself). All three
     * calls are independently best-effort; any failure still counts
     * this .uaem as "applied" if at least the sidecar parsed and the
     * target existed enough to attempt them -- matching restore's own
     * "degrade explicitly, don't abort the whole run over one field". */
    if (comment) SetComment((STRPTR)target_path, (STRPTR)comment);
    SetFileDate((STRPTR)target_path, &ds);
    SetProtection((STRPTR)target_path, prot);

    result->applied++;
}

static int walk_dir(const char *dir_path, amisnap_applyuaem_result *result)
{
    BPTR lock;
    struct FileInfoBlock *fib; /* AllocDosObject(DOS_FIB), NOT a stack
                                * struct: Examine()/ExNext() hand the FIB
                                * to the handler as a BPTR (addr >> 2), so
                                * it MUST be longword-aligned (dos.doc's
                                * Examine SPECIAL NOTE); m68k gcc only
                                * 2-byte-aligns a stack struct, so a
                                * mis-aligned FIB gets written two bytes
                                * early, clobbering the stack -- and here
                                * the FIB is also the live ExNext
                                * iteration state, so corrupting it
                                * derails the whole directory walk. */
    char *child_path;          /* heap, NOT a UAEM_PATH_BUF_LEN stack
                                * array: this recurses once per directory
                                * level against the fixed 32KB swap stack
                                * (stackswap.h), and a ~2KB buffer per
                                * frame overflows it a dozen levels deep
                                * -- silent corruption on Amiga (no guard
                                * page). One heap buffer per level bounds
                                * the stack cost to a small fixed frame. */
    int rc = AMISNAP_OK;

    lock = Lock((STRPTR)dir_path, ACCESS_READ);
    if (!lock) return AMISNAP_ERR_IO;

    fib = (struct FileInfoBlock *)AllocDosObject(DOS_FIB, NULL);
    if (!fib) { UnLock(lock); return AMISNAP_ERR_NOMEM; }

    child_path = (char *)malloc(UAEM_PATH_BUF_LEN);
    if (!child_path) { FreeDosObject(DOS_FIB, fib); UnLock(lock); return AMISNAP_ERR_NOMEM; }

    if (!Examine(lock, fib)) {
        free(child_path);
        FreeDosObject(DOS_FIB, fib);
        UnLock(lock);
        return AMISNAP_ERR_IO;
    }

    while (ExNext(lock, fib)) {
        const char *filename = (const char *)fib->fib_FileName;
        size_t namelen = strlen(filename);

        if (fib->fib_DirEntryType > 0) {
            if (amisnap_join_amiga_path(dir_path, (const uint8_t *)filename, namelen,
                                         child_path, UAEM_PATH_BUF_LEN) != AMISNAP_OK ||
                walk_dir(child_path, result) != AMISNAP_OK) /* fresh FileInfoBlock -- see header */
                result->failed++;
        } else if (namelen > UAEM_SUFFIX_LEN &&
                   strcmp(filename + namelen - UAEM_SUFFIX_LEN, UAEM_SUFFIX) == 0) {
            apply_one_uaem(dir_path, filename, result);
        }
    }
    if (IoErr() != ERROR_NO_MORE_ENTRIES) rc = AMISNAP_ERR_IO;

    free(child_path);
    FreeDosObject(DOS_FIB, fib);
    UnLock(lock);
    return rc;
}

int amisnap_applyuaem_run(const char *root_path, amisnap_applyuaem_result *result)
{
    result->applied = 0;
    result->failed = 0;
    return walk_dir(root_path, result);
}
