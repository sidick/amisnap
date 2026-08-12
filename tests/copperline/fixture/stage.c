/* stage.c -- test-only fixture (implementation-plan.md's item 8 scope):
 * creates a small source tree with deliberately non-default metadata
 * (protection bits beyond RWED, comments, fixed datestamps) directly
 * via Open/Write/Close/SetProtection/SetComment/SetFileDate, since a
 * minimal (no-Workbench) boot has no C:Protect/C:SetComment available.
 * Never shipped -- same convention as AmiPilot's own fixtures/.
 *
 * Deliberately avoids touching the R/W/E protection bits (active-low:
 * setting them DENIES access) -- this tree must still be freely
 * readable by AmiSnap's own later SNAPSHOT pass. HSPA-family bits
 * (Hold/Script/Pure/Archive) and Delete are safe to set freely; they
 * exercise full-mask round-trip fidelity without risking the read path.
 *
 * CreateDir()'s NDK autodoc note, confirmed before using it: it
 * returns an EXCLUSIVE lock on success -- UnLock() it before doing
 * anything else with that path, or later calls on the same directory
 * would contend with it.
 */
#include <stdio.h>
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>

static FILE *g_log;

static int write_file(const char *path, const char *content)
{
    BPTR fh;
    size_t len = strlen(content);

    fh = Open((STRPTR)path, MODE_NEWFILE);
    if (!fh) {
        fprintf(g_log, "stage: cannot create %s\n", path);
        return 0;
    }
    if (len > 0 && Write(fh, (APTR)content, (LONG)len) != (LONG)len) {
        fprintf(g_log, "stage: short write to %s\n", path);
        Close(fh);
        return 0;
    }
    Close(fh);
    return 1;
}

static void stamp(const char *path, LONG prot, const char *comment,
                   LONG days, LONG mins, LONG ticks)
{
    struct DateStamp ds;

    if (!SetProtection((STRPTR)path, prot))
        fprintf(g_log, "stage: SetProtection(%s) failed\n", path);
    if (comment && !SetComment((STRPTR)path, (STRPTR)comment))
        fprintf(g_log, "stage: SetComment(%s) failed\n", path);

    ds.ds_Days = days;
    ds.ds_Minute = mins;
    ds.ds_Tick = ticks;
    if (!SetFileDate((STRPTR)path, &ds))
        fprintf(g_log, "stage: SetFileDate(%s) failed\n", path);
}

int main(void)
{
    BPTR sublock;
    int failed = 0;

    /* Writes its own results file directly (matching AmiSnap's own
     * LOG= design) rather than relying on Shell/Startup-Sequence
     * stdout redirection, which is untested for a minimal boot -- see
     * implementation-plan.md's item 8 scope. */
    g_log = fopen("Results:stage.log", "w");
    if (!g_log) {
        printf("stage: cannot open Results:stage.log\n");
        return 1;
    }

    fprintf(g_log, "stage: creating source tree\n");

    if (!write_file("Source:root.txt", "root file content\n"))
        failed = 1;
    else
        stamp("Source:root.txt", FIBF_ARCHIVE | FIBF_DELETE, "root level file", 17000, 600, 10);

    sublock = CreateDir((STRPTR)"Source:Sub");
    if (!sublock) {
        fprintf(g_log, "stage: CreateDir(Source:Sub) failed\n");
        failed = 1;
    } else {
        UnLock(sublock);
        stamp("Source:Sub", FIBF_ARCHIVE, "a subdirectory", 17000, 0, 0);
    }

    if (!write_file("Source:Sub/nested.txt", "nested content here\n"))
        failed = 1;
    else
        stamp("Source:Sub/nested.txt", FIBF_ARCHIVE | FIBF_PURE, "a nested comment", 17001, 123, 7);

    if (!write_file("Source:Sub/empty.txt", ""))
        failed = 1;
    else
        stamp("Source:Sub/empty.txt", FIBF_ARCHIVE, "", 17002, 0, 0);

    fprintf(g_log, "stage: %s\n", failed ? "FAILED" : "done");
    fclose(g_log);
    return failed;
}
