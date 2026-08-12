/* readback.c -- test-only fixture (implementation-plan.md's item 8
 * scope): Examine()s the restored tree and writes observed protection/
 * comment/date/owner to Results:readback.log for the host script to
 * assert against expected values -- an Amiga-side verification
 * channel independent of AmiSnap's own restore reporting, run
 * alongside (not instead of) direct .uaem sidecar inspection on the
 * host side. Never shipped -- same convention as AmiPilot's fixtures/.
 *
 * Fixed, hardcoded paths rather than a generic recursive walk: this
 * fixture only ever examines the exact tree stage.c created, a known
 * quantity, so a walker would be unused generality.
 */
#include <stdio.h>

#include <dos/dos.h>
#include <proto/dos.h>

static FILE *g_log;

static void report(const char *path)
{
    BPTR lock;
    struct FileInfoBlock fib;

    lock = Lock((STRPTR)path, ACCESS_READ);
    if (!lock) {
        fprintf(g_log, "%s: LOCK-FAILED\n", path);
        return;
    }
    if (!Examine(lock, &fib)) {
        fprintf(g_log, "%s: EXAMINE-FAILED\n", path);
        UnLock(lock);
        return;
    }
    fprintf(g_log, "%s: type=%ld size=%ld prot=%08lx comment=\"%s\" date=%ld.%ld.%ld owner=%u.%u\n",
            path, (long)fib.fib_DirEntryType, (long)fib.fib_Size,
            (unsigned long)fib.fib_Protection, fib.fib_Comment,
            (long)fib.fib_Date.ds_Days, (long)fib.fib_Date.ds_Minute, (long)fib.fib_Date.ds_Tick,
            fib.fib_OwnerUID, fib.fib_OwnerGID);
    UnLock(lock);
}

int main(void)
{
    g_log = fopen("Results:readback.log", "w");
    if (!g_log) {
        printf("readback: cannot open Results:readback.log\n");
        return 1;
    }

    fprintf(g_log, "readback: begin\n");
    report("Restored:root.txt");
    report("Restored:Sub");
    report("Restored:Sub/nested.txt");
    report("Restored:Sub/empty.txt");
    fprintf(g_log, "readback: end\n");

    fclose(g_log);
    return 0;
}
