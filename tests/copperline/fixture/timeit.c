/* timeit.c -- test-only fixture (Phase 1's performance gate). Runs a
 * single command line via SystemTagList() (blocks until it completes,
 * V36 autodoc confirmed before using it) bracketed by DateStamp() reads,
 * and logs the elapsed time as measured by AmigaDOS's own clock -- which
 * under Copperline's deterministic emulation core tracks emulated time
 * exactly, independent of host wall-clock/warp-speed pacing. This is
 * what actually measures the gate ("...under a minute on emulated
 * 68030"), not a host-side timer.
 *
 * ds_Tick is ticks elapsed in the CURRENT MINUTE (0-2999 at
 * TICKS_PER_SECOND=50 -- i.e. 60 * TICKS_PER_SECOND, not TICKS_PER_
 * SECOND itself), per DateStamp()'s own autodoc; a first version of
 * this file misread that as "ticks past the second" and multiplied the
 * ds_Minute delta by TICKS_PER_SECOND instead of 60*TICKS_PER_SECOND,
 * silently producing a nonsensical negative elapsed time the moment a
 * real run crossed a minute boundary (confirmed via a dedicated diag
 * fixture, since removed, that DateStamp()/ds_Minute/ds_Tick are in
 * fact fully consistent and monotonic across process boundaries in
 * this minimal boot -- the clock itself was never the problem).
 *
 * Argv[0] is unused; the command line to run is passed as ARGS on the
 * Amiga command line (ReadArgs-free -- this is a fixture, not a real
 * CLI tool, so it just reads the raw argument string handed to it).
 *
 * Never shipped -- same convention as this repo's own stage.c/readback.c.
 */
#include <stdio.h>
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>
#include <utility/tagitem.h>

int main(int argc, char **argv)
{
    struct DateStamp start, end;
    LONG elapsed_ticks;
    LONG rc;
    FILE *g_log;
    char cmdline[512];
    int i;

    g_log = fopen("Results:timeit.log", "w");
    if (!g_log) {
        printf("timeit: cannot open Results:timeit.log\n");
        return 1;
    }

    cmdline[0] = '\0';
    for (i = 1; i < argc; i++) {
        if (i > 1) strcat(cmdline, " ");
        strcat(cmdline, argv[i]);
    }

    fprintf(g_log, "timeit: running: %s\n", cmdline);

    DateStamp(&start);
    rc = SystemTags((STRPTR)cmdline, TAG_DONE);
    DateStamp(&end);

    elapsed_ticks = ((end.ds_Days - start.ds_Days) * 24L * 60L + (end.ds_Minute - start.ds_Minute))
                        * (60L * TICKS_PER_SECOND)
                    + (end.ds_Tick - start.ds_Tick);

    fprintf(g_log, "timeit: command rc=%ld\n", (long)rc);
    fprintf(g_log, "timeit: elapsed_ticks=%ld\n", (long)elapsed_ticks);
    fprintf(g_log, "timeit: elapsed_seconds=%ld.%02ld\n",
            (long)(elapsed_ticks / TICKS_PER_SECOND),
            (long)((elapsed_ticks % TICKS_PER_SECOND) * 100 / TICKS_PER_SECOND));

    fclose(g_log);
    return 0;
}
