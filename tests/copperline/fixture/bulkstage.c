/* bulkstage.c -- test-only fixture (Phase 1's performance gate,
 * implementation-plan.md: "10k-file unchanged run under a minute on
 * emulated 68030 without archive-bit help"). Creates COUNT small files
 * directly under Source: via Open/Write/Close -- no subdirectories, a
 * flat directory being both the simplest case and a real one (a large
 * Downloads-style folder). Content is tiny and unique per file (the
 * index embedded as decimal text) so BLAKE2s/dedup see real, distinct
 * data rather than a degenerate all-identical-content shortcut.
 *
 * Never shipped -- same convention as AmiPilot's own fixtures/ and this
 * repo's own stage.c/readback.c.
 */
#include <stdio.h>
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>

#define FILE_COUNT 10000

static FILE *g_log;

int main(void)
{
    long i;
    long failed = 0;
    char path[32];
    char content[32];

    g_log = fopen("Results:bulkstage.log", "w");
    if (!g_log) {
        printf("bulkstage: cannot open Results:bulkstage.log\n");
        return 1;
    }

    fprintf(g_log, "bulkstage: creating %d files\n", FILE_COUNT);

    for (i = 0; i < FILE_COUNT; i++) {
        BPTR fh;
        int len;

        sprintf(path, "Source:f%05ld", i);
        len = sprintf(content, "file number %ld\n", i);

        fh = Open((STRPTR)path, MODE_NEWFILE);
        if (!fh) {
            fprintf(g_log, "bulkstage: cannot create %s\n", path);
            failed++;
            continue;
        }
        if (Write(fh, (APTR)content, (LONG)len) != (LONG)len) {
            fprintf(g_log, "bulkstage: short write to %s\n", path);
            failed++;
        }
        Close(fh);
    }

    fprintf(g_log, "bulkstage: %s (%ld failed)\n", failed ? "FAILED" : "done", failed);
    fclose(g_log);
    return failed ? 1 : 0;
}
