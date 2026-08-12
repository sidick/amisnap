/* modify.c -- test-only fixture: overwrites Source:root.txt with new
 * content between two SNAPSHOT runs, so run.sh can confirm the
 * archive-bit incremental fast path (implementation-plan.md's "The
 * archive bit is corroboration, never sole evidence" policy, wired
 * into cmd_snapshot's snapshot_on_entry()) correctly detects a real
 * change rather than skipping it -- Open(MODE_NEWFILE) on an existing
 * file both replaces its content and clears the archive bit real
 * AmigaDOS FFS sets automatically on write, so this alone is enough to
 * force the next snapshot to re-read and re-hash this one file while
 * everything else stage.c created stays untouched and should still be
 * recognized as unchanged.
 *
 * Never shipped -- same convention as this repo's own stage.c/readback.c.
 */
#include <dos/dos.h>
#include <proto/dos.h>

int main(void)
{
    BPTR fh;

    fh = Open((STRPTR)"Source:root.txt", MODE_NEWFILE);
    if (fh) {
        Write(fh, (APTR)"CHANGED content\n", 16);
        Close(fh);
    }
    return 0;
}
