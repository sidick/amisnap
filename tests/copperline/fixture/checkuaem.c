/* checkuaem.c -- test-only fixture for run-uaem.sh: Examine()s the four
 * known entries tests/cross/gen_sample_repo.c's fixture data produces
 * (readme.txt, Docs, Docs/notes.txt, empty.dat), reporting protection/
 * comment/date -- an independent verification channel from AmiSnap's
 * own ApplyUAEM summary line, same convention as readback.c.
 *
 * Never shipped -- same convention as this repo's own stage.c/readback.c.
 */
#include <stdio.h>

#include <dos/dos.h>
#include <proto/dos.h>

static FILE *g;

static void dump(const char *path)
{
    struct FileInfoBlock fib;
    BPTR lock = Lock((STRPTR)path, ACCESS_READ);
    if (!lock) { fprintf(g, "%s: Lock failed IoErr=%ld\n", path, (long)IoErr()); return; }
    if (Examine(lock, &fib)) {
        fprintf(g, "%s: prot=%08lx comment=\"%s\" date=%ld.%ld.%ld\n",
                path, (unsigned long)fib.fib_Protection, fib.fib_Comment,
                (long)fib.fib_Date.ds_Days, (long)fib.fib_Date.ds_Minute, (long)fib.fib_Date.ds_Tick);
    } else {
        fprintf(g, "%s: Examine failed IoErr=%ld\n", path, (long)IoErr());
    }
    UnLock(lock);
}

int main(void)
{
    g = fopen("Results:checkuaem.log", "w");
    if (!g) return 1;
    dump("Source:readme.txt");
    dump("Source:Docs");
    dump("Source:Docs/notes.txt");
    dump("Source:empty.dat");
    fclose(g);
    return 0;
}
