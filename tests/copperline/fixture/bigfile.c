/* bigfile.c -- test-only fixture (verifying repo.c's chunked writer,
 * AMISNAP_DEFAULT_CHUNK_SIZE = 8MB): writes a real file just over that
 * threshold to Source:bigfile.dat, with deterministic, non-repeating
 * content (a byte value that increments once per 64KB block) so a
 * byte-mismatch after restore is easy to localize by eye if this ever
 * fails, not just a generic "content differs" result.
 *
 * The write buffer is AllocMem()'d, not a stack array -- scan.c's own
 * established reasoning applies here too: a 64KB local array would
 * overflow a default CLI process's real stack (a few KB, not run
 * behind stackswap.c's own 32KB swapped stack the way AmiSnap's real
 * SNAPSHOT scan is) -- confirmed the hard way, a first version of this
 * fixture silently produced an empty log and no file at all.
 *
 * Never shipped -- same convention as this repo's own stage.c/readback.c.
 */
#include <stdio.h>

#include <dos/dos.h>
#include <exec/memory.h>
#include <proto/dos.h>
#include <proto/exec.h>

#define BLOCK_SIZE (64L * 1024L)
#define TOTAL_SIZE (8L * 1024L * 1024L + 300L * 1024L) /* ~300K over the 8MB chunk threshold */

int main(void)
{
    BPTR fh;
    unsigned char *block;
    LONG written = 0;
    long blocknum = 0;
    FILE *g = fopen("Results:bigfile.log", "w");

    if (!g) return 1;

    block = (unsigned char *)AllocMem(BLOCK_SIZE, MEMF_ANY);
    if (!block) {
        fprintf(g, "bigfile: AllocMem failed\n");
        fclose(g);
        return 1;
    }

    fh = Open((STRPTR)"Source:bigfile.dat", MODE_NEWFILE);
    if (!fh) {
        fprintf(g, "bigfile: cannot create Source:bigfile.dat\n");
        FreeMem(block, BLOCK_SIZE);
        fclose(g);
        return 1;
    }

    while (written < TOTAL_SIZE) {
        LONG this_size = BLOCK_SIZE;
        long i;
        if (TOTAL_SIZE - written < this_size) this_size = TOTAL_SIZE - written;
        for (i = 0; i < this_size; i++) block[i] = (unsigned char)(blocknum & 0xFF);
        if (Write(fh, block, this_size) != this_size) {
            fprintf(g, "bigfile: short write at block %ld\n", blocknum);
            Close(fh);
            FreeMem(block, BLOCK_SIZE);
            fclose(g);
            return 1;
        }
        written += this_size;
        blocknum++;
    }
    Close(fh);
    FreeMem(block, BLOCK_SIZE);

    fprintf(g, "bigfile: wrote %ld bytes in %ld blocks\n", (long)written, blocknum);
    fclose(g);
    return 0;
}
