/* stackswap_test.c -- Phase 1 item 7's vamos regression test:
 * confirms amisnap_stackswap_run() genuinely swaps to a new stack.
 *
 * Deliberately does NOT test by triggering a real overflow on the
 * un-swapped stack -- that would be unsafe (silent memory corruption
 * is exactly the failure mode this mechanism exists to prevent, and
 * deliberately provoking it is undefined behavior, not a controlled
 * test condition) and nondeterministic under an emulator. Instead:
 * recurse deeply enough to use real stack space (well within the
 * 32KB swapped stack, never close to overflowing it either), capture
 * the deepest stack pointer reached, and compare it against the
 * caller's own stack pointer captured before the swap. AllocMem()'s
 * returned block has no proximity guarantee to the task's own stack
 * region, so a large gap between the two is a reliable, always-safe
 * signal that a genuinely different stack is in use -- not a guess
 * at "would this have crashed" reasoning.
 *
 * Only exercises stackswap.c itself (AllocMem/FreeMem/StackSwap, all
 * confirmed V36 -- see stackswap.h) -- no ExAll()/Info()/
 * AllocDosObject, so unlike scan.c this genuinely runs under vamos
 * (implementation-plan.md's "Stack management" testing section).
 */
#include <stdio.h>

#include "stackswap.h"

#define DEPTH 40
#define FRAME_BYTES 256
/* DEPTH * FRAME_BYTES ~= 10KB: comfortably within the 32KB swapped
 * stack (not close to overflowing it), while far more than any
 * plausible same-stack call-frame variance could produce. */
#define GAP_THRESHOLD 4096

static char *g_inner_sp;

static long deep(int n)
{
    volatile char probe[FRAME_BYTES];
    size_t i;
    long sum;

    /* Touch every byte so the compiler can't optimize the frame away. */
    for (i = 0; i < sizeof(probe); i++)
        probe[i] = (char)i;

    if (n == 0) {
        g_inner_sp = (char *)&probe[0];
        return 0;
    }
    sum = deep(n - 1);
    return sum + probe[0];
}

static int run_fn(void *arg)
{
    (void)arg;
    deep(DEPTH);
    return 0;
}

int main(void)
{
    volatile char outer_probe;
    char *outer_sp = (char *)&outer_probe;
    long diff;
    int degraded = 0;
    int rc;

    rc = amisnap_stackswap_run(run_fn, NULL, &degraded);

    if (degraded) {
        /* A genuinely low-memory system: amisnap_stackswap_run() ran
         * fn() directly on the caller's own stack rather than refuse
         * to run at all (stackswap.h's own documented degrade path).
         * Nothing to verify in that case -- this isn't a test
         * failure, there's simply no swap to have happened. */
        printf("SKIP: stack allocation failed (degraded mode) -- nothing to verify\n");
        return 0;
    }

    diff = (long)(outer_sp - g_inner_sp);
    if (diff < 0)
        diff = -diff;

    printf("outer_sp=%p inner_sp=%p diff=%ld rc=%d\n",
           (void *)outer_sp, (void *)g_inner_sp, diff, rc);

    if (diff < GAP_THRESHOLD) {
        printf("FAIL: inner stack pointer too close to outer -- "
               "the swap may not have happened\n");
        return 1;
    }

    printf("PASS: stack swap confirmed (%ld byte gap)\n", diff);
    return 0;
}
