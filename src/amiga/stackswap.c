/* stackswap.c -- see stackswap.h.
 *
 * Struct layout (stk_Lower: APTR, stk_Upper: ULONG, stk_Pointer: APTR)
 * confirmed against the real NDK header (exec/tasks.h) rather than
 * assumed -- stk_Upper being ULONG, not APTR, is the one field easy to
 * get wrong from memory.
 */
#include <string.h>

#include <exec/memory.h>
#include <exec/tasks.h>
#include <proto/exec.h>

#include "stackswap.h"

int amisnap_stackswap_run(int (*fn)(void *arg), void *arg, int *out_degraded)
{
    struct StackSwapStruct sss;
    APTR newstack;
    int result;

    if (out_degraded)
        *out_degraded = 0;

    newstack = AllocMem(AMISNAP_STACK_SIZE, MEMF_ANY);
    if (!newstack) {
        if (out_degraded)
            *out_degraded = 1;
        return fn(arg);
    }

    sss.stk_Lower = newstack;
    sss.stk_Upper = (ULONG)newstack + AMISNAP_STACK_SIZE;
    sss.stk_Pointer = (APTR)sss.stk_Upper;

    StackSwap(&sss);
    result = fn(arg);
    StackSwap(&sss); /* StackSwap() itself keeps the struct valid for
                       * a symmetric second call -- swaps back to
                       * exactly the caller's original stack. */

    /* Scrub the whole swap stack before returning it to the system
     * pool: fn() (real_main and everything under it) runs entirely on
     * this stack, so decrypted repository subkeys, derived KDF keys,
     * and other secret material lived here as ordinary locals. AmigaOS
     * has no memory protection and AllocMem() without MEMF_CLEAR hands
     * out whatever bytes were last there -- AmiSnap's own
     * amisnap_random() (random.c) deliberately harvests that residue
     * for entropy, so an un-scrubbed key could be read straight back by
     * the next allocation. We've already swapped back to the caller's
     * stack, so newstack is idle and safe to wipe. One 32KB memset per
     * process, negligible. Complements the explicit per-buffer scrubs
     * elsewhere; this is the backstop for anything they miss. */
    memset(newstack, 0, AMISNAP_STACK_SIZE);
    FreeMem(newstack, AMISNAP_STACK_SIZE);
    return result;
}
