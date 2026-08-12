/* stackswap.c -- see stackswap.h.
 *
 * Struct layout (stk_Lower: APTR, stk_Upper: ULONG, stk_Pointer: APTR)
 * confirmed against the real NDK header (exec/tasks.h) rather than
 * assumed -- stk_Upper being ULONG, not APTR, is the one field easy to
 * get wrong from memory.
 */
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

    FreeMem(newstack, AMISNAP_STACK_SIZE);
    return result;
}
