/* stackswap.h -- StackSwap() to a generously sized, explicitly
 * allocated stack, per docs/implementation-plan.md's "Stack
 * management (StackSwap)" section: the Shell/Workbench default stack
 * is too small for AmiSnap's real recursion (directory walks, hashing/
 * encoding call depth), and an Amiga stack overflow is silent memory
 * corruption, not a clean crash -- unacceptable under principle 1 (a
 * data-losing bug is fatal).
 *
 * StackSwap() itself is exec.library, confirmed V36 against the real
 * NDK (ghcr.io/sidick/amiga-dev's exec_lib.sfd: grouped under its
 * "==version 36" marker, nothing higher before it) -- at or below our
 * V37 floor, so this needs no runtime version gate, unlike SetOwner()
 * (implementation-plan.md "OS floor is V37, not V39").
 */
#ifndef AMISNAP_STACKSWAP_H
#define AMISNAP_STACKSWAP_H

/* The size every AmiSnap entry point swaps to before doing real work.
 * Starting point per the plan ("start at 32KB, revisit once scan.c's
 * real recursion depth against a deep test tree is measured") -- not
 * yet revisited, since scan.c doesn't exist yet. */
#define AMISNAP_STACK_SIZE 32768ul

/* Allocates a fresh AMISNAP_STACK_SIZE-byte stack, swaps to it, calls
 * fn(arg) on it, swaps back, and frees the stack -- one AllocMem()/
 * FreeMem() pair per call (the plan's "one pair per process lifetime"
 * when this is called once from main(), wrapping everything else).
 *
 * If the stack cannot be allocated (a genuinely low-memory system),
 * fn(arg) still runs -- directly on the caller's own current stack,
 * without the safety margin -- rather than refusing to run at all;
 * *out_degraded (if non-NULL) is set to 1 so the caller can log a
 * warning about it. Returns fn's own return value either way. */
int amisnap_stackswap_run(int (*fn)(void *arg), void *arg, int *out_degraded);

#endif /* AMISNAP_STACKSWAP_H */
