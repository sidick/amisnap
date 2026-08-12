/* main.c -- AmiSnap CLI entry point.
 *
 * Phase 1 scaffold: prints identity and the planned command set, exits
 * RC 5 (WARN) so a script can't mistake it for a working backup run. The
 * real front-end is ReadArgs-based with per-command templates and proper
 * RC codes (docs/proposal.md "Operations (v1)"); it replaces this file's
 * body, not its role -- portable core stays out of here entirely.
 *
 * Kept buildable by both the host compiler (so `make test`'s toolchain
 * can smoke-build it if wanted) and m68k-amigaos-gcc.
 */
#include <stdio.h>

#ifndef VERSION
#define VERSION 0
#endif
#ifndef REVISION
#define REVISION 0
#endif

/* Standard AmigaDOS "$VER:" version cookie (RKRM: DOS, "The Version
 * Command") -- date is DD.MM.YYYY digits per the convention; bump it with
 * version.mk on release. `make dist` greps the binary for exactly this
 * string, so keep the format "AmiSnap <VERSION>.<REVISION> (date)". */
#define XSTR(s) STR(s)
#define STR(s) #s
static const char verstring[] =
    "$VER: AmiSnap " XSTR(VERSION) "." XSTR(REVISION) " (12.08.2026)";

int main(void)
{
    /* Reference verstring so no compiler discards it. */
    printf("%s\n", verstring + 6);
    printf("Versioned backup for classic AmigaOS -- nothing implemented yet.\n");
    printf("Planned commands: snapshot, restore, list, verify, prune.\n");
    return 5; /* RC_WARN: scaffold, not a working tool */
}
