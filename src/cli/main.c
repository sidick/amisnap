/* main.c -- AmiSnap CLI entry point.
 *
 * Phase 1 scaffold: prints identity and the planned command set, exits
 * RC 5 (WARN) so a script can't mistake it for a working backup run. The
 * real front-end is ReadArgs-based with per-command templates and proper
 * RC codes (docs/proposal.md "Operations (v1)"); it replaces amiga_main's
 * body, not its role -- portable core stays out of here entirely.
 *
 * m68k-amigaos-gcc only from here on: real_main() runs behind
 * amisnap_stackswap_run() (docs/implementation-plan.md "Stack
 * management"), which every AmiSnap entry point must do before any
 * real work, so this file establishes that pattern from its first
 * real line of logic rather than deferring it.
 */
#include <stdio.h>

#include "stackswap.h"

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

static int real_main(void *arg)
{
    (void)arg;

    /* Reference verstring so no compiler discards it. */
    printf("%s\n", verstring + 6);
    printf("Versioned backup for classic AmigaOS -- nothing implemented yet.\n");
    printf("Planned commands: snapshot, restore, list, verify, prune.\n");
    return 5; /* RC_WARN: scaffold, not a working tool */
}

int main(void)
{
    int degraded = 0;
    int rc = amisnap_stackswap_run(real_main, NULL, &degraded);

    if (degraded)
        fprintf(stderr, "AmiSnap: warning: could not allocate a larger stack; "
                         "running on the default stack (low memory?)\n");
    return rc;
}
