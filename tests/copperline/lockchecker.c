/* lockchecker.c -- dev-only diagnostic (never linked into AmiSnap):
 * the missing half of cipherconndiag.c's own repro attempt -- the
 * real run-webdav-tls.sh CIPHERS= bug is specifically that a LATER,
 * SEPARATE process's Lock() fails after an earlier process's TLS
 * work completed and self-verified successfully. cipherconndiag.c
 * alone can only test Lock() within its OWN process; this binary is
 * run as its own SYS: command right after cipherconndiag in
 * Startup-Sequence, to test the real cross-process failure mode.
 *
 * Usage: lockchecker <path> [<path> ...]
 */
#include <stdio.h>

#include <proto/dos.h>

int main(int argc, char **argv)
{
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
        BPTR lock = Lock((CONST_STRPTR)argv[i], ACCESS_READ);
        if (lock) {
            printf("lockchecker: Lock(%s) OK\n", argv[i]);
            UnLock(lock);
        } else {
            printf("lockchecker: Lock(%s) FAILED (IoErr=%ld)\n", argv[i], (long)IoErr());
        }
    }
    return 0;
}
