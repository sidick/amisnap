/* cipherlockdiag.c -- dev-only diagnostic (never linked into AmiSnap):
 * isolates the CIPHERS= corruption bug (implementation-plan.md Phase 3
 * item 4's still-open finding, run-webdav-tls.sh CIPHERS=<cipher>
 * against real https://) to the smallest possible repro -- does
 * amisnap_tls_lib_open() with a non-NULL cipher_list corrupt this
 * PROCESS's own ability to Lock() files, with no network connection at
 * all and no second process involved? If this reproduces here, the
 * corruption happens inside SSL_CTX_set_cipher_list() (or the
 * OpenAmiSSLTags()/SSL_CTX_new() calls immediately before it) itself,
 * not from anything tls_connect()'s BIO-pair pump or a later process
 * boundary does.
 *
 * Sequence, all in one process, real stack (amisnap_stackswap_run(),
 * same as production):
 *   1. Lock() a known-good file, print PASS/FAIL (baseline, before AmiSSL
 *      is touched at all).
 *   2. amisnap_socket_lib_open() + amisnap_tls_lib_open(0, 0, cipher) --
 *      no connect(), no BIO pair, no network I/O whatsoever.
 *   3. Lock() the same file again, print PASS/FAIL.
 *   4. Repeat step 2+3 three more times (4 total amisnap_tls_lib_open()
 *      calls, matching SNAPSHOT/LIST/VERIFY/RESTORE's own real per-
 *      process-invocation count in run-webdav-tls.sh) -- deliberately
 *      never calling amisnap_tls_lib_close() between them, matching
 *      main.c's own real behavior (grep confirms it's never called on
 *      any success path there).
 *
 * Usage: cipherlockdiag <cipher-list-or- to skip CIPHERS entirely>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <proto/dos.h>

#include "socket.h"
#include "stackswap.h"
#include "tls.h"
#include "tlv.h"

#define TESTFILE "SYS:S/Startup-Sequence"

static void try_lock(const char *label)
{
    BPTR lock = Lock((CONST_STRPTR)TESTFILE, ACCESS_READ);
    if (lock) {
        printf("cipherlockdiag: %s: Lock(%s) OK\n", label, TESTFILE);
        UnLock(lock);
    } else {
        printf("cipherlockdiag: %s: Lock(%s) FAILED (IoErr=%ld)\n", label, TESTFILE, (long)IoErr());
    }
}

static int run(void *arg)
{
    const char *cipher = (const char *)arg;
    int i;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("cipherlockdiag: cipher=%s\n", cipher && cipher[0] ? cipher : "(none)");

    try_lock("baseline");

    if (amisnap_socket_lib_open() != AMISNAP_OK) {
        printf("cipherlockdiag: FAIL bsdsocket.library not available\n");
        return 20;
    }

    for (i = 1; i <= 4; i++) {
        char label[64];

        rc = amisnap_tls_lib_open(0, 0, (cipher && cipher[0]) ? cipher : NULL);
        sprintf(label, "after tls_lib_open #%d (rc=%d)", i, rc);
        if (rc != 0) {
            printf("cipherlockdiag: %s -- open itself failed\n", label);
        }
        try_lock(label);
    }

    printf("cipherlockdiag: done\n");
    return 0;
}

int main(int argc, char **argv)
{
    int degraded = 0;
    int rc;
    const char *cipher = argc > 1 ? argv[1] : "";

    rc = amisnap_stackswap_run(run, (void *)cipher, &degraded);
    if (degraded) {
        printf("cipherlockdiag: note: ran on the default stack (StackSwap alloc failed)\n");
    }
    return rc;
}
