/* cipherconndiag.c -- dev-only diagnostic (never linked into AmiSnap):
 * matches main.c's own REAL usage pattern -- amisnap_tls_lib_open()
 * called exactly ONCE per process (guarded by g_tls_lib_open in
 * open_backend()), then tls_connect()/tls_send()/tls_recv()/
 * tls_close() called once per HTTP request against the SAME SSL_CTX
 * (a real RESTORE with N repository objects does one TCP+TLS
 * connection per object GET, all reusing the one CTX from the single
 * amisnap_tls_lib_open() call that process makes). An EARLIER version
 * of this file called amisnap_tls_lib_open()/close() every round
 * (full OpenAmiSSLTags()/CloseAmiSSL() teardown+reinit each time) and
 * found a real, reproducible hang on the 3rd such cycle -- but that
 * pattern doesn't match anything main.c actually does (it never calls
 * amisnap_tls_lib_close() at all, let alone re-opens per request), so
 * that finding doesn't explain run-webdav-tls.sh's own CIPHERS=
 * readback-corruption bug. This version narrows to the pattern that
 * actually matches production, to see whether cipher_list changes
 * behavior specifically across repeated tls_connect()/tls_close()
 * cycles sharing one SSL_CTX.
 *
 * Usage: cipherconndiag <host> <port> <cipher-or-empty> <insecure 0|1>
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

typedef struct {
    const char *host;
    unsigned short port;
    const char *cipher;
    int insecure;
    int round_offset;
    int rounds;
} diag_args;

static void try_lock(const char *label)
{
    BPTR lock = Lock((CONST_STRPTR)TESTFILE, ACCESS_READ);
    if (lock) {
        printf("cipherconndiag: %s: Lock(%s) OK\n", label, TESTFILE);
        UnLock(lock);
    } else {
        printf("cipherconndiag: %s: Lock(%s) FAILED (IoErr=%ld)\n", label, TESTFILE, (long)IoErr());
    }
}

static int run(void *arg)
{
    diag_args *a = (diag_args *)arg;
    int round;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("cipherconndiag: host=%s port=%u cipher=%s insecure=%d\n",
           a->host, (unsigned)a->port, a->cipher && a->cipher[0] ? a->cipher : "(none)", a->insecure);

    try_lock("baseline");

    if (amisnap_socket_lib_open() != AMISNAP_OK) {
        printf("cipherconndiag: FAIL bsdsocket.library not available\n");
        return 20;
    }

    {
        int rc = amisnap_tls_lib_open(0, a->insecure, (a->cipher && a->cipher[0]) ? a->cipher : NULL);
        printf("cipherconndiag: tls_lib_open (once) returned rc=%d\n", rc);
        if (rc != 0) {
            printf("cipherconndiag: tls_lib_open rc=%d -- FAIL\n", rc);
            return 20;
        }
    }

    for (round = a->round_offset; round < a->round_offset + a->rounds; round++) {
        amisnap_transport t;
        void *handle = NULL;
        char label[64];
        char outpath[64];
        int rc;
        static char sendbuf[16384];
        static char recvbuf[16384];
        size_t total_sent = 0, total_recv = 0;

        memset(sendbuf, 'A' + (round % 26), sizeof(sendbuf));

        t.ops = &amisnap_tls_transport_ops;
        t.ctx = NULL;
        rc = amisnap_transport_connect(&t, a->host, a->port, &handle);
        printf("cipherconndiag: round %d: connect rc=%d\n", round, rc);
        if (rc == AMISNAP_OK) {
            rc = amisnap_transport_send(&t, handle, sendbuf, sizeof(sendbuf));
            total_sent = sizeof(sendbuf);
            printf("cipherconndiag: round %d: send rc=%d (%lu bytes)\n", round, rc, (unsigned long)total_sent);
            if (rc == AMISNAP_OK) {
                while (total_recv < sizeof(recvbuf)) {
                    size_t got = 0;
                    rc = amisnap_transport_recv(&t, handle, recvbuf + total_recv,
                                                 sizeof(recvbuf) - total_recv, &got);
                    if (rc != AMISNAP_OK || got == 0) break;
                    total_recv += got;
                }
                printf("cipherconndiag: round %d: recv rc=%d total=%lu\n", round, rc, (unsigned long)total_recv);
            }
            amisnap_transport_close(&t, handle);
        }

        /* Real DOS file write interleaved with the TLS round-trip,
         * same as restore.c's own real workflow (open destination,
         * write decrypted bytes, close, verify by Lock()ing it back)
         * -- cipherconndiag's earlier version never touched DOS I/O at
         * all, so this narrows further toward what RESTORE actually
         * does that a bare network echo doesn't. */
        sprintf(outpath, "AmiSnapResults:scratch%d.dat", round);
        {
            BPTR fh = Open((CONST_STRPTR)outpath, MODE_NEWFILE);
            if (fh) {
                Write(fh, recvbuf, (LONG)total_recv);
                Close(fh);
            } else {
                printf("cipherconndiag: round %d: Open(%s) FAILED (IoErr=%ld)\n", round, outpath, (long)IoErr());
            }
        }

        sprintf(label, "after round %d", round);
        try_lock(label);

        {
            BPTR lock = Lock((CONST_STRPTR)outpath, ACCESS_READ);
            if (lock) {
                printf("cipherconndiag: round %d: Lock(%s) OK\n", round, outpath);
                UnLock(lock);
            } else {
                printf("cipherconndiag: round %d: Lock(%s) FAILED (IoErr=%ld)\n", round, outpath, (long)IoErr());
            }
        }
    }

    printf("cipherconndiag: done\n");
    return 0;
}

int main(int argc, char **argv)
{
    diag_args a;
    int degraded = 0;
    int rc;

    a.host = argc > 1 ? argv[1] : "127.0.0.1";
    a.port = argc > 2 ? (unsigned short)atoi(argv[2]) : 18830;
    a.cipher = argc > 3 ? argv[3] : "";
    if (a.cipher && strcmp(a.cipher, "NONE") == 0) a.cipher = "";
    a.insecure = argc > 4 ? atoi(argv[4]) : 1;
    a.round_offset = argc > 5 ? atoi(argv[5]) : 1;
    a.rounds = argc > 6 ? atoi(argv[6]) : 2;

    rc = amisnap_stackswap_run(run, &a, &degraded);
    if (degraded) {
        printf("cipherconndiag: note: ran on the default stack (StackSwap alloc failed)\n");
    }
    return rc;
}
