/* tlswebdavdiag.c -- dev-only diagnostic (never linked into AmiSnap):
 * calls the REAL, unmodified src/amiga/tls.c (amisnap_tls_lib_open()
 * + amisnap_tls_transport_ops) directly -- not a reimplementation like
 * tests/copperline/tlsbench.c -- to isolate why run-webdav-tls.sh's
 * own real SNAPSHOT (the actual production CLI) failed with a generic
 * "cannot open repository" (AMISNAP_ERR_IO) against a local TLS-
 * wrapped mini_webdav_server.py, when a plain curl MKCOL against the
 * identical server succeeds. Sends a hand-built MKCOL request over the
 * real transport and prints the raw response (or the exact step/error
 * that failed) instead of webdav.c's own undifferentiated error code.
 *
 * Runs behind amisnap_stackswap_run(), same as real_main() in
 * src/cli/main.c -- not optional here: this file's own first pass
 * (without it) produced a genuine, reproducible-looking hang inside
 * tls.c's BIO-pair pump that turned out to be this standalone binary's
 * own small default AmigaDOS stack overflowing under tls_pump()'s 4KB
 * local ciphertext buffer several frames deep (tls_connect ->
 * tls_run -> tls_pump -> tls_flush_out) -- silent corruption, not a
 * clean crash, per stackswap.h's own documented reasoning for why
 * every real entry point in this codebase swaps to a real 32KB stack
 * first. Confirmed as the actual cause, not just a guess: a bare
 * BIO_new_bio_pair()/BIO_write()/BIO_read() smoke test
 * (tests/copperline/biopairdiag.c, no deep call chain, no large local
 * buffers) worked perfectly first try on the *same* small default
 * stack, isolating the difference to stack depth specifically. This
 * diagnostic exists to test tls.c's own real code path faithfully, so
 * it needs the same real stack production code always has -- omitting
 * it here would keep reproducing an artifact of this test file, not
 * tls.c's own design.
 *
 * Usage: tlswebdavdiag <host> <port> <path>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "socket.h"
#include "stackswap.h"
#include "tls.h"
#include "tlv.h"

typedef struct {
    const char *host;
    unsigned short port;
    const char *path;
} diag_args;

static int run(void *arg)
{
    diag_args *a = (diag_args *)arg;
    amisnap_transport t;
    void *handle = NULL;
    char req[512];
    int n, rc;
    char buf[1024];

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("tlswebdavdiag: host=%s port=%u path=%s\n", a->host, (unsigned)a->port, a->path);

    if (amisnap_socket_lib_open() != AMISNAP_OK) {
        printf("tlswebdavdiag: FAIL bsdsocket.library not available\n");
        return 20;
    }

    rc = amisnap_tls_lib_open(0);
    if (rc != AMISNAP_OK) {
        printf("tlswebdavdiag: FAIL amisnap_tls_lib_open rc=%d\n", rc);
        return 20;
    }
    printf("tlswebdavdiag: amisnap_tls_lib_open OK\n");

    t.ops = &amisnap_tls_transport_ops;
    t.ctx = NULL;

    rc = amisnap_transport_connect(&t, a->host, a->port, &handle);
    printf("tlswebdavdiag: transport_connect rc=%d\n", rc);
    if (rc != AMISNAP_OK) {
        printf("tlswebdavdiag: FAIL connect (handshake or cert verification failed)\n");
        return 20;
    }

    n = snprintf(req, sizeof(req),
                 "MKCOL %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n\r\n",
                 a->path, a->host, (unsigned)a->port);
    rc = amisnap_transport_send(&t, handle, req, (size_t)n);
    printf("tlswebdavdiag: send MKCOL rc=%d (%d bytes)\n", rc, n);
    if (rc != AMISNAP_OK) {
        printf("tlswebdavdiag: FAIL send\n");
        amisnap_transport_close(&t, handle);
        return 20;
    }

    for (;;) {
        size_t got = 0;

        rc = amisnap_transport_recv(&t, handle, buf, sizeof(buf) - 1, &got);
        printf("tlswebdavdiag: recv rc=%d got=%lu\n", rc, (unsigned long)got);
        if (rc != AMISNAP_OK) {
            printf("tlswebdavdiag: FAIL recv\n");
            break;
        }
        if (got == 0) {
            printf("tlswebdavdiag: recv EOF (orderly close)\n");
            break;
        }
        buf[got] = '\0';
        printf("tlswebdavdiag: got %lu bytes: %s\n", (unsigned long)got, buf);
    }

    amisnap_transport_close(&t, handle);
    printf("tlswebdavdiag: done\n");
    return 0;
}

int main(int argc, char **argv)
{
    diag_args a;
    int degraded = 0;
    int rc;

    a.host = argc > 1 ? argv[1] : "127.0.0.1";
    a.port = argc > 2 ? (unsigned short)atoi(argv[2]) : 18794;
    a.path = argc > 3 ? argv[3] : "/repo";

    rc = amisnap_stackswap_run(run, &a, &degraded);
    if (degraded) {
        printf("tlswebdavdiag: note: ran on the default stack (StackSwap alloc failed)\n");
    }
    return rc;
}
