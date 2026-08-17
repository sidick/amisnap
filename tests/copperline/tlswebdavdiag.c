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
 * Usage: tlswebdavdiag <host> <port> <path>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "socket.h"
#include "tls.h"
#include "tlv.h"

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    unsigned short port = argc > 2 ? (unsigned short)atoi(argv[2]) : 18794;
    const char *path = argc > 3 ? argv[3] : "/repo";
    amisnap_transport t;
    void *handle = NULL;
    char req[512];
    int n, rc;
    char buf[1024];

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("tlswebdavdiag: host=%s port=%u path=%s\n", host, (unsigned)port, path);

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

    rc = amisnap_transport_connect(&t, host, port, &handle);
    printf("tlswebdavdiag: transport_connect rc=%d\n", rc);
    if (rc != AMISNAP_OK) {
        printf("tlswebdavdiag: FAIL connect (handshake or cert verification failed)\n");
        return 20;
    }

    n = snprintf(req, sizeof(req),
                 "MKCOL %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n\r\n",
                 path, host, (unsigned)port);
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
