/* posix_transport.c -- POSIX sockets implementation of transport.h's
 * amisnap_transport_ops, for Phase 3 item 5's own host-CI-only need:
 * exercising the portable webdav.c/http.c against a REAL WebDAV server
 * process (mini_webdav_server.py) from host test code, over a real TCP
 * connection -- an independent implementation from this project's own
 * in-memory mock (tests/test_webdav.c), which is what actually catches
 * interop bugs a self-consistent mock never could.
 *
 * NEVER built into src/core/ or shipped -- AmiSnap itself only ever
 * runs on m68k Amiga, where the real transport is src/amiga/socket.c's
 * bsdsocket.library glue. This file lives under tests/webdav/, not
 * src/core/, precisely so the Makefile's CORE_SRCS wildcard (shared by
 * both the host test build and the m68k cross-build) never picks it up
 * -- libnix -noixemul has no POSIX sockets at all, confirmed while
 * designing transport.h itself (see that file's own header comment).
 */
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "backend.h" /* AMISNAP_OK / AMISNAP_ERR_* */
#include "posix_transport.h"

static int posix_connect(amisnap_transport *t, const char *host, uint16_t port, void **handle_out)
{
    struct addrinfo hints, *res, *rp;
    char portbuf[8];
    int fd = -1;
    int rc;

    (void)t;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);

    rc = getaddrinfo(host, portbuf, &hints, &res);
    if (rc != 0) return AMISNAP_ERR_IO;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return AMISNAP_ERR_IO;

    *handle_out = (void *)(long)fd;
    return AMISNAP_OK;
}

static int posix_send(amisnap_transport *t, void *handle, const void *data, size_t len)
{
    int fd = (int)(long)handle;
    const unsigned char *p = (const unsigned char *)data;
    size_t remaining = len;

    (void)t;
    while (remaining > 0) {
        ssize_t n = send(fd, p, remaining, 0);
        if (n <= 0) return AMISNAP_ERR_IO;
        p += n;
        remaining -= (size_t)n;
    }
    return AMISNAP_OK;
}

static int posix_recv(amisnap_transport *t, void *handle, void *buf, size_t len, size_t *got)
{
    int fd = (int)(long)handle;
    ssize_t n;

    (void)t;
    n = recv(fd, buf, len, 0);
    if (n < 0) return AMISNAP_ERR_IO;
    *got = (size_t)n;
    return AMISNAP_OK;
}

static void posix_close(amisnap_transport *t, void *handle)
{
    int fd = (int)(long)handle;

    (void)t;
    if (fd >= 0) close(fd);
}

const amisnap_transport_ops amisnap_posix_transport_ops = {
    posix_connect, posix_send, posix_recv, posix_close
};
