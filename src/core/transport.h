/* transport.h -- the abstract byte-stream transport webdav.c is built
 * against, the same vtable-plus-opaque-context shape as backend.h's own
 * amisnap_backend_ops. This is what keeps webdav.c itself portable
 * (module map: "webdav.c, s3.c protocol clients over a socket
 * abstraction" -- listed under src/core/, not src/amiga/, deliberately):
 * webdav.c never calls bsdsocket.library (or any host sockets API)
 * directly, only through this interface, so it builds and runs
 * identically on the host (implementation-plan.md Phase 3's own "Host
 * CI runs the protocol code against a local WebDAV container", backed
 * by a POSIX transport under tests/) and on the real target (backed by
 * src/amiga/socket.c's bsdsocket.library glue, the one piece of this
 * whole path that IS Amiga-only).
 *
 * One amisnap_transport instance represents a connection *factory*, not
 * a connection itself -- `connect()` opens a fresh connection and hands
 * back an opaque per-connection handle, mirroring how one
 * amisnap_backend represents a whole repository/destination while
 * put_begin() hands back a per-upload handle.
 */
#ifndef AMISNAP_TRANSPORT_H
#define AMISNAP_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

typedef struct amisnap_transport amisnap_transport;

/* Field names are prefixed (tp_*) rather than the obvious connect/
 * send/recv/close -- bsdsocket.library's own inline/bsdsocket.h
 * (included by src/amiga/socket.c, the one real implementation of this
 * vtable) #defines connect/send/recv as function-like macros over its
 * own LVO stubs, which would otherwise silently mangle these very
 * field names wherever this header is included afterward -- confirmed
 * the hard way (a real cross-build failure: "macro 'connect' passed 4
 * arguments, but takes just 3"), not a hypothetical worry. */
typedef struct {
    /* Opens a new blocking TCP connection to host:port. Returns
     * AMISNAP_OK with *handle_out set, or a negative AMISNAP_ERR_*
     * (AMISNAP_ERR_IO for a resolution/connection failure). */
    int (*tp_connect)(amisnap_transport *t, const char *host, uint16_t port, void **handle_out);

    /* Sends every byte of data/len over `handle`, looping internally as
     * needed (a single underlying send may accept fewer bytes than
     * asked). Returns AMISNAP_OK or AMISNAP_ERR_IO. */
    int (*tp_send)(amisnap_transport *t, void *handle, const void *data, size_t len);

    /* One read: fills `buf` with up to `len` bytes, reporting the
     * actual count via *got (0 = orderly peer shutdown, matching
     * http.h's own end-of-response expectations -- not an error).
     * Returns AMISNAP_OK or AMISNAP_ERR_IO. */
    int (*tp_recv)(amisnap_transport *t, void *handle, void *buf, size_t len, size_t *got);

    /* Closes `handle`. A no-op on a NULL handle, same tolerant
     * convention as amisnap_backend_close(). */
    void (*tp_close)(amisnap_transport *t, void *handle);
} amisnap_transport_ops;

struct amisnap_transport {
    const amisnap_transport_ops *ops;
    void *ctx;
};

static inline int amisnap_transport_connect(amisnap_transport *t, const char *host, uint16_t port,
                                             void **handle_out)
{
    return t->ops->tp_connect(t, host, port, handle_out);
}

static inline int amisnap_transport_send(amisnap_transport *t, void *handle,
                                          const void *data, size_t len)
{
    return t->ops->tp_send(t, handle, data, len);
}

static inline int amisnap_transport_recv(amisnap_transport *t, void *handle,
                                          void *buf, size_t len, size_t *got)
{
    return t->ops->tp_recv(t, handle, buf, len, got);
}

static inline void amisnap_transport_close(amisnap_transport *t, void *handle)
{
    t->ops->tp_close(t, handle);
}

#endif /* AMISNAP_TRANSPORT_H */
