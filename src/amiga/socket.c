/* socket.c -- bsdsocket.library glue (docs/proposal.md "Tier 2 -- WebDAV
 * over HTTP(S)", implementation-plan.md Phase 3 item 2): a thin blocking
 * TCP client over bsdsocket.library, the Roadshow/AmiTCP de facto
 * standard networking API -- NOT part of the base NDK the rest of this
 * codebase's Amiga-side modules verify against (scan.c/restore_meta.c/
 * stackswap.c all cite exec.library/dos.library autodocs from
 * ndk32-autodocs); this module's function signatures were instead
 * verified against the real Roadshow SDK headers bundled in
 * ghcr.io/sidick/amiga-dev (proto/bsdsocket.h, clib/bsdsocket_protos.h,
 * libraries/bsdsocket.h, netdb.h, netinet/in.h), not assumed from
 * memory -- house rule 6 applies exactly the same to a third-party
 * library's headers as to Commodore/Hyperion's own.
 *
 * bsdsocket.library resolves every call through the module-global
 * SocketBase below via GCC inline-asm LVO stubs (inline/bsdsocket.h) --
 * the same jump-table-via-library-base pattern every other Amiga
 * library call in this codebase uses, just not auto-opened by the C
 * startup the way dos.library is, so amisnap_socket_lib_open() must run
 * first (see socket.h).
 *
 * m68k build only (this file lives in src/amiga/, per the module map) --
 * host CI cannot build or exercise it at all (no bsdsocket.library on a
 * host), so unlike the rest of this codebase's Amiga-side modules there
 * is no cross-build-then-vamos-then-Copperline staged verification story
 * yet: this is cross-build-verified only (compiles and links clean
 * under m68k-amigaos-gcc -noixemul against the real Roadshow headers).
 * vamos has no bsdsocket.library emulation (confirmed: no bsdsocket
 * references anywhere in the vamos skill's own reference material,
 * unlike its partial dos.library coverage) and Copperline's own
 * network-emulation capability is unconfirmed -- genuine on-target
 * verification is deferred to whenever webdav.c (item 3) gives this
 * module something real to connect to and Phase 3 item 5's host-CI
 * WebDAV-container plan clarifies what's actually testable where.
 */
#include <stdlib.h>
#include <string.h>

#include <exec/types.h>
#include <proto/bsdsocket.h>
#include <proto/exec.h>

#include "socket.h"
#include "tlv.h"

struct Library *SocketBase = NULL;

int amisnap_socket_lib_open(void)
{
    SocketBase = OpenLibrary((CONST_STRPTR)"bsdsocket.library", 4);
    return SocketBase ? AMISNAP_OK : AMISNAP_ERR_IO;
}

void amisnap_socket_lib_close(void)
{
    if (SocketBase) {
        CloseLibrary(SocketBase);
        SocketBase = NULL;
    }
}

/* Hand-rolled dotted-quad parser, deliberately NOT inet_aton() or
 * inet_addr(): confirmed live (real hang under Copperline's own
 * HostSocket board, its guest ROM/dispatch has no CALL_INET_ATON at
 * all -- grepped its own guest/hostsocket_board.h, only CALL_INET_ADDR
 * exists) that inet_aton() specifically isn't a safe cross-
 * implementation assumption to make; sibling project amipilot's own
 * tcp.c independently reached the same conclusion for a *different*
 * bsdsocket emulator (a real CPU trap there, not a hang), hand-rolling
 * its own parser for the identical reason -- not a one-off Copperline
 * quirk. inet_addr()'s own well-known ambiguity (255.255.255.255 is
 * indistinguishable from "not a dotted quad") is irrelevant for a
 * repository host address in practice, but avoided anyway now that a
 * parser this simple costs nothing to write directly against strtoul-
 * free digit parsing. Returns 1 on success, 0 if `s` isn't a plain
 * "n.n.n.n" (each n in 0-255, no leading/trailing garbage) -- callers
 * fall back to gethostbyname() in that case, same as inet_aton() itself
 * would have signalled via a 0 return. */
static int parse_dotted_quad(const char *s, struct in_addr *out)
{
    unsigned char octets[4];
    int i;

    for (i = 0; i < 4; i++) {
        unsigned int val = 0;
        int digits = 0;

        while (*s >= '0' && *s <= '9') {
            val = val * 10 + (unsigned int)(*s - '0');
            s++;
            digits++;
            if (digits > 3 || val > 255) return 0;
        }
        if (digits == 0) return 0;
        octets[i] = (unsigned char)val;
        if (i < 3) {
            if (*s != '.') return 0;
            s++;
        }
    }
    if (*s != '\0') return 0;

    /* m68k is big-endian, matching network byte order, so this 32-bit
     * value's own in-memory byte layout is already correct with no
     * separate htonl()-equivalent step -- octets[0] (the first octet
     * in the string) belongs in the most significant byte position,
     * exactly as it would arrive first over the wire. */
    out->s_addr = ((uint32_t)octets[0] << 24) | ((uint32_t)octets[1] << 16) |
                  ((uint32_t)octets[2] << 8) | (uint32_t)octets[3];
    return 1;
}

int amisnap_socket_connect(const char *host, uint16_t port, LONG *sock_out)
{
    struct sockaddr_in addr;
    LONG sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (!parse_dotted_quad(host, &addr.sin_addr)) {
        struct hostent *he = gethostbyname((STRPTR)host);

        /* h_length is the resolved address's own byte length (netdb.h);
         * checked against sizeof(struct in_addr) rather than assumed --
         * a resolver returning an AF_INET hit with a mismatched length
         * would otherwise read past he->h_addr_list[0] below. */
        if (!he || he->h_addrtype != AF_INET || he->h_length != (LONG)sizeof(struct in_addr))
            return AMISNAP_ERR_IO;
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return AMISNAP_ERR_IO;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CloseSocket(sock);
        return AMISNAP_ERR_IO;
    }

    *sock_out = sock;
    return AMISNAP_OK;
}

int amisnap_socket_send(LONG sock, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;

    while (remaining > 0) {
        LONG n = send(sock, (APTR)p, (LONG)remaining, 0);
        if (n <= 0) return AMISNAP_ERR_IO;
        p += n;
        remaining -= (size_t)n;
    }
    return AMISNAP_OK;
}

int amisnap_socket_recv(LONG sock, void *buf, size_t len, size_t *got)
{
    LONG n = recv(sock, buf, (LONG)len, 0);

    if (n < 0) return AMISNAP_ERR_IO;
    *got = (size_t)n;
    return AMISNAP_OK;
}

void amisnap_socket_close(LONG sock)
{
    if (sock >= 0)
        CloseSocket(sock);
}

/* --- amisnap_transport_ops adapter (transport.h) -- the one thing
 * webdav.c is allowed to depend on for network I/O, keeping webdav.c
 * itself portable/host-testable (see transport.h's own header comment).
 * Wraps the plain functions above behind the vtable shape; `t` is
 * unused (SocketBase is a true process-global, not per-instance) but
 * still threaded through for symmetry with a future transport that
 * genuinely needs per-instance state (a mock, for instance). */
typedef struct {
    LONG sock;
} bsdsocket_handle;

static int bsdsocket_transport_connect(amisnap_transport *t, const char *host, uint16_t port,
                                        void **handle_out)
{
    bsdsocket_handle *h;
    LONG sock;
    int rc;

    (void)t;
    rc = amisnap_socket_connect(host, port, &sock);
    if (rc != AMISNAP_OK) return rc;

    h = (bsdsocket_handle *)malloc(sizeof(*h));
    if (!h) {
        amisnap_socket_close(sock);
        return AMISNAP_ERR_NOMEM;
    }
    h->sock = sock;
    *handle_out = h;
    return AMISNAP_OK;
}

static int bsdsocket_transport_send(amisnap_transport *t, void *handle, const void *data, size_t len)
{
    (void)t;
    return amisnap_socket_send(((bsdsocket_handle *)handle)->sock, data, len);
}

static int bsdsocket_transport_recv(amisnap_transport *t, void *handle, void *buf, size_t len, size_t *got)
{
    (void)t;
    return amisnap_socket_recv(((bsdsocket_handle *)handle)->sock, buf, len, got);
}

static void bsdsocket_transport_close(amisnap_transport *t, void *handle)
{
    bsdsocket_handle *h = (bsdsocket_handle *)handle;

    (void)t;
    if (h) {
        amisnap_socket_close(h->sock);
        free(h);
    }
}

const amisnap_transport_ops amisnap_bsdsocket_transport_ops = {
    bsdsocket_transport_connect,
    bsdsocket_transport_send,
    bsdsocket_transport_recv,
    bsdsocket_transport_close
};
