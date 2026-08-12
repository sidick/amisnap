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

int amisnap_socket_connect(const char *host, uint16_t port, LONG *sock_out)
{
    struct sockaddr_in addr;
    LONG sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (!inet_aton((STRPTR)host, &addr.sin_addr)) {
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
