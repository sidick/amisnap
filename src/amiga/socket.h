/* socket.h -- see socket.c. */
#ifndef AMISNAP_SOCKET_H
#define AMISNAP_SOCKET_H

#include <stddef.h>
#include <stdint.h>

#include <exec/types.h>

/* Opens bsdsocket.library (version 4, Roadshow/AmiTCP's own long-
 * standing baseline -- the inet_aton/getaddrinfo-era API this module
 * uses is well past that floor on any TCP/IP stack actually in use
 * today) and sets the module-global SocketBase every inline call in
 * socket.c resolves against. Must be called once before any other
 * function here, bracketing their use the same explicit way
 * stackswap.c's own StackSwap() lifecycle works -- bsdsocket.library is
 * NOT auto-opened by the C startup the way dos.library is. Returns
 * AMISNAP_OK or AMISNAP_ERR_IO if the library isn't installed (no
 * TCP/IP stack running -- a normal, expected condition on an offline
 * Amiga, not a crash-worthy one). */
int amisnap_socket_lib_open(void);
void amisnap_socket_lib_close(void);

/* A blocking TCP connection to host:port. `host` may be a dotted-quad
 * (tried first via inet_aton(), never inet_addr() -- inet_addr()'s
 * return value is ambiguous for the legitimate address
 * 255.255.255.255, a well-known BSD API wart) or a DNS name (resolved
 * via gethostbyname(), the classic synchronous BSD resolver -- Roadshow
 * ships no asynchronous alternative worth using for this tool's
 * serialized request/response traffic). Returns AMISNAP_OK with
 * *sock_out set, or AMISNAP_ERR_IO (resolution failure, connection
 * refused, any bsdsocket.library-reported error -- Errno() detail is
 * not surfaced yet; see socket.c's own note on where that will land). */
int amisnap_socket_connect(const char *host, uint16_t port, LONG *sock_out);

/* Sends every byte of `data`/`len`, looping over send() as needed --
 * a single send() call is not guaranteed to accept the whole buffer,
 * same partial-write contract as a POSIX TCP socket. Returns
 * AMISNAP_OK or AMISNAP_ERR_IO. */
int amisnap_socket_send(LONG sock, const void *data, size_t len);

/* One recv() call: fills `buf` with up to `len` bytes, reporting the
 * actual count via *got (0 = the peer performed an orderly shutdown --
 * matches http.h's own end-of-response-body expectations, not treated
 * as an error here). Returns AMISNAP_OK or AMISNAP_ERR_IO. */
int amisnap_socket_recv(LONG sock, void *buf, size_t len, size_t *got);

/* CloseSocket(); a no-op if sock < 0 (never opened / already closed),
 * matching amisnap_backend_close()'s own tolerant convention. */
void amisnap_socket_close(LONG sock);

#endif /* AMISNAP_SOCKET_H */
