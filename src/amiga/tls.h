/* tls.h -- see tls.c. */
#ifndef AMISNAP_TLS_H
#define AMISNAP_TLS_H

#include "transport.h"

/* Soft-loads amisslmaster.library + AmiSSL itself (OpenAmiSSLTagList,
 * AmiSSL v5's own recommended one-call init), sharing bsdsocket.
 * library's existing SocketBase (src/amiga/socket.c -- must already be
 * open via amisnap_socket_lib_open() before this is called; TLS always
 * rides on top of a real TCP connection, proposal.md's own "AmiSSL
 * (optional TLS)" framing, never a replacement for socket.c). Builds
 * one shared SSL_CTX with real certificate-chain AND hostname
 * verification enabled (SSL_VERIFY_PEER + SSL_CTX_load_verify_locations
 * against "AmiSSL:Certs", the hashed CA directory AmiSSL's own
 * installer sets up and assigns) -- fails closed (a negative
 * AMISNAP_ERR_* code, never a silently-insecure connection) if that
 * verification setup itself can't be established, matching this
 * project's "trust is everything" house rule; a destination that asked
 * for `https://` gets real TLS or a clear failure, never a silent
 * downgrade. Returns AMISNAP_OK or a negative AMISNAP_ERR_* code
 * (AMISNAP_ERR_IO covers every failure mode here -- library absent,
 * AmiSSL init failure, cert store unavailable -- deliberately
 * undifferentiated at this layer; the caller's own message is what
 * tells the user which). */
int amisnap_tls_lib_open(void);
void amisnap_tls_lib_close(void);

/* transport.h adapter: connect() opens a real bsdsocket TCP connection
 * (src/amiga/socket.c's amisnap_socket_connect()) then wraps it in a
 * TLS session over the shared SSL_CTX above, verifying both the
 * presented certificate's chain AND that its hostname matches the
 * connected host (SSL_set1_host() -- chain trust alone is not enough).
 * send()/recv() are SSL_write()/SSL_read(); close() attempts an orderly
 * SSL_shutdown() before tearing down the underlying socket (best
 * effort -- a shutdown that itself fails doesn't block teardown, same
 * "never let cleanup itself become the failure" convention as every
 * other close() in this codebase). */
extern const amisnap_transport_ops amisnap_tls_transport_ops;

#endif /* AMISNAP_TLS_H */
