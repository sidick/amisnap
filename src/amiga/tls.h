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
 * verification enabled by default (SSL_VERIFY_PEER +
 * SSL_CTX_load_verify_locations against "AmiSSL:Certs", the hashed CA
 * directory AmiSSL's own installer sets up and assigns) -- fails
 * closed (a negative AMISNAP_ERR_* code, never a silently-insecure
 * connection) if that verification setup itself can't be established,
 * matching this project's "trust is everything" house rule; a
 * destination that asked for `https://` gets real TLS or a clear
 * failure, never a silent downgrade. Returns AMISNAP_OK or a negative
 * AMISNAP_ERR_* code (AMISNAP_ERR_IO covers every failure mode here --
 * library absent, AmiSSL init failure, cert store unavailable --
 * deliberately undifferentiated at this layer; the caller's own
 * message is what tells the user which).
 *
 * `allow_tls13`: 0 caps the negotiated protocol at TLS 1.2 (the
 * default the CLI passes -- implementation-plan.md Phase 3 item 4's
 * own on-target diagnostic verified this exact blocking design
 * reliably completes real TLS 1.2 handshakes locally at every cipher
 * weight tried), non-zero allows TLS 1.3 too (CLI: the TLS13 switch --
 * opt-in because 1.3 hasn't had that same local verification pass
 * yet, not because it's assumed broken). Never below TLS 1.2 either
 * way.
 *
 * `insecure`: 0 keeps the real verification described above (the
 * default). Non-zero (CLI: the TLSINSECURE switch) disables it
 * entirely -- SSL_VERIFY_NONE, and AmiSSL:Certs is never even loaded
 * (so this also works on a system without a real CA store set up) --
 * for destinations with a self-signed or otherwise untrusted
 * certificate, the common case for a home-lab NAS/WebDAV server that
 * was never issued a certificate by a real CA. A deliberate, explicit
 * opt-in per house rule ("trust is everything" governs the *default*,
 * not the ceiling a user can choose to give up for a destination they
 * already trust some other way, e.g. it's on their own LAN) -- never
 * silent: amisnap_tls_lib_open() itself doesn't warn (it has no
 * per-destination context), but every caller that passes a non-zero
 * `insecure` is expected to log a visible warning first, the same way
 * main.c's own open_backend() does. */
int amisnap_tls_lib_open(int allow_tls13, int insecure);
void amisnap_tls_lib_close(void);

/* transport.h adapter: connect() opens a real bsdsocket TCP connection
 * (src/amiga/socket.c's amisnap_socket_connect()) then wraps it in a
 * TLS session over the shared SSL_CTX above. When amisnap_tls_lib_open()
 * ran with `insecure` clear (the default), this also verifies the
 * presented certificate's chain AND that its hostname matches the
 * connected host (SSL_set1_host() -- chain trust alone is not enough).
 * With `insecure` set, neither runs: SSL_set1_host() is skipped
 * entirely (a self-signed cert's CN/SAN commonly doesn't match a
 * home-lab server's real address anyway) and SSL_VERIFY_NONE means the
 * chain is never consulted either. send()/recv() are SSL_write()/
 * SSL_read(); close() attempts an orderly SSL_shutdown() before
 * tearing down the underlying socket (best effort -- a shutdown that
 * itself fails doesn't block teardown, same "never let cleanup itself
 * become the failure" convention as every other close() in this
 * codebase). */
extern const amisnap_transport_ops amisnap_tls_transport_ops;

#endif /* AMISNAP_TLS_H */
