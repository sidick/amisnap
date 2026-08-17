/* tls.c -- soft-loaded AmiSSL TLS transport (docs/proposal.md "TLS bulk
 * transfer (AmiSSL)", implementation-plan.md Phase 3 item 4): a real
 * amisnap_transport_ops implementation wrapping a plain bsdsocket TCP
 * connection (src/amiga/socket.c) in a real TLS session via AmiSSL, so
 * webdav.c can speak https:// through the same abstract transport.h
 * interface it already speaks http:// through -- webdav.c itself never
 * knows the difference.
 *
 * AmiSSL v5's own API surface (amisslmaster.library's OpenAmiSSLTagList
 * + amissl.library/amissl2.library's real OpenSSL-compatible SSL_*
 * functions) was verified against the real AmiSSL 5.27 SDK
 * (tests/copperline/fetch-amissl-sdk.sh -- headers under
 * Developer/include/, Autodocs under Developer/Autodocs/amissl.doc and
 * amisslmaster.doc), not assumed from memory -- house rule 6 applies
 * the same to a third-party SDK as to Commodore/Hyperion's own NDK.
 * The soft-load sequence itself (OpenLibrary("amisslmaster.library",
 * 5), then OpenAmiSSLTags with AmiSSL_UsesOpenSSLStructs=FALSE, an
 * AmiSSLBase/AmiSSLExtBase pair captured via
 * AmiSSL_GetAmiSSLBase/AmiSSL_GetAmiSSLExtBase) mirrors the pattern
 * sibling project AmiAuth already exercised for real
 * (tests/copperline/amisslbench.c, issue #85 groundwork) -- reused
 * here rather than re-derived, now for a real TLS connection instead
 * of a PBKDF2 benchmark.
 *
 * m68k build only (this file lives in src/amiga/, per the module map,
 * same as socket.c) -- AmiSSL has no 68000 path at all (confirmed by
 * AmiAuth's own amissl-bench.sh comment), so this is naturally gated
 * behind this project's already-020+ CPU floor with no separate check
 * needed.
 *
 * Connection setup uses a BIO pair, not SSL_set_fd() + a single
 * blocking SSL_connect() -- implementation-plan.md Phase 3 item 4's
 * own on-target diagnostics (tests/copperline/tlswebdavdiag.c,
 * confirmed live under Copperline twice, deterministic, purely local)
 * found the SSL_set_fd() path genuinely hangs inside AmiSSL's own
 * SSL_connect() whenever SSL_VERIFY_PEER + SSL_set1_host() are both
 * active -- i.e. always, in production, since "trust is everything"
 * means those are never optional here. This is the same failure mode
 * micropython/ports/amiga/modssl.c's own header comment already
 * documented independently on this exact platform ("its single
 * blocking SSL_connect was the more fragile of the two -- it
 * intermittently broke the pipe under the Amiga's slow handshakes,
 * where the BIO pump (with proper EAGAIN handling) succeeds") and
 * already ships a proven fix for: BIO_new_bio_pair() gives AmiSSL a
 * pair of in-memory BIOs instead of the raw socket fd, so
 * SSL_do_handshake()/SSL_read()/SSL_write() can never block inside
 * AmiSSL's own I/O code at all -- they either make progress or return
 * SSL_ERROR_WANT_READ/WANT_WRITE immediately, and *this file's own*
 * loop (tls_pump(), below) does the actual blocking send()/recv() over
 * the real socket, using the plain, already-correct blocking
 * amisnap_socket_send()/amisnap_socket_recv() from socket.c.
 *
 * Simpler than micropython's own version, deliberately: modssl.c has
 * to support non-blocking sockets (asyncio) and partial/stashed writes
 * because MicroPython's stream protocol can report EAGAIN from a
 * single write() call. AmiSnap's own transport.h contract is
 * unconditionally blocking end to end (amisnap_socket_send() itself
 * already loops until every byte is sent or a real error occurs, per
 * socket.h's own documented contract) -- so tls_pump() never needs to
 * stash a partial ciphertext tail across calls the way modssl.c's
 * ssl_flush_out()/out_buf does, and want_read always really blocks
 * until data arrives rather than needing an EAGAIN/poll-mask path.
 *
 * Cross-build-verified against the real SDK's headers and
 * libamisslstubs.a; genuine on-target execution needs a boot volume
 * with AmiSSL actually installed (the "AmiSSL:" assign + LIBS:AmiSSL/
 * setup its own installer performs -- AmiAuth's own amissl-bench.sh
 * documents that OpenAmiSSLTags() reliably crashes ramlib on a
 * from-scratch minimal boot lacking that assign) -- this BIO-pair
 * redesign was itself verified the same way item 4's earlier work
 * was: a real cloned WB+AmiSSL install, a throwaway CA installed into
 * its own AmiSSL:Certs, real SSL_VERIFY_PEER + SSL_set1_host() (the
 * exact configuration that hung before), see implementation-plan.md
 * for the full record.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <exec/types.h>
#include <proto/bsdsocket.h> /* SocketBase extern -- shared with socket.c, AmiSSL_SocketBase needs it */
#include <proto/exec.h>

#include <libraries/amisslmaster.h>
#include <proto/amisslmaster.h>
#include <amissl/tags.h>
#include <proto/amissl.h> /* pulls in amissl/amissl.h -> openssl/ssl.h transitively */
#include <openssl/err.h> /* ERR_clear_error() -- see tls_do_handshake()'s own comment */

#include "socket.h"
#include "tls.h"
#include "tlv.h"

struct Library *AmiSSLMasterBase = NULL;
struct Library *AmiSSLBase = NULL;
struct Library *AmiSSLExtBase = NULL;

static SSL_CTX *g_tls_ctx = NULL;
/* Mirrors the `insecure` argument amisnap_tls_lib_open() ran with --
 * tls_connect() below needs it too (to skip SSL_set1_host()), and
 * there's exactly one SSL_CTX/session policy live at a time in this
 * codebase, same reasoning g_tls_ctx itself is a module global. */
static int g_tls_insecure = 0;

void amisnap_tls_lib_close(void)
{
    if (g_tls_ctx) {
        SSL_CTX_free(g_tls_ctx);
        g_tls_ctx = NULL;
    }
    if (AmiSSLMasterBase) {
        /* CloseAmiSSL() also calls CleanupAmiSSL() for us (AmiSSL_InitAmiSSL
         * defaulted TRUE in amisnap_tls_lib_open()'s own OpenAmiSSLTags call)
         * and frees AmiSSLBase/AmiSSLExtBase itself -- must not CloseLibrary()
         * either of those directly, per amissl.doc's own InitAmiSSLA entry. */
        CloseAmiSSL();
        AmiSSLBase = NULL;
        AmiSSLExtBase = NULL;
        CloseLibrary(AmiSSLMasterBase);
        AmiSSLMasterBase = NULL;
    }
}

int amisnap_tls_lib_open(int allow_tls13, int insecure, const char *cipher_list)
{
    LONG rc;

    g_tls_insecure = insecure;

    AmiSSLMasterBase = OpenLibrary((CONST_STRPTR)"amisslmaster.library", 5);
    if (!AmiSSLMasterBase) return AMISNAP_ERR_IO;

    /* AmiSSL_ErrNoPtr: amissl.doc's own InitAmiSSLA entry warns "You
     * should always specify this tag or errno error detection in your
     * program will not work reliably", and AmiSSL's own internal
     * socket calls -- exactly the ones the blocking SSL_connect() path
     * below depends on -- need it to interpret retry conditions
     * correctly, independent of whether this file itself reads errno.
     * Previously omitted (reasoned at the time as optional); added
     * after confirming it's what the one other real, shipped AmiSSL
     * client on this platform (~/src/micropython/ports/amiga/
     * amiga_ssl.c) always passes, and after tests/copperline/
     * tlsbench.c's own on-target diagnostic (implementation-plan.md
     * Phase 3 item 4) used it throughout every one of its successful
     * local handshakes. */
    rc = OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
        AmiSSL_UsesOpenSSLStructs, FALSE, /* amissl.doc's own recommendation: avoid
                                            * pinning to today's struct layouts */
        AmiSSL_SocketBase,         (ULONG)SocketBase, /* must already be open --
                                                         * amisnap_socket_lib_open() first */
        AmiSSL_GetAmiSSLBase,      (ULONG)&AmiSSLBase,
        AmiSSL_GetAmiSSLExtBase,   (ULONG)&AmiSSLExtBase,
        AmiSSL_ErrNoPtr,           (ULONG)&errno,
        TAG_DONE);
    if (rc != 0 || !AmiSSLBase) {
        amisnap_tls_lib_close();
        return AMISNAP_ERR_IO;
    }

    g_tls_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_tls_ctx) {
        amisnap_tls_lib_close();
        return AMISNAP_ERR_IO;
    }

    /* TLS 1.2 by default, TLS 1.3 opt-in (CLI: TLS13 switch, main.c).
     * The version cap itself is unrelated to the BIO-pair redesign
     * above (this file's own header comment) -- kept because TLS 1.3
     * still hasn't had a dedicated local verification pass of its own
     * (only TLS 1.2 has, both before and after the BIO-pair fix),
     * not because 1.3 is assumed broken. Never below 1.2 either way
     * (TLS 1.0/1.1 are deprecated protocols this project has no reason
     * to accept from a server). */
    SSL_CTX_set_min_proto_version(g_tls_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_tls_ctx, allow_tls13 ? TLS1_3_VERSION : TLS1_2_VERSION);

    /* cipher_list override -- currently always NULL in practice (no
     * caller in this codebase wires it up; tls.h's own doc comment on
     * this parameter has the full "why not" -- a real, intermittent
     * on-target corruption when this was tried as a CLI switch).
     * Applied before the insecure/verified branch below since it's
     * orthogonal to both. Fails closed: an unrecognized or unsupported
     * cipher string is a real setup error, not silently ignored in
     * favor of the default list. */
    if (cipher_list && SSL_CTX_set_cipher_list(g_tls_ctx, cipher_list) != 1) {
        amisnap_tls_lib_close();
        return AMISNAP_ERR_IO;
    }

    if (insecure) {
        /* Explicit, deliberate opt-in (CLI: TLSINSECURE switch, never
         * the default) -- a home-lab NAS/WebDAV server with a
         * self-signed or otherwise untrusted certificate is a common,
         * legitimate destination this project has no business
         * refusing outright just because it can't build a chain to a
         * public CA. No callback, no AmiSSL:Certs load (skipped
         * entirely -- this mode has no use for it, and it means
         * TLSINSECURE also works on a system with no real CA store set
         * up at all, another common home-lab case). tls_connect()
         * below also skips SSL_set1_host() when this is set, per its
         * own comment. */
        // nosemgrep: cpp.lang.security.crypto.certificate.openssl-disabled-cert-validation.openssl-disabled-cert-validation
        SSL_CTX_set_verify(g_tls_ctx, SSL_VERIFY_NONE, NULL);
        return AMISNAP_OK;
    }

    /* Real verification, not a placeholder: chain trust against AmiSSL's
     * own bundled, pre-hashed CA directory (the standard OpenSSL c_rehash
     * layout -- confirmed present under the OS3 runtime package's own
     * AmiSSL/Certs/, tests/copperline/fetch-amissl-sdk.sh). If this
     * directory isn't set up (AmiSSL not actually installed on this
     * system, just amisslmaster.library present), fail closed here
     * rather than silently connecting without any way to check who's on
     * the other end -- "trust is everything" (TLSINSECURE above is the
     * explicit, opt-in escape hatch from that policy; this is the
     * default path, and it stays strict). Hostname verification
     * against the connected host happens per-connection in
     * tls_connect() below (SSL_set1_host()), not here.
     *
     * The next line's NULL is the verify *callback* (a custom hook),
     * not the mode -- the mode is SSL_VERIFY_PEER, real chain
     * verification, the opposite of SSL_VERIFY_NONE. NULL there means
     * "use OpenSSL's own default verification procedure", the
     * standard, correct idiom for real verification with no custom
     * logic -- not disabled validation, despite how the lint rule
     * below reads it on sight. */
    // nosemgrep: cpp.lang.security.crypto.certificate.openssl-disabled-cert-validation.openssl-disabled-cert-validation
    SSL_CTX_set_verify(g_tls_ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(g_tls_ctx, NULL, "AmiSSL:Certs") != 1) {
        amisnap_tls_lib_close();
        return AMISNAP_ERR_IO;
    }

    return AMISNAP_OK;
}

typedef struct {
    LONG sock;
    SSL *ssl;
    BIO *net_bio; /* our side of the pair; SSL owns the other side (internal_bio)
                    * once SSL_set_bio() runs -- freed automatically by SSL_free(). */
    /* Bytes already read off the real socket but not yet fully handed
     * to net_bio -- see tls_flush_in()'s own comment for why this
     * stash exists (a short BIO_write() into the pair's bounded
     * buffer is a real, legitimate outcome, unlike a blocking socket
     * send()). [off, len) is the unwritten remainder. */
    char pending_in[4096];
    size_t pending_in_len;
    size_t pending_in_off;
} tls_handle;

/* Buffer size for both directions of tls_pump() below -- comfortably
 * under BIO_new_bio_pair()'s own default per-side buffer (17KB, since
 * this file passes 0/0 for "use the default"), so a single chunk can
 * never itself overflow the pair. Not tied to any TLS record-size
 * limit -- SSL_do_handshake()/SSL_read()/SSL_write() each drain
 * whatever's already in internal_bio before ever reporting
 * WANT_READ/WANT_WRITE again, so tls_pump() is always called again for
 * more before the pair can back up. Must match tls_handle's own
 * `pending_in` size above (one buffer's worth of unwritten input is
 * the most tls_flush_in() ever needs to stash at once). */
#define TLS_PUMP_CHUNK 4096

/* Pushes every byte AmiSSL currently has queued in net_bio (its
 * outgoing ciphertext -- handshake flights, encrypted records, or a
 * queued close_notify) out over the real, already-blocking
 * amisnap_socket_send() (which itself loops until every byte is sent
 * or a real error occurs, per socket.h's own contract) -- so there is
 * nothing to stash across calls the way a non-blocking pump would
 * need to (see this file's own header comment for the contrast with
 * micropython/ports/amiga/modssl.c's own ssl_flush_out()). */
static int tls_flush_out(tls_handle *h)
{
    size_t pending = BIO_ctrl_pending(h->net_bio);

    while (pending > 0) {
        char buf[TLS_PUMP_CHUNK];
        int n = BIO_read(h->net_bio, buf,
                          (int)(pending < sizeof(buf) ? pending : sizeof(buf)));

        if (n <= 0) break; /* BIO_ctrl_pending() just said pending>0 -- not expected */
        if (amisnap_socket_send(h->sock, buf, (size_t)n) != AMISNAP_OK) return AMISNAP_ERR_IO;
        pending = BIO_ctrl_pending(h->net_bio);
    }
    return AMISNAP_OK;
}

/* One round of shuttling ciphertext between AmiSSL's side of the BIO
 * pair and the real socket -- the whole point of the BIO-pair redesign
 * (this file's own header comment): called only when
 * SSL_do_handshake()/SSL_read()/SSL_write() just reported
 * SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, meaning AmiSSL made
 * whatever progress it could with what it already had and is now
 * blocked purely on I/O -- never inside AmiSSL's own call stack, so a
 * real blocking recv() here is exactly as safe as it would be in any
 * other transport.h implementation.
 *
 * Always flushes pending output first regardless of `want_read`: a
 * WANT_READ can still have unrelated queued output (e.g. mid-
 * handshake flights are not strictly request/response), and a
 * WANT_WRITE by definition has output to flush. Only blocks on a real
 * recv() when `want_read` is set -- otherwise this call is pure
 * output-flushing and returns as soon as that's done. */

/* Pushes h->pending_in[off..len) into net_bio, as much as fits.
 * BIO_write() into a BIO pair is NOT the same as the always-loops-to-
 * completion amisnap_socket_send() this file's own header comment
 * contrasts it with: the pair's buffer is a fixed, bounded size
 * (~17KB/side, this file's own BIO_new_bio_pair() call), so a short
 * write is a real, legitimate outcome whenever AmiSSL hasn't yet
 * drained everything already queued on its side (plausible mid a
 * real certificate-chain-heavy handshake, or any record large enough
 * to need more than one pump round) -- not a bug in AmiSSL, a genuine
 * capacity limit this file must handle. Advances h->pending_in_off as
 * progress is made; stops (without error) on a retryable short write
 * so tls_run()'s own loop gets a chance to call the SSL op again and
 * drain the pair before the next tls_pump() tries to push more. A
 * non-retryable failure (BIO_should_retry() false) is a real error. */
static int tls_flush_in(tls_handle *h)
{
    while (h->pending_in_off < h->pending_in_len) {
        int n = BIO_write(h->net_bio, h->pending_in + h->pending_in_off,
                           (int)(h->pending_in_len - h->pending_in_off));

        if (n > 0) {
            h->pending_in_off += (size_t)n;
            continue;
        }
        if (BIO_should_retry(h->net_bio)) return AMISNAP_OK; /* pair full for now, try again later */
        return AMISNAP_ERR_IO; /* real, non-retryable BIO error */
    }
    return AMISNAP_OK;
}

static int tls_pump(tls_handle *h, int want_read)
{
    int rc = tls_flush_out(h);

    if (rc != AMISNAP_OK) return rc;

    rc = tls_flush_in(h);
    if (rc != AMISNAP_OK) return rc;

    /* Never read more off the socket while a previous chunk is still
     * only partly delivered into net_bio -- pending_in has room for
     * exactly one chunk, and tls_run()'s retry loop will call this
     * again (after giving the SSL op a chance to drain the pair)
     * before any new data is needed. */
    if (want_read && h->pending_in_off >= h->pending_in_len) {
        size_t got = 0;

        rc = amisnap_socket_recv(h->sock, h->pending_in, sizeof(h->pending_in), &got);
        if (rc != AMISNAP_OK) return AMISNAP_ERR_IO;
        /* The real TCP connection closing while AmiSSL is still
         * waiting for more bytes is never a clean outcome at this
         * layer, handshake or otherwise -- tls_recv()'s own
         * SSL_ERROR_ZERO_RETURN check (a real, in-protocol
         * close_notify) is the only path a clean EOF can take. */
        if (got == 0) return AMISNAP_ERR_IO;
        h->pending_in_len = got;
        h->pending_in_off = 0;
        rc = tls_flush_in(h);
        if (rc != AMISNAP_OK) return rc;
    }
    return AMISNAP_OK;
}

/* Drives any AmiSSL operation whose blocking should happen out here
 * (pumped over the real socket) rather than inside AmiSSL's own call
 * stack: retries `op` until it succeeds, hits a real (non-WANT_*)
 * error, or a pump round itself fails. `op`'s return follows normal
 * OpenSSL convention (<=0 means "check SSL_get_error()"). Shared by
 * the handshake, tls_send(), and tls_recv() below -- all three are
 * "call something, and if AmiSSL says WANT_READ/WANT_WRITE, pump and
 * retry" with only the something and the success test differing. */
typedef int (*tls_op_fn)(SSL *ssl, void *ctx);

static int tls_run(tls_handle *h, tls_op_fn op, void *ctx, int *op_result_out)
{
    for (;;) {
        int r, err;

        /* SSL_get_error()'s own contract: it only reports reliably
         * when the thread-local error queue is empty going in, or a
         * stale error left behind by an earlier, unrelated failure can
         * make a perfectly normal WANT_READ/WANT_WRITE misreport as
         * fatal -- confirmed load-bearing by a real, shipped AmiSSL
         * client on this exact platform
         * (~/src/micropython/ports/amiga/modssl.c's own comment at
         * every one of its SSL_get_error() call sites). */
        ERR_clear_error();
        r = op(h->ssl, ctx);
        if (r > 0) {
            *op_result_out = r;
            return AMISNAP_OK;
        }
        err = SSL_get_error(h->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            int rc = tls_pump(h, err == SSL_ERROR_WANT_READ);

            if (rc != AMISNAP_OK) return rc;
            continue;
        }
        *op_result_out = r;
        /* Real terminal error (SSL_ERROR_SSL, SSL_ERROR_SYSCALL, or
         * SSL_ERROR_ZERO_RETURN) -- the caller distinguishes those by
         * its own SSL_get_error() call on the now-final state, same as
         * before this redesign; tls_run() itself only arbitrates the
         * pump-and-retry loop. */
        return AMISNAP_ERR_IO;
    }
}

static int do_handshake_op(SSL *ssl, void *ctx)
{
    (void)ctx;
    return SSL_do_handshake(ssl);
}

typedef struct { void *buf; int len; } tls_io_args;

static int do_read_op(SSL *ssl, void *ctx)
{
    tls_io_args *a = (tls_io_args *)ctx;
    return SSL_read(ssl, a->buf, a->len);
}

static int do_write_op(SSL *ssl, void *ctx)
{
    tls_io_args *a = (tls_io_args *)ctx;
    return SSL_write(ssl, a->buf, a->len);
}

static int tls_connect(amisnap_transport *t, const char *host, uint16_t port, void **handle_out)
{
    tls_handle *h;
    LONG sock;
    int rc, op_result;
    BIO *internal_bio;

    (void)t;
    if (!g_tls_ctx) return AMISNAP_ERR_IO;

    rc = amisnap_socket_connect(host, port, &sock);
    if (rc != AMISNAP_OK) return rc;

    h = (tls_handle *)malloc(sizeof(*h));
    if (!h) {
        amisnap_socket_close(sock);
        return AMISNAP_ERR_NOMEM;
    }
    h->sock = sock;
    h->net_bio = NULL;
    h->pending_in_len = 0;
    h->pending_in_off = 0;

    h->ssl = SSL_new(g_tls_ctx);
    if (!h->ssl) {
        amisnap_socket_close(sock);
        free(h);
        return AMISNAP_ERR_IO;
    }

    internal_bio = NULL;
    if (BIO_new_bio_pair(&internal_bio, 0, &h->net_bio, 0) != 1) {
        SSL_free(h->ssl);
        amisnap_socket_close(sock);
        free(h);
        return AMISNAP_ERR_IO;
    }
    SSL_set_bio(h->ssl, internal_bio, internal_bio); /* SSL now owns internal_bio */
    SSL_set_connect_state(h->ssl);

    /* SNI (the server-side name selection extension) and the client-side
     * hostname-match check are two distinct things -- both point at the
     * same `host`, but setting one never implies the other. SNI stays
     * on even in TLSINSECURE mode (it just helps the server pick the
     * right vhost/cert, harmless with no verification happening on our
     * end); SSL_set1_host() is skipped entirely when g_tls_insecure --
     * a self-signed home-lab cert's CN/SAN commonly doesn't match the
     * server's real address anyway, and with SSL_VERIFY_NONE already
     * set in amisnap_tls_lib_open() a hostname mismatch wouldn't abort
     * the connection regardless, so setting it would only be
     * misleading, not protective. */
    if (!SSL_set_tlsext_host_name(h->ssl, host) ||
        (!g_tls_insecure && !SSL_set1_host(h->ssl, host))) {
        SSL_free(h->ssl); /* frees internal_bio too */
        BIO_free(h->net_bio);
        amisnap_socket_close(sock);
        free(h);
        return AMISNAP_ERR_IO;
    }

    if (tls_run(h, do_handshake_op, NULL, &op_result) != AMISNAP_OK) {
        SSL_free(h->ssl);
        BIO_free(h->net_bio);
        amisnap_socket_close(sock);
        free(h);
        return AMISNAP_ERR_IO;
    }

    *handle_out = h;
    return AMISNAP_OK;
}

static int tls_send(amisnap_transport *t, void *handle, const void *data, size_t len)
{
    tls_handle *h = (tls_handle *)handle;
    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;

    (void)t;
    while (remaining > 0) {
        tls_io_args args;
        int op_result, rc;

        args.buf = (void *)p;
        /* SSL_write()'s own len parameter is a plain int -- a single
         * call is never asked to accept more than fits, same reasoning
         * TLS_PUMP_CHUNK's own comment gives, just at the plaintext
         * layer instead of the ciphertext one. */
        args.len = (int)(remaining < 0x7fffffffu ? remaining : 0x7fffffff);

        rc = tls_run(h, do_write_op, &args, &op_result);
        if (rc != AMISNAP_OK) return rc;
        /* SSL_write() only queues the record into the BIO pair --
         * tls_run()'s own pump-on-WANT_WRITE loop pushes most of it
         * already, but push the tail (if SSL_write() itself succeeded
         * without ever needing to pump) before considering these bytes
         * truly sent. */
        rc = tls_flush_out(h);
        if (rc != AMISNAP_OK) return rc;
        p += (size_t)op_result;
        remaining -= (size_t)op_result;
    }
    return AMISNAP_OK;
}

static int tls_recv(amisnap_transport *t, void *handle, void *buf, size_t len, size_t *got)
{
    tls_handle *h = (tls_handle *)handle;
    tls_io_args args;
    int op_result, rc;

    (void)t;
    args.buf = buf;
    args.len = (int)(len < 0x7fffffffu ? len : 0x7fffffff);

    rc = tls_run(h, do_read_op, &args, &op_result);
    if (rc == AMISNAP_OK) {
        *got = (size_t)op_result;
        return AMISNAP_OK;
    }

    /* An orderly TLS close (a real close_notify alert, not just the
     * underlying TCP connection dropping) reports as *got=0 -- the same
     * "peer performed an orderly shutdown" convention transport.h's own
     * tp_recv contract already documents for the plain bsdsocket path.
     * Anything else (a real I/O error, a truncated/reset connection) is
     * a genuine error -- never silently treated as a clean EOF. */
    if (SSL_get_error(h->ssl, op_result) == SSL_ERROR_ZERO_RETURN) {
        *got = 0;
        return AMISNAP_OK;
    }
    return AMISNAP_ERR_IO;
}

static void tls_close(amisnap_transport *t, void *handle)
{
    tls_handle *h = (tls_handle *)handle;

    (void)t;
    if (h) {
        if (h->ssl) {
            /* Best effort, same convention as every other close() in
             * this codebase: SSL_shutdown() queues a close_notify into
             * net_bio (it may need two calls for a full bidirectional
             * shutdown, but this never waits for the peer's own
             * close_notify back) -- one flush pushes it out; a flush
             * failure here still doesn't block teardown. */
            SSL_shutdown(h->ssl);
            tls_flush_out(h);
            SSL_free(h->ssl); /* frees internal_bio too */
        }
        if (h->net_bio) BIO_free(h->net_bio);
        amisnap_socket_close(h->sock);
        free(h);
    }
}

const amisnap_transport_ops amisnap_tls_transport_ops = {
    tls_connect, tls_send, tls_recv, tls_close
};
