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
 * needed. Cross-build-verified against the real SDK's headers and
 * libamisslstubs.a; genuine on-target execution needs a boot volume
 * with AmiSSL actually installed (the "AmiSSL:" assign + LIBS:AmiSSL/
 * setup its own installer performs -- AmiAuth's own amissl-bench.sh
 * documents that OpenAmiSSLTags() reliably crashes ramlib on a
 * from-scratch minimal boot lacking that assign), so unlike socket.c's
 * own bsdsocket path this has no Copperline regression yet -- tracked
 * as an open item, not silently assumed working.
 */
#include <stdlib.h>
#include <string.h>

#include <exec/types.h>
#include <proto/bsdsocket.h> /* SocketBase extern -- shared with socket.c, AmiSSL_SocketBase needs it */
#include <proto/exec.h>

#include <libraries/amisslmaster.h>
#include <proto/amisslmaster.h>
#include <amissl/tags.h>
#include <proto/amissl.h> /* pulls in amissl/amissl.h -> openssl/ssl.h transitively */

#include "socket.h"
#include "tls.h"
#include "tlv.h"

struct Library *AmiSSLMasterBase = NULL;
struct Library *AmiSSLBase = NULL;
struct Library *AmiSSLExtBase = NULL;

static SSL_CTX *g_tls_ctx = NULL;

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

int amisnap_tls_lib_open(void)
{
    LONG rc;

    AmiSSLMasterBase = OpenLibrary((CONST_STRPTR)"amisslmaster.library", 5);
    if (!AmiSSLMasterBase) return AMISNAP_ERR_IO;

    rc = OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
        AmiSSL_UsesOpenSSLStructs, FALSE, /* amissl.doc's own recommendation: avoid
                                            * pinning to today's struct layouts */
        AmiSSL_SocketBase,         (ULONG)SocketBase, /* must already be open --
                                                         * amisnap_socket_lib_open() first */
        AmiSSL_GetAmiSSLBase,      (ULONG)&AmiSSLBase,
        AmiSSL_GetAmiSSLExtBase,   (ULONG)&AmiSSLExtBase,
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

    /* Real verification, not a placeholder: chain trust against AmiSSL's
     * own bundled, pre-hashed CA directory (the standard OpenSSL c_rehash
     * layout -- confirmed present under the OS3 runtime package's own
     * AmiSSL/Certs/, tests/copperline/fetch-amissl-sdk.sh). If this
     * directory isn't set up (AmiSSL not actually installed on this
     * system, just amisslmaster.library present), fail closed here
     * rather than silently connecting without any way to check who's on
     * the other end -- "trust is everything". Hostname verification
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
} tls_handle;

static int tls_connect(amisnap_transport *t, const char *host, uint16_t port, void **handle_out)
{
    tls_handle *h;
    LONG sock;
    int rc;

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

    h->ssl = SSL_new(g_tls_ctx);
    if (!h->ssl) {
        amisnap_socket_close(sock);
        free(h);
        return AMISNAP_ERR_IO;
    }

    /* SNI (the server-side name selection extension) and the client-side
     * hostname-match check are two distinct things -- both point at the
     * same `host`, but setting one never implies the other. */
    if (!SSL_set_fd(h->ssl, (int)sock) ||
        !SSL_set_tlsext_host_name(h->ssl, host) ||
        !SSL_set1_host(h->ssl, host) ||
        SSL_connect(h->ssl) != 1) {
        SSL_free(h->ssl);
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
        int n = SSL_write(h->ssl, p, (int)remaining);

        if (n <= 0) return AMISNAP_ERR_IO;
        p += (size_t)n;
        remaining -= (size_t)n;
    }
    return AMISNAP_OK;
}

static int tls_recv(amisnap_transport *t, void *handle, void *buf, size_t len, size_t *got)
{
    tls_handle *h = (tls_handle *)handle;
    int n;

    (void)t;
    n = SSL_read(h->ssl, buf, (int)len);
    if (n > 0) {
        *got = (size_t)n;
        return AMISNAP_OK;
    }

    /* An orderly TLS close (a real close_notify alert, not just the
     * underlying TCP connection dropping) reports as *got=0 -- the same
     * "peer performed an orderly shutdown" convention transport.h's own
     * tp_recv contract already documents for the plain bsdsocket path.
     * Anything else (a real I/O error, a truncated/reset connection) is
     * a genuine error -- never silently treated as a clean EOF. */
    if (SSL_get_error(h->ssl, n) == SSL_ERROR_ZERO_RETURN) {
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
            SSL_shutdown(h->ssl); /* best effort -- never blocks teardown on its own result */
            SSL_free(h->ssl);
        }
        amisnap_socket_close(h->sock);
        free(h);
    }
}

const amisnap_transport_ops amisnap_tls_transport_ops = {
    tls_connect, tls_send, tls_recv, tls_close
};
