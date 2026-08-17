/* tlsbench.c -- dev-only, throwaway-style diagnostic (never linked into
 * AmiSnap itself, not part of any `make` target the shipped tool
 * depends on) testing whether tls.c's existing blocking
 * SSL_set_fd()+SSL_connect() design (implementation-plan.md Phase 3
 * item 4's own "confirmed, understood, real design flaw" -- an
 * independently-documented AmiSSL fragility "under the Amiga's slow
 * handshakes", per micropython/ports/amiga/modssl.c's own header
 * comment) can complete a real handshake at all once BOTH suspected
 * contributors to "slow" are removed at once: real internet RTT (the
 * item 4 diagnosis hung against a real `example.com:443`; this targets
 * a LOCAL server over Copperline's HostSocket loopback instead) and
 * handshake compute cost (starting with the cheapest real TLS cipher
 * there is, PSK-NULL-SHA -- no certificate exchange, no asymmetric key
 * exchange, no bulk encryption at all).
 *
 * Deliberately does NOT modify or link src/amiga/tls.c -- reimplements
 * its exact soft-load sequence directly (same amisslmaster.library +
 * OpenAmiSSLTags(AmiSSL_UsesOpenSSLStructs=FALSE, ...) pattern that
 * item 4's own on-target work already confirmed correct against a
 * real AmiSSL install) so cipher list / protocol version / PSK
 * callback can be freely swapped per run without touching production
 * code or needing to expose tls.c's file-scope SSL_CTX.
 *
 * Usage: tlsbench <host> <port> <cipher>
 *   host/port: a real, already-listening TLS server (this project's
 *   own run-tls-bench.sh starts a local `openssl s_server`).
 *   cipher: an OpenSSL SSL_CTX_set_cipher_list() string, tried against
 *   TLS <=1.2 only (PSK_* suites predate 1.3's fixed cipher-suite
 *   list, which has no PSK-only/NULL-encryption members).
 *
 * All progress is fprintf(stdout)+fflush()ed after every step, on
 * purpose: if a later step genuinely hangs, everything up to that
 * point is still on disk (Results:tlsbench.log, LOG-redirected same as
 * every other Copperline fixture in this tree) rather than lost in a
 * stdio buffer never flushed before Copperline itself is killed.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <exec/types.h>
#include <devices/timer.h>
#include <libraries/amisslmaster.h>

#include <proto/exec.h>
#include <proto/timer.h>
#include <proto/bsdsocket.h>
#include <proto/amisslmaster.h>
#include <amissl/tags.h>
#include <proto/amissl.h> /* pulls amissl/amissl.h -> openssl/ssl.h transitively */
#include <openssl/err.h>

#include "socket.h"
#include "tlv.h" /* AMISNAP_OK/AMISNAP_ERR_* */

struct Library *AmiSSLMasterBase = NULL;
struct Library *AmiSSLBase = NULL;
struct Library *AmiSSLExtBase = NULL;
struct Device *TimerBase = NULL;

/* A fixed, throwaway PSK identity/key -- this is a diagnostic against a
 * local, ephemeral `openssl s_server` instance the test script itself
 * starts and tears down, never a real credential. */
static const char PSK_IDENTITY[] = "amisnap-tlsbench";
static const unsigned char PSK_KEY[16] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09
};

static unsigned int psk_client_cb(SSL *ssl, const char *hint,
                                   char *identity, unsigned int max_identity_len,
                                   unsigned char *psk, unsigned int max_psk_len)
{
    (void)ssl;
    (void)hint;
    if (max_identity_len < sizeof(PSK_IDENTITY)) return 0;
    memcpy(identity, PSK_IDENTITY, sizeof(PSK_IDENTITY));
    if (max_psk_len < sizeof(PSK_KEY)) return 0;
    memcpy(psk, PSK_KEY, sizeof(PSK_KEY));
    return (unsigned int)sizeof(PSK_KEY);
}

static struct MsgPort *g_timer_port;
static struct timerequest *g_timer_req;

static int timer_open(void)
{
    g_timer_port = CreateMsgPort();
    if (!g_timer_port) return 0;
    g_timer_req = (struct timerequest *)CreateIORequest(g_timer_port, sizeof(*g_timer_req));
    if (!g_timer_req) return 0;
    if (OpenDevice((STRPTR)TIMERNAME, UNIT_ECLOCK, (struct IORequest *)g_timer_req, 0) != 0)
        return 0;
    TimerBase = g_timer_req->tr_node.io_Device;
    return 1;
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    unsigned short port = argc > 2 ? (unsigned short)atoi(argv[2]) : 4433;
    const char *cipher = argc > 3 ? argv[3] : "PSK-NULL-SHA";
    /* verify=1: exercise the exact real-production verification path
     * (SSL_VERIFY_PEER + SSL_CTX_load_verify_locations("AmiSSL:Certs")
     * + per-connection SSL_set1_host()) instead of this diagnostic's
     * original narrower VERIFY_NONE scope -- added to bisect a real
     * hang found in tls.c's own real tls_connect() (via the separate
     * tlswebdavdiag.c) that never reproduced in any VERIFY_NONE run
     * here, to find out whether it's specifically SSL_set1_host()/real
     * chain verification, not handshake mechanics generally. */
    int verify = argc > 4 && strcmp(argv[4], "1") == 0;
    LONG sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int rc;
    struct EClockVal t0, t1;
    ULONG freq = 0;
    int have_timer;

    /* Unbuffered, not just fflush()ed after each printf: a step that
     * genuinely hangs or crashes leaves nothing to fflush from -- this
     * is the only way every line up to that point is guaranteed to
     * already be on disk (confirmed the hard way: an earlier run's
     * final steps genuinely all succeeded, independently confirmed via
     * the server's own log showing a clean close_notify exchange, but
     * the client-side log stopped mid-run anyway because those later
     * printf()s were sitting in a stdio buffer Copperline's own
     * benchmark cutoff never gave a chance to flush). */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("tlsbench: host=%s port=%u cipher=%s\n", host, (unsigned)port, cipher);
    fflush(stdout);

    have_timer = timer_open();
    if (!have_timer) printf("tlsbench: note: no timer.device, timings will read 0\n");

    if (amisnap_socket_lib_open() != AMISNAP_OK) {
        printf("tlsbench: FAIL bsdsocket.library not available\n");
        return 20;
    }

    AmiSSLMasterBase = OpenLibrary((CONST_STRPTR)"amisslmaster.library", 5);
    if (!AmiSSLMasterBase) {
        printf("tlsbench: FAIL amisslmaster.library not available\n");
        return 20;
    }

    /* AmiSSL_ErrNoPtr: implementation-plan.md Phase 3 item 4's own
     * finding -- tls.c's production amisnap_tls_lib_open() currently
     * omits this (reasoned at the time as optional since nothing there
     * reads errno directly), but amissl.doc's InitAmiSSLA entry warns
     * "You should always specify this tag or errno error detection in
     * your program will not work reliably", and AmiSSL's *own*
     * internal socket calls -- exactly the ones driving the
     * now-confirmed-fragile blocking SSL_connect() path this
     * diagnostic is probing -- depend on it to interpret retry
     * conditions correctly, independent of whether this file ever
     * reads errno itself. micropython's own working
     * ~/src/micropython/ports/amiga/amiga_ssl.c (a real, shipped
     * AmiSSL client on this exact platform) always passes it; matched
     * here rather than reproducing tls.c's current omission. */
    rc = OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
        AmiSSL_UsesOpenSSLStructs, FALSE,
        AmiSSL_SocketBase,         (ULONG)SocketBase,
        AmiSSL_GetAmiSSLBase,      (ULONG)&AmiSSLBase,
        AmiSSL_GetAmiSSLExtBase,   (ULONG)&AmiSSLExtBase,
        AmiSSL_ErrNoPtr,           (ULONG)&errno,
        TAG_DONE);
    if (rc != 0 || !AmiSSLBase) {
        printf("tlsbench: FAIL OpenAmiSSLTags rc=%ld\n", (long)rc);
        return 20;
    }
    printf("tlsbench: OpenAmiSSLTags ok\n");
    fflush(stdout);

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("tlsbench: FAIL SSL_CTX_new\n");
        return 20;
    }

    /* PSK_* / *_NULL_* suites predate TLS 1.3's own fixed cipher-suite
     * list (AES-GCM/ChaCha20-Poly1305 only, selected via
     * SSL_CTX_set_ciphersuites(), not this call) -- cap the top end so
     * SSL_CTX_set_cipher_list() below can actually select one. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_set_cipher_list(ctx, cipher) != 1) {
        printf("tlsbench: FAIL SSL_CTX_set_cipher_list(\"%s\") -- not supported by "
               "this AmiSSL build\n", cipher);
        return 20;
    }
    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    if (verify) {
        /* Real production verification, not the narrower VERIFY_NONE
         * scope below: matches amisnap_tls_lib_open() exactly. */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // nosemgrep: cpp.lang.security.crypto.certificate.openssl-disabled-cert-validation.openssl-disabled-cert-validation
        if (SSL_CTX_load_verify_locations(ctx, NULL, "AmiSSL:Certs") != 1) {
            printf("tlsbench: FAIL SSL_CTX_load_verify_locations(AmiSSL:Certs)\n");
            return 20;
        }
    } else {
        /* PSK authenticates via the shared key itself, not a
         * certificate -- no chain to verify (this is a deliberate
         * diagnostic scope narrowing, not how amisnap_tls_lib_open()
         * behaves in production: that path keeps real SSL_VERIFY_PEER
         * always). */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // nosemgrep: cpp.lang.security.crypto.certificate.openssl-disabled-cert-validation.openssl-disabled-cert-validation
    }

    printf("tlsbench: connecting TCP %s:%u\n", host, (unsigned)port);
    fflush(stdout);
    rc = amisnap_socket_connect(host, port, &sock);
    if (rc != AMISNAP_OK) {
        printf("tlsbench: FAIL TCP connect rc=%d\n", rc);
        return 20;
    }
    printf("tlsbench: TCP connected, starting handshake\n");
    fflush(stdout);

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("tlsbench: FAIL SSL_new\n");
        return 20;
    }
    if (!SSL_set_fd(ssl, (int)sock)) {
        printf("tlsbench: FAIL SSL_set_fd\n");
        return 20;
    }
    /* SNI -- matches tls.c's own real tls_connect() (SSL_set_tlsext_
     * host_name()), not just the hostname-match check SSL_set1_host()
     * would add: real multi-tenant servers/CDNs (a real target this
     * diagnostic is trying to faithfully reproduce, unlike the local
     * single-vhost openssl s_server) commonly need SNI to select the
     * right virtual host's certificate/config at all, independent of
     * anything this diagnostic is actually trying to measure. */
    SSL_set_tlsext_host_name(ssl, host);
    if (verify) {
        /* The real production hostname-match check tls.c's own
         * tls_connect() always adds -- chain trust alone isn't enough.
         * This is the specific call this bisection run exists to
         * isolate. */
        if (!SSL_set1_host(ssl, host)) {
            printf("tlsbench: FAIL SSL_set1_host\n");
            return 20;
        }
        printf("tlsbench: SSL_set1_host OK, starting handshake\n");
    }

    if (have_timer) freq = ReadEClock(&t0);
    rc = SSL_connect(ssl);
    if (have_timer) ReadEClock(&t1);
    if (have_timer && freq > 0) {
        ULONG ticks = t1.ev_lo - t0.ev_lo;
        printf("tlsbench: SSL_connect returned %d after %lu ticks (%lu.%02lu sec, freq=%lu)\n",
               rc, (unsigned long)ticks, (unsigned long)(ticks / freq),
               (unsigned long)(((ticks % freq) * 100) / freq), (unsigned long)freq);
    } else {
        printf("tlsbench: SSL_connect returned %d\n", rc);
    }
    fflush(stdout);

    if (rc != 1) {
        int ssl_err = SSL_get_error(ssl, rc);
        unsigned long e;
        char errbuf[256];

        printf("tlsbench: FAIL handshake (SSL_get_error=%d)\n", ssl_err);
        while ((e = ERR_get_error()) != 0) {
            ERR_error_string_n(e, errbuf, sizeof(errbuf));
            printf("tlsbench: openssl error: %s\n", errbuf);
        }
        return 20;
    }
    printf("tlsbench: handshake OK, cipher=%s version=%s\n",
           SSL_get_cipher(ssl), SSL_get_version(ssl));
    fflush(stdout);

    {
        /* A minimal HTTP/1.0 GET -- the test script's own local server
         * runs `openssl s_server -www`, which answers any request with
         * a canned HTML status page, so this is a genuine bidirectional
         * data exchange over the negotiated session (not just a
         * handshake), without needing a bespoke echo protocol on the
         * server side. */
        static const char MSG[] = "GET / HTTP/1.0\r\n\r\n";
        char buf[256];
        int n;

        if (SSL_write(ssl, MSG, (int)sizeof(MSG) - 1) <= 0) {
            printf("tlsbench: FAIL SSL_write after handshake\n");
            return 20;
        }
        n = SSL_read(ssl, buf, (int)sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("tlsbench: got %d bytes after handshake, first line: %.40s\n", n, buf);
        } else {
            printf("tlsbench: FAIL SSL_read after handshake n=%d SSL_get_error=%d\n",
                   n, SSL_get_error(ssl, n));
            return 20;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    amisnap_socket_close(sock);
    SSL_CTX_free(ctx);
    CloseAmiSSL();
    AmiSSLBase = NULL;
    AmiSSLExtBase = NULL;
    CloseLibrary(AmiSSLMasterBase);
    AmiSSLMasterBase = NULL;
    amisnap_socket_lib_close();

    printf("tlsbench: PASS\n");
    return 0;
}
