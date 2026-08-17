/* tlsthroughput.c -- dev-only diagnostic (never linked into AmiSnap):
 * measures real bulk-cipher throughput on real 68020 hardware timing,
 * for the follow-up question implementation-plan.md Phase 3 item 4
 * raised after the TLS fix landed -- is a cipher override worth adding
 * for CPU budget on slower Amigas (proposal.md's own "CPU budget"
 * principle), not security/interop (TLSINSECURE already covers that)?
 *
 * Reimplements the connect sequence directly (same pattern as
 * tests/copperline/tlsbench.c, not the real tls.c) so cipher list can
 * be freely swapped per run; PSK mode isolates bulk-cipher cost from
 * key-exchange/certificate-verification cost entirely (no asymmetric
 * crypto at all), which is what this benchmark is actually trying to
 * measure -- real handshake-plus-transfer numbers for a realistic
 * certificate-based cipher are a separate, secondary measurement (see
 * run-tls-cipher-bench.sh's own real-cipher pass).
 *
 * Runs behind amisnap_stackswap_run() (src/amiga/stackswap.c) --
 * implementation-plan.md's own documented lesson from tlswebdavdiag.c:
 * a standalone binary's small default AmigaDOS stack can silently
 * corrupt state several frames deep under a real TLS call chain,
 * masquerading as a hang. Not optional here for the same reason.
 *
 * Usage: tlsthroughput <host> <port> <cipher> <psk_hex|-> <total_kb>
 *   psk_hex: hex-encoded PSK for a PSK_* cipher, or "-" for a
 *   certificate-based cipher (SSL_VERIFY_NONE -- this benchmark measures
 *   throughput, not trust; tests/copperline/tlsbench.c's own separate
 *   diagnostic already covers real verification).
 */
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
#include <proto/amissl.h>
#include <openssl/err.h>

#include "socket.h"
#include "stackswap.h"
#include "tlv.h"

struct Library *AmiSSLMasterBase = NULL;
struct Library *AmiSSLBase = NULL;
struct Library *AmiSSLExtBase = NULL;
struct Device *TimerBase = NULL;

static unsigned char g_psk_key[64];
static unsigned int g_psk_key_len = 0;

static unsigned int psk_client_cb(SSL *ssl, const char *hint,
                                   char *identity, unsigned int max_identity_len,
                                   unsigned char *psk, unsigned int max_psk_len)
{
    static const char IDENTITY[] = "amisnap-bench";

    (void)ssl;
    (void)hint;
    if (max_identity_len < sizeof(IDENTITY)) return 0;
    memcpy(identity, IDENTITY, sizeof(IDENTITY));
    if (max_psk_len < g_psk_key_len) return 0;
    memcpy(psk, g_psk_key, g_psk_key_len);
    return g_psk_key_len;
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

static int hex_decode(const char *hex, unsigned char *out, unsigned int out_cap)
{
    unsigned int len = (unsigned int)strlen(hex);
    unsigned int i;

    if (len % 2 != 0 || len / 2 > out_cap) return -1;
    for (i = 0; i < len / 2; i++) {
        unsigned int hi, lo;
        char c1 = hex[i * 2], c2 = hex[i * 2 + 1];

        if (c1 >= '0' && c1 <= '9') hi = (unsigned)(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') hi = (unsigned)(c1 - 'a' + 10);
        else return -1;
        if (c2 >= '0' && c2 <= '9') lo = (unsigned)(c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') lo = (unsigned)(c2 - 'a' + 10);
        else return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return (int)(len / 2);
}

typedef struct {
    const char *host;
    unsigned short port;
    const char *cipher;
    const char *psk_hex;
    unsigned long total_bytes;
} bench_args;

#define CHUNK 8192

static int run(void *arg)
{
    bench_args *a = (bench_args *)arg;
    LONG sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int rc, have_timer;
    struct EClockVal t0, t1;
    ULONG freq = 0;
    static char sendbuf[CHUNK];
    static char recvbuf[CHUNK];
    unsigned long remaining, sent_total, recv_total;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tlsthroughput: host=%s port=%u cipher=%s total_kb=%lu\n",
           a->host, (unsigned)a->port, a->cipher, a->total_bytes / 1024);

    have_timer = timer_open();
    if (!have_timer) printf("tlsthroughput: note: no timer.device, timings will read 0\n");

    if (amisnap_socket_lib_open() != AMISNAP_OK) {
        printf("tlsthroughput: FAIL bsdsocket.library not available\n");
        return 20;
    }

    AmiSSLMasterBase = OpenLibrary((CONST_STRPTR)"amisslmaster.library", 5);
    if (!AmiSSLMasterBase) {
        printf("tlsthroughput: FAIL amisslmaster.library not available\n");
        return 20;
    }

    rc = OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
        AmiSSL_UsesOpenSSLStructs, FALSE,
        AmiSSL_SocketBase,         (ULONG)SocketBase,
        AmiSSL_GetAmiSSLBase,      (ULONG)&AmiSSLBase,
        AmiSSL_GetAmiSSLExtBase,   (ULONG)&AmiSSLExtBase,
        TAG_DONE);
    if (rc != 0 || !AmiSSLBase) {
        printf("tlsthroughput: FAIL OpenAmiSSLTags rc=%ld\n", (long)rc);
        return 20;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("tlsthroughput: FAIL SSL_CTX_new\n");
        return 20;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_set_cipher_list(ctx, a->cipher) != 1) {
        printf("tlsthroughput: FAIL SSL_CTX_set_cipher_list(\"%s\") -- not supported\n", a->cipher);
        return 20;
    }

    if (strcmp(a->psk_hex, "-") != 0) {
        int klen = hex_decode(a->psk_hex, g_psk_key, sizeof(g_psk_key));

        if (klen <= 0) {
            printf("tlsthroughput: FAIL bad psk_hex\n");
            return 20;
        }
        g_psk_key_len = (unsigned int)klen;
        SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    }
    /* Throughput, not trust -- real verification is tests/copperline/
     * tlsbench.c's own separate concern. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // nosemgrep: cpp.lang.security.crypto.certificate.openssl-disabled-cert-validation.openssl-disabled-cert-validation

    rc = amisnap_socket_connect(a->host, a->port, &sock);
    if (rc != AMISNAP_OK) {
        printf("tlsthroughput: FAIL TCP connect rc=%d\n", rc);
        return 20;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("tlsthroughput: FAIL SSL_new\n");
        return 20;
    }
    if (!SSL_set_fd(ssl, (int)sock)) {
        printf("tlsthroughput: FAIL SSL_set_fd\n");
        return 20;
    }
    SSL_set_tlsext_host_name(ssl, a->host);

    rc = SSL_connect(ssl);
    if (rc != 1) {
        int ssl_err = SSL_get_error(ssl, rc);
        unsigned long e;
        char errbuf[256];

        printf("tlsthroughput: FAIL handshake (SSL_get_error=%d)\n", ssl_err);
        while ((e = ERR_get_error()) != 0) {
            ERR_error_string_n(e, errbuf, sizeof(errbuf));
            printf("tlsthroughput: openssl error: %s\n", errbuf);
        }
        return 20;
    }
    printf("tlsthroughput: handshake OK, cipher=%s\n", SSL_get_cipher(ssl));

    for (i = 0; i < CHUNK; i++) sendbuf[i] = (char)(i & 0xff);

    remaining = a->total_bytes;
    sent_total = 0;
    recv_total = 0;

    if (have_timer) freq = ReadEClock(&t0);
    while (remaining > 0) {
        int want = (int)(remaining < CHUNK ? remaining : CHUNK);
        int off = 0;

        while (off < want) {
            int n = SSL_write(ssl, sendbuf + off, want - off);

            if (n <= 0) {
                printf("tlsthroughput: FAIL SSL_write at sent_total=%lu\n", sent_total);
                return 20;
            }
            off += n;
        }
        sent_total += (unsigned long)want;

        off = 0;
        while (off < want) {
            int n = SSL_read(ssl, recvbuf + off, want - off);

            if (n <= 0) {
                printf("tlsthroughput: FAIL SSL_read at recv_total=%lu\n", recv_total);
                return 20;
            }
            off += n;
        }
        recv_total += (unsigned long)want;
        if (memcmp(sendbuf, recvbuf, (size_t)want) != 0) {
            printf("tlsthroughput: FAIL echo mismatch at offset %lu\n", sent_total);
            return 20;
        }

        remaining -= (unsigned long)want;
    }
    if (have_timer) ReadEClock(&t1);

    if (have_timer && freq > 0) {
        ULONG ticks = t1.ev_lo - t0.ev_lo;
        unsigned long ms = (unsigned long)(((unsigned long long)ticks * 1000ull) / freq);
        unsigned long kbps = ms > 0 ? (unsigned long)(((unsigned long long)sent_total * 1000ull) / ms / 1024ull) : 0;

        printf("tlsthroughput: RESULT cipher=%s bytes=%lu ms=%lu KBps=%lu\n",
               a->cipher, sent_total, ms, kbps);
    } else {
        printf("tlsthroughput: RESULT cipher=%s bytes=%lu (no timing available)\n",
               a->cipher, sent_total);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    amisnap_socket_close(sock);
    SSL_CTX_free(ctx);
    CloseAmiSSL();
    CloseLibrary(AmiSSLMasterBase);
    amisnap_socket_lib_close();

    printf("tlsthroughput: PASS\n");
    return 0;
}

int main(int argc, char **argv)
{
    bench_args a;
    int degraded = 0;
    int rc;

    if (argc < 6) {
        printf("usage: tlsthroughput <host> <port> <cipher> <psk_hex|-> <total_kb>\n");
        return 20;
    }
    a.host = argv[1];
    a.port = (unsigned short)atoi(argv[2]);
    a.cipher = argv[3];
    a.psk_hex = argv[4];
    a.total_bytes = (unsigned long)atol(argv[5]) * 1024ul;

    rc = amisnap_stackswap_run(run, &a, &degraded);
    if (degraded) {
        printf("tlsthroughput: note: ran on the default stack (StackSwap alloc failed)\n");
    }
    return rc;
}
