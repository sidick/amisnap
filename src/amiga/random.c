/* random.c -- AmigaOS CSPRNG for the repository key/salt/WRAPPED_KEY
 * nonce (docs/format.md "Encryption"), plus RAW no-echo passphrase
 * input that doubles as an entropy source (per-keystroke timing).
 * Adapted from sibling AmiAuth v1.0's src/amiga/random.c -- the entropy
 * gathering, timer.device handling, and RAW-mode passphrase reading are
 * unchanged; only the running accumulator hash moves from SHA-1 to
 * SHA-256 (src/core/sha256.c, already vendored for PBKDF2 -- see
 * drbg.h for why the DRBG itself made the same swap) so this doesn't
 * need a second, otherwise-unused hash primitive in the tree.
 *
 * AmigaOS has no strong built-in RNG, so we gather entropy from
 * timer.device EClock timing jitter and assorted volatile system state,
 * accumulate it in a SHA-256 pool, and whiten/expand through an
 * HMAC-DRBG (src/core/drbg.c). The honest limits (a quiescent 68000
 * yields little timing entropy; a deterministic emulator yields even
 * less) apply here exactly as AmiAuth documents for its own vault --
 * which is why the interactive keystroke timing during passphrase entry
 * matters, why each request folds a per-process call counter (distinct
 * draws within a run), and why amisnap_stir_file() exists to fold the
 * previous repository header's own random bytes before generating a
 * fresh one, so the nonce chain stays distinct across runs too.
 *
 * m68k build only (src/amiga/, per the module map) -- host CI cannot
 * build or exercise it (no exec.library/timer.device on a host); the
 * portable DRBG it feeds is host-tested against known-answer vectors
 * instead (tests/test_drbg.c).
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <devices/timer.h>
#include <dos/dos.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>

#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "drbg.h"
#include "entropy.h"

struct Device *TimerBase;          /* set while a timer.device unit is open
                                    * (type per proto/timer.h) */

static amisnap_sha256_ctx g_pool;          /* running entropy accumulator */
static int                g_pool_ready;
static amisnap_drbg_state g_drbg;
static int                g_drbg_ready;
static uint32_t           g_calls;         /* monotonic, folded into every request */

static void pool_ensure(void)
{
    if (!g_pool_ready) {
        struct DateStamp ds;
        void *sysbase = (void *)SysBase;
        amisnap_sha256_init(&g_pool);
        amisnap_sha256_update(&g_pool, &sysbase, sizeof sysbase);
        DateStamp(&ds);
        amisnap_sha256_update(&g_pool, &ds, sizeof ds);
        g_pool_ready = 1;
    }
}

void amisnap_entropy_stir(const void *p, size_t n)
{
    pool_ensure();
    amisnap_sha256_update(&g_pool, p, n);
}

void amisnap_stir_file(const char *path, size_t n)
{
    uint8_t buf[128];
    FILE *f;
    size_t got;

    if (!path || n == 0) return;
    if (n > sizeof buf) n = sizeof buf;
    f = fopen(path, "rb");
    if (!f) return;                     /* no file yet: nothing to fold */
    got = fread(buf, 1, n, f);
    fclose(f);
    if (got) amisnap_entropy_stir(buf, got);
    memset(buf, 0, sizeof buf);
}

/* timer.device UNIT_ECLOCK, opened once and shared by the entropy gatherer
 * and amisnap_millis, so TimerBase stays valid throughout -- hence no
 * per-call open/close. Exec does NOT reclaim device opens/ports at exit;
 * the CLI front-end calls amisnap_entropy_cleanup() on its way out, or
 * every run would leak the port + IORequest and bump timer.device's open
 * count until reboot. */
static struct MsgPort     *g_tport;
static struct timerequest *g_treq;
static int                 g_timer_tried;

static int timer_ready(void)
{
    if (!g_timer_tried) {
        struct MsgPort *port = CreateMsgPort();
        g_timer_tried = 1;
        if (port) {
            struct timerequest *tr =
                (struct timerequest *)CreateIORequest(port, sizeof *tr);
            if (tr && OpenDevice((STRPTR)TIMERNAME, UNIT_ECLOCK,
                                 (struct IORequest *)tr, 0) == 0) {
                TimerBase = tr->tr_node.io_Device;
                g_tport = port;
                g_treq = tr;
            } else {
                if (tr) DeleteIORequest((struct IORequest *)tr);
                DeleteMsgPort(port);
            }
        }
    }
    return g_treq != NULL;
}

void amisnap_entropy_cleanup(void)
{
    if (g_treq) {
        CloseDevice((struct IORequest *)g_treq);
        DeleteIORequest((struct IORequest *)g_treq);
        g_treq = NULL;
        TimerBase = NULL;
    }
    if (g_tport) {
        DeleteMsgPort(g_tport);
        g_tport = NULL;
    }
    g_timer_tried = 0;                  /* a later call may reopen */
    /* Scrub the RNG state too: the pool has absorbed keystroke timings and
     * the DRBG key stream generated repository key material. */
    memset(&g_pool, 0, sizeof g_pool);
    memset(&g_drbg, 0, sizeof g_drbg);
    g_pool_ready = g_drbg_ready = 0;
    g_calls = 0;
}

/* Milliseconds from the E-clock, monotonic (wraps ~every 49 days). 0 if no
 * timer -- the caller then falls back to a default PBKDF2 iteration count. */
uint32_t amisnap_millis(void)
{
    struct EClockVal ev;
    ULONG freq;
    uint64_t ticks;
    if (!timer_ready()) return 0;
    freq = ReadEClock(&ev);
    if (!freq) return 0;
    ticks = ((uint64_t)ev.ev_hi << 32) | ev.ev_lo;
    return (uint32_t)(ticks * 1000u / freq);
}

/* Fold a fresh EClock reading into the pool (TimerBase must be valid). */
static void stir_eclock(void)
{
    struct EClockVal ev;
    ReadEClock(&ev);
    amisnap_sha256_update(&g_pool, &ev, sizeof ev);
}

void amisnap_stir_keystroke(void)
{
    pool_ensure();
    if (timer_ready()) stir_eclock();
}

/* Fold volatile system state that varies run-to-run. */
static void stir_system_state(void)
{
    struct DateStamp ds;
    ULONG mem[3];
    void *addrs[3];
    void *blk;

    DateStamp(&ds);
    amisnap_sha256_update(&g_pool, &ds, sizeof ds);

    mem[0] = AvailMem(MEMF_ANY);
    mem[1] = AvailMem(MEMF_CHIP);
    mem[2] = AvailMem(MEMF_FAST);
    amisnap_sha256_update(&g_pool, mem, sizeof mem);

    addrs[0] = (void *)FindTask(NULL);
    addrs[1] = (void *)&ds;                     /* a stack address */
    addrs[2] = (void *)SysBase;
    amisnap_sha256_update(&g_pool, addrs, sizeof addrs);

    /* A fresh allocation: its address, plus its residual (uninitialised) bytes. */
    blk = AllocMem(64, MEMF_ANY);               /* no MEMF_CLEAR: keep residue */
    if (blk) {
        amisnap_sha256_update(&g_pool, &blk, sizeof blk);
        amisnap_sha256_update(&g_pool, blk, 64);
        FreeMem(blk, 64);
    }
}

int amisnap_random(uint8_t *buf, size_t n)
{
    amisnap_sha256_ctx snap;
    uint8_t seed[AMISNAP_SHA256_DIGEST_SIZE];

    pool_ensure();

    /* Fail closed without the EClock timer. It is this generator's only
     * high-quality entropy source -- the jitter loop below, and (its
     * only would-be fallback) the keystroke-timing jitter in
     * amisnap_read_passphrase(), are BOTH gated on it. Without the
     * timer the pool holds only a low-resolution DateStamp, a few
     * AvailMem/pointer values, and 64 bytes of allocation residue --
     * near-guessable on a fresh deterministic emulator, and this
     * function is used ONLY to mint long-lived repository key material
     * (INIT/REKEY: the repo key, KDF salt, wrap nonce, repo id). A weak
     * key here silently undermines every encrypted backup, so refuse
     * rather than proceed: cmd_init()/cmd_rekey() already surface a
     * "could not gather entropy" error to the user on a nonzero return.
     * (timer_ready() opens the timer once and latches, so this is a
     * deterministic per-process decision, not a transient flake.) */
    if (!timer_ready())
        return -1;

    g_calls++;
    amisnap_sha256_update(&g_pool, &g_calls, sizeof g_calls);
    stir_system_state();

    /* EClock jitter: rapid reads with a little work between them. */
    {
        int i;
        for (i = 0; i < 96; i++) {
            stir_eclock();
            (void)AvailMem(MEMF_ANY);           /* perturb timing slightly */
        }
    }

    /* Whiten/expand: seed (first call) or reseed (later) the DRBG from a
     * snapshot of the pool, then emit. The snapshot finalises a copy so the
     * running pool keeps accumulating. */
    snap = g_pool;
    amisnap_sha256_final(&snap, seed);
    if (!g_drbg_ready) { amisnap_drbg_init(&g_drbg, seed, sizeof seed); g_drbg_ready = 1; }
    else               { amisnap_drbg_reseed(&g_drbg, seed, sizeof seed); }
    amisnap_drbg_generate(&g_drbg, buf, n);

    memset(seed, 0, sizeof seed);
    return 0;
}

int amisnap_read_passphrase(const char *prompt, char *buf, size_t cap)
{
    BPTR in = Input(), out = Output();
    size_t len = 0;
    int raw_ok, have_timer;

    if (cap == 0) return -1;
    if (!IsInteractive(in)) return -1;          /* encrypted repositories need a console */

    pool_ensure();

    have_timer = timer_ready();                 /* per-keystroke timing source */
    raw_ok = (SetMode(in, 1) != 0);             /* 1 = RAW (unbuffered, no echo) */
    if (!raw_ok) return -1;   /* can't guarantee no-echo: refuse rather than
                                * risk the passphrase appearing on screen
                                * (RAW's own echo alongside our own "*"s) */

    if (prompt) Write(out, (APTR)prompt, (LONG)strlen(prompt));

    for (;;) {
        char c;
        if (Read(in, &c, 1) <= 0) break;        /* EOF/error ends input */
        if (c == '\n' || c == '\r') break;
        if (have_timer) stir_eclock();          /* inter-keystroke jitter */
        if (c == '\b' || c == 0x7f) {           /* backspace / delete */
            if (len) { len--; Write(out, (APTR)"\b \b", 3); }
            continue;
        }
        if ((unsigned char)c < 0x20) continue;  /* ignore other control chars */
        if (len < cap - 1) { buf[len++] = c; Write(out, (APTR)"*", 1); }
    }
    buf[len] = '\0';

    if (raw_ok) SetMode(in, 0);                 /* restore cooked mode */
    Write(out, (APTR)"\n", 1);
    return 0;
}

int amisnap_read_line(const char *prompt, char *buf, size_t cap)
{
    BPTR in = Input(), out = Output();
    size_t len = 0;
    int raw_ok;

    if (cap == 0) return -1;
    if (!IsInteractive(in)) return -1;          /* prompts are interactive-only */
    if (prompt) Write(out, (APTR)prompt, (LONG)strlen(prompt));

    /* Read char-by-char in RAW mode (with echo). Not FGets: this handle is also
     * read unbuffered via Read() for the passphrase, and mixing buffered FGets
     * with unbuffered Read() makes FGets return EOF immediately. */
    raw_ok = (SetMode(in, 1) != 0);
    for (;;) {
        char c;
        if (Read(in, &c, 1) <= 0) break;
        if (c == '\n' || c == '\r') break;
        if (c == '\b' || c == 0x7f) {           /* backspace / delete */
            if (len) { len--; Write(out, (APTR)"\b \b", 3); }
            continue;
        }
        if ((unsigned char)c < 0x20) continue;
        if (len < cap - 1) { buf[len++] = c; Write(out, &c, 1); }   /* echo */
    }
    buf[len] = '\0';

    if (raw_ok) SetMode(in, 0);
    Write(out, (APTR)"\n", 1);
    return 0;
}
