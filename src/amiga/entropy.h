/* entropy.h -- AmigaOS CSPRNG + secure passphrase input, adapted from
 * sibling AmiAuth v1.0's src/amiga/entropy.h/random.c (see random.c for
 * the full rationale). Implemented in random.c and linked into the
 * m68k build only -- AmiSnap has no host CLI build to give a /dev/urandom
 * equivalent to (see docs/implementation-plan.md Phase 4 item 2). The
 * core (drbg.c, subkey derivation) stays deterministic and takes
 * seed/salt/nonce as parameters.
 */
#ifndef AMISNAP_AMIGA_ENTROPY_H
#define AMISNAP_AMIGA_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

/* Fill buf with n cryptographically-random bytes. Returns 0 (always succeeds:
 * best-effort entropy whitened through an HMAC-DRBG -- see drbg.h). */
int amisnap_random(uint8_t *buf, size_t n);

/* Fold an application-supplied sample into the entropy pool. */
void amisnap_entropy_stir(const void *p, size_t n);

/* Fold the first n bytes (capped at 128) of a file into the entropy pool.
 * Called with the repository path before generating a fresh WRAPPED_KEY
 * nonce: the previous header's own random bytes get folded in, so two
 * runs from an identical cold-boot state (deterministic emulator, frozen
 * RTC) still diverge at their second-ever (re-)init. A missing file
 * folds nothing. */
void amisnap_stir_file(const char *path, size_t n);

/* Fold a fresh E-clock reading into the entropy pool -- call this on every
 * keystroke of any UI's own passphrase input loop (amisnap_read_passphrase()
 * already does this internally). */
void amisnap_stir_keystroke(void);

/* Prompt and read a passphrase with no echo, using RAW console mode. Each
 * keystroke's arrival time is stirred into the entropy pool. Returns 0 on
 * success, -1 if there is no interactive console or on error. */
int amisnap_read_passphrase(const char *prompt, char *buf, size_t cap);

/* Monotonic milliseconds from timer.device E-clock (for PBKDF2 iteration
 * calibration, docs/implementation-plan.md Phase 4 item 3). Returns 0 if
 * no timer is available. */
uint32_t amisnap_millis(void);

/* Close the shared timer.device unit/port and scrub the RNG state. Exec has
 * no resource tracking, so the CLI front-end must call this on exit --
 * without it every run leaks the port + IORequest until reboot. Safe to
 * call when nothing was ever opened; entropy calls after it simply reopen. */
void amisnap_entropy_cleanup(void);

/* Prompt and read a line with normal echo (for y/N re-key confirmations).
 * Returns 0 on success, -1 if there is no interactive console or on EOF. */
int amisnap_read_line(const char *prompt, char *buf, size_t cap);

#endif /* AMISNAP_AMIGA_ENTROPY_H */
