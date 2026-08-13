/* repo_crypto.h -- CIPHER 1 (docs/format.md "Encryption") glue: subkey
 * derivation, deterministic object/manifest nonces, the nonce||
 * ciphertext||mac object/manifest frame, and repository-key wrap/
 * unwrap. Built entirely on the vendored primitives (chacha20.h,
 * blake2s.h, pbkdf2.h) -- no new crypto here, only the composition
 * docs/format.md's Encryption section specifies precisely.
 *
 * Deliberately has no dependency on any RNG: every key/nonce this file
 * touches is either passed in by the caller (the repository key,
 * already generated with real entropy at init -- see
 * src/amiga/entropy.h) or derived deterministically from data that is
 * already unique by construction (see the nonce functions below). This
 * keeps repo_crypto.c fully portable and host-testable, same as every
 * other src/core/ module -- randomness stays an Amiga-side concern.
 */
#ifndef AMISNAP_REPO_CRYPTO_H
#define AMISNAP_REPO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AMISNAP_REPO_KEY_SIZE     32
#define AMISNAP_REPO_NONCE_SIZE   12
#define AMISNAP_REPO_MAC_SIZE     16
/* WRAPPED_KEY tag content: nonce(12) + ciphertext(32) + mac(16). */
#define AMISNAP_WRAPPED_KEY_SIZE  60

typedef struct {
    uint8_t enc[AMISNAP_REPO_KEY_SIZE];    /* K_enc: object/manifest ChaCha20 key */
    uint8_t mac[AMISNAP_REPO_KEY_SIZE];    /* K_mac: object/manifest MAC key */
    uint8_t nonce[AMISNAP_REPO_KEY_SIZE];  /* K_nonce: deterministic nonce derivation key */
} amisnap_repo_subkeys;

/* Derives K_enc/K_mac/K_nonce from the repository key K via
 * domain-separated keyed BLAKE2s-256 (docs/format.md "Subkey
 * derivation"). */
void amisnap_repo_derive_subkeys(const uint8_t key[AMISNAP_REPO_KEY_SIZE],
                                  amisnap_repo_subkeys *out);

/* Object nonce = first 12 bytes of keyed-BLAKE2s-256(key=K_nonce,
 * message=content_hash) -- content_hash is the object's own plaintext
 * BLAKE2s-256 content address (the same hash that names it under
 * objects/<hh>/<hex64>), so this can never repeat for two different
 * plaintexts, and dedup guarantees a repeated plaintext is never
 * re-encrypted rather than re-nonced. */
void amisnap_repo_object_nonce(const uint8_t subkey_nonce[AMISNAP_REPO_KEY_SIZE],
                                const uint8_t content_hash[32],
                                uint8_t nonce_out[AMISNAP_REPO_NONCE_SIZE]);

/* Manifest nonce = first 12 bytes of keyed-BLAKE2s-256(key=K_nonce,
 * message=snapid), snapid being the manifest's own 16-hex-character
 * identifier (docs/format.md "Layout"), unique per manifest by
 * construction. `snapid` need not be NUL-terminated; `snapid_len` is
 * normally 16. */
void amisnap_repo_manifest_nonce(const uint8_t subkey_nonce[AMISNAP_REPO_KEY_SIZE],
                                  const uint8_t *snapid, size_t snapid_len,
                                  uint8_t nonce_out[AMISNAP_REPO_NONCE_SIZE]);

/* Encrypts `plaintext`/`len` into `out` (caller-allocated, must hold at
 * least len + AMISNAP_REPO_NONCE_SIZE + AMISNAP_REPO_MAC_SIZE bytes):
 * nonce || ChaCha20(K_enc, nonce, plaintext) || mac, mac = first 16
 * bytes of keyed-BLAKE2s-256(key=K_mac, nonce || ciphertext). `nonce`
 * is caller-supplied (from amisnap_repo_object_nonce/manifest_nonce
 * above) so callers control which derivation applies. */
void amisnap_repo_encrypt_frame(const amisnap_repo_subkeys *sk,
                                 const uint8_t nonce[AMISNAP_REPO_NONCE_SIZE],
                                 const uint8_t *plaintext, size_t len,
                                 uint8_t *out);

/* Inverse of amisnap_repo_encrypt_frame: `frame`/`framelen` is
 * nonce||ciphertext||mac (framelen must be >= NONCE+MAC size);
 * `plaintext_out` must hold framelen - NONCE - MAC bytes. Verifies the
 * MAC in constant time before decrypting. Returns AMISNAP_OK, or
 * AMISNAP_ERR_HASH_MISMATCH if the MAC doesn't match (tampering, wrong
 * key, or truncation -- the caller MUST NOT trust plaintext_out on
 * this path, format.md's "verify is a first-class command" principle
 * applies to encrypted repositories too), or AMISNAP_ERR_MALFORMED if
 * framelen is too short to even contain a nonce+mac. */
int amisnap_repo_decrypt_frame(const amisnap_repo_subkeys *sk,
                                const uint8_t *frame, size_t framelen,
                                uint8_t *plaintext_out);

/* Wraps the 32-byte repository key under the KDF-derived wrapping key
 * K_wrap (already computed by the caller via
 * amisnap_pbkdf2_hmac_sha256(passphrase, salt, iters, 32, K_wrap) --
 * this function only does the wrap, not the KDF, so callers can
 * calibrate/reuse K_wrap independently). `wrap_nonce` is caller-
 * supplied (a genuinely random 12 bytes at wrap time -- see
 * docs/format.md "Nonce discipline"). `wrapped_out` must hold
 * AMISNAP_WRAPPED_KEY_SIZE bytes -- this is exactly the WRAPPED_KEY
 * tag's content. */
void amisnap_repo_wrap_key(const uint8_t k_wrap[AMISNAP_REPO_KEY_SIZE],
                            const uint8_t wrap_nonce[AMISNAP_REPO_NONCE_SIZE],
                            const uint8_t repo_key[AMISNAP_REPO_KEY_SIZE],
                            uint8_t wrapped_out[AMISNAP_WRAPPED_KEY_SIZE]);

/* Inverse of amisnap_repo_wrap_key. Returns AMISNAP_OK with
 * *repo_key_out set, or AMISNAP_ERR_HASH_MISMATCH on a wrong
 * passphrase/corrupt header (the caller MUST fail closed -- never use
 * repo_key_out on this path). */
int amisnap_repo_unwrap_key(const uint8_t k_wrap[AMISNAP_REPO_KEY_SIZE],
                             const uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE],
                             uint8_t repo_key_out[AMISNAP_REPO_KEY_SIZE]);

#endif /* AMISNAP_REPO_CRYPTO_H */
