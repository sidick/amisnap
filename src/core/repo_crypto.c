/* repo_crypto.c -- see repo_crypto.h. Implements docs/format.md's
 * "Encryption (CIPHER 1)" section exactly: subkey derivation, the
 * deterministic object/manifest nonce scheme, the nonce||ciphertext||
 * mac frame, and WRAPPED_KEY wrap/unwrap.
 */
#include <string.h>

#include "repo_crypto.h"
#include "blake2s.h"
#include "chacha20.h"
#include "tlv.h"

static void subkey(const uint8_t *parent, size_t parentlen,
                    const char *label, uint8_t out[32])
{
    amisnap_blake2s_ctx ctx;
    amisnap_blake2s_init_key(&ctx, 32, parent, parentlen);
    amisnap_blake2s_update(&ctx, label, strlen(label));
    amisnap_blake2s_final(&ctx, out);
}

void amisnap_repo_derive_subkeys(const uint8_t key[AMISNAP_REPO_KEY_SIZE],
                                  amisnap_repo_subkeys *out)
{
    subkey(key, AMISNAP_REPO_KEY_SIZE, "AmiSnap-object-enc-v1", out->enc);
    subkey(key, AMISNAP_REPO_KEY_SIZE, "AmiSnap-object-mac-v1", out->mac);
    subkey(key, AMISNAP_REPO_KEY_SIZE, "AmiSnap-object-nonce-v1", out->nonce);
}

void amisnap_repo_object_nonce(const uint8_t subkey_nonce[AMISNAP_REPO_KEY_SIZE],
                                const uint8_t content_hash[32],
                                uint8_t nonce_out[AMISNAP_REPO_NONCE_SIZE])
{
    uint8_t full[32];
    amisnap_blake2s_ctx ctx;
    amisnap_blake2s_init_key(&ctx, 32, subkey_nonce, AMISNAP_REPO_KEY_SIZE);
    amisnap_blake2s_update(&ctx, content_hash, 32);
    amisnap_blake2s_final(&ctx, full);
    memcpy(nonce_out, full, AMISNAP_REPO_NONCE_SIZE);
}

void amisnap_repo_manifest_nonce(const uint8_t subkey_nonce[AMISNAP_REPO_KEY_SIZE],
                                  const uint8_t *snapid, size_t snapid_len,
                                  uint8_t nonce_out[AMISNAP_REPO_NONCE_SIZE])
{
    uint8_t full[32];
    amisnap_blake2s_ctx ctx;
    amisnap_blake2s_init_key(&ctx, 32, subkey_nonce, AMISNAP_REPO_KEY_SIZE);
    amisnap_blake2s_update(&ctx, snapid, snapid_len);
    amisnap_blake2s_final(&ctx, full);
    memcpy(nonce_out, full, AMISNAP_REPO_NONCE_SIZE);
}

static void mac16(const uint8_t key[AMISNAP_REPO_KEY_SIZE],
                   const uint8_t *nonce, const uint8_t *ciphertext, size_t ctlen,
                   uint8_t out[AMISNAP_REPO_MAC_SIZE])
{
    uint8_t full[32];
    amisnap_blake2s_ctx ctx;
    amisnap_blake2s_init_key(&ctx, 32, key, AMISNAP_REPO_KEY_SIZE);
    amisnap_blake2s_update(&ctx, nonce, AMISNAP_REPO_NONCE_SIZE);
    amisnap_blake2s_update(&ctx, ciphertext, ctlen);
    amisnap_blake2s_final(&ctx, full);
    memcpy(out, full, AMISNAP_REPO_MAC_SIZE);
}

/* Constant-time compare -- MAC verification must not leak timing
 * information about where the first mismatching byte is. */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

void amisnap_repo_encrypt_frame(const amisnap_repo_subkeys *sk,
                                 const uint8_t nonce[AMISNAP_REPO_NONCE_SIZE],
                                 const uint8_t *plaintext, size_t len,
                                 uint8_t *out)
{
    uint8_t *ct = out + AMISNAP_REPO_NONCE_SIZE;
    uint8_t *mac = ct + len;

    memcpy(out, nonce, AMISNAP_REPO_NONCE_SIZE);
    amisnap_chacha20_xor(sk->enc, nonce, 0, plaintext, ct, len);
    mac16(sk->mac, nonce, ct, len, mac);
}

int amisnap_repo_decrypt_frame(const amisnap_repo_subkeys *sk,
                                const uint8_t *frame, size_t framelen,
                                uint8_t *plaintext_out)
{
    size_t ctlen;
    const uint8_t *nonce, *ct, *mac;
    uint8_t want_mac[AMISNAP_REPO_MAC_SIZE];

    if (framelen < AMISNAP_REPO_NONCE_SIZE + AMISNAP_REPO_MAC_SIZE)
        return AMISNAP_ERR_MALFORMED;

    ctlen = framelen - AMISNAP_REPO_NONCE_SIZE - AMISNAP_REPO_MAC_SIZE;
    nonce = frame;
    ct = frame + AMISNAP_REPO_NONCE_SIZE;
    mac = ct + ctlen;

    mac16(sk->mac, nonce, ct, ctlen, want_mac);
    if (!ct_eq(want_mac, mac, AMISNAP_REPO_MAC_SIZE))
        return AMISNAP_ERR_HASH_MISMATCH;

    amisnap_chacha20_xor(sk->enc, nonce, 0, ct, plaintext_out, ctlen);
    return AMISNAP_OK;
}

void amisnap_repo_wrap_key(const uint8_t k_wrap[AMISNAP_REPO_KEY_SIZE],
                            const uint8_t wrap_nonce[AMISNAP_REPO_NONCE_SIZE],
                            const uint8_t repo_key[AMISNAP_REPO_KEY_SIZE],
                            uint8_t wrapped_out[AMISNAP_WRAPPED_KEY_SIZE])
{
    uint8_t enc[32], mac[32];

    subkey(k_wrap, AMISNAP_REPO_KEY_SIZE, "AmiSnap-wrap-enc-v1", enc);
    subkey(k_wrap, AMISNAP_REPO_KEY_SIZE, "AmiSnap-wrap-mac-v1", mac);

    {
        amisnap_repo_subkeys sk;
        memcpy(sk.enc, enc, 32);
        memcpy(sk.mac, mac, 32);
        /* K_nonce unused on this path (the nonce is caller-supplied). */
        memset(sk.nonce, 0, 32);
        amisnap_repo_encrypt_frame(&sk, wrap_nonce, repo_key,
                                    AMISNAP_REPO_KEY_SIZE, wrapped_out);
        memset(&sk, 0, sizeof sk); /* sk holds copies of enc/mac -- scrub it too */
    }

    memset(enc, 0, sizeof enc);
    memset(mac, 0, sizeof mac);
}

int amisnap_repo_unwrap_key(const uint8_t k_wrap[AMISNAP_REPO_KEY_SIZE],
                             const uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE],
                             uint8_t repo_key_out[AMISNAP_REPO_KEY_SIZE])
{
    uint8_t enc[32], mac[32];
    int rc;

    subkey(k_wrap, AMISNAP_REPO_KEY_SIZE, "AmiSnap-wrap-enc-v1", enc);
    subkey(k_wrap, AMISNAP_REPO_KEY_SIZE, "AmiSnap-wrap-mac-v1", mac);

    {
        amisnap_repo_subkeys sk;
        memcpy(sk.enc, enc, 32);
        memcpy(sk.mac, mac, 32);
        memset(sk.nonce, 0, 32);
        rc = amisnap_repo_decrypt_frame(&sk, wrapped, AMISNAP_WRAPPED_KEY_SIZE,
                                         repo_key_out);
        memset(&sk, 0, sizeof sk); /* sk holds copies of enc/mac -- scrub it too */
    }

    memset(enc, 0, sizeof enc);
    memset(mac, 0, sizeof mac);
    return rc;
}
