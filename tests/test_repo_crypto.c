/* test_repo_crypto.c -- docs/format.md "Encryption (CIPHER 1)" vectors,
 * independently computed by a from-spec Python reimplementation
 * (hashlib.blake2s for the keyed subkey/nonce/MAC derivation, the
 * `cryptography` package's ChaCha20 for the cipher) -- a genuine
 * cross-implementation check against the written spec, not a
 * self-consistency snapshot, per house rule. Plus round-trip and
 * MAC-tamper-detection structural checks.
 */
#include <string.h>

#include "test.h"
#include "repo_crypto.h"
#include "tlv.h"

static int hex_eq(const uint8_t *buf, size_t len, const char *hex)
{
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return 0;
        if (buf[i] != (uint8_t)v) return 0;
    }
    return hex[len * 2] == '\0';
}

void run_repo_crypto_tests(void)
{
    uint8_t key[32];
    int i;
    amisnap_repo_subkeys sk;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    amisnap_repo_derive_subkeys(key, &sk);

    TEST_CHECK(hex_eq(sk.enc, 32,
        "832459ccc2d8e5207eb0be063219ac6a86cd7d8155ad603d57033bccb7e51b75"));
    TEST_CHECK(hex_eq(sk.mac, 32,
        "92e2f5939e6f6af615d760dc0e704c8ef81657e55eeb675177af6e9803111fdc"));
    TEST_CHECK(hex_eq(sk.nonce, 32,
        "6c1a4020b8dc8d39c1ab9a3f3aecfd166087d1f9cd8c8b74ab493795984285c3"));

    /* Object nonce, derived from a stand-in content hash (32..63 ramp). */
    {
        uint8_t content_hash[32], nonce[AMISNAP_REPO_NONCE_SIZE];
        for (i = 0; i < 32; i++) content_hash[i] = (uint8_t)(32 + i);
        amisnap_repo_object_nonce(sk.nonce, content_hash, nonce);
        TEST_CHECK(hex_eq(nonce, AMISNAP_REPO_NONCE_SIZE, "95f097ae24a6bd1838905868"));
    }

    /* Manifest nonce, derived from a snapid. */
    {
        uint8_t nonce[AMISNAP_REPO_NONCE_SIZE];
        static const uint8_t snapid[16] = {
            '0','0','0','0','4','2','6','8','0','2','5','8','0','0','0','a'
        };
        amisnap_repo_manifest_nonce(sk.nonce, snapid, 16, nonce);
        TEST_CHECK(hex_eq(nonce, AMISNAP_REPO_NONCE_SIZE, "355ef61b0c6d595b2cf1f426"));
    }

    /* Object frame: encrypt, compare to the independently-computed frame,
     * then decrypt and confirm round-trip. */
    {
        static const char PLAINTEXT[] = "Hello, AmiSnap encrypted object!";
        size_t len = sizeof(PLAINTEXT) - 1;
        uint8_t content_hash[32];
        uint8_t nonce[AMISNAP_REPO_NONCE_SIZE];
        uint8_t frame[128];
        uint8_t back[64];
        size_t framelen = AMISNAP_REPO_NONCE_SIZE + len + AMISNAP_REPO_MAC_SIZE;

        for (i = 0; i < 32; i++) content_hash[i] = (uint8_t)(32 + i);
        amisnap_repo_object_nonce(sk.nonce, content_hash, nonce);

        amisnap_repo_encrypt_frame(&sk, nonce, (const uint8_t *)PLAINTEXT, len, frame);
        TEST_CHECK(hex_eq(frame, framelen,
            "95f097ae24a6bd18389058685d0f0156d5206f6ec8b2dbc6e3acd6028dd4f3f9"
            "9c4a0ad125f228a0ae226ecc421d1572c5850ac9266f5de057c7bd39"));

        TEST_CHECK(amisnap_repo_decrypt_frame(&sk, frame, framelen, back) == AMISNAP_OK);
        TEST_CHECK(memcmp(back, PLAINTEXT, len) == 0);

        /* Tamper with one ciphertext byte: decrypt must fail closed. */
        frame[AMISNAP_REPO_NONCE_SIZE] ^= 0x01;
        TEST_CHECK(amisnap_repo_decrypt_frame(&sk, frame, framelen, back)
                   == AMISNAP_ERR_HASH_MISMATCH);
    }

    /* WRAPPED_KEY: wrap the repository key under a PBKDF2-derived K_wrap,
     * compare to the independently-computed wrap, then unwrap. */
    {
        uint8_t k_wrap[32];
        uint8_t wrap_nonce[AMISNAP_REPO_NONCE_SIZE];
        uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE];
        uint8_t unwrapped[AMISNAP_REPO_KEY_SIZE];

        for (i = 0; i < AMISNAP_REPO_NONCE_SIZE; i++) wrap_nonce[i] = (uint8_t)(100 + i);

        {
            /* K_wrap = PBKDF2-HMAC-SHA256("correct horse battery staple",
             * "somesalt12345678", 4096, 32) -- computed and cross-checked
             * the same way tests/test_pbkdf2.c's vectors were. */
            static const uint8_t expect_kwrap[32] = {
                0x31,0x7c,0x88,0x91,0x08,0x69,0x89,0x68,0x2d,0x92,0x1f,0xb2,
                0x13,0xcd,0x60,0xa8,0x1e,0x72,0x0d,0x63,0x52,0xc1,0x56,0xbf,
                0x22,0xf2,0x93,0x08,0x8f,0x50,0xd4,0xfb
            };
            memcpy(k_wrap, expect_kwrap, 32);
        }

        amisnap_repo_wrap_key(k_wrap, wrap_nonce, key, wrapped);
        TEST_CHECK(hex_eq(wrapped, AMISNAP_WRAPPED_KEY_SIZE,
            "6465666768696a6b6c6d6e6fbdc786d99d5ec337d02602b1705753b63dbfbb"
            "ca82999be3718c931c80e3e7c9f900e4a36fe1b615b6c76f04b8953c71"));

        TEST_CHECK(amisnap_repo_unwrap_key(k_wrap, wrapped, unwrapped) == AMISNAP_OK);
        TEST_CHECK(memcmp(unwrapped, key, AMISNAP_REPO_KEY_SIZE) == 0);

        /* Wrong K_wrap (wrong passphrase) must fail closed, never produce
         * a wrong-but-plausible key silently. */
        {
            uint8_t bad_kwrap[32];
            uint8_t bad_out[AMISNAP_REPO_KEY_SIZE];
            memcpy(bad_kwrap, k_wrap, 32);
            bad_kwrap[0] ^= 0x01;
            TEST_CHECK(amisnap_repo_unwrap_key(bad_kwrap, wrapped, bad_out)
                       == AMISNAP_ERR_HASH_MISMATCH);
        }
    }
}
