/* test_sigv4.c -- AWS Signature Version 4 vectors, taken verbatim from
 * AWS's own published `aws-sig-v4-test-suite` (fetched live from its
 * GitHub mirror, github.com/saibotsivad/aws-sig-v4-test-suite, which
 * parses the exact .req/.creq/.sts/.authz files AWS's own
 * documentation links to -- not transcribed from memory, and not this
 * project's own self-consistency check). Config used by every case in
 * that suite: accessKeyId=AKIDEXAMPLE,
 * secretAccessKey=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
 * region=us-east-1, service=service.
 *
 * Each case below checks the canonical request text, the string to
 * sign, AND the final signature -- the whole chain end to end, not
 * just intermediate values.
 */
#include <stdio.h>
#include <string.h>

#include "test.h"
#include "sigv4.h"

#define AK "AKIDEXAMPLE"
#define SK "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLE" "KEY"
#define REGION "us-east-1"
#define SERVICE "service"
#define DATE "20150830"
#define DATE_TIME "20150830T123600Z"
#define SCOPE "20150830/us-east-1/service/aws4_request"
#define EMPTY_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

static void run_case(const char *method, const char *uri, const char *query,
                      const amisnap_sigv4_header *headers, size_t header_count,
                      const char *payload_hash,
                      const char *expect_creq, const char *expect_sts,
                      const char *expect_sig)
{
    amisnap_buf creq, signed_headers, sts;
    uint8_t signing_key[32];
    char sig_hex[65];

    TEST_CHECK(amisnap_sigv4_canonical_request(method, uri, query, headers, header_count,
                                                payload_hash, &creq, &signed_headers) == AMISNAP_OK);
    TEST_CHECK(creq.len == strlen(expect_creq) &&
               memcmp(creq.data, expect_creq, creq.len) == 0);

    TEST_CHECK(amisnap_sigv4_string_to_sign(DATE_TIME, SCOPE, creq.data, creq.len, &sts) == AMISNAP_OK);
    TEST_CHECK(sts.len == strlen(expect_sts) && memcmp(sts.data, expect_sts, sts.len) == 0);

    amisnap_sigv4_signing_key(SK, DATE, REGION, SERVICE, signing_key);
    amisnap_sigv4_signature_hex(signing_key, sts.data, sts.len, sig_hex);
    TEST_CHECK(strcmp(sig_hex, expect_sig) == 0);

    {
        amisnap_buf authz;
        char expect_authz[512];
        snprintf(expect_authz, sizeof(expect_authz),
                 "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%.*s, Signature=%s",
                 AK, SCOPE, (int)signed_headers.len, (const char *)signed_headers.data, sig_hex);
        TEST_CHECK(amisnap_sigv4_authorization_header(AK, SCOPE, (const char *)signed_headers.data,
                                                        sig_hex, &authz) == AMISNAP_OK);
        TEST_CHECK(authz.len == strlen(expect_authz) &&
                   memcmp(authz.data, expect_authz, authz.len) == 0);
        amisnap_buf_free(&authz);
    }

    amisnap_buf_free(&creq);
    amisnap_buf_free(&signed_headers);
    amisnap_buf_free(&sts);
}

void run_sigv4_tests(void)
{
    /* get-vanilla: a bare GET / with no query string. */
    {
        amisnap_sigv4_header headers[] = {
            { "Host", "example.amazonaws.com" },
            { "X-Amz-Date", DATE_TIME },
        };
        run_case("GET", "/", "", headers, 2, EMPTY_SHA256,
            "GET\n/\n\n"
            "host:example.amazonaws.com\n"
            "x-amz-date:20150830T123600Z\n"
            "\n"
            "host;x-amz-date\n"
            EMPTY_SHA256,
            "AWS4-HMAC-SHA256\n" DATE_TIME "\n" SCOPE "\n"
            "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    }

    /* get-vanilla-query-unreserved: every unreserved char appears
     * literally (unencoded) in an already-built canonical query
     * string -- this exercises the canonical-request assembly with a
     * real, non-trivial query string; amisnap_sigv4_uri_encode()
     * itself (used by callers to build such a string) is tested
     * separately below. */
    {
        amisnap_sigv4_header headers[] = {
            { "Host", "example.amazonaws.com" },
            { "X-Amz-Date", DATE_TIME },
        };
        const char *query =
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        run_case("GET", "/", query, headers, 2, EMPTY_SHA256,
            "GET\n/\n"
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
            "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n"
            "host:example.amazonaws.com\n"
            "x-amz-date:20150830T123600Z\n"
            "\n"
            "host;x-amz-date\n"
            EMPTY_SHA256,
            "AWS4-HMAC-SHA256\n" DATE_TIME "\n" SCOPE "\n"
            "c30d4703d9f799439be92736156d47ccfb2d879ddf56f5befa6d1d6aab979177",
            "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197");
    }

    /* get-header-value-trim: header values with internal whitespace
     * runs (even inside a quoted string) collapse to a single space,
     * and headers are sorted by lowercased name. */
    {
        amisnap_sigv4_header headers[] = {
            { "Host", "example.amazonaws.com" },
            { "My-Header1", "value1" },
            { "My-Header2", "\"a   b   c\"" },
            { "X-Amz-Date", DATE_TIME },
        };
        run_case("GET", "/", "", headers, 4, EMPTY_SHA256,
            "GET\n/\n\n"
            "host:example.amazonaws.com\n"
            "my-header1:value1\n"
            "my-header2:\"a b c\"\n"
            "x-amz-date:20150830T123600Z\n"
            "\n"
            "host;my-header1;my-header2;x-amz-date\n"
            EMPTY_SHA256,
            "AWS4-HMAC-SHA256\n" DATE_TIME "\n" SCOPE "\n"
            "a726db9b0df21c14f559d0a978e563112acb1b9e05476f0a6a1c7d68f28605c7",
            "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736");
    }

    /* post-vanilla: same shape as get-vanilla but a different method,
     * confirming the method itself flows through untouched. */
    {
        amisnap_sigv4_header headers[] = {
            { "Host", "example.amazonaws.com" },
            { "X-Amz-Date", DATE_TIME },
        };
        run_case("POST", "/", "", headers, 2, EMPTY_SHA256,
            "POST\n/\n\n"
            "host:example.amazonaws.com\n"
            "x-amz-date:20150830T123600Z\n"
            "\n"
            "host;x-amz-date\n"
            EMPTY_SHA256,
            "AWS4-HMAC-SHA256\n" DATE_TIME "\n" SCOPE "\n"
            "553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87",
            "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b");
    }

    /* amisnap_sigv4_uri_encode(): the primitive callers use to build a
     * canonical query string/path from a real key name -- unreserved
     * characters pass through, everything else (including '/', when
     * encode_slash is set) becomes uppercase-hex "%XX", space becomes
     * "%20" not "+". */
    {
        amisnap_buf out;
        amisnap_buf_init(&out);
        TEST_CHECK(amisnap_sigv4_uri_encode("a/b c", 5, 1, &out) == AMISNAP_OK);
        TEST_CHECK(out.len == 9 && memcmp(out.data, "a%2Fb%20c", 9) == 0);
        amisnap_buf_free(&out);

        amisnap_buf_init(&out);
        TEST_CHECK(amisnap_sigv4_uri_encode("a/b c", 5, 0, &out) == AMISNAP_OK);
        TEST_CHECK(out.len == 7 && memcmp(out.data, "a/b%20c", 7) == 0);
        amisnap_buf_free(&out);

        amisnap_buf_init(&out);
        TEST_CHECK(amisnap_sigv4_uri_encode("-._~AZaz09", 10, 1, &out) == AMISNAP_OK);
        TEST_CHECK(out.len == 10 && memcmp(out.data, "-._~AZaz09", 10) == 0);
        amisnap_buf_free(&out);
    }
}
