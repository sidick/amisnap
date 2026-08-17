/* biopairdiag.c -- dev-only diagnostic (never linked into AmiSnap):
 * isolates whether AmiSSL's own BIO_new_bio_pair()/BIO_write()/
 * BIO_read()/BIO_ctrl_pending() work at all on this platform,
 * independent of SSL/TLS entirely -- tests/copperline/tlswebdavdiag.c
 * found BIO_read() on a bio-pair endpoint apparently never returning
 * even though BIO_ctrl_pending() just reported real pending bytes,
 * which would be a serious, surprising deviation from normal OpenSSL
 * memory-BIO semantics (a memory BIO can never legitimately block).
 * This writes a small, known buffer into one side and reads it back
 * from the other, with no SSL involved, to find out whether the
 * primitive itself is broken on this AmiSSL build or whether the bug
 * is specific to how tls.c drives it through SSL_do_handshake().
 */
#include <stdio.h>
#include <string.h>

#include <exec/types.h>
#include <utility/tagitem.h>
#include <proto/exec.h>

#include <libraries/amisslmaster.h>
#include <proto/amisslmaster.h>
#include <amissl/tags.h>
#include <proto/amissl.h>

struct Library *AmiSSLMasterBase = NULL;
struct Library *AmiSSLBase = NULL;
struct Library *AmiSSLExtBase = NULL;

int main(void)
{
    BIO *bio1 = NULL, *bio2 = NULL;
    static const char MSG[] = "hello bio pair";
    char buf[64];
    int n;
    LONG rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("biopairdiag: start\n");

    AmiSSLMasterBase = OpenLibrary((CONST_STRPTR)"amisslmaster.library", 5);
    if (!AmiSSLMasterBase) {
        printf("biopairdiag: FAIL amisslmaster.library not available\n");
        return 20;
    }
    rc = OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
        AmiSSL_UsesOpenSSLStructs, FALSE,
        AmiSSL_GetAmiSSLBase,      (ULONG)&AmiSSLBase,
        AmiSSL_GetAmiSSLExtBase,   (ULONG)&AmiSSLExtBase,
        TAG_DONE);
    if (rc != 0 || !AmiSSLBase) {
        printf("biopairdiag: FAIL OpenAmiSSLTags rc=%ld\n", (long)rc);
        return 20;
    }
    printf("biopairdiag: OpenAmiSSLTags ok\n");

    if (BIO_new_bio_pair(&bio1, 0, &bio2, 0) != 1) {
        printf("biopairdiag: FAIL BIO_new_bio_pair\n");
        return 20;
    }
    printf("biopairdiag: BIO_new_bio_pair ok, bio1=%p bio2=%p\n", (void *)bio1, (void *)bio2);

    n = BIO_write(bio1, MSG, (int)sizeof(MSG));
    printf("biopairdiag: BIO_write(bio1) = %d\n", n);

    {
        size_t pending = BIO_ctrl_pending(bio2);
        printf("biopairdiag: BIO_ctrl_pending(bio2) = %lu\n", (unsigned long)pending);
    }

    printf("biopairdiag: about to BIO_read(bio2)\n");
    n = BIO_read(bio2, buf, (int)sizeof(buf));
    printf("biopairdiag: BIO_read(bio2) = %d\n", n);
    if (n > 0) {
        buf[n] = '\0';
        printf("biopairdiag: got \"%s\"\n", buf);
    }

    BIO_free(bio1);
    BIO_free(bio2);
    printf("biopairdiag: PASS\n");
    return 0;
}
