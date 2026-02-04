/*
 * Fuzzer for PKCS12 certificate/key parsing
 * Target: sslcontext.c:ssl_load_pkcs12 (lines 880-921)
 *
 * This fuzzer tests PKCS12 file parsing including:
 * - ASN.1 DER decoding (d2i_PKCS12_bio)
 * - Password verification
 * - Certificate/key extraction
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* Test multiple password scenarios */
static const char *test_passwords[] = {
    "",           /* Empty password */
    "password",   /* Common password */
    NULL          /* NULL password */
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    BIO *bio = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int i;

    /* Ignore very small inputs */
    if (size < 16) {
        return 0;
    }

    /* Create BIO from fuzzer input */
    bio = BIO_new_mem_buf(data, size);
    if (!bio) {
        return 0;
    }

    /* Attempt to parse as PKCS12 */
    p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);

    if (p12) {
        /* Try parsing with different passwords */
        for (i = 0; i < sizeof(test_passwords) / sizeof(test_passwords[0]); i++) {
            pkey = NULL;
            cert = NULL;
            ca = NULL;

            /* Attempt to parse PKCS12 structure */
            PKCS12_parse(p12, test_passwords[i], &pkey, &cert, &ca);

            /* Cleanup */
            if (pkey) EVP_PKEY_free(pkey);
            if (cert) X509_free(cert);
            if (ca) sk_X509_pop_free(ca, X509_free);
        }

        /* Also test MAC verification */
        PKCS12_verify_mac(p12, "", 0);
        PKCS12_verify_mac(p12, "password", 8);
        PKCS12_verify_mac(p12, NULL, 0);

        PKCS12_free(p12);
    }

    /* Clear error queue */
    ERR_clear_error();

    return 0;
}
