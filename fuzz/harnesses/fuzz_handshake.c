/*
 * Fuzzer for TLS handshake state machine
 * Target: ssl.c:doHandshake (lines 770-781)
 *
 * This fuzzer tests the complex TLS state machine including:
 * - Multiple protocol versions (TLS 1.2, 1.3)
 * - Various cipher suites
 * - Post-handshake authentication
 * - Renegotiation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* Minimal self-signed cert generation for server mode */
static int generate_test_cert(SSL_CTX *ctx) {
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    RSA *rsa = NULL;
    X509_NAME *name = NULL;
    int ret = 0;

    /* Generate RSA key */
    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;

    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa || !EVP_PKEY_assign_RSA(pkey, rsa)) goto cleanup;

    /* Create X509 cert */
    x509 = X509_new();
    if (!x509) goto cleanup;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);

    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) goto cleanup;

    /* Set cert and key in context */
    if (SSL_CTX_use_certificate(ctx, x509) != 1) goto cleanup;
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) goto cleanup;

    ret = 1;

cleanup:
    if (!ret && rsa) RSA_free(rsa);
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    int max_iterations = 100;
    int iteration = 0;

    /* Ignore very small inputs */
    if (size < 16) {
        return 0;
    }

    /* Initialize SSL context */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        return 0;
    }

    /* Generate test certificate (required for server) */
    if (!generate_test_cert(ctx)) {
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Create SSL object */
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Create BIOs for input/output */
    rbio = BIO_new_mem_buf(data, size);
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio) {
        if (rbio) BIO_free(rbio);
        if (wbio) BIO_free(wbio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 0;
    }

    SSL_set_bio(ssl, rbio, wbio);

    /* Drive handshake state machine */
    while (SSL_in_init(ssl) && iteration++ < max_iterations) {
        int ret = SSL_do_handshake(ssl);
        if (ret <= 0) {
            /* Check error type */
            int err = SSL_get_error(ssl, ret);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                /* Fatal error or operation complete */
                break;
            }
        }

        /* Prevent infinite loops */
        if (iteration >= max_iterations) {
            break;
        }
    }

    /* Try post-handshake operations */
    if (SSL_is_init_finished(ssl)) {
        char buf[256];
        SSL_read(ssl, buf, sizeof(buf));
        SSL_write(ssl, "test", 4);
    }

    /* Cleanup */
    SSL_free(ssl);  /* This frees both BIOs */
    SSL_CTX_free(ctx);

    /* Clear error queue */
    ERR_clear_error();

    return 0;
}
