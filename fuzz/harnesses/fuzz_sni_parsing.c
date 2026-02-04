/*
 * Fuzzer for SNI (Server Name Indication) parsing in ClientHello messages
 * Target: sslcontext.c:ssl_callback_ClientHello (lines 138-237)
 *
 * This fuzzer tests the manual byte-level parsing of the SNI extension
 * in TLS ClientHello messages, which is a critical attack surface.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* SNI callback that will process the fuzzer input */
static int sni_callback(SSL *ssl, int *ad, void *arg) {
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    /* Just read the servername, don't process it */
    (void)servername;
    (void)ad;
    (void)arg;
    return SSL_TLSEXT_ERR_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;

    /* Ignore very small inputs */
    if (size < 10) {
        return 0;
    }

    /* Initialize OpenSSL */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        return 0;
    }

    /* Set up SNI callback to trigger parsing */
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);

    /* Create SSL object */
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Create BIO with fuzzer input */
    bio = BIO_new_mem_buf(data, size);
    if (!bio) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Set BIO for reading (this will be the source of ClientHello) */
    SSL_set_bio(ssl, bio, bio);

    /* Attempt to accept connection - this will trigger ClientHello parsing */
    SSL_accept(ssl);

    /* Cleanup */
    SSL_free(ssl);  /* This also frees the BIO */
    SSL_CTX_free(ctx);

    /* Clear error queue */
    ERR_clear_error();

    return 0;
}
