/*
 * Fuzzer for BIO read/write operations
 * Target: ssl.c (writeToBIO, readFromBIO, writeToSSL, readFromSSL)
 *
 * This fuzzer tests the BIO data flow which handles all encrypted
 * TLS records from the network.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *internal_bio = NULL;
    BIO *network_bio = NULL;
    char read_buf[4096];
    int ret;

    /* Ignore very small inputs */
    if (size < 5) {
        return 0;
    }

    /* Initialize SSL context */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        return 0;
    }

    /* Create SSL object */
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Create BIO pair for non-blocking I/O */
    if (BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Set BIO for SSL */
    SSL_set_bio(ssl, internal_bio, internal_bio);

    /* Feed fuzzer data to network BIO (simulating network input) */
    BIO_write(network_bio, data, size);

    /* Attempt various SSL operations that will read from BIO */
    SSL_accept(ssl);
    SSL_read(ssl, read_buf, sizeof(read_buf));
    SSL_peek(ssl, read_buf, sizeof(read_buf));

    /* Try to get handshake data */
    while ((ret = BIO_read(network_bio, read_buf, sizeof(read_buf))) > 0) {
        /* Consume handshake output */
    }

    /* Cleanup */
    BIO_free(network_bio);
    SSL_free(ssl);  /* This frees internal_bio */
    SSL_CTX_free(ctx);

    /* Clear error queue */
    ERR_clear_error();

    return 0;
}
