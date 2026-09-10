// TLS for the test harness, using OpenSSL. The device uses mbedTLS through
// esp-tls instead; both are just a ts_io as far as the protocol code cares.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl_io.h"

static int tls_read(void *ctx, uint8_t *buf, size_t len) {
    openssl_io *t = (openssl_io *)ctx;
    int r = SSL_read(t->ssl, buf, (int)len);
    return r > 0 ? r : -1;
}

static int tls_write(void *ctx, const uint8_t *buf, size_t len) {
    openssl_io *t = (openssl_io *)ctx;
    size_t sent = 0;
    while (sent < len) {
        int w = SSL_write(t->ssl, buf + sent, (int)(len - sent));
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return (int)len;
}

int openssl_io_connect(openssl_io *t, const char *host, const char *port) {
    memset(t, 0, sizeof(*t));

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) return -1;
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
    // The DERP handshake authenticates the server by its own public key, so
    // the certificate is belt and braces here rather than the trust anchor.
    SSL_CTX_set_default_verify_paths(t->ctx);

    t->bio = BIO_new_ssl_connect(t->ctx);
    if (!t->bio) return -1;
    {
        char target[256];
        snprintf(target, sizeof(target), "%s:%s", host, port);
        BIO_set_conn_hostname(t->bio, target);
    }
    BIO_get_ssl(t->bio, &t->ssl);
    if (!t->ssl) return -1;
    SSL_set_tlsext_host_name(t->ssl, host);
    SSL_set1_host(t->ssl, host);

    if (BIO_do_connect(t->bio) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_get_verify_result(t->ssl) != X509_V_OK)
        fprintf(stderr, "warning: certificate did not verify\n");

    t->io.read = tls_read;
    t->io.write = tls_write;
    t->io.ctx = t;
    return 0;
}

void openssl_io_close(openssl_io *t) {
    if (t->bio) BIO_free_all(t->bio);
    if (t->ctx) SSL_CTX_free(t->ctx);
    t->bio = NULL;
    t->ctx = NULL;
    t->ssl = NULL;
}
