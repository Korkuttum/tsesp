#ifndef OPENSSL_IO_H
#define OPENSSL_IO_H
#include <openssl/ssl.h>
#include "ts_io.h"
typedef struct { ts_io io; SSL_CTX *ctx; BIO *bio; SSL *ssl; } openssl_io;
int  openssl_io_connect(openssl_io *t, const char *host, const char *port);
void openssl_io_close(openssl_io *t);
#endif
