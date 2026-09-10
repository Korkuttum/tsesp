#ifndef TLS_IO_H
#define TLS_IO_H
#include "ts_io.h"
typedef struct { ts_io io; void *tls; } tls_io;
// Connects with TLS and wraps it as a ts_io. Returns 0 on success.
int  tls_io_connect(tls_io *t, const char *host, int port, int timeout_s);
void tls_io_close(tls_io *t);
#endif
