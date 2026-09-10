#ifndef POSIX_IO_H
#define POSIX_IO_H
#include "ts_io.h"
typedef struct { ts_io io; int fd; } posix_io;
int  posix_io_connect(posix_io *pio, const char *host, const char *port);
void posix_io_close(posix_io *pio);
int  posix_random(uint8_t *out, size_t n);
#endif
