// Byte-stream abstraction. Everything above this line is portable; the only
// platform-specific code in the project is one implementation of this struct
// (POSIX sockets on the host, lwIP sockets on the ESP32).
#ifndef TS_IO_H
#define TS_IO_H

#include <stddef.h>
#include <stdint.h>

typedef struct ts_io {
    // Reads up to len bytes. Returns the count, 0 on clean EOF, <0 on error.
    int (*read)(void *ctx, uint8_t *buf, size_t len);
    // Writes all len bytes. Returns len, or <0 on error.
    int (*write)(void *ctx, const uint8_t *buf, size_t len);
    void *ctx;
} ts_io;

// Reads exactly len bytes. Returns 0 on success, -1 on EOF or error.
int ts_io_read_full(ts_io *io, uint8_t *buf, size_t len);

// Reads and discards len bytes.
int ts_io_skip(ts_io *io, size_t len);

#endif
