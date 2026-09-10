#include "ts_io.h"

int ts_io_read_full(ts_io *io, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int r = io->read(io->ctx, buf + got, len - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int ts_io_skip(ts_io *io, size_t len) {
    uint8_t junk[64];
    while (len > 0) {
        size_t take = len > sizeof(junk) ? sizeof(junk) : len;
        int r = io->read(io->ctx, junk, take);
        if (r <= 0) return -1;
        len -= (size_t)r;
    }
    return 0;
}
