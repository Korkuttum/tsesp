// The only platform-specific file on the host side: a ts_io over a socket.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include "posix_io.h"

static int sock_read(void *ctx, uint8_t *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t r;
    do { r = read(fd, buf, len); } while (r < 0 && errno == EINTR);
    return (int)r;
}

static int sock_write(void *ctx, const uint8_t *buf, size_t len) {
    int fd = *(int *)ctx;
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(fd, buf + sent, len - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return (int)len;
}

int posix_io_connect(posix_io *pio, const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    {
        // Fail fast instead of hanging forever when the peer goes quiet.
        // A followup register call long-polls until a human approves the
        // login, so that path needs a much larger value.
        const char *env = getenv("TSESP_TIMEOUT");
        struct timeval tv = { env ? atoi(env) : 20, 0 };
        if (tv.tv_sec <= 0) tv.tv_sec = 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    pio->fd = fd;
    pio->io.read = sock_read;
    pio->io.write = sock_write;
    pio->io.ctx = &pio->fd;
    return 0;
}

void posix_io_close(posix_io *pio) {
    if (pio->fd >= 0) close(pio->fd);
    pio->fd = -1;
}

int posix_random(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;
    if (!f) return -1;
    got = fread(out, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}
