// The only ESP-specific transport code. lwIP's socket API is close enough to
// POSIX that this is almost the same file as the host version - which is the
// point: the protocol above it never had to know.
#include <string.h>
#include <errno.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "esp_io.h"

static const char *TAG = "esp_io";

static int sock_read(void *ctx, uint8_t *buf, size_t len) {
    int fd = *(int *)ctx;
    int r;
    do { r = recv(fd, buf, len, 0); } while (r < 0 && errno == EINTR);
    return r;
}

static int sock_write(void *ctx, const uint8_t *buf, size_t len) {
    int fd = *(int *)ctx;
    size_t sent = 0;
    while (sent < len) {
        int w = send(fd, buf + sent, len - sent, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return (int)len;
}

int esp_io_connect(esp_io *eio, const char *host, const char *port, int timeout_s) {
    struct addrinfo hints, *res, *rp;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;          // the control plane is reachable over v4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        ESP_LOGW(TAG, "cannot resolve %s", host);
        return -1;
    }
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
        // A streaming map session is quiet for long stretches, so the read
        // timeout has to be generous; without one a dead link would hang the
        // task forever.
        struct timeval tv = { timeout_s, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    eio->fd = fd;
    eio->io.read = sock_read;
    eio->io.write = sock_write;
    eio->io.ctx = &eio->fd;
    return 0;
}

void esp_io_close(esp_io *eio) {
    if (eio->fd >= 0) close(eio->fd);
    eio->fd = -1;
}
