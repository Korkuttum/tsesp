// POSIX harness: performs a real ts2021 handshake against a control server
// over plain HTTP port 80. Same protocol code the ESP32 firmware will run,
// only the socket layer differs.
//
//   ./ts2021_handshake [host] [port]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include "ts2021.h"
#include "tscrypto.h"

static void hexdump(const char *label, const uint8_t *b, size_t n) {
    size_t i;
    printf("%s", label);
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int random_bytes(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(out, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

static int tcp_connect(const char *host, const char *port) {
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
    return fd;
}

static int read_full(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "controlplane.tailscale.com";
    const char *port = argc > 2 ? argv[2] : "80";

    uint8_t machine_priv[32], eph_priv[32], control_pub[32];
    uint8_t init[TS2021_INIT_LEN];
    uint8_t resp[TS2021_RESP_LEN];
    char b64[256], req[1024];
    uint8_t rxbuf[8192];
    ts2021_handshake hs;
    ts2021_conn conn;
    int fd, rc;
    size_t hdr_end = 0, have = 0;

    if (random_bytes(machine_priv, 32) != 0 || random_bytes(eph_priv, 32) != 0) {
        fprintf(stderr, "no entropy\n");
        return 1;
    }
    x25519_clamp(machine_priv);

    if (ts2021_parse_hex32(control_pub, TS2021_TAILSCALE_CONTROL_KEY) != 0) {
        fprintf(stderr, "bad pinned control key\n");
        return 1;
    }

    {
        uint8_t mpub[32];
        x25519_base(mpub, machine_priv);
        hexdump("machine key (pub) : ", mpub, 32);
    }
    hexdump("control key (pin) : ", control_pub, 32);
    printf("target            : %s:%s  capver %d\n\n", host, port, TS2021_PROTOCOL_VERSION);

    if (ts2021_handshake_start(&hs, machine_priv, control_pub,
                               TS2021_PROTOCOL_VERSION, eph_priv, init) != 0) {
        fprintf(stderr, "handshake_start failed\n");
        return 1;
    }
    printf("-> initiation %d bytes\n", TS2021_INIT_LEN);

    ts2021_base64(b64, sizeof(b64), init, sizeof(init));

    fd = tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "connect: %s\n", strerror(errno)); return 1; }

    int reqlen = snprintf(req, sizeof(req),
        "POST /ts2021 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: tailscale-control-protocol\r\n"
        "Connection: upgrade\r\n"
        "X-Tailscale-Handshake: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n", host, b64);
    if (write(fd, req, (size_t)reqlen) != reqlen) {
        fprintf(stderr, "short write\n"); close(fd); return 1;
    }

    // Read the HTTP response head, keeping any body bytes that arrive with it.
    while (have < sizeof(rxbuf)) {
        ssize_t r = read(fd, rxbuf + have, sizeof(rxbuf) - have);
        if (r <= 0) { fprintf(stderr, "eof before headers\n"); close(fd); return 1; }
        have += (size_t)r;
        for (size_t i = 3; i < have; i++) {
            if (rxbuf[i - 3] == '\r' && rxbuf[i - 2] == '\n' &&
                rxbuf[i - 1] == '\r' && rxbuf[i] == '\n') {
                hdr_end = i + 1;
                break;
            }
        }
        if (hdr_end) break;
    }

    printf("<- %.*s\n", (int)(strchr((char *)rxbuf, '\r') - (char *)rxbuf), rxbuf);
    if (memcmp(rxbuf, "HTTP/1.1 101", 12) != 0) {
        fprintf(stderr, "\nserver refused the upgrade:\n%.*s\n", (int)have, rxbuf);
        close(fd);
        return 1;
    }

    // The Noise response follows immediately on the upgraded connection.
    size_t leftover = have - hdr_end;
    if (leftover > TS2021_RESP_LEN) leftover = TS2021_RESP_LEN;
    memcpy(resp, rxbuf + hdr_end, leftover);
    if (leftover < TS2021_RESP_LEN &&
        read_full(fd, resp + leftover, TS2021_RESP_LEN - leftover) != 0) {
        fprintf(stderr, "short noise response\n"); close(fd); return 1;
    }

    if (resp[0] == TS2021_MSG_ERROR) {
        uint16_t n = (uint16_t)((resp[1] << 8) | resp[2]);
        fprintf(stderr, "server error frame: %.*s\n", n > 48 ? 48 : n, resp + 3);
        close(fd);
        return 1;
    }
    printf("<- response %d bytes (type %d)\n", TS2021_RESP_LEN, resp[0]);

    rc = ts2021_handshake_finish(&hs, resp, &conn);
    if (rc != 0) {
        fprintf(stderr, "\nHANDSHAKE FAILED (%d)%s\n", rc,
                rc == -2 ? " - tag mismatch: wrong control key or version" : "");
        close(fd);
        return 1;
    }

    printf("\nNOISE HANDSHAKE OK\n");
    hexdump("handshake hash    : ", conn.handshake_hash, 32);
    hexdump("tx key            : ", conn.tx_key, 32);
    hexdump("rx key            : ", conn.rx_key, 32);
    printf("\nThe channel is live. Next layer: HTTP/2 inside these records.\n");

    close(fd);
    return 0;
}
