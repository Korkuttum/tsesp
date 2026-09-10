// Known-answer test from RFC 5769, then a live query so we can see the NAT
// mapping this machine actually gets.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "stun.h"
#include "posix_io.h"

static int fails = 0;

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (*hex && n < cap) {
        unsigned b;
        if (*hex == ' ' || *hex == '\n') { hex++; continue; }
        if (sscanf(hex, "%2x", &b) != 1) break;
        out[n++] = (uint8_t)b;
        hex += 2;
    }
    return n;
}

// RFC 5769 section 2.2: a sample IPv4 binding success response.
static void test_vector(void) {
    // RFC 5769 2.2 with its MESSAGE-INTEGRITY attribute removed (we do not
    // verify it), so the length field is 0x24 rather than the RFC's 0x3c.
    static const char *hex =
        "01010024" "2112a442" "b7e7a701bc34d686fa87dfae"
        "802200 0b" "74657374 20766563 746f7220"          // SOFTWARE
        "0020 0008 0001a147 e112a643"                     // XOR-MAPPED-ADDRESS
        "8028 0004 c07d4c96";                             // FINGERPRINT
    uint8_t buf[128], txid[12], addr[16];
    size_t n;
    int is_ipv6 = -1;
    uint16_t port = 0;
    char s[64];

    printf("RFC 5769 vector\n");
    n = unhex(hex, buf, sizeof(buf));
    unhex("b7e7a701bc34d686fa87dfae", txid, sizeof(txid));

    if (stun_parse_response(buf, n, txid, addr, &is_ipv6, &port) != 0) {
        printf("  FAIL parse rejected the sample response\n");
        fails++;
        return;
    }
    stun_format_addr(s, sizeof(s), addr, is_ipv6, port);
    if (strcmp(s, "192.0.2.1:32853") != 0) {
        printf("  FAIL got %s, want 192.0.2.1:32853\n", s);
        fails++;
        return;
    }
    printf("  ok   XOR-MAPPED-ADDRESS decoded as %s\n", s);

    // A response for a different transaction must be refused.
    txid[0] ^= 1;
    if (stun_parse_response(buf, n, txid, addr, &is_ipv6, &port) != -2) {
        printf("  FAIL wrong transaction id accepted\n");
        fails++;
    } else {
        printf("  ok   wrong transaction id rejected\n");
    }

    // Traffic that shares the socket must not be mistaken for STUN.
    {
        uint8_t wg[64] = { 1, 0, 0, 0 };             // WireGuard handshake init
        uint8_t disco[64] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };  // "TS.."
        if (stun_looks_like_stun(wg, sizeof(wg)) ||
            stun_looks_like_stun(disco, sizeof(disco))) {
            printf("  FAIL WireGuard/DISCO datagram misread as STUN\n");
            fails++;
        } else {
            printf("  ok   WireGuard and DISCO datagrams not mistaken for STUN\n");
        }
    }
}

static void test_live(const char *host, const char *port_s) {
    struct addrinfo hints, *res;
    uint8_t req[STUN_HEADER_LEN], txid[STUN_TXID_LEN], buf[512], addr[16];
    int fd, is_ipv6 = 0;
    uint16_t port = 0;
    ssize_t n;
    char s[64];
    struct timeval tv = { 5, 0 };

    printf("live query to %s:%s\n", host, port_s);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port_s, &hints, &res) != 0) {
        printf("  SKIP could not resolve\n");
        return;
    }
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); printf("  SKIP no socket\n"); return; }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    posix_random(txid, sizeof(txid));
    stun_build_request(req, txid);
    if (sendto(fd, req, sizeof(req), 0, res->ai_addr, res->ai_addrlen) < 0) {
        printf("  SKIP send failed\n");
        close(fd); freeaddrinfo(res); return;
    }
    n = recv(fd, buf, sizeof(buf), 0);
    freeaddrinfo(res);
    if (n <= 0) { printf("  SKIP no response (blocked or offline)\n"); close(fd); return; }

    if (stun_parse_response(buf, (size_t)n, txid, addr, &is_ipv6, &port) != 0) {
        printf("  FAIL could not parse the live response (%zd bytes)\n", n);
        fails++;
        close(fd);
        return;
    }
    stun_format_addr(s, sizeof(s), addr, is_ipv6, port);
    printf("  ok   this machine looks like %s from outside\n", s);
    close(fd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    test_vector();
    // Tailscale's own DERP nodes answer STUN here, which is what the ESP32
    // will use once it has a DERP map.
    test_live(argc > 1 ? argv[1] : "derp1.tailscale.com", argc > 2 ? argv[2] : "3478");
    printf("\n%s\n", fails ? "STUN TESTS FAILED" : "all STUN tests passed");
    return fails ? 1 : 0;
}
