// Live DERP handshake against a real relay.
//
// The handshake is the interesting part: the server's reply is a NaCl box we
// can only open if our half of the key exchange is right, so a successful
// open proves the whole chain end to end.
//
//   ./derp_test [host] [port]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "openssl_io.h"
#include "derp.h"
#include "tscrypto.h"
#include "posix_io.h"

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "derp4h.tailscale.com";
    const char *port = argc > 2 ? argv[2] : "443";
    uint8_t node_priv[32], node_pub[32];
    openssl_io tls;
    derp_conn c;
    derp_opts opts;
    int rc, i;
    time_t start;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (posix_random(node_priv, sizeof(node_priv)) != 0) return 1;
    x25519_clamp(node_priv);
    x25519_base(node_pub, node_priv);

    printf("relay       : %s:%s\n", host, port);
    if (openssl_io_connect(&tls, host, port) != 0) {
        fprintf(stderr, "TLS failed\n");
        return 1;
    }
    printf("tls         : up\n");

    memset(&opts, 0, sizeof(opts));
    opts.host = host;
    opts.node_priv = node_priv;
    opts.node_pub = node_pub;
    opts.preferred = 1;

    rc = derp_connect(&c, &tls.io, &opts);
    if (rc != 0) {
        fprintf(stderr, "derp handshake failed (%d)%s\n", rc,
                rc == -3 ? ": the server's reply did not authenticate" : "");
        openssl_io_close(&tls);
        return 1;
    }

    printf("derp        : connected\n");
    printf("server key  : ");
    for (i = 0; i < 8; i++) printf("%02x", c.server_key[i]);
    printf("...\n");
    printf("our key     : ");
    for (i = 0; i < 8; i++) printf("%02x", node_pub[i]);
    printf("...\n");
    printf("\nServerInfo opened, so the shared key is right and we are\n"
           "registered on this relay as a reachable node.\n");

    // Sending to ourselves is the simplest end-to-end check: the relay knows
    // exactly one client with this key, so the packet should come straight
    // back.
    {
        static const uint8_t probe[] = "tsesp-derp-loopback";
        printf("\nsending a packet addressed to ourselves...\n");
        if (derp_send(&c, node_pub, probe, sizeof(probe)) != 0)
            printf("  send failed\n");
    }

    printf("listening for 20 seconds\n");
    start = time(NULL);
    while (time(NULL) - start < 20) {
        uint8_t src[32], buf[1500];
        size_t len = 0;
        int r = derp_recv(&c, src, buf, sizeof(buf), &len);
        if (r < 0) { printf("  connection closed\n"); break; }
        if (r == 1) {
            printf("  packet: %zu bytes from ", len);
            for (i = 0; i < 8; i++) printf("%02x", src[i]);
            printf("...  %s\n", memcmp(src, node_pub, 32) == 0 ? "(ourselves)" : "");
            printf("  payload: %.*s\n", (int)len, buf);
        }
    }

    printf("\nframes: sent %u, received %u, keepalives %u, pings %u\n",
           c.sent, c.received, c.keepalives, c.pings);
    openssl_io_close(&tls);
    return 0;
}
