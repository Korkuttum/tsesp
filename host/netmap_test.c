// Fetches the netmap for an already-registered node and prints what the
// ESP32 would keep: our tailnet address, and each peer's keys and endpoints.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "posix_io.h"
#include "ts_control.h"
#include "tscrypto.h"

#define KEYFILE "tsesp-keys.bin"

// machine key | node key | disco key
static int load_keys(uint8_t m[32], uint8_t n[32], uint8_t d[32]) {
    FILE *f = fopen(KEYFILE, "rb");
    int have_disco = 0;

    if (!f) return -1;
    if (fread(m, 1, 32, f) != 32 || fread(n, 1, 32, f) != 32) { fclose(f); return -1; }
    have_disco = fread(d, 1, 32, f) == 32;
    fclose(f);

    if (!have_disco) {
        // Older key file from before disco existed: append one, keeping the
        // machine and node keys so the node stays the same device.
        if (posix_random(d, 32) != 0) return -1;
        x25519_clamp(d);
        f = fopen(KEYFILE, "r+b");
        if (!f) return -1;
        fseek(f, 64, SEEK_SET);
        fwrite(d, 1, 32, f);
        fclose(f);
        printf("disco key   : generated and appended\n");
    }
    return 0;
}

static void print_peer(void *ctx, const ts_peer *p) {
    int i;
    (void)ctx;
    printf("  peer %-28s %s\n", p->name[0] ? p->name : "(unnamed)",
           p->has_online ? (p->online ? "online" : "offline") : "");
    for (i = 0; i < p->naddrs; i++)     printf("       addr     %s\n", p->addrs[i]);
    for (i = 0; i < p->nendpoints; i++)
        printf("       endpoint %-42s (score %u)\n", p->endpoints[i], p->endpoint_score[i]);
    if (p->dropped_endpoints) printf("       (%d weaker endpoints discarded)\n", p->dropped_endpoints);
    if (p->home_derp) printf("       DERP     region %u\n", p->home_derp);
    printf("       keys     node=%s disco=%s\n",
           p->has_node_key ? "yes" : "NO", p->has_disco_key ? "yes" : "no");
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "controlplane.tailscale.com";
    const char *port = argc > 2 ? argv[2] : "80";
    uint8_t machine_priv[32], node_priv[32], disco_priv[32];
    uint8_t node_pub[32], disco_pub[32], control_pub[32], eph_priv[32];
    posix_io pio;
    ts_control tc;
    ts_map_req req;
    ts_netmap_parser parser;
    int rc, status = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (load_keys(machine_priv, node_priv, disco_priv) != 0) {
        fprintf(stderr, "no %s - run register_test first\n", KEYFILE);
        return 1;
    }
    x25519_base(node_pub, node_priv);
    x25519_base(disco_pub, disco_priv);
    if (posix_random(eph_priv, 32) != 0) return 1;
    ts2021_parse_hex32(control_pub, TS2021_TAILSCALE_CONTROL_KEY);

    if (posix_io_connect(&pio, host, port) != 0) { fprintf(stderr, "connect failed\n"); return 1; }
    rc = ts_control_connect(&tc, &pio.io, host, machine_priv, control_pub, eph_priv);
    if (rc != 0) { fprintf(stderr, "control connect failed (%d)\n", rc); return 1; }
    printf("noise + h2  : up\n");

    ts_netmap_parser_init(&parser, print_peer, NULL);
    memset(&req, 0, sizeof(req));
    req.node_pub = node_pub;
    req.disco_pub = disco_pub;
    req.hostname = "tsesp";
    req.stream = 0;

    printf("fetching netmap...\n\n");
    rc = ts_control_map(&tc, &req, &parser, &status);
    printf("\nmap         : rc=%d http=%d messages=%d\n",
           rc, status, parser.info.message_count);
    if (rc != 0) { posix_io_close(&pio); return 1; }

    printf("\nTHIS DEVICE\n");
    printf("  name    : %s\n", parser.info.self_name);
    {
        int i;
        for (i = 0; i < parser.info.self_naddrs; i++)
            printf("  address : %s\n", parser.info.self_addrs[i]);
    }
    if (parser.info.domain[0]) printf("  tailnet : %s\n", parser.info.domain);
    printf("  peers   : %d\n", parser.info.peer_count);

    posix_io_close(&pio);
    return 0;
}
