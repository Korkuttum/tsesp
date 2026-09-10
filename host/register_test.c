// Full stack against a real control server: TCP -> ts2021 -> HTTP/2 ->
// POST /machine/register.
//
// Without an auth key the server just hands back a login URL. Nothing is
// created in anyone's tailnet unless a human chooses to open that URL, so
// this is safe to run.
//
//   ./register_test [host] [port]
//   TSESP_AUTHKEY=tskey-auth-...  to register non-interactively
//   TSESP_FOLLOWUP=<url>          to block until the login is approved
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "posix_io.h"
#include "ts_control.h"
#include "tscrypto.h"

#define KEYFILE "tsesp-keys.bin"

// Machine key identifies the device to the control plane; node key identifies
// it inside the tailnet. Both must survive a reboot, so on the ESP32 these
// land in NVS instead of a file.
static int load_or_create_keys(uint8_t machine_priv[32], uint8_t node_priv[32]) {
    FILE *f = fopen(KEYFILE, "rb");
    if (f) {
        int ok = fread(machine_priv, 1, 32, f) == 32 &&
                 fread(node_priv, 1, 32, f) == 32;
        fclose(f);
        if (ok) { printf("keys        : loaded from %s\n", KEYFILE); return 0; }
    }
    if (posix_random(machine_priv, 32) != 0 || posix_random(node_priv, 32) != 0)
        return -1;
    x25519_clamp(machine_priv);
    x25519_clamp(node_priv);
    f = fopen(KEYFILE, "wb");
    if (!f) return -1;
    fwrite(machine_priv, 1, 32, f);
    fwrite(node_priv, 1, 32, f);
    fclose(f);
    printf("keys        : generated, saved to %s\n", KEYFILE);
    return 0;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "controlplane.tailscale.com";
    const char *port = argc > 2 ? argv[2] : "80";
    const char *authkey = getenv("TSESP_AUTHKEY");
    const char *followup = getenv("TSESP_FOLLOWUP");

    uint8_t machine_priv[32], node_priv[32], node_pub[32];
    uint8_t control_pub[32], eph_priv[32];
    posix_io pio;
    ts_control tc;
    ts_register_req req;
    ts_register_resp resp;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (load_or_create_keys(machine_priv, node_priv) != 0) {
        fprintf(stderr, "key setup failed\n");
        return 1;
    }
    x25519_base(node_pub, node_priv);
    if (posix_random(eph_priv, 32) != 0) return 1;
    if (ts2021_parse_hex32(control_pub, TS2021_TAILSCALE_CONTROL_KEY) != 0) return 1;

    printf("target      : %s:%s\n", host, port);
    if (posix_io_connect(&pio, host, port) != 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }

    printf("upgrade     : POST /ts2021 ...\n");
    rc = ts_control_connect(&tc, &pio.io, host, machine_priv, control_pub, eph_priv);
    if (rc != 0) {
        fprintf(stderr, "control connect failed (%d)\n", rc);
        posix_io_close(&pio);
        return 1;
    }
    printf("noise + h2  : up (peer max frame %u, window %u)\n",
           tc.h2.peer_max_frame, tc.h2.peer_initial_window);

    memset(&req, 0, sizeof(req));
    req.node_pub = node_pub;
    req.hostname = "tsesp";
    req.auth_key = authkey;
    req.followup = followup;

    rc = ts_control_register(&tc, &req, &resp);
    printf("register    : rc=%d http=%d\n", rc, resp.http_status);
    if (rc != 0) {
        if (resp.error[0]) fprintf(stderr, "server error: %s\n", resp.error);
        posix_io_close(&pio);
        return 1;
    }

    if (resp.error[0])        printf("  Error            : %s\n", resp.error);
    if (resp.login_name[0])   printf("  Login            : %s\n", resp.login_name);
    if (resp.user_display[0]) printf("  User             : %s\n", resp.user_display);
    printf("  MachineAuthorized: %s\n", resp.machine_authorized ? "yes" : "no");
    printf("  NodeKeyExpired   : %s\n", resp.node_key_expired ? "yes" : "no");

    if (resp.auth_url[0]) {
        printf("\nLOGIN URL (this is what the ESP32 will show on its screen):\n  %s\n",
               resp.auth_url);
        printf("\nNothing has been added to any tailnet. Open that URL only if you\n"
               "want this device to join, then re-run with TSESP_FOLLOWUP set to it.\n");
    } else if (resp.machine_authorized) {
        printf("\nREGISTERED. The node is live in the tailnet.\n");
    }

    posix_io_close(&pio);
    return 0;
}
