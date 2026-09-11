// tsesp: a Tailscale node on an ESP32-WROOM-32U.
//
// Boot order is deliberate. Wi-Fi first, because without it nothing else can
// happen and because the setup portal is how credentials get in. Then the
// identity from flash, then the control plane, driven by the same state
// machine the host tests exercise.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_random.h"
#include <time.h>
#include "nvs_flash.h"
#include "esp_sntp.h"

#include "tscrypto.h"
#include "ts2021.h"
#include "ts_control.h"
#include "ts_client.h"
#include "tsesp_selftest.h"
#include "esp_io.h"
#include "net.h"
#include "device_nvs.h"
#include "peers.h"
#include "magic.h"
#include "derp_task.h"
#include "tun.h"
#include "lwip/lwip_napt.h"
#include "esp_netif.h"
#include "lwip/inet.h"

static const char *TAG = "tsesp";

#define CONTROL_HOST "controlplane.tailscale.com"
#define CONTROL_PORT "80"
// Experiment: what the request body claims, separate from the Noise
// handshake version. Lower values ask control to behave like it would
// for a client that cannot exchange endpoints over DERP.
#ifndef TSESP_MAP_CAPVER
#define TSESP_MAP_CAPVER 0    /* 0 = use the protocol version */
#endif
// A streaming map session sits idle between updates; the server sends a
// keep-alive well inside this.
#define SOCKET_TIMEOUT_S 120

static uint8_t s_machine[32], s_node_priv[32], s_disco_priv[32];
static uint8_t s_node_pub[32], s_disco_pub[32], s_control_pub[32];

static ts_control     *s_tc;          // 13.5 KB: heap, never the stack
static esp_io          s_io;
static ts_netmap_parser s_netmap;
static ts_client       s_client;

static char s_tailnet_addr[48];
static char s_login_url[TS_AUTH_URL_MAX];
static bool s_stun_done;
static volatile bool s_push_wanted;
static uint32_t s_last_push_ms;
static char s_local_ep[32];      // 192.168.x.y:41641
static char s_route[24];         // the LAN we offer to route for
static bool s_napt_on;
static char s_public_ep[52];     // what STUN told us, if anything

static void log_request_body(const char *body, size_t len) {
    // Split across lines: the log macro truncates long messages.
    size_t i;
    ESP_LOGI(TAG, "MapRequest (%u bytes):", (unsigned)len);
    for (i = 0; i < len; i += 120)
        ESP_LOGI(TAG, "  %.*s", (int)(len - i > 120 ? 120 : len - i), body + i);
}

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

static void publish_status(const char *state) {
    portal_status st = {
        .state = state,
        .tailnet_addr = s_tailnet_addr,
        .login_url = s_login_url,
        .peers = peers_count(),
        .paths_up = magic_paths_up(),
        .free_heap = (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
    };
    portal_set_status(&st);
}

// ------------------------------------------------------------ control plane

static void on_peer(void *ctx, const ts_peer *p) {
    peer_entry *e;
    (void)ctx;

    // Merge rather than replace: an incremental update carries the peer's
    // identity and little else, and overwriting would drop its endpoints.
    e = peers_upsert(p);
    if (!e) return;
    ESP_LOGI(TAG, "peer %-36s %s  %-19s endpoints=%d%s",
             e->name[0] ? e->name : "(unnamed)",
             e->online ? "online " : "offline",
             e->addr[0] ? e->addr : "-",
             e->nendpoints, p->from_changed ? "  (update)" : "");
}

static void on_peer_removed(void *ctx, uint64_t id) {
    (void)ctx;
    ESP_LOGI(TAG, "peer %llu left the tailnet", (unsigned long long)id);
    peers_remove(id);
}

static int on_netmap_message(void *ctx, const ts_netmap_info *info) {
    (void)ctx;

    // The map request carries our home relay, and it was not known when this
    // session opened. Ending the session makes the next one report it.
    // Once the relay is up we know our home region, which is part of what
    // control needs. Ending this session is the simplest way to get back to
    // a point where a second connection can be opened safely.
    if (derp_task_take_changed() && derp_task_region()) {
        ESP_LOGI(TAG, "relay up; will report our endpoints");
        s_push_wanted = true;
        return 1;
    }
    if (info->self_naddrs)
        snprintf(s_tailnet_addr, sizeof(s_tailnet_addr), "%s", info->self_addrs[0]);
    // The relay hostnames only exist inside the netmap, so this is the first
    // moment the device knows where to connect.
    if (info->nderp > 0 && info->derp[0].host[0])
        derp_task_set_region(info->derp[0].region_id, info->derp[0].host,
                             info->derp[0].code);

    // Hand the freshly merged table to path discovery, then let it probe.
    magic_sync_peers();

    // Only a message that restates our own record says anything about this;
    // an incremental update carries peers only.
    // Our own tailnet address arrives with the netmap, and the interface
    // cannot exist before we know it.
    if (info->self_naddrs && !tun_is_up()) {
        unsigned a, b, c, d;
        if (sscanf(info->self_addrs[0], "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            uint32_t ip = (uint32_t)a | ((uint32_t)b << 8) |
                          ((uint32_t)c << 16) | ((uint32_t)d << 24);
            tun_start(ip, magic_tun_sender());
        }
    }

    if (info->self_naddrs) {
        int i;
        for (i = 0; i < info->self_nendpoints; i++)
            ESP_LOGI(TAG, "control plane lists us at %s", info->self_endpoints[i]);
        if (!info->self_nendpoints)
            ESP_LOGW(TAG, "control plane lists no endpoints for us; peers have "
                          "no address to reach this device at");
    }

    ESP_LOGI(TAG, "netmap #%d: %s, %d peers known, heap %u",
             info->message_count,
             info->self_name[0] ? info->self_name : "(no name yet)",
             peers_count(),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

    // One STUN lookup, from the same socket DISCO uses, so the address we
    // learn is the mapping that socket actually has.
    if (!s_stun_done) {
        s_stun_done = true;
        magic_request_stun();
    }

    publish_status("running");
    return 0;      // keep the session open
}

static int open_control(void) {
    uint8_t eph[32];

    esp_io_close(&s_io);
    if (esp_io_connect(&s_io, CONTROL_HOST, CONTROL_PORT, SOCKET_TIMEOUT_S) != 0)
        return -1;

    esp_fill_random(eph, sizeof(eph));
    if (ts_control_connect(s_tc, &s_io.io, CONTROL_HOST,
                           s_machine, s_control_pub, eph) != 0) {
        esp_io_close(&s_io);
        return -1;
    }
    return 0;
}

static ts_result do_register(const char *followup) {
    ts_register_req req = {0};
    ts_register_resp resp;
    int rc;

    req.node_pub = s_node_pub;
    req.hostname = "tsesp";
    req.followup = followup;

    rc = ts_control_register(s_tc, &req, &resp);
    if (rc != 0) {
        if (resp.http_status == 429) return TS_ERR_RATE_LIMITED;
        if (resp.error[0]) ESP_LOGW(TAG, "register: %s", resp.error);
        return TS_ERR_TRANSPORT;
    }
    if (resp.auth_url[0]) {
        snprintf(s_login_url, sizeof(s_login_url), "%s", resp.auth_url);
        return TS_ERR_NEEDS_LOGIN;
    }
    if (resp.machine_authorized) {
        s_login_url[0] = '\0';
        ESP_LOGI(TAG, "registered as %s", resp.login_name);
        device_set_registered(true);
        return TS_OK;
    }
    return TS_ERR_AUTH;
}

// Our own addresses, as peers should try them: the one on this LAN, and the
// one the world sees. Without these the control plane hands peers nothing and
// no one can start a conversation with this device.
static void collect_endpoints(ts_map_req *req) {
    esp_netif_ip_info_t ip;
    esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");

    req->nendpoints = 0;
    if (nif && esp_netif_get_ip_info(nif, &ip) == ESP_OK && ip.ip.addr) {
        snprintf(s_local_ep, sizeof(s_local_ep), IPSTR ":%d",
                 IP2STR(&ip.ip), MAGIC_PORT);
        req->endpoints[req->nendpoints++] = s_local_ep;
    }
    if (magic_get_public(s_public_ep, sizeof(s_public_ep)) && s_public_ep[0])
        req->endpoints[req->nendpoints++] = s_public_ep;
}

// Tells control where we are, on its own short-lived connection. The
// streaming session stays open; this is the request shape tailcfg documents
// for exactly that.
static void push_endpoints(void) {
    ts_map_req req;
    ts_control *tc;
    esp_io io;
    uint8_t eph[32];
    int status = 0, rc;

    tc = calloc(1, sizeof(*tc));
    if (!tc) return;
    io.fd = -1;

    if (esp_io_connect(&io, CONTROL_HOST, CONTROL_PORT, 20) != 0) { free(tc); return; }
    esp_fill_random(eph, sizeof(eph));
    if (ts_control_connect(tc, &io.io, CONTROL_HOST, s_machine, s_control_pub, eph) != 0) {
        esp_io_close(&io);
        free(tc);
        return;
    }

    memset(&req, 0, sizeof(req));
    req.node_pub = s_node_pub;
    req.disco_pub = s_disco_pub;
    req.hostname = "tsesp";
    req.preferred_derp = derp_task_region();
    req.working_udp = 1;
    collect_endpoints(&req);
    if (s_route[0]) {
        req.routes[0] = s_route;
        req.nroutes = 1;
    }

    rc = ts_control_update_endpoints(tc, &req, &status);
    ESP_LOGI(TAG, "endpoint update: rc=%d http=%d, %d endpoint(s), derp %u, routes %s",
             rc, status, req.nendpoints, derp_task_region(),
             req.nroutes ? req.routes[0] : "none");

    esp_io_close(&io);
    free(tc);
}

static ts_result do_map(void) {
    ts_map_req req = {0};
    int rc, status = 0;

    req.node_pub = s_node_pub;
    req.disco_pub = s_disco_pub;
    req.hostname = "tsesp";
    req.stream = 1;
    // Region 4 is what every other node in this tailnet uses. We cannot
    // actually relay through it yet, so this is provisional: it exists to
    // make the control plane treat us as a reachable node and hand our disco
    // key to peers. Once DERP is implemented this becomes a measured value.
    req.capver = TSESP_MAP_CAPVER;
    req.preferred_derp = derp_task_region();
    req.working_udp = 1;
    if (s_route[0]) {
        req.routes[0] = s_route;
        req.nroutes = 1;
    }
    collect_endpoints(&req);
    if (s_route[0]) {
        req.routes[0] = s_route;
        req.nroutes = 1;
    }
    if (req.nendpoints)
        ESP_LOGI(TAG, "advertising %d endpoint(s): %s%s%s", req.nendpoints,
                 req.endpoints[0],
                 req.nendpoints > 1 ? ", " : "",
                 req.nendpoints > 1 ? req.endpoints[1] : "");

    ts_netmap_parser_init(&s_netmap, on_peer, NULL);
    ts_netmap_parser_on_message(&s_netmap, on_netmap_message);
    ts_netmap_parser_on_removed(&s_netmap, on_peer_removed);

    rc = ts_control_map(s_tc, &req, &s_netmap, &status);
    ESP_LOGW(TAG, "map session ended rc=%d http=%d", rc, status);
    if (status == 401 || status == 403) return TS_ERR_AUTH;
    return rc == 0 ? TS_OK : TS_ERR_TRANSPORT;
}

static void control_task(void *arg) {
    (void)arg;

    for (;;) {
        ts_action act = ts_client_next(&s_client, now_ms());
        ts_result res = TS_OK;

        switch (act.kind) {
        case TS_ACT_WAIT:
            publish_status(ts_client_state_name(s_client.state));
            // Real clients re-announce as their addresses change; doing it
            // on a timer also covers a relay that came up after the last one.
            if (s_push_wanted ||
                (uint32_t)(now_ms() - s_last_push_ms) > 60000) {
                s_push_wanted = false;
                s_last_push_ms = now_ms();
                push_endpoints();
            }
            vTaskDelay(pdMS_TO_TICKS(act.wait_ms ? act.wait_ms : 200));
            continue;

        case TS_ACT_CONNECT:
            publish_status("connecting");
            ESP_LOGI(TAG, "connecting to %s:%s", CONTROL_HOST, CONTROL_PORT);
            res = open_control() == 0 ? TS_OK : TS_ERR_TRANSPORT;
            if (res == TS_OK) ESP_LOGI(TAG, "control channel up (noise + http/2)");
            break;

        case TS_ACT_REGISTER:
            publish_status("registering");
            res = do_register(NULL);
            break;

        case TS_ACT_SHOW_LOGIN:
            ESP_LOGW(TAG, "");
            ESP_LOGW(TAG, "  ==> approve this device:  %s", act.login_url);
            ESP_LOGW(TAG, "      (also on the device's own status page)");
            ESP_LOGW(TAG, "");
            publish_status("waiting for login");
            continue;                       // no result to report

        case TS_ACT_POLL_LOGIN:
            // Followup re-opens the request and blocks server-side until a
            // human clicks, so the connection has to be fresh each time.
            if (open_control() != 0) { res = TS_ERR_TRANSPORT; break; }
            res = do_register(act.login_url);
            break;

        case TS_ACT_MAP:
            publish_status("fetching netmap");
            res = do_map();
            break;

        case TS_ACT_STOP:
            publish_status("stopped");
            ESP_LOGE(TAG, "stopped; fix the problem and reboot");
            vTaskDelay(pdMS_TO_TICKS(10000));
            continue;
        }

        ts_client_report(&s_client, act.kind, res, s_login_url, now_ms());
        if (res != TS_OK) esp_io_close(&s_io);
    }
}

// -------------------------------------------------------------------- boot

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    printf("\n=== tsesp ===\n");
    if (tsesp_crypto_selftest() != 0) {
        // Refusing to run is the right answer: a device whose crypto is wrong
        // would fail in ways that look like network problems.
        ESP_LOGE(TAG, "crypto self-test failed; refusing to continue");
        while (1) vTaskDelay(pdMS_TO_TICKS(10000));
    }

    if (!net_start()) {
        char ssid[24];
        net_get_ap_ssid(ssid, sizeof(ssid));
        portal_start(true);
        ESP_LOGW(TAG, "");
        ESP_LOGW(TAG, "  ==> join wifi \"%s\" and the setup page should open", ssid);
        ESP_LOGW(TAG, "      or browse to http://192.168.4.1/");
        ESP_LOGW(TAG, "");
        while (1) vTaskDelay(pdMS_TO_TICKS(10000));
    }

    portal_start(false);

    // WireGuard timestamps need a real clock, and so does certificate
    // validation. Both fail quietly with a 1970 date.
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();
    {
        int tries;
        time_t t = 0;
        for (tries = 0; tries < 20; tries++) {
            time(&t);
            if (t > 1700000000) break;
            vTaskDelay(pdMS_TO_TICKS(500));
        }
        ESP_LOGI(TAG, "clock: %s", t > 1700000000 ? "set from ntp" : "NOT SET");
    }

    // Scoring a peer's endpoints needs to know which network we are on: an
    // address on this same LAN is worth more than any public one. The route
    // we offer comes from the same place.
    {
        esp_netif_ip_info_t ip;
        esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (nif && esp_netif_get_ip_info(nif, &ip) == ESP_OK) {
            uint32_t host_order = ntohl(ip.ip.addr);
            uint32_t mask = ntohl(ip.netmask.addr);
            uint8_t v4[4], net[4];
            int prefix = 0;

            v4[0] = (uint8_t)(host_order >> 24); v4[1] = (uint8_t)(host_order >> 16);
            v4[2] = (uint8_t)(host_order >> 8);  v4[3] = (uint8_t)host_order;

            // Read the prefix length off the interface rather than assuming
            // /24. Plenty of routers hand out something else, and a wrong
            // prefix means advertising a route that does not match the LAN.
            while (prefix < 32 && (mask & (0x80000000u >> prefix))) prefix++;
            if (prefix == 0 || prefix > 30) prefix = 24;   // nothing sane: fall back

            ts_netmap_set_local_v4(v4, (uint8_t)prefix);

            {
                uint32_t network = host_order & mask;
                net[0] = (uint8_t)(network >> 24); net[1] = (uint8_t)(network >> 16);
                net[2] = (uint8_t)(network >> 8);  net[3] = (uint8_t)network;
                snprintf(s_route, sizeof(s_route), "%u.%u.%u.%u/%d",
                         net[0], net[1], net[2], net[3], prefix);
            }
            ESP_LOGI(TAG, "local network %s (this device is %u.%u.%u.%u)",
                     s_route, v4[0], v4[1], v4[2], v4[3]);

            // Masquerade forwarded packets as coming from this device, so a
            // LAN machine that knows nothing about the tailnet still knows
            // where to send its replies.
            ip_napt_enable(ip.ip.addr, 1);
            s_napt_on = true;
            ESP_LOGI(TAG, "subnet routing ready for %s "
                          "(approve the route in the admin console)", s_route);
        }
    }

    ESP_ERROR_CHECK(device_keys_load(s_machine, s_node_priv, s_disco_priv));
    x25519_base(s_node_pub, s_node_priv);
    x25519_base(s_disco_pub, s_disco_priv);
    if (ts2021_parse_hex32(s_control_pub, TS2021_TAILSCALE_CONTROL_KEY) != 0) {
        ESP_LOGE(TAG, "bad pinned control key");
        return;
    }

    s_tc = calloc(1, sizeof(*s_tc));
    if (!s_tc) {
        ESP_LOGE(TAG, "out of memory for the control channel");
        return;
    }
    s_io.fd = -1;
    if (0) ts_control_debug_body = log_request_body;  /* flip to trace requests */

    // Seed the retry jitter from our own node key so two devices on the same
    // network do not retry in lockstep.
    ts_client_init(&s_client, device_is_registered(),
                   ((uint32_t)s_node_pub[0] << 24) | ((uint32_t)s_node_pub[1] << 16) |
                   ((uint32_t)s_node_pub[2] << 8) | s_node_pub[3]);

    ESP_LOGI(TAG, "identity ready, %s",
             device_is_registered() ? "already registered" : "not yet registered");
    if (magic_start(s_disco_priv, s_node_pub, s_node_priv) != 0)
        ESP_LOGE(TAG, "could not open the udp socket; no direct paths possible");
    derp_task_start(s_node_priv, s_node_pub);

    ESP_LOGI(TAG, "free heap before control plane: %u",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

    xTaskCreate(control_task, "control", 8192, NULL, 5, NULL);
}
