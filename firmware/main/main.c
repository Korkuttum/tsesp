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
#include "nvs_flash.h"

#include "tscrypto.h"
#include "ts2021.h"
#include "ts_control.h"
#include "ts_client.h"
#include "tsesp_selftest.h"
#include "esp_io.h"
#include "net.h"
#include "device_nvs.h"

static const char *TAG = "tsesp";

#define CONTROL_HOST "controlplane.tailscale.com"
#define CONTROL_PORT "80"
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
static int  s_peer_count;

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

static void publish_status(const char *state) {
    portal_status st = {
        .state = state,
        .tailnet_addr = s_tailnet_addr,
        .login_url = s_login_url,
        .peers = s_peer_count,
        .paths_up = 0,
        .free_heap = (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
    };
    portal_set_status(&st);
}

// ------------------------------------------------------------ control plane

static void on_peer(void *ctx, const ts_peer *p) {
    (void)ctx;
    s_peer_count++;
    ESP_LOGI(TAG, "peer %-34s %s  %s  endpoints=%d derp=%u",
             p->name[0] ? p->name : "(unnamed)",
             p->has_online ? (p->online ? "online " : "offline") : "       ",
             p->naddrs ? p->addrs[0] : "-",
             p->nendpoints, p->home_derp);
}

static int on_netmap_message(void *ctx, const ts_netmap_info *info) {
    (void)ctx;
    if (info->self_naddrs)
        snprintf(s_tailnet_addr, sizeof(s_tailnet_addr), "%s", info->self_addrs[0]);
    ESP_LOGI(TAG, "netmap #%d: %s, %d peers, heap %u",
             info->message_count,
             info->self_name[0] ? info->self_name : "(no name yet)",
             info->peer_count,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
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

static ts_result do_map(void) {
    ts_map_req req = {0};
    int rc, status = 0;

    req.node_pub = s_node_pub;
    req.disco_pub = s_disco_pub;
    req.hostname = "tsesp";
    req.stream = 1;

    s_peer_count = 0;
    ts_netmap_parser_init(&s_netmap, on_peer, NULL);
    ts_netmap_parser_on_message(&s_netmap, on_netmap_message);

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

    // Seed the retry jitter from our own node key so two devices on the same
    // network do not retry in lockstep.
    ts_client_init(&s_client, device_is_registered(),
                   ((uint32_t)s_node_pub[0] << 24) | ((uint32_t)s_node_pub[1] << 16) |
                   ((uint32_t)s_node_pub[2] << 8) | s_node_pub[3]);

    ESP_LOGI(TAG, "identity ready, %s",
             device_is_registered() ? "already registered" : "not yet registered");
    ESP_LOGI(TAG, "free heap before control plane: %u",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

    xTaskCreate(control_task, "control", 8192, NULL, 5, NULL);
}
